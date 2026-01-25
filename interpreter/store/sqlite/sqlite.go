// Package sqlite provides a SQLite implementation of the program store.
//
// # Calling Conventions
//
// This store is a pure data access layer with no internal transaction management.
// Individual methods execute against s.conn, which may be either the underlying
// *sql.DB (autocommit mode) or a *sql.Tx (transactional mode).
//
// For operations that require atomicity across multiple calls, use RunInTransaction:
//
//	err := store.RunInTransaction(ctx, func(txStore interpreter.Store) error {
//	    if err := txStore.Save(ctx, id, prog); err != nil {
//	        return err // triggers rollback
//	    }
//	    return txStore.SaveTracepointLink(ctx, summary, details) // commits if nil
//	})
//
// # Autocommit Behaviour
//
// When methods are called outside a transaction (directly on the store), each
// SQL statement executes in its own implicit transaction that commits immediately
// upon completion. This means:
//
//   - Single-statement methods (Get, Delete, List) are atomic by themselves.
//   - Multi-statement methods (Save, Save*Link) are NOT atomic: if the second
//     statement fails, the first statement's changes are already committed.
//     For example, Save inserts the program, then deletes old metadata index
//     entries, then inserts new ones. A failure partway through leaves partial
//     state.
//
// # Reader/Writer Implications
//
// The database is opened with WAL (Write-Ahead Logging) mode, which provides:
//
//   - Readers do not block writers; writers do not block readers.
//   - A reader sees a consistent snapshot from when its transaction (or
//     statement in autocommit mode) began.
//   - Without an explicit transaction, consecutive reads may see changes from
//     concurrent writers between reads. Use RunInTransaction for consistent
//     multi-read operations.
//
// # When to Use RunInTransaction
//
// Use RunInTransaction when you need:
//
//   - Atomicity: all-or-nothing semantics across multiple operations
//   - Consistency: read-your-writes within a sequence of operations
//   - Isolation: a stable view of data across multiple reads
//
// The caller (typically the manager or executor layer) decides atomicity
// requirements based on the operation being performed.
//
// # Concurrency Model
//
// The application layer (manager) serialises access via an RWMutex: multiple
// readers can proceed concurrently, but writers get exclusive access. This
// means there is no concurrent writer contention at the database level.
//
// SQLite transactions use the default DEFERRED type, which is sufficient
// given the application-level serialisation. The transaction provides
// atomicity and rollback semantics, not concurrent writer coordination.
//
// WAL mode is enabled for better crash recovery and write performance,
// though its concurrency benefits (readers don't block writers) are
// secondary given the RWMutex already coordinates access.
//
// # SQLite Transaction Types
//
// SQLite supports three transaction types, specified at BEGIN:
//
//   - DEFERRED (default): No locks are acquired until the first read or write.
//     A read acquires a SHARED lock (allowing other readers). A write acquires
//     a RESERVED lock (blocking other writers but allowing readers), then an
//     EXCLUSIVE lock at commit time. Risk: a read-then-write transaction may
//     fail at write time if another connection acquired a write lock in between.
//
//   - IMMEDIATE: Acquires a RESERVED lock immediately when the transaction
//     begins, blocking other writers but allowing readers. Guarantees that
//     writes will succeed (no "database is locked" errors mid-transaction).
//     Preferred for transactions that will write, but Go's database/sql does
//     not expose this directly.
//
//   - EXCLUSIVE: Acquires an EXCLUSIVE lock immediately, blocking all other
//     connections (readers and writers). Rarely needed; mainly useful when
//     you need to guarantee no other connection accesses the database at all.
//
// This implementation uses DEFERRED because: (1) Go's database/sql does not
// expose SQLite-specific transaction types, and (2) the application-level
// RWMutex already prevents concurrent writers, making IMMEDIATE unnecessary.
//
// # Prepared Statements
//
// All SQL queries use prepared statements rather than inline SQL strings.
// When a query is executed with an inline string (e.g., db.QueryContext(ctx,
// "SELECT ...")), SQLite must parse the SQL text, validate it, and generate
// a query plan on every call. Prepared statements move this work to
// initialisation time: the SQL is parsed and compiled once, and subsequent
// executions reuse the compiled representation.
//
// Benefits:
//
//   - Reduced CPU overhead: parsing and planning happen once, not per-query
//   - Predictable latency: no parsing jitter during normal operations
//   - Cleaner code: SQL is defined in one place (prepareStatements) rather
//     than scattered across methods
//
// The cost is modest additional complexity in managing statement lifecycles,
// particularly for transactions where tx.StmtContext must create transaction-
// bound handles from the master statements. See RunInTransaction for details.
package sqlite

import (
	"context"
	"database/sql"
	_ "embed"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/frobware/go-bpfman"
	"github.com/frobware/go-bpfman/dispatcher"
	"github.com/frobware/go-bpfman/interpreter"
	"github.com/frobware/go-bpfman/interpreter/store"
)

// msec formats a duration as milliseconds with 3 decimal places.
func msec(d time.Duration) string {
	return fmt.Sprintf("%.3f", float64(d.Microseconds())/1000)
}

//go:embed schema.sql
var schemaSQL string

// dbConn abstracts *sql.DB and *sql.Tx for query execution.
type dbConn interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// sqliteStore implements interpreter.Store using SQLite.
type sqliteStore struct {
	db     *sql.DB // original connection, used for BeginTx
	conn   dbConn  // active connection (db or tx)
	logger *slog.Logger

	// Prepared statements for program operations
	stmtGetProgram                 *sql.Stmt
	stmtSaveProgram                *sql.Stmt
	stmtDeleteProgramMetadataIndex *sql.Stmt
	stmtInsertProgramMetadataIndex *sql.Stmt
	stmtDeleteProgram              *sql.Stmt
	stmtListPrograms               *sql.Stmt
	stmtFindProgramByMetadata      *sql.Stmt
	stmtFindAllProgramsByMetadata  *sql.Stmt

	// Prepared statements for program tags
	stmtInsertTag  *sql.Stmt
	stmtDeleteTags *sql.Stmt

	// Prepared statements for link registry operations
	stmtDeleteLink         *sql.Stmt
	stmtGetLinkRegistry    *sql.Stmt
	stmtListLinks          *sql.Stmt
	stmtListLinksByProgram *sql.Stmt
	stmtInsertLinkRegistry *sql.Stmt

	// Prepared statements for link detail queries
	stmtGetTracepointDetails *sql.Stmt
	stmtGetKprobeDetails     *sql.Stmt
	stmtGetUprobeDetails     *sql.Stmt
	stmtGetFentryDetails     *sql.Stmt
	stmtGetFexitDetails      *sql.Stmt
	stmtGetXDPDetails        *sql.Stmt
	stmtGetTCDetails         *sql.Stmt
	stmtGetTCXDetails        *sql.Stmt

	// Prepared statements for link detail inserts
	stmtSaveTracepointDetails *sql.Stmt
	stmtSaveKprobeDetails     *sql.Stmt
	stmtSaveUprobeDetails     *sql.Stmt
	stmtSaveFentryDetails     *sql.Stmt
	stmtSaveFexitDetails      *sql.Stmt
	stmtSaveXDPDetails        *sql.Stmt
	stmtSaveTCDetails         *sql.Stmt
	stmtSaveTCXDetails        *sql.Stmt

	// Prepared statements for dispatcher operations
	stmtGetDispatcher       *sql.Stmt
	stmtSaveDispatcher      *sql.Stmt
	stmtDeleteDispatcher    *sql.Stmt
	stmtIncrementRevision   *sql.Stmt
	stmtGetDispatcherByType *sql.Stmt
}

// New creates a new SQLite store at the given path.
func New(dbPath string, logger *slog.Logger) (interpreter.Store, error) {
	if logger == nil {
		logger = slog.Default()
	}
	logger = logger.With("component", "store", "db", dbPath)

	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create database directory: %w", err)
	}

	db, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	s := &sqliteStore{db: db, conn: db, logger: logger}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to migrate database: %w", err)
	}
	if err := s.prepareStatements(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to prepare statements: %w", err)
	}

	logger.Info("opened database", "path", dbPath)
	return s, nil
}

// NewInMemory creates an in-memory SQLite store for testing.
func NewInMemory(logger *slog.Logger) (interpreter.Store, error) {
	if logger == nil {
		logger = slog.Default()
	}
	logger = logger.With("component", "store", "db", ":memory:")

	db, err := sql.Open("sqlite", ":memory:?_pragma=foreign_keys(1)")
	if err != nil {
		return nil, fmt.Errorf("failed to open in-memory database: %w", err)
	}

	s := &sqliteStore{db: db, conn: db, logger: logger}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to migrate database: %w", err)
	}
	if err := s.prepareStatements(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to prepare statements: %w", err)
	}

	logger.Info("opened in-memory database")
	return s, nil
}

// Close closes the database connection.
func (s *sqliteStore) Close() error {
	return s.db.Close()
}

func (s *sqliteStore) migrate() error {
	// Execute the embedded schema
	if _, err := s.db.Exec(schemaSQL); err != nil {
		return fmt.Errorf("failed to execute schema: %w", err)
	}
	return nil
}

// prepareStatements prepares all SQL statements for reuse.
func (s *sqliteStore) prepareStatements() error {
	if err := s.prepareProgramStatements(); err != nil {
		return err
	}
	if err := s.prepareLinkRegistryStatements(); err != nil {
		return err
	}
	if err := s.prepareLinkDetailStatements(); err != nil {
		return err
	}
	return s.prepareDispatcherStatements()
}

func (s *sqliteStore) prepareProgramStatements() error {
	var err error

	const sqlGetProgram = `
		SELECT m.program_name, m.program_type, m.object_path, m.pin_path, m.attach_func,
		       m.global_data, m.map_owner_id, m.image_source, m.owner, m.description, m.created_at,
		       GROUP_CONCAT(t.tag) as tags
		FROM managed_programs m
		LEFT JOIN program_tags t ON m.kernel_id = t.kernel_id
		WHERE m.kernel_id = ?
		GROUP BY m.kernel_id`
	if s.stmtGetProgram, err = s.db.Prepare(sqlGetProgram); err != nil {
		return fmt.Errorf("prepare GetProgram: %w", err)
	}

	const sqlSaveProgram = `
		INSERT OR REPLACE INTO managed_programs
		(kernel_id, program_name, program_type, object_path, pin_path, attach_func,
		 global_data, map_owner_id, image_source, owner, description, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	if s.stmtSaveProgram, err = s.db.Prepare(sqlSaveProgram); err != nil {
		return fmt.Errorf("prepare SaveProgram: %w", err)
	}

	const sqlDeleteProgramMetadataIndex = "DELETE FROM program_metadata_index WHERE kernel_id = ?"
	if s.stmtDeleteProgramMetadataIndex, err = s.db.Prepare(sqlDeleteProgramMetadataIndex); err != nil {
		return fmt.Errorf("prepare DeleteProgramMetadataIndex: %w", err)
	}

	const sqlInsertProgramMetadataIndex = "INSERT INTO program_metadata_index (kernel_id, key, value) VALUES (?, ?, ?)"
	if s.stmtInsertProgramMetadataIndex, err = s.db.Prepare(sqlInsertProgramMetadataIndex); err != nil {
		return fmt.Errorf("prepare InsertProgramMetadataIndex: %w", err)
	}

	const sqlDeleteProgram = "DELETE FROM managed_programs WHERE kernel_id = ?"
	if s.stmtDeleteProgram, err = s.db.Prepare(sqlDeleteProgram); err != nil {
		return fmt.Errorf("prepare DeleteProgram: %w", err)
	}

	const sqlListPrograms = `
		SELECT m.kernel_id, m.program_name, m.program_type, m.object_path, m.pin_path, m.attach_func,
		       m.global_data, m.map_owner_id, m.image_source, m.owner, m.description, m.created_at,
		       GROUP_CONCAT(t.tag) as tags
		FROM managed_programs m
		LEFT JOIN program_tags t ON m.kernel_id = t.kernel_id
		GROUP BY m.kernel_id`
	if s.stmtListPrograms, err = s.db.Prepare(sqlListPrograms); err != nil {
		return fmt.Errorf("prepare ListPrograms: %w", err)
	}

	const sqlFindProgramByMetadata = `
		SELECT m.kernel_id, m.program_name, m.program_type, m.object_path, m.pin_path, m.attach_func,
		       m.global_data, m.map_owner_id, m.image_source, m.owner, m.description, m.created_at,
		       GROUP_CONCAT(t.tag) as tags
		FROM managed_programs m
		JOIN program_metadata_index i ON m.kernel_id = i.kernel_id
		LEFT JOIN program_tags t ON m.kernel_id = t.kernel_id
		WHERE i.key = ? AND i.value = ?
		GROUP BY m.kernel_id
		LIMIT 1`
	if s.stmtFindProgramByMetadata, err = s.db.Prepare(sqlFindProgramByMetadata); err != nil {
		return fmt.Errorf("prepare FindProgramByMetadata: %w", err)
	}

	const sqlFindAllProgramsByMetadata = `
		SELECT m.kernel_id, m.program_name, m.program_type, m.object_path, m.pin_path, m.attach_func,
		       m.global_data, m.map_owner_id, m.image_source, m.owner, m.description, m.created_at,
		       GROUP_CONCAT(t.tag) as tags
		FROM managed_programs m
		JOIN program_metadata_index i ON m.kernel_id = i.kernel_id
		LEFT JOIN program_tags t ON m.kernel_id = t.kernel_id
		WHERE i.key = ? AND i.value = ?
		GROUP BY m.kernel_id`
	if s.stmtFindAllProgramsByMetadata, err = s.db.Prepare(sqlFindAllProgramsByMetadata); err != nil {
		return fmt.Errorf("prepare FindAllProgramsByMetadata: %w", err)
	}

	// Tag statements
	const sqlInsertTag = "INSERT INTO program_tags (kernel_id, tag) VALUES (?, ?)"
	if s.stmtInsertTag, err = s.db.Prepare(sqlInsertTag); err != nil {
		return fmt.Errorf("prepare InsertTag: %w", err)
	}

	const sqlDeleteTags = "DELETE FROM program_tags WHERE kernel_id = ?"
	if s.stmtDeleteTags, err = s.db.Prepare(sqlDeleteTags); err != nil {
		return fmt.Errorf("prepare DeleteTags: %w", err)
	}

	return nil
}

func (s *sqliteStore) prepareLinkRegistryStatements() error {
	var err error

	const sqlDeleteLink = "DELETE FROM link_registry WHERE kernel_link_id = ?"
	if s.stmtDeleteLink, err = s.db.Prepare(sqlDeleteLink); err != nil {
		return fmt.Errorf("prepare DeleteLink: %w", err)
	}

	const sqlGetLinkRegistry = `
		SELECT kernel_link_id, link_type, kernel_program_id, pin_path, created_at
		FROM link_registry WHERE kernel_link_id = ?`
	if s.stmtGetLinkRegistry, err = s.db.Prepare(sqlGetLinkRegistry); err != nil {
		return fmt.Errorf("prepare GetLinkRegistry: %w", err)
	}

	const sqlListLinks = `
		SELECT kernel_link_id, link_type, kernel_program_id, pin_path, created_at
		FROM link_registry`
	if s.stmtListLinks, err = s.db.Prepare(sqlListLinks); err != nil {
		return fmt.Errorf("prepare ListLinks: %w", err)
	}

	const sqlListLinksByProgram = `
		SELECT kernel_link_id, link_type, kernel_program_id, pin_path, created_at
		FROM link_registry WHERE kernel_program_id = ?`
	if s.stmtListLinksByProgram, err = s.db.Prepare(sqlListLinksByProgram); err != nil {
		return fmt.Errorf("prepare ListLinksByProgram: %w", err)
	}

	const sqlInsertLinkRegistry = `
		INSERT INTO link_registry (kernel_link_id, link_type, kernel_program_id, pin_path, created_at)
		VALUES (?, ?, ?, ?, ?)`
	if s.stmtInsertLinkRegistry, err = s.db.Prepare(sqlInsertLinkRegistry); err != nil {
		return fmt.Errorf("prepare InsertLinkRegistry: %w", err)
	}

	return nil
}

func (s *sqliteStore) prepareLinkDetailStatements() error {
	var err error

	// Get statements
	const sqlGetTracepointDetails = "SELECT tracepoint_group, tracepoint_name FROM tracepoint_link_details WHERE kernel_link_id = ?"
	if s.stmtGetTracepointDetails, err = s.db.Prepare(sqlGetTracepointDetails); err != nil {
		return fmt.Errorf("prepare GetTracepointDetails: %w", err)
	}

	const sqlGetKprobeDetails = "SELECT fn_name, offset, retprobe FROM kprobe_link_details WHERE kernel_link_id = ?"
	if s.stmtGetKprobeDetails, err = s.db.Prepare(sqlGetKprobeDetails); err != nil {
		return fmt.Errorf("prepare GetKprobeDetails: %w", err)
	}

	const sqlGetUprobeDetails = "SELECT target, fn_name, offset, pid, retprobe FROM uprobe_link_details WHERE kernel_link_id = ?"
	if s.stmtGetUprobeDetails, err = s.db.Prepare(sqlGetUprobeDetails); err != nil {
		return fmt.Errorf("prepare GetUprobeDetails: %w", err)
	}

	const sqlGetFentryDetails = "SELECT fn_name FROM fentry_link_details WHERE kernel_link_id = ?"
	if s.stmtGetFentryDetails, err = s.db.Prepare(sqlGetFentryDetails); err != nil {
		return fmt.Errorf("prepare GetFentryDetails: %w", err)
	}

	const sqlGetFexitDetails = "SELECT fn_name FROM fexit_link_details WHERE kernel_link_id = ?"
	if s.stmtGetFexitDetails, err = s.db.Prepare(sqlGetFexitDetails); err != nil {
		return fmt.Errorf("prepare GetFexitDetails: %w", err)
	}

	const sqlGetXDPDetails = `
		SELECT interface, ifindex, priority, position, proceed_on, netns, nsid, dispatcher_id, revision
		FROM xdp_link_details WHERE kernel_link_id = ?`
	if s.stmtGetXDPDetails, err = s.db.Prepare(sqlGetXDPDetails); err != nil {
		return fmt.Errorf("prepare GetXDPDetails: %w", err)
	}

	const sqlGetTCDetails = `
		SELECT interface, ifindex, direction, priority, position, proceed_on, netns, nsid, dispatcher_id, revision
		FROM tc_link_details WHERE kernel_link_id = ?`
	if s.stmtGetTCDetails, err = s.db.Prepare(sqlGetTCDetails); err != nil {
		return fmt.Errorf("prepare GetTCDetails: %w", err)
	}

	const sqlGetTCXDetails = `
		SELECT interface, ifindex, direction, priority, netns, nsid
		FROM tcx_link_details WHERE kernel_link_id = ?`
	if s.stmtGetTCXDetails, err = s.db.Prepare(sqlGetTCXDetails); err != nil {
		return fmt.Errorf("prepare GetTCXDetails: %w", err)
	}

	// Save statements
	const sqlSaveTracepointDetails = `
		INSERT INTO tracepoint_link_details (kernel_link_id, tracepoint_group, tracepoint_name)
		VALUES (?, ?, ?)`
	if s.stmtSaveTracepointDetails, err = s.db.Prepare(sqlSaveTracepointDetails); err != nil {
		return fmt.Errorf("prepare SaveTracepointDetails: %w", err)
	}

	const sqlSaveKprobeDetails = `
		INSERT INTO kprobe_link_details (kernel_link_id, fn_name, offset, retprobe)
		VALUES (?, ?, ?, ?)`
	if s.stmtSaveKprobeDetails, err = s.db.Prepare(sqlSaveKprobeDetails); err != nil {
		return fmt.Errorf("prepare SaveKprobeDetails: %w", err)
	}

	const sqlSaveUprobeDetails = `
		INSERT INTO uprobe_link_details (kernel_link_id, target, fn_name, offset, pid, retprobe)
		VALUES (?, ?, ?, ?, ?, ?)`
	if s.stmtSaveUprobeDetails, err = s.db.Prepare(sqlSaveUprobeDetails); err != nil {
		return fmt.Errorf("prepare SaveUprobeDetails: %w", err)
	}

	const sqlSaveFentryDetails = `
		INSERT INTO fentry_link_details (kernel_link_id, fn_name)
		VALUES (?, ?)`
	if s.stmtSaveFentryDetails, err = s.db.Prepare(sqlSaveFentryDetails); err != nil {
		return fmt.Errorf("prepare SaveFentryDetails: %w", err)
	}

	const sqlSaveFexitDetails = `
		INSERT INTO fexit_link_details (kernel_link_id, fn_name)
		VALUES (?, ?)`
	if s.stmtSaveFexitDetails, err = s.db.Prepare(sqlSaveFexitDetails); err != nil {
		return fmt.Errorf("prepare SaveFexitDetails: %w", err)
	}

	const sqlSaveXDPDetails = `
		INSERT INTO xdp_link_details (kernel_link_id, interface, ifindex, priority, position, proceed_on, netns, nsid, dispatcher_id, revision)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	if s.stmtSaveXDPDetails, err = s.db.Prepare(sqlSaveXDPDetails); err != nil {
		return fmt.Errorf("prepare SaveXDPDetails: %w", err)
	}

	const sqlSaveTCDetails = `
		INSERT INTO tc_link_details (kernel_link_id, interface, ifindex, direction, priority, position, proceed_on, netns, nsid, dispatcher_id, revision)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	if s.stmtSaveTCDetails, err = s.db.Prepare(sqlSaveTCDetails); err != nil {
		return fmt.Errorf("prepare SaveTCDetails: %w", err)
	}

	const sqlSaveTCXDetails = `
		INSERT INTO tcx_link_details (kernel_link_id, interface, ifindex, direction, priority, netns, nsid)
		VALUES (?, ?, ?, ?, ?, ?, ?)`
	if s.stmtSaveTCXDetails, err = s.db.Prepare(sqlSaveTCXDetails); err != nil {
		return fmt.Errorf("prepare SaveTCXDetails: %w", err)
	}

	return nil
}

func (s *sqliteStore) prepareDispatcherStatements() error {
	var err error

	const sqlGetDispatcher = `
		SELECT id, type, nsid, ifindex, revision, kernel_id, link_id, link_pin_path, prog_pin_path, num_extensions
		FROM dispatchers WHERE type = ? AND nsid = ? AND ifindex = ?`
	if s.stmtGetDispatcher, err = s.db.Prepare(sqlGetDispatcher); err != nil {
		return fmt.Errorf("prepare GetDispatcher: %w", err)
	}

	const sqlSaveDispatcher = `
		INSERT INTO dispatchers (type, nsid, ifindex, revision, kernel_id, link_id, link_pin_path, prog_pin_path, num_extensions, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(type, nsid, ifindex) DO UPDATE SET
		  revision = excluded.revision,
		  kernel_id = excluded.kernel_id,
		  link_id = excluded.link_id,
		  link_pin_path = excluded.link_pin_path,
		  prog_pin_path = excluded.prog_pin_path,
		  num_extensions = excluded.num_extensions,
		  updated_at = excluded.updated_at`
	if s.stmtSaveDispatcher, err = s.db.Prepare(sqlSaveDispatcher); err != nil {
		return fmt.Errorf("prepare SaveDispatcher: %w", err)
	}

	const sqlDeleteDispatcher = "DELETE FROM dispatchers WHERE type = ? AND nsid = ? AND ifindex = ?"
	if s.stmtDeleteDispatcher, err = s.db.Prepare(sqlDeleteDispatcher); err != nil {
		return fmt.Errorf("prepare DeleteDispatcher: %w", err)
	}

	const sqlIncrementRevision = `
		UPDATE dispatchers
		SET revision = CASE WHEN revision = 4294967295 THEN 1 ELSE revision + 1 END,
		    updated_at = ?
		WHERE type = ? AND nsid = ? AND ifindex = ?`
	if s.stmtIncrementRevision, err = s.db.Prepare(sqlIncrementRevision); err != nil {
		return fmt.Errorf("prepare IncrementRevision: %w", err)
	}

	const sqlGetDispatcherByType = "SELECT revision FROM dispatchers WHERE type = ? AND nsid = ? AND ifindex = ?"
	if s.stmtGetDispatcherByType, err = s.db.Prepare(sqlGetDispatcherByType); err != nil {
		return fmt.Errorf("prepare GetDispatcherByType: %w", err)
	}

	return nil
}

// Get retrieves program metadata by kernel ID.
// Returns store.ErrNotFound if the program does not exist.
func (s *sqliteStore) Get(ctx context.Context, kernelID uint32) (bpfman.Program, error) {
	start := time.Now()
	row := s.stmtGetProgram.QueryRowContext(ctx, kernelID)

	prog, err := s.scanProgram(row)
	if err == sql.ErrNoRows {
		s.logger.Debug("sql", "stmt", "GetProgram", "args", []any{kernelID}, "duration_ms", msec(time.Since(start)), "rows", 0)
		return bpfman.Program{}, fmt.Errorf("program %d: %w", kernelID, store.ErrNotFound)
	}
	if err != nil {
		s.logger.Debug("sql", "stmt", "GetProgram", "args", []any{kernelID}, "duration_ms", msec(time.Since(start)), "error", err)
		return bpfman.Program{}, err
	}
	s.logger.Debug("sql", "stmt", "GetProgram", "args", []any{kernelID}, "duration_ms", msec(time.Since(start)), "rows", 1)

	// Get user metadata (tags are already included via JOIN)
	metadata, err := s.getUserMetadata(ctx, kernelID)
	if err != nil {
		return bpfman.Program{}, err
	}
	prog.UserMetadata = metadata

	return prog, nil
}

// scanProgram scans a single row into a Program struct.
// The row must include the tags column from GROUP_CONCAT.
func (s *sqliteStore) scanProgram(row *sql.Row) (bpfman.Program, error) {
	var prog bpfman.Program
	var programType string
	var attachFunc, globalDataJSON, imageSourceJSON, owner, description, tagsStr sql.NullString
	var mapOwnerID sql.NullInt64
	var createdAtStr string

	err := row.Scan(
		&prog.LoadSpec.ProgramName,
		&programType,
		&prog.LoadSpec.ObjectPath,
		&prog.LoadSpec.PinPath,
		&attachFunc,
		&globalDataJSON,
		&mapOwnerID,
		&imageSourceJSON,
		&owner,
		&description,
		&createdAtStr,
		&tagsStr,
	)
	if err != nil {
		return bpfman.Program{}, err
	}

	// Parse program type
	pt, _ := bpfman.ParseProgramType(programType)
	prog.LoadSpec.ProgramType = pt

	// Parse nullable fields
	if attachFunc.Valid {
		prog.LoadSpec.AttachFunc = attachFunc.String
	}
	if mapOwnerID.Valid {
		prog.LoadSpec.MapOwnerID = uint32(mapOwnerID.Int64)
	}
	if owner.Valid {
		prog.Owner = owner.String
	}
	if description.Valid {
		prog.Description = description.String
	}

	// Parse JSON fields
	if globalDataJSON.Valid {
		if err := json.Unmarshal([]byte(globalDataJSON.String), &prog.LoadSpec.GlobalData); err != nil {
			return bpfman.Program{}, fmt.Errorf("failed to unmarshal global_data: %w", err)
		}
	}
	if imageSourceJSON.Valid {
		if err := json.Unmarshal([]byte(imageSourceJSON.String), &prog.LoadSpec.ImageSource); err != nil {
			return bpfman.Program{}, fmt.Errorf("failed to unmarshal image_source: %w", err)
		}
	}

	// Parse tags from GROUP_CONCAT result
	if tagsStr.Valid && tagsStr.String != "" {
		prog.Tags = strings.Split(tagsStr.String, ",")
	}

	// Parse timestamp
	prog.CreatedAt, _ = time.Parse(time.RFC3339, createdAtStr)

	return prog, nil
}

// getUserMetadata retrieves user metadata for a program from the metadata index.
func (s *sqliteStore) getUserMetadata(ctx context.Context, kernelID uint32) (map[string]string, error) {
	// We need a separate query for this since we don't have a prepared statement
	start := time.Now()
	rows, err := s.conn.QueryContext(ctx, "SELECT key, value FROM program_metadata_index WHERE kernel_id = ?", kernelID)
	if err != nil {
		s.logger.Debug("sql", "stmt", "GetUserMetadata", "args", []any{kernelID}, "duration_ms", msec(time.Since(start)), "error", err)
		return nil, err
	}
	defer rows.Close()

	metadata := make(map[string]string)
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return nil, err
		}
		metadata[key] = value
	}
	s.logger.Debug("sql", "stmt", "GetUserMetadata", "args", []any{kernelID}, "duration_ms", msec(time.Since(start)), "rows", len(metadata))
	return metadata, rows.Err()
}

// Save stores program metadata.
// For atomicity with other operations, wrap in RunInTransaction.
func (s *sqliteStore) Save(ctx context.Context, kernelID uint32, metadata bpfman.Program) error {
	// Marshal only opaque fields to JSON
	var globalDataJSON, imageSourceJSON sql.NullString
	if metadata.LoadSpec.GlobalData != nil {
		data, err := json.Marshal(metadata.LoadSpec.GlobalData)
		if err != nil {
			return fmt.Errorf("failed to marshal global_data: %w", err)
		}
		globalDataJSON = sql.NullString{String: string(data), Valid: true}
	}
	if metadata.LoadSpec.ImageSource != nil {
		data, err := json.Marshal(metadata.LoadSpec.ImageSource)
		if err != nil {
			return fmt.Errorf("failed to marshal image_source: %w", err)
		}
		imageSourceJSON = sql.NullString{String: string(data), Valid: true}
	}

	// Handle nullable fields
	var mapOwnerID sql.NullInt64
	if metadata.LoadSpec.MapOwnerID != 0 {
		mapOwnerID = sql.NullInt64{Int64: int64(metadata.LoadSpec.MapOwnerID), Valid: true}
	}
	var attachFunc, owner, description sql.NullString
	if metadata.LoadSpec.AttachFunc != "" {
		attachFunc = sql.NullString{String: metadata.LoadSpec.AttachFunc, Valid: true}
	}
	if metadata.Owner != "" {
		owner = sql.NullString{String: metadata.Owner, Valid: true}
	}
	if metadata.Description != "" {
		description = sql.NullString{String: metadata.Description, Valid: true}
	}

	start := time.Now()
	result, err := s.stmtSaveProgram.ExecContext(ctx,
		kernelID,
		metadata.LoadSpec.ProgramName,
		metadata.LoadSpec.ProgramType.String(),
		metadata.LoadSpec.ObjectPath,
		metadata.LoadSpec.PinPath,
		attachFunc,
		globalDataJSON,
		mapOwnerID,
		imageSourceJSON,
		owner,
		description,
		metadata.CreatedAt.Format(time.RFC3339),
	)
	if err != nil {
		s.logger.Debug("sql", "stmt", "SaveProgram", "args", []any{kernelID, metadata.LoadSpec.ProgramName, "(columns)"}, "duration_ms", msec(time.Since(start)), "error", err)
		return fmt.Errorf("failed to insert program: %w", err)
	}
	rows, _ := result.RowsAffected()
	s.logger.Debug("sql", "stmt", "SaveProgram", "args", []any{kernelID, metadata.LoadSpec.ProgramName, "(columns)"}, "duration_ms", msec(time.Since(start)), "rows_affected", rows)

	// Clear old tags and insert new ones
	start = time.Now()
	result, err = s.stmtDeleteTags.ExecContext(ctx, kernelID)
	if err != nil {
		s.logger.Debug("sql", "stmt", "DeleteTags", "args", []any{kernelID}, "duration_ms", msec(time.Since(start)), "error", err)
		return fmt.Errorf("failed to clear tags: %w", err)
	}
	rows, _ = result.RowsAffected()
	s.logger.Debug("sql", "stmt", "DeleteTags", "args", []any{kernelID}, "duration_ms", msec(time.Since(start)), "rows_affected", rows)

	for _, tag := range metadata.Tags {
		start = time.Now()
		_, err = s.stmtInsertTag.ExecContext(ctx, kernelID, tag)
		if err != nil {
			s.logger.Debug("sql", "stmt", "InsertTag", "args", []any{kernelID, tag}, "duration_ms", msec(time.Since(start)), "error", err)
			return fmt.Errorf("failed to insert tag: %w", err)
		}
		s.logger.Debug("sql", "stmt", "InsertTag", "args", []any{kernelID, tag}, "duration_ms", msec(time.Since(start)), "rows_affected", 1)
	}

	// Clear old metadata index entries for this program
	start = time.Now()
	result, err = s.stmtDeleteProgramMetadataIndex.ExecContext(ctx, kernelID)
	if err != nil {
		s.logger.Debug("sql", "stmt", "DeleteProgramMetadataIndex", "args", []any{kernelID}, "duration_ms", msec(time.Since(start)), "error", err)
		return fmt.Errorf("failed to clear metadata index: %w", err)
	}
	rows, _ = result.RowsAffected()
	s.logger.Debug("sql", "stmt", "DeleteProgramMetadataIndex", "args", []any{kernelID}, "duration_ms", msec(time.Since(start)), "rows_affected", rows)

	// Insert metadata index entries for UserMetadata
	for key, value := range metadata.UserMetadata {
		start = time.Now()
		_, err = s.stmtInsertProgramMetadataIndex.ExecContext(ctx, kernelID, key, value)
		if err != nil {
			s.logger.Debug("sql", "stmt", "InsertProgramMetadataIndex", "args", []any{kernelID, key, value}, "duration_ms", msec(time.Since(start)), "error", err)
			return fmt.Errorf("failed to insert metadata index: %w", err)
		}
		s.logger.Debug("sql", "stmt", "InsertProgramMetadataIndex", "args", []any{kernelID, key, value}, "duration_ms", msec(time.Since(start)), "rows_affected", 1)
	}

	return nil
}

// Delete removes program metadata.
func (s *sqliteStore) Delete(ctx context.Context, kernelID uint32) error {
	start := time.Now()
	result, err := s.stmtDeleteProgram.ExecContext(ctx, kernelID)
	if err != nil {
		s.logger.Debug("sql", "stmt", "DeleteProgram", "args", []any{kernelID}, "duration_ms", msec(time.Since(start)), "error", err)
		return err
	}
	rows, _ := result.RowsAffected()
	s.logger.Debug("sql", "stmt", "DeleteProgram", "args", []any{kernelID}, "duration_ms", msec(time.Since(start)), "rows_affected", rows)
	return nil
}

// List returns all program metadata.
func (s *sqliteStore) List(ctx context.Context) (map[uint32]bpfman.Program, error) {
	start := time.Now()
	rows, err := s.stmtListPrograms.QueryContext(ctx)
	if err != nil {
		s.logger.Debug("sql", "stmt", "ListPrograms", "duration_ms", msec(time.Since(start)), "error", err)
		return nil, err
	}
	defer rows.Close()

	result := make(map[uint32]bpfman.Program)
	for rows.Next() {
		kernelID, prog, err := s.scanProgramFromRows(rows)
		if err != nil {
			return nil, err
		}
		result[kernelID] = prog
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Fetch metadata for each program (tags are already included via JOIN)
	for kernelID, prog := range result {
		metadata, err := s.getUserMetadata(ctx, kernelID)
		if err != nil {
			return nil, err
		}
		prog.UserMetadata = metadata
		result[kernelID] = prog
	}

	s.logger.Debug("sql", "stmt", "ListPrograms", "duration_ms", msec(time.Since(start)), "rows", len(result))
	return result, nil
}

// scanProgramFromRows scans a single row from *sql.Rows into a Program struct.
// The row must include the tags column from GROUP_CONCAT.
func (s *sqliteStore) scanProgramFromRows(rows *sql.Rows) (uint32, bpfman.Program, error) {
	var kernelID uint32
	var prog bpfman.Program
	var programType string
	var attachFunc, globalDataJSON, imageSourceJSON, owner, description, tagsStr sql.NullString
	var mapOwnerID sql.NullInt64
	var createdAtStr string

	err := rows.Scan(
		&kernelID,
		&prog.LoadSpec.ProgramName,
		&programType,
		&prog.LoadSpec.ObjectPath,
		&prog.LoadSpec.PinPath,
		&attachFunc,
		&globalDataJSON,
		&mapOwnerID,
		&imageSourceJSON,
		&owner,
		&description,
		&createdAtStr,
		&tagsStr,
	)
	if err != nil {
		return 0, bpfman.Program{}, err
	}

	// Parse program type
	pt, _ := bpfman.ParseProgramType(programType)
	prog.LoadSpec.ProgramType = pt

	// Parse nullable fields
	if attachFunc.Valid {
		prog.LoadSpec.AttachFunc = attachFunc.String
	}
	if mapOwnerID.Valid {
		prog.LoadSpec.MapOwnerID = uint32(mapOwnerID.Int64)
	}
	if owner.Valid {
		prog.Owner = owner.String
	}
	if description.Valid {
		prog.Description = description.String
	}

	// Parse JSON fields
	if globalDataJSON.Valid {
		if err := json.Unmarshal([]byte(globalDataJSON.String), &prog.LoadSpec.GlobalData); err != nil {
			return 0, bpfman.Program{}, fmt.Errorf("failed to unmarshal global_data for %d: %w", kernelID, err)
		}
	}
	if imageSourceJSON.Valid {
		if err := json.Unmarshal([]byte(imageSourceJSON.String), &prog.LoadSpec.ImageSource); err != nil {
			return 0, bpfman.Program{}, fmt.Errorf("failed to unmarshal image_source for %d: %w", kernelID, err)
		}
	}

	// Parse tags from GROUP_CONCAT result
	if tagsStr.Valid && tagsStr.String != "" {
		prog.Tags = strings.Split(tagsStr.String, ",")
	}

	// Parse timestamp
	prog.CreatedAt, _ = time.Parse(time.RFC3339, createdAtStr)

	return kernelID, prog, nil
}

// FindProgramByMetadata finds a program by a specific metadata key/value pair.
// Returns store.ErrNotFound if no program matches.
func (s *sqliteStore) FindProgramByMetadata(ctx context.Context, key, value string) (bpfman.Program, uint32, error) {
	start := time.Now()
	rows, err := s.stmtFindProgramByMetadata.QueryContext(ctx, key, value)
	if err != nil {
		s.logger.Debug("sql", "stmt", "FindProgramByMetadata", "args", []any{key, value}, "duration_ms", msec(time.Since(start)), "error", err)
		return bpfman.Program{}, 0, err
	}

	if !rows.Next() {
		rows.Close()
		s.logger.Debug("sql", "stmt", "FindProgramByMetadata", "args", []any{key, value}, "duration_ms", msec(time.Since(start)), "rows", 0)
		return bpfman.Program{}, 0, fmt.Errorf("program with %s=%s: %w", key, value, store.ErrNotFound)
	}

	kernelID, prog, err := s.scanProgramFromRows(rows)
	rows.Close() // Close rows before making additional queries
	if err != nil {
		s.logger.Debug("sql", "stmt", "FindProgramByMetadata", "args", []any{key, value}, "duration_ms", msec(time.Since(start)), "error", err)
		return bpfman.Program{}, 0, err
	}
	s.logger.Debug("sql", "stmt", "FindProgramByMetadata", "args", []any{key, value}, "duration_ms", msec(time.Since(start)), "rows", 1)

	// Get user metadata (tags are already included via JOIN)
	metadata, err := s.getUserMetadata(ctx, kernelID)
	if err != nil {
		return bpfman.Program{}, 0, err
	}
	prog.UserMetadata = metadata

	return prog, kernelID, nil
}

// FindAllProgramsByMetadata finds all programs with a specific metadata key/value pair.
func (s *sqliteStore) FindAllProgramsByMetadata(ctx context.Context, key, value string) ([]struct {
	KernelID uint32
	Metadata bpfman.Program
}, error) {
	start := time.Now()
	rows, err := s.stmtFindAllProgramsByMetadata.QueryContext(ctx, key, value)
	if err != nil {
		s.logger.Debug("sql", "stmt", "FindAllProgramsByMetadata", "args", []any{key, value}, "duration_ms", msec(time.Since(start)), "error", err)
		return nil, err
	}
	defer rows.Close()

	var result []struct {
		KernelID uint32
		Metadata bpfman.Program
	}

	for rows.Next() {
		kernelID, prog, err := s.scanProgramFromRows(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, struct {
			KernelID uint32
			Metadata bpfman.Program
		}{KernelID: kernelID, Metadata: prog})
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Fetch metadata for each program (tags are already included via JOIN)
	for i := range result {
		metadata, err := s.getUserMetadata(ctx, result[i].KernelID)
		if err != nil {
			return nil, err
		}
		result[i].Metadata.UserMetadata = metadata
	}

	s.logger.Debug("sql", "stmt", "FindAllProgramsByMetadata", "args", []any{key, value}, "duration_ms", msec(time.Since(start)), "rows", len(result))
	return result, nil
}

// ----------------------------------------------------------------------------
// Link Registry Operations
// ----------------------------------------------------------------------------

// DeleteLink removes link metadata by kernel link ID.
// Due to CASCADE, this also removes the corresponding detail table entry.
func (s *sqliteStore) DeleteLink(ctx context.Context, kernelLinkID uint32) error {
	start := time.Now()
	result, err := s.stmtDeleteLink.ExecContext(ctx, kernelLinkID)
	if err != nil {
		s.logger.Debug("sql", "stmt", "DeleteLink", "args", []any{kernelLinkID}, "duration_ms", msec(time.Since(start)), "error", err)
		return fmt.Errorf("failed to delete link: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	s.logger.Debug("sql", "stmt", "DeleteLink", "args", []any{kernelLinkID}, "duration_ms", msec(time.Since(start)), "rows_affected", rows)
	if rows == 0 {
		return fmt.Errorf("link %d: %w", kernelLinkID, store.ErrNotFound)
	}

	return nil
}

// GetLink retrieves link metadata by kernel link ID using two-phase lookup.
func (s *sqliteStore) GetLink(ctx context.Context, kernelLinkID uint32) (bpfman.LinkSummary, bpfman.LinkDetails, error) {
	// Phase 1: Get summary from registry
	start := time.Now()
	row := s.stmtGetLinkRegistry.QueryRowContext(ctx, kernelLinkID)

	summary, err := s.scanLinkSummary(row)
	if err != nil {
		s.logger.Debug("sql", "stmt", "GetLinkRegistry", "args", []any{kernelLinkID}, "duration_ms", msec(time.Since(start)), "rows", 0)
		return bpfman.LinkSummary{}, nil, err
	}
	s.logger.Debug("sql", "stmt", "GetLinkRegistry", "args", []any{kernelLinkID}, "duration_ms", msec(time.Since(start)), "rows", 1)

	// Phase 2: Get details based on link type
	details, err := s.getLinkDetails(ctx, summary.LinkType, kernelLinkID)
	if err != nil {
		return bpfman.LinkSummary{}, nil, err
	}

	return summary, details, nil
}

// ListLinks returns all links (summary only).
func (s *sqliteStore) ListLinks(ctx context.Context) ([]bpfman.LinkSummary, error) {
	start := time.Now()
	rows, err := s.stmtListLinks.QueryContext(ctx)
	if err != nil {
		s.logger.Debug("sql", "stmt", "ListLinks", "duration_ms", msec(time.Since(start)), "error", err)
		return nil, err
	}
	defer rows.Close()

	result, err := s.scanLinkSummaries(rows)
	if err != nil {
		return nil, err
	}
	s.logger.Debug("sql", "stmt", "ListLinks", "duration_ms", msec(time.Since(start)), "rows", len(result))
	return result, nil
}

// ListLinksByProgram returns all links for a given program kernel ID.
func (s *sqliteStore) ListLinksByProgram(ctx context.Context, programKernelID uint32) ([]bpfman.LinkSummary, error) {
	start := time.Now()
	rows, err := s.stmtListLinksByProgram.QueryContext(ctx, programKernelID)
	if err != nil {
		s.logger.Debug("sql", "stmt", "ListLinksByProgram", "args", []any{programKernelID}, "duration_ms", msec(time.Since(start)), "error", err)
		return nil, err
	}
	defer rows.Close()

	result, err := s.scanLinkSummaries(rows)
	if err != nil {
		return nil, err
	}
	s.logger.Debug("sql", "stmt", "ListLinksByProgram", "args", []any{programKernelID}, "duration_ms", msec(time.Since(start)), "rows", len(result))
	return result, nil
}

// ----------------------------------------------------------------------------
// Type-Specific Link Save Methods
// ----------------------------------------------------------------------------

// SaveTracepointLink saves a tracepoint link.
// For atomicity with other operations, wrap in RunInTransaction.
func (s *sqliteStore) SaveTracepointLink(ctx context.Context, summary bpfman.LinkSummary, details bpfman.TracepointDetails) error {
	if err := s.insertLinkRegistry(ctx, summary); err != nil {
		return err
	}

	start := time.Now()
	_, err := s.stmtSaveTracepointDetails.ExecContext(ctx,
		summary.KernelLinkID, details.Group, details.Name)
	if err != nil {
		s.logger.Debug("sql", "stmt", "SaveTracepointDetails", "args", []any{summary.KernelLinkID, details.Group, details.Name}, "duration_ms", msec(time.Since(start)), "error", err)
		return fmt.Errorf("failed to insert tracepoint details: %w", err)
	}
	s.logger.Debug("sql", "stmt", "SaveTracepointDetails", "args", []any{summary.KernelLinkID, details.Group, details.Name}, "duration_ms", msec(time.Since(start)), "rows_affected", 1)

	return nil
}

// SaveKprobeLink saves a kprobe/kretprobe link.
// For atomicity with other operations, wrap in RunInTransaction.
func (s *sqliteStore) SaveKprobeLink(ctx context.Context, summary bpfman.LinkSummary, details bpfman.KprobeDetails) error {
	if err := s.insertLinkRegistry(ctx, summary); err != nil {
		return err
	}

	retprobe := 0
	if details.Retprobe {
		retprobe = 1
	}

	start := time.Now()
	_, err := s.stmtSaveKprobeDetails.ExecContext(ctx,
		summary.KernelLinkID, details.FnName, details.Offset, retprobe)
	if err != nil {
		s.logger.Debug("sql", "stmt", "SaveKprobeDetails", "args", []any{summary.KernelLinkID, details.FnName, details.Offset, retprobe}, "duration_ms", msec(time.Since(start)), "error", err)
		return fmt.Errorf("failed to insert kprobe details: %w", err)
	}
	s.logger.Debug("sql", "stmt", "SaveKprobeDetails", "args", []any{summary.KernelLinkID, details.FnName, details.Offset, retprobe}, "duration_ms", msec(time.Since(start)), "rows_affected", 1)

	return nil
}

// SaveUprobeLink saves a uprobe/uretprobe link.
// For atomicity with other operations, wrap in RunInTransaction.
func (s *sqliteStore) SaveUprobeLink(ctx context.Context, summary bpfman.LinkSummary, details bpfman.UprobeDetails) error {
	if err := s.insertLinkRegistry(ctx, summary); err != nil {
		return err
	}

	retprobe := 0
	if details.Retprobe {
		retprobe = 1
	}

	start := time.Now()
	_, err := s.stmtSaveUprobeDetails.ExecContext(ctx,
		summary.KernelLinkID, details.Target, details.FnName, details.Offset, details.PID, retprobe)
	if err != nil {
		s.logger.Debug("sql", "stmt", "SaveUprobeDetails", "args", []any{summary.KernelLinkID, details.Target, details.FnName, details.Offset, details.PID, retprobe}, "duration_ms", msec(time.Since(start)), "error", err)
		return fmt.Errorf("failed to insert uprobe details: %w", err)
	}
	s.logger.Debug("sql", "stmt", "SaveUprobeDetails", "args", []any{summary.KernelLinkID, details.Target, details.FnName, details.Offset, details.PID, retprobe}, "duration_ms", msec(time.Since(start)), "rows_affected", 1)

	return nil
}

// SaveFentryLink saves a fentry link.
// For atomicity with other operations, wrap in RunInTransaction.
func (s *sqliteStore) SaveFentryLink(ctx context.Context, summary bpfman.LinkSummary, details bpfman.FentryDetails) error {
	if err := s.insertLinkRegistry(ctx, summary); err != nil {
		return err
	}

	start := time.Now()
	_, err := s.stmtSaveFentryDetails.ExecContext(ctx, summary.KernelLinkID, details.FnName)
	if err != nil {
		s.logger.Debug("sql", "stmt", "SaveFentryDetails", "args", []any{summary.KernelLinkID, details.FnName}, "duration_ms", msec(time.Since(start)), "error", err)
		return fmt.Errorf("failed to insert fentry details: %w", err)
	}
	s.logger.Debug("sql", "stmt", "SaveFentryDetails", "args", []any{summary.KernelLinkID, details.FnName}, "duration_ms", msec(time.Since(start)), "rows_affected", 1)

	return nil
}

// SaveFexitLink saves a fexit link.
// For atomicity with other operations, wrap in RunInTransaction.
func (s *sqliteStore) SaveFexitLink(ctx context.Context, summary bpfman.LinkSummary, details bpfman.FexitDetails) error {
	if err := s.insertLinkRegistry(ctx, summary); err != nil {
		return err
	}

	start := time.Now()
	_, err := s.stmtSaveFexitDetails.ExecContext(ctx, summary.KernelLinkID, details.FnName)
	if err != nil {
		s.logger.Debug("sql", "stmt", "SaveFexitDetails", "args", []any{summary.KernelLinkID, details.FnName}, "duration_ms", msec(time.Since(start)), "error", err)
		return fmt.Errorf("failed to insert fexit details: %w", err)
	}
	s.logger.Debug("sql", "stmt", "SaveFexitDetails", "args", []any{summary.KernelLinkID, details.FnName}, "duration_ms", msec(time.Since(start)), "rows_affected", 1)

	return nil
}

// SaveXDPLink saves an XDP link.
// For atomicity with other operations, wrap in RunInTransaction.
func (s *sqliteStore) SaveXDPLink(ctx context.Context, summary bpfman.LinkSummary, details bpfman.XDPDetails) error {
	if err := s.insertLinkRegistry(ctx, summary); err != nil {
		return err
	}

	proceedOnJSON, err := json.Marshal(details.ProceedOn)
	if err != nil {
		return fmt.Errorf("failed to marshal proceed_on: %w", err)
	}

	start := time.Now()
	_, err = s.stmtSaveXDPDetails.ExecContext(ctx,
		summary.KernelLinkID, details.Interface, details.Ifindex, details.Priority, details.Position,
		string(proceedOnJSON), details.Netns, details.Nsid, details.DispatcherID, details.Revision)
	if err != nil {
		s.logger.Debug("sql", "stmt", "SaveXDPDetails", "args", []any{summary.KernelLinkID, details.Interface, details.Ifindex, details.Priority, details.Position, "(proceed_on)", details.Netns, details.Nsid, details.DispatcherID, details.Revision}, "duration_ms", msec(time.Since(start)), "error", err)
		return fmt.Errorf("failed to insert xdp details: %w", err)
	}
	s.logger.Debug("sql", "stmt", "SaveXDPDetails", "args", []any{summary.KernelLinkID, details.Interface, details.Ifindex, details.Priority, details.Position, "(proceed_on)", details.Netns, details.Nsid, details.DispatcherID, details.Revision}, "duration_ms", msec(time.Since(start)), "rows_affected", 1)

	return nil
}

// SaveTCLink saves a TC link.
// For atomicity with other operations, wrap in RunInTransaction.
func (s *sqliteStore) SaveTCLink(ctx context.Context, summary bpfman.LinkSummary, details bpfman.TCDetails) error {
	if err := s.insertLinkRegistry(ctx, summary); err != nil {
		return err
	}

	proceedOnJSON, err := json.Marshal(details.ProceedOn)
	if err != nil {
		return fmt.Errorf("failed to marshal proceed_on: %w", err)
	}

	start := time.Now()
	_, err = s.stmtSaveTCDetails.ExecContext(ctx,
		summary.KernelLinkID, details.Interface, details.Ifindex, details.Direction, details.Priority, details.Position,
		string(proceedOnJSON), details.Netns, details.Nsid, details.DispatcherID, details.Revision)
	if err != nil {
		s.logger.Debug("sql", "stmt", "SaveTCDetails", "args", []any{summary.KernelLinkID, details.Interface, details.Ifindex, details.Direction, details.Priority, details.Position, "(proceed_on)", details.Netns, details.Nsid, details.DispatcherID, details.Revision}, "duration_ms", msec(time.Since(start)), "error", err)
		return fmt.Errorf("failed to insert tc details: %w", err)
	}
	s.logger.Debug("sql", "stmt", "SaveTCDetails", "args", []any{summary.KernelLinkID, details.Interface, details.Ifindex, details.Direction, details.Priority, details.Position, "(proceed_on)", details.Netns, details.Nsid, details.DispatcherID, details.Revision}, "duration_ms", msec(time.Since(start)), "rows_affected", 1)

	return nil
}

// SaveTCXLink saves a TCX link.
// For atomicity with other operations, wrap in RunInTransaction.
func (s *sqliteStore) SaveTCXLink(ctx context.Context, summary bpfman.LinkSummary, details bpfman.TCXDetails) error {
	if err := s.insertLinkRegistry(ctx, summary); err != nil {
		return err
	}

	start := time.Now()
	_, err := s.stmtSaveTCXDetails.ExecContext(ctx,
		summary.KernelLinkID, details.Interface, details.Ifindex, details.Direction, details.Priority, details.Netns, details.Nsid)
	if err != nil {
		s.logger.Debug("sql", "stmt", "SaveTCXDetails", "args", []any{summary.KernelLinkID, details.Interface, details.Ifindex, details.Direction, details.Priority, details.Netns, details.Nsid}, "duration_ms", msec(time.Since(start)), "error", err)
		return fmt.Errorf("failed to insert tcx details: %w", err)
	}
	s.logger.Debug("sql", "stmt", "SaveTCXDetails", "args", []any{summary.KernelLinkID, details.Interface, details.Ifindex, details.Direction, details.Priority, details.Netns, details.Nsid}, "duration_ms", msec(time.Since(start)), "rows_affected", 1)

	return nil
}

// ----------------------------------------------------------------------------
// Helper Functions
// ----------------------------------------------------------------------------

// insertLinkRegistry inserts a record into the link_registry table.
func (s *sqliteStore) insertLinkRegistry(ctx context.Context, summary bpfman.LinkSummary) error {
	start := time.Now()
	_, err := s.stmtInsertLinkRegistry.ExecContext(ctx,
		summary.KernelLinkID, string(summary.LinkType), summary.KernelProgramID,
		summary.PinPath, summary.CreatedAt.Format(time.RFC3339))
	if err != nil {
		s.logger.Debug("sql", "stmt", "InsertLinkRegistry", "args", []any{summary.KernelLinkID, summary.LinkType, summary.KernelProgramID, summary.PinPath, "(timestamp)"}, "duration_ms", msec(time.Since(start)), "error", err)
		return fmt.Errorf("failed to insert link registry: %w", err)
	}
	s.logger.Debug("sql", "stmt", "InsertLinkRegistry", "args", []any{summary.KernelLinkID, summary.LinkType, summary.KernelProgramID, summary.PinPath, "(timestamp)"}, "duration_ms", msec(time.Since(start)), "rows_affected", 1)
	return nil
}

// scanLinkSummary scans a single row into a LinkSummary.
func (s *sqliteStore) scanLinkSummary(row *sql.Row) (bpfman.LinkSummary, error) {
	var summary bpfman.LinkSummary
	var linkType string
	var pinPath sql.NullString
	var createdAtStr string

	err := row.Scan(&summary.KernelLinkID, &linkType, &summary.KernelProgramID, &pinPath, &createdAtStr)
	if err == sql.ErrNoRows {
		return bpfman.LinkSummary{}, fmt.Errorf("link: %w", store.ErrNotFound)
	}
	if err != nil {
		return bpfman.LinkSummary{}, err
	}

	summary.LinkType = bpfman.LinkType(linkType)
	if pinPath.Valid {
		summary.PinPath = pinPath.String
	}
	summary.CreatedAt, _ = time.Parse(time.RFC3339, createdAtStr)

	return summary, nil
}

// scanLinkSummaries scans multiple rows into a slice of LinkSummary.
func (s *sqliteStore) scanLinkSummaries(rows *sql.Rows) ([]bpfman.LinkSummary, error) {
	var result []bpfman.LinkSummary

	for rows.Next() {
		var summary bpfman.LinkSummary
		var linkType string
		var pinPath sql.NullString
		var createdAtStr string

		err := rows.Scan(&summary.KernelLinkID, &linkType, &summary.KernelProgramID, &pinPath, &createdAtStr)
		if err != nil {
			return nil, err
		}

		summary.LinkType = bpfman.LinkType(linkType)
		if pinPath.Valid {
			summary.PinPath = pinPath.String
		}
		summary.CreatedAt, _ = time.Parse(time.RFC3339, createdAtStr)

		result = append(result, summary)
	}

	return result, rows.Err()
}

// getLinkDetails retrieves the type-specific details for a link.
func (s *sqliteStore) getLinkDetails(ctx context.Context, linkType bpfman.LinkType, kernelLinkID uint32) (bpfman.LinkDetails, error) {
	switch linkType {
	case bpfman.LinkTypeTracepoint:
		return s.getTracepointDetails(ctx, kernelLinkID)
	case bpfman.LinkTypeKprobe, bpfman.LinkTypeKretprobe:
		return s.getKprobeDetails(ctx, kernelLinkID)
	case bpfman.LinkTypeUprobe, bpfman.LinkTypeUretprobe:
		return s.getUprobeDetails(ctx, kernelLinkID)
	case bpfman.LinkTypeFentry:
		return s.getFentryDetails(ctx, kernelLinkID)
	case bpfman.LinkTypeFexit:
		return s.getFexitDetails(ctx, kernelLinkID)
	case bpfman.LinkTypeXDP:
		return s.getXDPDetails(ctx, kernelLinkID)
	case bpfman.LinkTypeTC:
		return s.getTCDetails(ctx, kernelLinkID)
	case bpfman.LinkTypeTCX:
		return s.getTCXDetails(ctx, kernelLinkID)
	default:
		return nil, fmt.Errorf("unknown link type: %s", linkType)
	}
}

func (s *sqliteStore) getTracepointDetails(ctx context.Context, kernelLinkID uint32) (bpfman.TracepointDetails, error) {
	start := time.Now()
	row := s.stmtGetTracepointDetails.QueryRowContext(ctx, kernelLinkID)

	var details bpfman.TracepointDetails
	err := row.Scan(&details.Group, &details.Name)
	if err == sql.ErrNoRows {
		s.logger.Debug("sql", "stmt", "GetTracepointDetails", "args", []any{kernelLinkID}, "duration_ms", msec(time.Since(start)), "rows", 0)
		return bpfman.TracepointDetails{}, fmt.Errorf("tracepoint details for %d: %w", kernelLinkID, store.ErrNotFound)
	}
	if err != nil {
		s.logger.Debug("sql", "stmt", "GetTracepointDetails", "args", []any{kernelLinkID}, "duration_ms", msec(time.Since(start)), "error", err)
		return bpfman.TracepointDetails{}, err
	}
	s.logger.Debug("sql", "stmt", "GetTracepointDetails", "args", []any{kernelLinkID}, "duration_ms", msec(time.Since(start)), "rows", 1)
	return details, nil
}

func (s *sqliteStore) getKprobeDetails(ctx context.Context, kernelLinkID uint32) (bpfman.KprobeDetails, error) {
	start := time.Now()
	row := s.stmtGetKprobeDetails.QueryRowContext(ctx, kernelLinkID)

	var details bpfman.KprobeDetails
	var retprobe int
	err := row.Scan(&details.FnName, &details.Offset, &retprobe)
	if err == sql.ErrNoRows {
		s.logger.Debug("sql", "stmt", "GetKprobeDetails", "args", []any{kernelLinkID}, "duration_ms", msec(time.Since(start)), "rows", 0)
		return bpfman.KprobeDetails{}, fmt.Errorf("kprobe details for %d: %w", kernelLinkID, store.ErrNotFound)
	}
	if err != nil {
		s.logger.Debug("sql", "stmt", "GetKprobeDetails", "args", []any{kernelLinkID}, "duration_ms", msec(time.Since(start)), "error", err)
		return bpfman.KprobeDetails{}, err
	}
	s.logger.Debug("sql", "stmt", "GetKprobeDetails", "args", []any{kernelLinkID}, "duration_ms", msec(time.Since(start)), "rows", 1)
	details.Retprobe = retprobe == 1
	return details, nil
}

func (s *sqliteStore) getUprobeDetails(ctx context.Context, kernelLinkID uint32) (bpfman.UprobeDetails, error) {
	start := time.Now()
	row := s.stmtGetUprobeDetails.QueryRowContext(ctx, kernelLinkID)

	var details bpfman.UprobeDetails
	var fnName sql.NullString
	var pid sql.NullInt64
	var retprobe int
	err := row.Scan(&details.Target, &fnName, &details.Offset, &pid, &retprobe)
	if err == sql.ErrNoRows {
		s.logger.Debug("sql", "stmt", "GetUprobeDetails", "args", []any{kernelLinkID}, "duration_ms", msec(time.Since(start)), "rows", 0)
		return bpfman.UprobeDetails{}, fmt.Errorf("uprobe details for %d: %w", kernelLinkID, store.ErrNotFound)
	}
	if err != nil {
		s.logger.Debug("sql", "stmt", "GetUprobeDetails", "args", []any{kernelLinkID}, "duration_ms", msec(time.Since(start)), "error", err)
		return bpfman.UprobeDetails{}, err
	}
	s.logger.Debug("sql", "stmt", "GetUprobeDetails", "args", []any{kernelLinkID}, "duration_ms", msec(time.Since(start)), "rows", 1)
	if fnName.Valid {
		details.FnName = fnName.String
	}
	if pid.Valid {
		details.PID = int32(pid.Int64)
	}
	details.Retprobe = retprobe == 1
	return details, nil
}

func (s *sqliteStore) getFentryDetails(ctx context.Context, kernelLinkID uint32) (bpfman.FentryDetails, error) {
	start := time.Now()
	row := s.stmtGetFentryDetails.QueryRowContext(ctx, kernelLinkID)

	var details bpfman.FentryDetails
	err := row.Scan(&details.FnName)
	if err == sql.ErrNoRows {
		s.logger.Debug("sql", "stmt", "GetFentryDetails", "args", []any{kernelLinkID}, "duration_ms", msec(time.Since(start)), "rows", 0)
		return bpfman.FentryDetails{}, fmt.Errorf("fentry details for %d: %w", kernelLinkID, store.ErrNotFound)
	}
	if err != nil {
		s.logger.Debug("sql", "stmt", "GetFentryDetails", "args", []any{kernelLinkID}, "duration_ms", msec(time.Since(start)), "error", err)
		return bpfman.FentryDetails{}, err
	}
	s.logger.Debug("sql", "stmt", "GetFentryDetails", "args", []any{kernelLinkID}, "duration_ms", msec(time.Since(start)), "rows", 1)
	return details, nil
}

func (s *sqliteStore) getFexitDetails(ctx context.Context, kernelLinkID uint32) (bpfman.FexitDetails, error) {
	start := time.Now()
	row := s.stmtGetFexitDetails.QueryRowContext(ctx, kernelLinkID)

	var details bpfman.FexitDetails
	err := row.Scan(&details.FnName)
	if err == sql.ErrNoRows {
		s.logger.Debug("sql", "stmt", "GetFexitDetails", "args", []any{kernelLinkID}, "duration_ms", msec(time.Since(start)), "rows", 0)
		return bpfman.FexitDetails{}, fmt.Errorf("fexit details for %d: %w", kernelLinkID, store.ErrNotFound)
	}
	if err != nil {
		s.logger.Debug("sql", "stmt", "GetFexitDetails", "args", []any{kernelLinkID}, "duration_ms", msec(time.Since(start)), "error", err)
		return bpfman.FexitDetails{}, err
	}
	s.logger.Debug("sql", "stmt", "GetFexitDetails", "args", []any{kernelLinkID}, "duration_ms", msec(time.Since(start)), "rows", 1)
	return details, nil
}

func (s *sqliteStore) getXDPDetails(ctx context.Context, kernelLinkID uint32) (bpfman.XDPDetails, error) {
	start := time.Now()
	row := s.stmtGetXDPDetails.QueryRowContext(ctx, kernelLinkID)

	var details bpfman.XDPDetails
	var proceedOnJSON string
	var netns sql.NullString
	err := row.Scan(&details.Interface, &details.Ifindex, &details.Priority, &details.Position,
		&proceedOnJSON, &netns, &details.Nsid, &details.DispatcherID, &details.Revision)
	if err == sql.ErrNoRows {
		s.logger.Debug("sql", "stmt", "GetXDPDetails", "args", []any{kernelLinkID}, "duration_ms", msec(time.Since(start)), "rows", 0)
		return bpfman.XDPDetails{}, fmt.Errorf("xdp details for %d: %w", kernelLinkID, store.ErrNotFound)
	}
	if err != nil {
		s.logger.Debug("sql", "stmt", "GetXDPDetails", "args", []any{kernelLinkID}, "duration_ms", msec(time.Since(start)), "error", err)
		return bpfman.XDPDetails{}, err
	}
	s.logger.Debug("sql", "stmt", "GetXDPDetails", "args", []any{kernelLinkID}, "duration_ms", msec(time.Since(start)), "rows", 1)

	if err := json.Unmarshal([]byte(proceedOnJSON), &details.ProceedOn); err != nil {
		return bpfman.XDPDetails{}, fmt.Errorf("failed to unmarshal proceed_on: %w", err)
	}
	if netns.Valid {
		details.Netns = netns.String
	}
	return details, nil
}

func (s *sqliteStore) getTCDetails(ctx context.Context, kernelLinkID uint32) (bpfman.TCDetails, error) {
	start := time.Now()
	row := s.stmtGetTCDetails.QueryRowContext(ctx, kernelLinkID)

	var details bpfman.TCDetails
	var proceedOnJSON string
	var netns sql.NullString
	err := row.Scan(&details.Interface, &details.Ifindex, &details.Direction, &details.Priority, &details.Position,
		&proceedOnJSON, &netns, &details.Nsid, &details.DispatcherID, &details.Revision)
	if err == sql.ErrNoRows {
		s.logger.Debug("sql", "stmt", "GetTCDetails", "args", []any{kernelLinkID}, "duration_ms", msec(time.Since(start)), "rows", 0)
		return bpfman.TCDetails{}, fmt.Errorf("tc details for %d: %w", kernelLinkID, store.ErrNotFound)
	}
	if err != nil {
		s.logger.Debug("sql", "stmt", "GetTCDetails", "args", []any{kernelLinkID}, "duration_ms", msec(time.Since(start)), "error", err)
		return bpfman.TCDetails{}, err
	}
	s.logger.Debug("sql", "stmt", "GetTCDetails", "args", []any{kernelLinkID}, "duration_ms", msec(time.Since(start)), "rows", 1)

	if err := json.Unmarshal([]byte(proceedOnJSON), &details.ProceedOn); err != nil {
		return bpfman.TCDetails{}, fmt.Errorf("failed to unmarshal proceed_on: %w", err)
	}
	if netns.Valid {
		details.Netns = netns.String
	}
	return details, nil
}

func (s *sqliteStore) getTCXDetails(ctx context.Context, kernelLinkID uint32) (bpfman.TCXDetails, error) {
	start := time.Now()
	row := s.stmtGetTCXDetails.QueryRowContext(ctx, kernelLinkID)

	var details bpfman.TCXDetails
	var netns sql.NullString
	var nsid sql.NullInt64
	err := row.Scan(&details.Interface, &details.Ifindex, &details.Direction, &details.Priority, &netns, &nsid)
	if err == sql.ErrNoRows {
		s.logger.Debug("sql", "stmt", "GetTCXDetails", "args", []any{kernelLinkID}, "duration_ms", msec(time.Since(start)), "rows", 0)
		return bpfman.TCXDetails{}, fmt.Errorf("tcx details for %d: %w", kernelLinkID, store.ErrNotFound)
	}
	if err != nil {
		s.logger.Debug("sql", "stmt", "GetTCXDetails", "args", []any{kernelLinkID}, "duration_ms", msec(time.Since(start)), "error", err)
		return bpfman.TCXDetails{}, err
	}
	s.logger.Debug("sql", "stmt", "GetTCXDetails", "args", []any{kernelLinkID}, "duration_ms", msec(time.Since(start)), "rows", 1)

	if netns.Valid {
		details.Netns = netns.String
	}
	if nsid.Valid {
		details.Nsid = uint64(nsid.Int64)
	}
	return details, nil
}

// ----------------------------------------------------------------------------
// Dispatcher Store Operations
// ----------------------------------------------------------------------------

// GetDispatcher retrieves a dispatcher by type, nsid, and ifindex.
func (s *sqliteStore) GetDispatcher(ctx context.Context, dispType string, nsid uint64, ifindex uint32) (dispatcher.State, error) {
	start := time.Now()
	row := s.stmtGetDispatcher.QueryRowContext(ctx, dispType, nsid, ifindex)

	var state dispatcher.State
	var id int64
	var dispTypeStr string
	err := row.Scan(&id, &dispTypeStr, &state.Nsid, &state.Ifindex, &state.Revision,
		&state.KernelID, &state.LinkID, &state.LinkPinPath, &state.ProgPinPath, &state.NumExtensions)
	if err == sql.ErrNoRows {
		s.logger.Debug("sql", "stmt", "GetDispatcher", "args", []any{dispType, nsid, ifindex}, "duration_ms", msec(time.Since(start)), "rows", 0)
		return dispatcher.State{}, fmt.Errorf("dispatcher (%s, %d, %d): %w", dispType, nsid, ifindex, store.ErrNotFound)
	}
	if err != nil {
		s.logger.Debug("sql", "stmt", "GetDispatcher", "args", []any{dispType, nsid, ifindex}, "duration_ms", msec(time.Since(start)), "error", err)
		return dispatcher.State{}, err
	}
	s.logger.Debug("sql", "stmt", "GetDispatcher", "args", []any{dispType, nsid, ifindex}, "duration_ms", msec(time.Since(start)), "rows", 1)

	state.Type = dispatcher.DispatcherType(dispTypeStr)
	return state, nil
}

// SaveDispatcher creates or updates a dispatcher.
func (s *sqliteStore) SaveDispatcher(ctx context.Context, state dispatcher.State) error {
	now := time.Now().Format(time.RFC3339)

	start := time.Now()
	result, err := s.stmtSaveDispatcher.ExecContext(ctx,
		string(state.Type), state.Nsid, state.Ifindex, state.Revision,
		state.KernelID, state.LinkID, state.LinkPinPath, state.ProgPinPath,
		state.NumExtensions, now, now)
	if err != nil {
		s.logger.Debug("sql", "stmt", "SaveDispatcher", "args", []any{state.Type, state.Nsid, state.Ifindex, state.Revision, state.KernelID, state.LinkID, state.LinkPinPath, state.ProgPinPath, state.NumExtensions, "(timestamp)", "(timestamp)"}, "duration_ms", msec(time.Since(start)), "error", err)
		return fmt.Errorf("save dispatcher: %w", err)
	}
	rows, _ := result.RowsAffected()
	s.logger.Debug("sql", "stmt", "SaveDispatcher", "args", []any{state.Type, state.Nsid, state.Ifindex, state.Revision, state.KernelID, state.LinkID, state.LinkPinPath, state.ProgPinPath, state.NumExtensions, "(timestamp)", "(timestamp)"}, "duration_ms", msec(time.Since(start)), "rows_affected", rows)

	return nil
}

// DeleteDispatcher removes a dispatcher by type, nsid, and ifindex.
func (s *sqliteStore) DeleteDispatcher(ctx context.Context, dispType string, nsid uint64, ifindex uint32) error {
	start := time.Now()
	result, err := s.stmtDeleteDispatcher.ExecContext(ctx, dispType, nsid, ifindex)
	if err != nil {
		s.logger.Debug("sql", "stmt", "DeleteDispatcher", "args", []any{dispType, nsid, ifindex}, "duration_ms", msec(time.Since(start)), "error", err)
		return fmt.Errorf("delete dispatcher: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	s.logger.Debug("sql", "stmt", "DeleteDispatcher", "args", []any{dispType, nsid, ifindex}, "duration_ms", msec(time.Since(start)), "rows_affected", rows)
	if rows == 0 {
		return fmt.Errorf("dispatcher (%s, %d, %d): %w", dispType, nsid, ifindex, store.ErrNotFound)
	}

	return nil
}

// IncrementRevision atomically increments the dispatcher revision.
// Returns the new revision number. Wraps from MaxUint32 to 1.
// For atomicity with other operations, wrap in RunInTransaction.
func (s *sqliteStore) IncrementRevision(ctx context.Context, dispType string, nsid uint64, ifindex uint32) (uint32, error) {
	now := time.Now().Format(time.RFC3339)

	// Use CASE to handle wrap-around at MaxUint32
	start := time.Now()
	result, err := s.stmtIncrementRevision.ExecContext(ctx, now, dispType, nsid, ifindex)
	if err != nil {
		s.logger.Debug("sql", "stmt", "IncrementRevision", "args", []any{"(timestamp)", dispType, nsid, ifindex}, "duration_ms", msec(time.Since(start)), "error", err)
		return 0, fmt.Errorf("increment revision: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	s.logger.Debug("sql", "stmt", "IncrementRevision", "args", []any{"(timestamp)", dispType, nsid, ifindex}, "duration_ms", msec(time.Since(start)), "rows_affected", rows)
	if rows == 0 {
		return 0, fmt.Errorf("dispatcher (%s, %d, %d): %w", dispType, nsid, ifindex, store.ErrNotFound)
	}

	// Fetch the new revision
	start = time.Now()
	var newRevision uint32
	err = s.stmtGetDispatcherByType.QueryRowContext(ctx, dispType, nsid, ifindex).Scan(&newRevision)
	if err != nil {
		s.logger.Debug("sql", "stmt", "GetDispatcherByType", "args", []any{dispType, nsid, ifindex}, "duration_ms", msec(time.Since(start)), "error", err)
		return 0, fmt.Errorf("fetch new revision: %w", err)
	}
	s.logger.Debug("sql", "stmt", "GetDispatcherByType", "args", []any{dispType, nsid, ifindex}, "duration_ms", msec(time.Since(start)), "rows", 1)

	return newRevision, nil
}

// RunInTransaction executes the callback within a database transaction.
// If the callback returns nil, the transaction commits.
// If the callback returns an error, the transaction rolls back.
//
// # Prepared Statement Handling
//
// The Store holds "master" prepared statements that are compiled once when the
// database is opened and remain valid for the lifetime of the connection. These
// masters live on s.stmtXXX fields, prepared against *sql.DB.
//
// For transactional use, tx.StmtContext creates lightweight transaction-bound
// handles that reference the already-compiled master statements. No SQL parsing
// occurs here - we're just binding existing compiled queries to this transaction.
//
// After commit or rollback, the tx-bound handles become invalid, but that's fine:
// txStore goes out of scope and subsequent RunInTransaction calls create fresh
// handles from the still-valid masters. The masters are never invalidated by
// transaction lifecycle events.
func (s *sqliteStore) RunInTransaction(ctx context.Context, fn func(interpreter.Store) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	txStore := &sqliteStore{
		db:     s.db,
		conn:   tx,
		logger: s.logger,
		// Program statements
		stmtGetProgram:                 tx.StmtContext(ctx, s.stmtGetProgram),
		stmtSaveProgram:                tx.StmtContext(ctx, s.stmtSaveProgram),
		stmtDeleteProgramMetadataIndex: tx.StmtContext(ctx, s.stmtDeleteProgramMetadataIndex),
		stmtInsertProgramMetadataIndex: tx.StmtContext(ctx, s.stmtInsertProgramMetadataIndex),
		stmtDeleteProgram:              tx.StmtContext(ctx, s.stmtDeleteProgram),
		stmtListPrograms:               tx.StmtContext(ctx, s.stmtListPrograms),
		stmtFindProgramByMetadata:      tx.StmtContext(ctx, s.stmtFindProgramByMetadata),
		stmtFindAllProgramsByMetadata:  tx.StmtContext(ctx, s.stmtFindAllProgramsByMetadata),
		// Tag statements
		stmtInsertTag:  tx.StmtContext(ctx, s.stmtInsertTag),
		stmtDeleteTags: tx.StmtContext(ctx, s.stmtDeleteTags),
		// Link registry statements
		stmtDeleteLink:         tx.StmtContext(ctx, s.stmtDeleteLink),
		stmtGetLinkRegistry:    tx.StmtContext(ctx, s.stmtGetLinkRegistry),
		stmtListLinks:          tx.StmtContext(ctx, s.stmtListLinks),
		stmtListLinksByProgram: tx.StmtContext(ctx, s.stmtListLinksByProgram),
		stmtInsertLinkRegistry: tx.StmtContext(ctx, s.stmtInsertLinkRegistry),
		// Link detail get statements
		stmtGetTracepointDetails: tx.StmtContext(ctx, s.stmtGetTracepointDetails),
		stmtGetKprobeDetails:     tx.StmtContext(ctx, s.stmtGetKprobeDetails),
		stmtGetUprobeDetails:     tx.StmtContext(ctx, s.stmtGetUprobeDetails),
		stmtGetFentryDetails:     tx.StmtContext(ctx, s.stmtGetFentryDetails),
		stmtGetFexitDetails:      tx.StmtContext(ctx, s.stmtGetFexitDetails),
		stmtGetXDPDetails:        tx.StmtContext(ctx, s.stmtGetXDPDetails),
		stmtGetTCDetails:         tx.StmtContext(ctx, s.stmtGetTCDetails),
		stmtGetTCXDetails:        tx.StmtContext(ctx, s.stmtGetTCXDetails),
		// Link detail save statements
		stmtSaveTracepointDetails: tx.StmtContext(ctx, s.stmtSaveTracepointDetails),
		stmtSaveKprobeDetails:     tx.StmtContext(ctx, s.stmtSaveKprobeDetails),
		stmtSaveUprobeDetails:     tx.StmtContext(ctx, s.stmtSaveUprobeDetails),
		stmtSaveFentryDetails:     tx.StmtContext(ctx, s.stmtSaveFentryDetails),
		stmtSaveFexitDetails:      tx.StmtContext(ctx, s.stmtSaveFexitDetails),
		stmtSaveXDPDetails:        tx.StmtContext(ctx, s.stmtSaveXDPDetails),
		stmtSaveTCDetails:         tx.StmtContext(ctx, s.stmtSaveTCDetails),
		stmtSaveTCXDetails:        tx.StmtContext(ctx, s.stmtSaveTCXDetails),
		// Dispatcher statements
		stmtGetDispatcher:       tx.StmtContext(ctx, s.stmtGetDispatcher),
		stmtSaveDispatcher:      tx.StmtContext(ctx, s.stmtSaveDispatcher),
		stmtDeleteDispatcher:    tx.StmtContext(ctx, s.stmtDeleteDispatcher),
		stmtIncrementRevision:   tx.StmtContext(ctx, s.stmtIncrementRevision),
		stmtGetDispatcherByType: tx.StmtContext(ctx, s.stmtGetDispatcherByType),
	}

	if err := fn(txStore); err != nil {
		return err
	}

	return tx.Commit()
}
