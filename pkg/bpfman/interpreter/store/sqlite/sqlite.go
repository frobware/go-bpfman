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
	"time"

	_ "modernc.org/sqlite"

	"github.com/frobware/go-bpfman/pkg/bpfman/dispatcher"
	"github.com/frobware/go-bpfman/pkg/bpfman/interpreter"
	"github.com/frobware/go-bpfman/pkg/bpfman/interpreter/store"
	"github.com/frobware/go-bpfman/pkg/bpfman/managed"
)

//go:embed schema.sql
var schemaSQL string

// dbConn abstracts *sql.DB and *sql.Tx for query execution.
type dbConn interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// Store implements interpreter.ProgramStore using SQLite.
type Store struct {
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
func New(dbPath string, logger *slog.Logger) (*Store, error) {
	if logger == nil {
		logger = slog.Default()
	}
	logger = logger.With("component", "store")

	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create database directory: %w", err)
	}

	db, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)")
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	s := &Store{db: db, conn: db, logger: logger}
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
func NewInMemory(logger *slog.Logger) (*Store, error) {
	if logger == nil {
		logger = slog.Default()
	}
	logger = logger.With("component", "store")

	db, err := sql.Open("sqlite", ":memory:?_pragma=foreign_keys(1)")
	if err != nil {
		return nil, fmt.Errorf("failed to open in-memory database: %w", err)
	}

	s := &Store{db: db, conn: db, logger: logger}
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
func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) migrate() error {
	// Execute the embedded schema
	if _, err := s.db.Exec(schemaSQL); err != nil {
		return fmt.Errorf("failed to execute schema: %w", err)
	}
	return nil
}

// prepareStatements prepares all SQL statements for reuse.
func (s *Store) prepareStatements() error {
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

func (s *Store) prepareProgramStatements() error {
	var err error

	const sqlGetProgram = "SELECT metadata FROM managed_programs WHERE kernel_id = ?"
	if s.stmtGetProgram, err = s.db.Prepare(sqlGetProgram); err != nil {
		return fmt.Errorf("prepare GetProgram: %w", err)
	}

	const sqlSaveProgram = "INSERT OR REPLACE INTO managed_programs (kernel_id, metadata, created_at) VALUES (?, ?, ?)"
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

	const sqlListPrograms = "SELECT kernel_id, metadata FROM managed_programs"
	if s.stmtListPrograms, err = s.db.Prepare(sqlListPrograms); err != nil {
		return fmt.Errorf("prepare ListPrograms: %w", err)
	}

	const sqlFindProgramByMetadata = `
		SELECT m.kernel_id, m.metadata
		FROM managed_programs m
		JOIN program_metadata_index i ON m.kernel_id = i.kernel_id
		WHERE i.key = ? AND i.value = ?
		LIMIT 1`
	if s.stmtFindProgramByMetadata, err = s.db.Prepare(sqlFindProgramByMetadata); err != nil {
		return fmt.Errorf("prepare FindProgramByMetadata: %w", err)
	}

	const sqlFindAllProgramsByMetadata = `
		SELECT m.kernel_id, m.metadata
		FROM managed_programs m
		JOIN program_metadata_index i ON m.kernel_id = i.kernel_id
		WHERE i.key = ? AND i.value = ?`
	if s.stmtFindAllProgramsByMetadata, err = s.db.Prepare(sqlFindAllProgramsByMetadata); err != nil {
		return fmt.Errorf("prepare FindAllProgramsByMetadata: %w", err)
	}

	return nil
}

func (s *Store) prepareLinkRegistryStatements() error {
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

func (s *Store) prepareLinkDetailStatements() error {
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

func (s *Store) prepareDispatcherStatements() error {
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
func (s *Store) Get(ctx context.Context, kernelID uint32) (managed.Program, error) {
	row := s.stmtGetProgram.QueryRowContext(ctx, kernelID)

	var metadataJSON string
	err := row.Scan(&metadataJSON)
	if err == sql.ErrNoRows {
		return managed.Program{}, fmt.Errorf("program %d: %w", kernelID, store.ErrNotFound)
	}
	if err != nil {
		return managed.Program{}, err
	}

	var metadata managed.Program
	if err := json.Unmarshal([]byte(metadataJSON), &metadata); err != nil {
		return managed.Program{}, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	return metadata, nil
}

// Save stores program metadata.
// For atomicity with other operations, wrap in RunInTransaction.
func (s *Store) Save(ctx context.Context, kernelID uint32, metadata managed.Program) error {
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	_, err = s.stmtSaveProgram.ExecContext(ctx,
		kernelID, string(metadataJSON), time.Now().Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("failed to insert program: %w", err)
	}

	// Clear old metadata index entries for this program
	_, err = s.stmtDeleteProgramMetadataIndex.ExecContext(ctx, kernelID)
	if err != nil {
		return fmt.Errorf("failed to clear metadata index: %w", err)
	}

	// Insert metadata index entries for UserMetadata
	for key, value := range metadata.UserMetadata {
		_, err = s.stmtInsertProgramMetadataIndex.ExecContext(ctx, kernelID, key, value)
		if err != nil {
			return fmt.Errorf("failed to insert metadata index: %w", err)
		}
	}

	s.logger.Debug("saved program", "kernel_id", kernelID)
	return nil
}

// Delete removes program metadata.
func (s *Store) Delete(ctx context.Context, kernelID uint32) error {
	_, err := s.stmtDeleteProgram.ExecContext(ctx, kernelID)
	if err == nil {
		s.logger.Debug("deleted program", "kernel_id", kernelID)
	}
	return err
}

// List returns all program metadata.
func (s *Store) List(ctx context.Context) (map[uint32]managed.Program, error) {
	rows, err := s.stmtListPrograms.QueryContext(ctx)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[uint32]managed.Program)
	for rows.Next() {
		var kernelID uint32
		var metadataJSON string
		if err := rows.Scan(&kernelID, &metadataJSON); err != nil {
			return nil, err
		}

		var metadata managed.Program
		if err := json.Unmarshal([]byte(metadataJSON), &metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata for %d: %w", kernelID, err)
		}

		result[kernelID] = metadata
	}

	return result, rows.Err()
}

// FindProgramByMetadata finds a program by a specific metadata key/value pair.
// Returns store.ErrNotFound if no program matches.
func (s *Store) FindProgramByMetadata(ctx context.Context, key, value string) (managed.Program, uint32, error) {
	row := s.stmtFindProgramByMetadata.QueryRowContext(ctx, key, value)

	var kernelID uint32
	var metadataJSON string
	err := row.Scan(&kernelID, &metadataJSON)
	if err == sql.ErrNoRows {
		return managed.Program{}, 0, fmt.Errorf("program with %s=%s: %w", key, value, store.ErrNotFound)
	}
	if err != nil {
		return managed.Program{}, 0, err
	}

	var metadata managed.Program
	if err := json.Unmarshal([]byte(metadataJSON), &metadata); err != nil {
		return managed.Program{}, 0, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	return metadata, kernelID, nil
}

// FindAllProgramsByMetadata finds all programs with a specific metadata key/value pair.
func (s *Store) FindAllProgramsByMetadata(ctx context.Context, key, value string) ([]struct {
	KernelID uint32
	Metadata managed.Program
}, error) {
	rows, err := s.stmtFindAllProgramsByMetadata.QueryContext(ctx, key, value)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []struct {
		KernelID uint32
		Metadata managed.Program
	}

	for rows.Next() {
		var kernelID uint32
		var metadataJSON string
		if err := rows.Scan(&kernelID, &metadataJSON); err != nil {
			return nil, err
		}

		var metadata managed.Program
		if err := json.Unmarshal([]byte(metadataJSON), &metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata for %d: %w", kernelID, err)
		}

		result = append(result, struct {
			KernelID uint32
			Metadata managed.Program
		}{KernelID: kernelID, Metadata: metadata})
	}

	return result, rows.Err()
}

// ----------------------------------------------------------------------------
// Link Registry Operations
// ----------------------------------------------------------------------------

// DeleteLink removes link metadata by kernel link ID.
// Due to CASCADE, this also removes the corresponding detail table entry.
func (s *Store) DeleteLink(ctx context.Context, kernelLinkID uint32) error {
	result, err := s.stmtDeleteLink.ExecContext(ctx, kernelLinkID)
	if err != nil {
		return fmt.Errorf("failed to delete link: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("link %d: %w", kernelLinkID, store.ErrNotFound)
	}

	s.logger.Debug("deleted link", "kernel_link_id", kernelLinkID)
	return nil
}

// GetLink retrieves link metadata by kernel link ID using two-phase lookup.
func (s *Store) GetLink(ctx context.Context, kernelLinkID uint32) (managed.LinkSummary, managed.LinkDetails, error) {
	// Phase 1: Get summary from registry
	row := s.stmtGetLinkRegistry.QueryRowContext(ctx, kernelLinkID)

	summary, err := s.scanLinkSummary(row)
	if err != nil {
		return managed.LinkSummary{}, nil, err
	}

	// Phase 2: Get details based on link type
	details, err := s.getLinkDetails(ctx, summary.LinkType, kernelLinkID)
	if err != nil {
		return managed.LinkSummary{}, nil, err
	}

	return summary, details, nil
}

// ListLinks returns all links (summary only).
func (s *Store) ListLinks(ctx context.Context) ([]managed.LinkSummary, error) {
	rows, err := s.stmtListLinks.QueryContext(ctx)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return s.scanLinkSummaries(rows)
}

// ListLinksByProgram returns all links for a given program kernel ID.
func (s *Store) ListLinksByProgram(ctx context.Context, programKernelID uint32) ([]managed.LinkSummary, error) {
	rows, err := s.stmtListLinksByProgram.QueryContext(ctx, programKernelID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return s.scanLinkSummaries(rows)
}

// ----------------------------------------------------------------------------
// Type-Specific Link Save Methods
// ----------------------------------------------------------------------------

// SaveTracepointLink saves a tracepoint link.
// For atomicity with other operations, wrap in RunInTransaction.
func (s *Store) SaveTracepointLink(ctx context.Context, summary managed.LinkSummary, details managed.TracepointDetails) error {
	if err := s.insertLinkRegistry(ctx, summary); err != nil {
		return err
	}

	_, err := s.stmtSaveTracepointDetails.ExecContext(ctx,
		summary.KernelLinkID, details.Group, details.Name)
	if err != nil {
		return fmt.Errorf("failed to insert tracepoint details: %w", err)
	}

	s.logger.Debug("saved tracepoint link", "kernel_link_id", summary.KernelLinkID, "group", details.Group, "name", details.Name)
	return nil
}

// SaveKprobeLink saves a kprobe/kretprobe link.
// For atomicity with other operations, wrap in RunInTransaction.
func (s *Store) SaveKprobeLink(ctx context.Context, summary managed.LinkSummary, details managed.KprobeDetails) error {
	if err := s.insertLinkRegistry(ctx, summary); err != nil {
		return err
	}

	retprobe := 0
	if details.Retprobe {
		retprobe = 1
	}

	_, err := s.stmtSaveKprobeDetails.ExecContext(ctx,
		summary.KernelLinkID, details.FnName, details.Offset, retprobe)
	if err != nil {
		return fmt.Errorf("failed to insert kprobe details: %w", err)
	}

	s.logger.Debug("saved kprobe link", "kernel_link_id", summary.KernelLinkID, "fn_name", details.FnName)
	return nil
}

// SaveUprobeLink saves a uprobe/uretprobe link.
// For atomicity with other operations, wrap in RunInTransaction.
func (s *Store) SaveUprobeLink(ctx context.Context, summary managed.LinkSummary, details managed.UprobeDetails) error {
	if err := s.insertLinkRegistry(ctx, summary); err != nil {
		return err
	}

	retprobe := 0
	if details.Retprobe {
		retprobe = 1
	}

	_, err := s.stmtSaveUprobeDetails.ExecContext(ctx,
		summary.KernelLinkID, details.Target, details.FnName, details.Offset, details.PID, retprobe)
	if err != nil {
		return fmt.Errorf("failed to insert uprobe details: %w", err)
	}

	s.logger.Debug("saved uprobe link", "kernel_link_id", summary.KernelLinkID, "target", details.Target)
	return nil
}

// SaveFentryLink saves a fentry link.
// For atomicity with other operations, wrap in RunInTransaction.
func (s *Store) SaveFentryLink(ctx context.Context, summary managed.LinkSummary, details managed.FentryDetails) error {
	if err := s.insertLinkRegistry(ctx, summary); err != nil {
		return err
	}

	_, err := s.stmtSaveFentryDetails.ExecContext(ctx, summary.KernelLinkID, details.FnName)
	if err != nil {
		return fmt.Errorf("failed to insert fentry details: %w", err)
	}

	s.logger.Debug("saved fentry link", "kernel_link_id", summary.KernelLinkID, "fn_name", details.FnName)
	return nil
}

// SaveFexitLink saves a fexit link.
// For atomicity with other operations, wrap in RunInTransaction.
func (s *Store) SaveFexitLink(ctx context.Context, summary managed.LinkSummary, details managed.FexitDetails) error {
	if err := s.insertLinkRegistry(ctx, summary); err != nil {
		return err
	}

	_, err := s.stmtSaveFexitDetails.ExecContext(ctx, summary.KernelLinkID, details.FnName)
	if err != nil {
		return fmt.Errorf("failed to insert fexit details: %w", err)
	}

	s.logger.Debug("saved fexit link", "kernel_link_id", summary.KernelLinkID, "fn_name", details.FnName)
	return nil
}

// SaveXDPLink saves an XDP link.
// For atomicity with other operations, wrap in RunInTransaction.
func (s *Store) SaveXDPLink(ctx context.Context, summary managed.LinkSummary, details managed.XDPDetails) error {
	if err := s.insertLinkRegistry(ctx, summary); err != nil {
		return err
	}

	proceedOnJSON, err := json.Marshal(details.ProceedOn)
	if err != nil {
		return fmt.Errorf("failed to marshal proceed_on: %w", err)
	}

	_, err = s.stmtSaveXDPDetails.ExecContext(ctx,
		summary.KernelLinkID, details.Interface, details.Ifindex, details.Priority, details.Position,
		string(proceedOnJSON), details.Netns, details.Nsid, details.DispatcherID, details.Revision)
	if err != nil {
		return fmt.Errorf("failed to insert xdp details: %w", err)
	}

	s.logger.Debug("saved xdp link", "kernel_link_id", summary.KernelLinkID, "interface", details.Interface)
	return nil
}

// SaveTCLink saves a TC link.
// For atomicity with other operations, wrap in RunInTransaction.
func (s *Store) SaveTCLink(ctx context.Context, summary managed.LinkSummary, details managed.TCDetails) error {
	if err := s.insertLinkRegistry(ctx, summary); err != nil {
		return err
	}

	proceedOnJSON, err := json.Marshal(details.ProceedOn)
	if err != nil {
		return fmt.Errorf("failed to marshal proceed_on: %w", err)
	}

	_, err = s.stmtSaveTCDetails.ExecContext(ctx,
		summary.KernelLinkID, details.Interface, details.Ifindex, details.Direction, details.Priority, details.Position,
		string(proceedOnJSON), details.Netns, details.Nsid, details.DispatcherID, details.Revision)
	if err != nil {
		return fmt.Errorf("failed to insert tc details: %w", err)
	}

	s.logger.Debug("saved tc link", "kernel_link_id", summary.KernelLinkID, "interface", details.Interface, "direction", details.Direction)
	return nil
}

// SaveTCXLink saves a TCX link.
// For atomicity with other operations, wrap in RunInTransaction.
func (s *Store) SaveTCXLink(ctx context.Context, summary managed.LinkSummary, details managed.TCXDetails) error {
	if err := s.insertLinkRegistry(ctx, summary); err != nil {
		return err
	}

	_, err := s.stmtSaveTCXDetails.ExecContext(ctx,
		summary.KernelLinkID, details.Interface, details.Ifindex, details.Direction, details.Priority, details.Netns, details.Nsid)
	if err != nil {
		return fmt.Errorf("failed to insert tcx details: %w", err)
	}

	s.logger.Debug("saved tcx link", "kernel_link_id", summary.KernelLinkID, "interface", details.Interface, "direction", details.Direction)
	return nil
}

// ----------------------------------------------------------------------------
// Helper Functions
// ----------------------------------------------------------------------------

// insertLinkRegistry inserts a record into the link_registry table.
func (s *Store) insertLinkRegistry(ctx context.Context, summary managed.LinkSummary) error {
	_, err := s.stmtInsertLinkRegistry.ExecContext(ctx,
		summary.KernelLinkID, string(summary.LinkType), summary.KernelProgramID,
		summary.PinPath, summary.CreatedAt.Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("failed to insert link registry: %w", err)
	}
	return nil
}

// scanLinkSummary scans a single row into a LinkSummary.
func (s *Store) scanLinkSummary(row *sql.Row) (managed.LinkSummary, error) {
	var summary managed.LinkSummary
	var linkType string
	var pinPath sql.NullString
	var createdAtStr string

	err := row.Scan(&summary.KernelLinkID, &linkType, &summary.KernelProgramID, &pinPath, &createdAtStr)
	if err == sql.ErrNoRows {
		return managed.LinkSummary{}, fmt.Errorf("link: %w", store.ErrNotFound)
	}
	if err != nil {
		return managed.LinkSummary{}, err
	}

	summary.LinkType = managed.LinkType(linkType)
	if pinPath.Valid {
		summary.PinPath = pinPath.String
	}
	summary.CreatedAt, _ = time.Parse(time.RFC3339, createdAtStr)

	return summary, nil
}

// scanLinkSummaries scans multiple rows into a slice of LinkSummary.
func (s *Store) scanLinkSummaries(rows *sql.Rows) ([]managed.LinkSummary, error) {
	var result []managed.LinkSummary

	for rows.Next() {
		var summary managed.LinkSummary
		var linkType string
		var pinPath sql.NullString
		var createdAtStr string

		err := rows.Scan(&summary.KernelLinkID, &linkType, &summary.KernelProgramID, &pinPath, &createdAtStr)
		if err != nil {
			return nil, err
		}

		summary.LinkType = managed.LinkType(linkType)
		if pinPath.Valid {
			summary.PinPath = pinPath.String
		}
		summary.CreatedAt, _ = time.Parse(time.RFC3339, createdAtStr)

		result = append(result, summary)
	}

	return result, rows.Err()
}

// getLinkDetails retrieves the type-specific details for a link.
func (s *Store) getLinkDetails(ctx context.Context, linkType managed.LinkType, kernelLinkID uint32) (managed.LinkDetails, error) {
	switch linkType {
	case managed.LinkTypeTracepoint:
		return s.getTracepointDetails(ctx, kernelLinkID)
	case managed.LinkTypeKprobe, managed.LinkTypeKretprobe:
		return s.getKprobeDetails(ctx, kernelLinkID)
	case managed.LinkTypeUprobe, managed.LinkTypeUretprobe:
		return s.getUprobeDetails(ctx, kernelLinkID)
	case managed.LinkTypeFentry:
		return s.getFentryDetails(ctx, kernelLinkID)
	case managed.LinkTypeFexit:
		return s.getFexitDetails(ctx, kernelLinkID)
	case managed.LinkTypeXDP:
		return s.getXDPDetails(ctx, kernelLinkID)
	case managed.LinkTypeTC:
		return s.getTCDetails(ctx, kernelLinkID)
	case managed.LinkTypeTCX:
		return s.getTCXDetails(ctx, kernelLinkID)
	default:
		return nil, fmt.Errorf("unknown link type: %s", linkType)
	}
}

func (s *Store) getTracepointDetails(ctx context.Context, kernelLinkID uint32) (managed.TracepointDetails, error) {
	row := s.stmtGetTracepointDetails.QueryRowContext(ctx, kernelLinkID)

	var details managed.TracepointDetails
	err := row.Scan(&details.Group, &details.Name)
	if err == sql.ErrNoRows {
		return managed.TracepointDetails{}, fmt.Errorf("tracepoint details for %d: %w", kernelLinkID, store.ErrNotFound)
	}
	if err != nil {
		return managed.TracepointDetails{}, err
	}
	return details, nil
}

func (s *Store) getKprobeDetails(ctx context.Context, kernelLinkID uint32) (managed.KprobeDetails, error) {
	row := s.stmtGetKprobeDetails.QueryRowContext(ctx, kernelLinkID)

	var details managed.KprobeDetails
	var retprobe int
	err := row.Scan(&details.FnName, &details.Offset, &retprobe)
	if err == sql.ErrNoRows {
		return managed.KprobeDetails{}, fmt.Errorf("kprobe details for %d: %w", kernelLinkID, store.ErrNotFound)
	}
	if err != nil {
		return managed.KprobeDetails{}, err
	}
	details.Retprobe = retprobe == 1
	return details, nil
}

func (s *Store) getUprobeDetails(ctx context.Context, kernelLinkID uint32) (managed.UprobeDetails, error) {
	row := s.stmtGetUprobeDetails.QueryRowContext(ctx, kernelLinkID)

	var details managed.UprobeDetails
	var fnName sql.NullString
	var pid sql.NullInt64
	var retprobe int
	err := row.Scan(&details.Target, &fnName, &details.Offset, &pid, &retprobe)
	if err == sql.ErrNoRows {
		return managed.UprobeDetails{}, fmt.Errorf("uprobe details for %d: %w", kernelLinkID, store.ErrNotFound)
	}
	if err != nil {
		return managed.UprobeDetails{}, err
	}
	if fnName.Valid {
		details.FnName = fnName.String
	}
	if pid.Valid {
		details.PID = int32(pid.Int64)
	}
	details.Retprobe = retprobe == 1
	return details, nil
}

func (s *Store) getFentryDetails(ctx context.Context, kernelLinkID uint32) (managed.FentryDetails, error) {
	row := s.stmtGetFentryDetails.QueryRowContext(ctx, kernelLinkID)

	var details managed.FentryDetails
	err := row.Scan(&details.FnName)
	if err == sql.ErrNoRows {
		return managed.FentryDetails{}, fmt.Errorf("fentry details for %d: %w", kernelLinkID, store.ErrNotFound)
	}
	if err != nil {
		return managed.FentryDetails{}, err
	}
	return details, nil
}

func (s *Store) getFexitDetails(ctx context.Context, kernelLinkID uint32) (managed.FexitDetails, error) {
	row := s.stmtGetFexitDetails.QueryRowContext(ctx, kernelLinkID)

	var details managed.FexitDetails
	err := row.Scan(&details.FnName)
	if err == sql.ErrNoRows {
		return managed.FexitDetails{}, fmt.Errorf("fexit details for %d: %w", kernelLinkID, store.ErrNotFound)
	}
	if err != nil {
		return managed.FexitDetails{}, err
	}
	return details, nil
}

func (s *Store) getXDPDetails(ctx context.Context, kernelLinkID uint32) (managed.XDPDetails, error) {
	row := s.stmtGetXDPDetails.QueryRowContext(ctx, kernelLinkID)

	var details managed.XDPDetails
	var proceedOnJSON string
	var netns sql.NullString
	err := row.Scan(&details.Interface, &details.Ifindex, &details.Priority, &details.Position,
		&proceedOnJSON, &netns, &details.Nsid, &details.DispatcherID, &details.Revision)
	if err == sql.ErrNoRows {
		return managed.XDPDetails{}, fmt.Errorf("xdp details for %d: %w", kernelLinkID, store.ErrNotFound)
	}
	if err != nil {
		return managed.XDPDetails{}, err
	}

	if err := json.Unmarshal([]byte(proceedOnJSON), &details.ProceedOn); err != nil {
		return managed.XDPDetails{}, fmt.Errorf("failed to unmarshal proceed_on: %w", err)
	}
	if netns.Valid {
		details.Netns = netns.String
	}
	return details, nil
}

func (s *Store) getTCDetails(ctx context.Context, kernelLinkID uint32) (managed.TCDetails, error) {
	row := s.stmtGetTCDetails.QueryRowContext(ctx, kernelLinkID)

	var details managed.TCDetails
	var proceedOnJSON string
	var netns sql.NullString
	err := row.Scan(&details.Interface, &details.Ifindex, &details.Direction, &details.Priority, &details.Position,
		&proceedOnJSON, &netns, &details.Nsid, &details.DispatcherID, &details.Revision)
	if err == sql.ErrNoRows {
		return managed.TCDetails{}, fmt.Errorf("tc details for %d: %w", kernelLinkID, store.ErrNotFound)
	}
	if err != nil {
		return managed.TCDetails{}, err
	}

	if err := json.Unmarshal([]byte(proceedOnJSON), &details.ProceedOn); err != nil {
		return managed.TCDetails{}, fmt.Errorf("failed to unmarshal proceed_on: %w", err)
	}
	if netns.Valid {
		details.Netns = netns.String
	}
	return details, nil
}

func (s *Store) getTCXDetails(ctx context.Context, kernelLinkID uint32) (managed.TCXDetails, error) {
	row := s.stmtGetTCXDetails.QueryRowContext(ctx, kernelLinkID)

	var details managed.TCXDetails
	var netns sql.NullString
	var nsid sql.NullInt64
	err := row.Scan(&details.Interface, &details.Ifindex, &details.Direction, &details.Priority, &netns, &nsid)
	if err == sql.ErrNoRows {
		return managed.TCXDetails{}, fmt.Errorf("tcx details for %d: %w", kernelLinkID, store.ErrNotFound)
	}
	if err != nil {
		return managed.TCXDetails{}, err
	}

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
func (s *Store) GetDispatcher(ctx context.Context, dispType string, nsid uint64, ifindex uint32) (managed.DispatcherState, error) {
	row := s.stmtGetDispatcher.QueryRowContext(ctx, dispType, nsid, ifindex)

	var state managed.DispatcherState
	var id int64
	var dispTypeStr string
	err := row.Scan(&id, &dispTypeStr, &state.Nsid, &state.Ifindex, &state.Revision,
		&state.KernelID, &state.LinkID, &state.LinkPinPath, &state.ProgPinPath, &state.NumExtensions)
	if err == sql.ErrNoRows {
		return managed.DispatcherState{}, fmt.Errorf("dispatcher (%s, %d, %d): %w", dispType, nsid, ifindex, store.ErrNotFound)
	}
	if err != nil {
		return managed.DispatcherState{}, err
	}

	state.Type = dispatcher.DispatcherType(dispTypeStr)
	return state, nil
}

// SaveDispatcher creates or updates a dispatcher.
func (s *Store) SaveDispatcher(ctx context.Context, state managed.DispatcherState) error {
	now := time.Now().Format(time.RFC3339)

	_, err := s.stmtSaveDispatcher.ExecContext(ctx,
		string(state.Type), state.Nsid, state.Ifindex, state.Revision,
		state.KernelID, state.LinkID, state.LinkPinPath, state.ProgPinPath,
		state.NumExtensions, now, now)
	if err != nil {
		return fmt.Errorf("save dispatcher: %w", err)
	}

	s.logger.Debug("saved dispatcher",
		"type", state.Type, "nsid", state.Nsid, "ifindex", state.Ifindex, "revision", state.Revision)
	return nil
}

// DeleteDispatcher removes a dispatcher by type, nsid, and ifindex.
func (s *Store) DeleteDispatcher(ctx context.Context, dispType string, nsid uint64, ifindex uint32) error {
	result, err := s.stmtDeleteDispatcher.ExecContext(ctx, dispType, nsid, ifindex)
	if err != nil {
		return fmt.Errorf("delete dispatcher: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("dispatcher (%s, %d, %d): %w", dispType, nsid, ifindex, store.ErrNotFound)
	}

	s.logger.Debug("deleted dispatcher", "type", dispType, "nsid", nsid, "ifindex", ifindex)
	return nil
}

// IncrementRevision atomically increments the dispatcher revision.
// Returns the new revision number. Wraps from MaxUint32 to 1.
// For atomicity with other operations, wrap in RunInTransaction.
func (s *Store) IncrementRevision(ctx context.Context, dispType string, nsid uint64, ifindex uint32) (uint32, error) {
	now := time.Now().Format(time.RFC3339)

	// Use CASE to handle wrap-around at MaxUint32
	result, err := s.stmtIncrementRevision.ExecContext(ctx, now, dispType, nsid, ifindex)
	if err != nil {
		return 0, fmt.Errorf("increment revision: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return 0, err
	}
	if rows == 0 {
		return 0, fmt.Errorf("dispatcher (%s, %d, %d): %w", dispType, nsid, ifindex, store.ErrNotFound)
	}

	// Fetch the new revision
	var newRevision uint32
	err = s.stmtGetDispatcherByType.QueryRowContext(ctx, dispType, nsid, ifindex).Scan(&newRevision)
	if err != nil {
		return 0, fmt.Errorf("fetch new revision: %w", err)
	}

	s.logger.Debug("incremented dispatcher revision",
		"type", dispType, "nsid", nsid, "ifindex", ifindex, "new_revision", newRevision)
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
func (s *Store) RunInTransaction(ctx context.Context, fn func(interpreter.Store) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	txStore := &Store{
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
