// Package sqlite provides a SQLite implementation of the program store.
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
	inTx   bool    // true if this store is operating within a transaction
	logger *slog.Logger
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

// Get retrieves program metadata by kernel ID.
// Returns store.ErrNotFound if the program does not exist.
func (s *Store) Get(ctx context.Context, kernelID uint32) (managed.Program, error) {
	row := s.conn.QueryRowContext(ctx,
		"SELECT metadata FROM managed_programs WHERE kernel_id = ?",
		kernelID)

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

	_, err = s.conn.ExecContext(ctx,
		"INSERT OR REPLACE INTO managed_programs (kernel_id, metadata, created_at) VALUES (?, ?, ?)",
		kernelID, string(metadataJSON), time.Now().Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("failed to insert program: %w", err)
	}

	// Clear old metadata index entries for this program
	_, err = s.conn.ExecContext(ctx,
		"DELETE FROM program_metadata_index WHERE kernel_id = ?",
		kernelID)
	if err != nil {
		return fmt.Errorf("failed to clear metadata index: %w", err)
	}

	// Insert metadata index entries for UserMetadata
	for key, value := range metadata.UserMetadata {
		_, err = s.conn.ExecContext(ctx,
			"INSERT INTO program_metadata_index (kernel_id, key, value) VALUES (?, ?, ?)",
			kernelID, key, value)
		if err != nil {
			return fmt.Errorf("failed to insert metadata index: %w", err)
		}
	}

	s.logger.Debug("saved program", "kernel_id", kernelID)
	return nil
}

// Delete removes program metadata.
func (s *Store) Delete(ctx context.Context, kernelID uint32) error {
	_, err := s.conn.ExecContext(ctx,
		"DELETE FROM managed_programs WHERE kernel_id = ?",
		kernelID)
	if err == nil {
		s.logger.Debug("deleted program", "kernel_id", kernelID)
	}
	return err
}

// List returns all program metadata.
func (s *Store) List(ctx context.Context) (map[uint32]managed.Program, error) {
	rows, err := s.conn.QueryContext(ctx,
		"SELECT kernel_id, metadata FROM managed_programs")
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
	row := s.conn.QueryRowContext(ctx, `
		SELECT m.kernel_id, m.metadata
		FROM managed_programs m
		JOIN program_metadata_index i ON m.kernel_id = i.kernel_id
		WHERE i.key = ? AND i.value = ?
		LIMIT 1
	`, key, value)

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
	rows, err := s.conn.QueryContext(ctx, `
		SELECT m.kernel_id, m.metadata
		FROM managed_programs m
		JOIN program_metadata_index i ON m.kernel_id = i.kernel_id
		WHERE i.key = ? AND i.value = ?
	`, key, value)
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
	result, err := s.conn.ExecContext(ctx,
		"DELETE FROM link_registry WHERE kernel_link_id = ?",
		kernelLinkID)
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
	row := s.conn.QueryRowContext(ctx,
		`SELECT kernel_link_id, link_type, kernel_program_id, pin_path, created_at
		 FROM link_registry WHERE kernel_link_id = ?`, kernelLinkID)

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
	rows, err := s.conn.QueryContext(ctx,
		`SELECT kernel_link_id, link_type, kernel_program_id, pin_path, created_at
		 FROM link_registry`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return s.scanLinkSummaries(rows)
}

// ListLinksByProgram returns all links for a given program kernel ID.
func (s *Store) ListLinksByProgram(ctx context.Context, programKernelID uint32) ([]managed.LinkSummary, error) {
	rows, err := s.conn.QueryContext(ctx,
		`SELECT kernel_link_id, link_type, kernel_program_id, pin_path, created_at
		 FROM link_registry WHERE kernel_program_id = ?`, programKernelID)
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

	_, err := s.conn.ExecContext(ctx,
		`INSERT INTO tracepoint_link_details (kernel_link_id, tracepoint_group, tracepoint_name)
		 VALUES (?, ?, ?)`,
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

	_, err := s.conn.ExecContext(ctx,
		`INSERT INTO kprobe_link_details (kernel_link_id, fn_name, offset, retprobe)
		 VALUES (?, ?, ?, ?)`,
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

	_, err := s.conn.ExecContext(ctx,
		`INSERT INTO uprobe_link_details (kernel_link_id, target, fn_name, offset, pid, retprobe)
		 VALUES (?, ?, ?, ?, ?, ?)`,
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

	_, err := s.conn.ExecContext(ctx,
		`INSERT INTO fentry_link_details (kernel_link_id, fn_name)
		 VALUES (?, ?)`,
		summary.KernelLinkID, details.FnName)
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

	_, err := s.conn.ExecContext(ctx,
		`INSERT INTO fexit_link_details (kernel_link_id, fn_name)
		 VALUES (?, ?)`,
		summary.KernelLinkID, details.FnName)
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

	_, err = s.conn.ExecContext(ctx,
		`INSERT INTO xdp_link_details (kernel_link_id, interface, ifindex, priority, position, proceed_on, netns, nsid, dispatcher_id, revision)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
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

	_, err = s.conn.ExecContext(ctx,
		`INSERT INTO tc_link_details (kernel_link_id, interface, ifindex, direction, priority, position, proceed_on, netns, nsid, dispatcher_id, revision)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
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

	_, err := s.conn.ExecContext(ctx,
		`INSERT INTO tcx_link_details (kernel_link_id, interface, ifindex, direction, priority, netns, nsid)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
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
	_, err := s.conn.ExecContext(ctx,
		`INSERT INTO link_registry (kernel_link_id, link_type, kernel_program_id, pin_path, created_at)
		 VALUES (?, ?, ?, ?, ?)`,
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
	row := s.conn.QueryRowContext(ctx,
		`SELECT tracepoint_group, tracepoint_name FROM tracepoint_link_details WHERE kernel_link_id = ?`, kernelLinkID)

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
	row := s.conn.QueryRowContext(ctx,
		`SELECT fn_name, offset, retprobe FROM kprobe_link_details WHERE kernel_link_id = ?`, kernelLinkID)

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
	row := s.conn.QueryRowContext(ctx,
		`SELECT target, fn_name, offset, pid, retprobe FROM uprobe_link_details WHERE kernel_link_id = ?`, kernelLinkID)

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
	row := s.conn.QueryRowContext(ctx,
		`SELECT fn_name FROM fentry_link_details WHERE kernel_link_id = ?`, kernelLinkID)

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
	row := s.conn.QueryRowContext(ctx,
		`SELECT fn_name FROM fexit_link_details WHERE kernel_link_id = ?`, kernelLinkID)

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
	row := s.conn.QueryRowContext(ctx,
		`SELECT interface, ifindex, priority, position, proceed_on, netns, nsid, dispatcher_id, revision
		 FROM xdp_link_details WHERE kernel_link_id = ?`, kernelLinkID)

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
	row := s.conn.QueryRowContext(ctx,
		`SELECT interface, ifindex, direction, priority, position, proceed_on, netns, nsid, dispatcher_id, revision
		 FROM tc_link_details WHERE kernel_link_id = ?`, kernelLinkID)

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
	row := s.conn.QueryRowContext(ctx,
		`SELECT interface, ifindex, direction, priority, netns, nsid
		 FROM tcx_link_details WHERE kernel_link_id = ?`, kernelLinkID)

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
	row := s.conn.QueryRowContext(ctx,
		`SELECT id, type, nsid, ifindex, revision, kernel_id, link_id, link_pin_path, prog_pin_path, num_extensions
		 FROM dispatchers WHERE type = ? AND nsid = ? AND ifindex = ?`,
		dispType, nsid, ifindex)

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

	_, err := s.conn.ExecContext(ctx,
		`INSERT INTO dispatchers (type, nsid, ifindex, revision, kernel_id, link_id, link_pin_path, prog_pin_path, num_extensions, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(type, nsid, ifindex) DO UPDATE SET
		   revision = excluded.revision,
		   kernel_id = excluded.kernel_id,
		   link_id = excluded.link_id,
		   link_pin_path = excluded.link_pin_path,
		   prog_pin_path = excluded.prog_pin_path,
		   num_extensions = excluded.num_extensions,
		   updated_at = excluded.updated_at`,
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
	result, err := s.conn.ExecContext(ctx,
		`DELETE FROM dispatchers WHERE type = ? AND nsid = ? AND ifindex = ?`,
		dispType, nsid, ifindex)
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
	result, err := s.conn.ExecContext(ctx,
		`UPDATE dispatchers
		 SET revision = CASE WHEN revision = 4294967295 THEN 1 ELSE revision + 1 END,
		     updated_at = ?
		 WHERE type = ? AND nsid = ? AND ifindex = ?`,
		now, dispType, nsid, ifindex)
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
	err = s.conn.QueryRowContext(ctx,
		`SELECT revision FROM dispatchers WHERE type = ? AND nsid = ? AND ifindex = ?`,
		dispType, nsid, ifindex).Scan(&newRevision)
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
func (s *Store) RunInTransaction(ctx context.Context, fn func(interpreter.Store) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Create a transactional store using the same db but with tx as conn
	txStore := &Store{
		db:     s.db,
		conn:   tx,
		inTx:   true,
		logger: s.logger,
	}

	if err := fn(txStore); err != nil {
		return err
	}

	return tx.Commit()
}
