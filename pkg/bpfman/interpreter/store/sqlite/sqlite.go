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

// Store implements interpreter.ProgramStore using SQLite.
type Store struct {
	db     *sql.DB
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

	s := &Store{db: db, logger: logger}
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

	s := &Store{db: db, logger: logger}
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
// Only returns programs with state=loaded.
func (s *Store) Get(ctx context.Context, kernelID uint32) (managed.Program, error) {
	row := s.db.QueryRowContext(ctx,
		"SELECT metadata FROM managed_programs WHERE kernel_id = ? AND state = ?",
		kernelID, string(managed.StateLoaded))

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
func (s *Store) Save(ctx context.Context, kernelID uint32, metadata managed.Program) error {
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx,
		"INSERT OR REPLACE INTO managed_programs (kernel_id, uuid, metadata, created_at) VALUES (?, ?, ?, ?)",
		kernelID, metadata.UUID, string(metadataJSON), time.Now().Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("failed to insert program: %w", err)
	}

	// Clear old metadata index entries for this program
	_, err = tx.ExecContext(ctx,
		"DELETE FROM program_metadata_index WHERE kernel_id = ?",
		kernelID)
	if err != nil {
		return fmt.Errorf("failed to clear metadata index: %w", err)
	}

	// Insert metadata index entries for UserMetadata
	for key, value := range metadata.UserMetadata {
		_, err = tx.ExecContext(ctx,
			"INSERT INTO program_metadata_index (kernel_id, key, value) VALUES (?, ?, ?)",
			kernelID, key, value)
		if err != nil {
			return fmt.Errorf("failed to insert metadata index: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return err
	}
	s.logger.Debug("saved program", "kernel_id", kernelID, "uuid", metadata.UUID)
	return nil
}

// GetByUUID retrieves program metadata by UUID.
// Returns store.ErrNotFound if the program does not exist.
// Only returns programs with state=loaded.
func (s *Store) GetByUUID(ctx context.Context, uuid string) (managed.Program, uint32, error) {
	row := s.db.QueryRowContext(ctx,
		"SELECT kernel_id, metadata FROM managed_programs WHERE uuid = ? AND state = ?",
		uuid, string(managed.StateLoaded))

	var kernelID uint32
	var metadataJSON string
	err := row.Scan(&kernelID, &metadataJSON)
	if err == sql.ErrNoRows {
		return managed.Program{}, 0, fmt.Errorf("uuid %s: %w", uuid, store.ErrNotFound)
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

// Delete removes program metadata.
func (s *Store) Delete(ctx context.Context, kernelID uint32) error {
	_, err := s.db.ExecContext(ctx,
		"DELETE FROM managed_programs WHERE kernel_id = ?",
		kernelID)
	if err == nil {
		s.logger.Debug("deleted program", "kernel_id", kernelID)
	}
	return err
}

// MarkUnloading transitions a program to unloading state.
func (s *Store) MarkUnloading(ctx context.Context, kernelID uint32) error {
	now := time.Now().Format(time.RFC3339)

	result, err := s.db.ExecContext(ctx,
		`UPDATE managed_programs
		 SET state = ?, updated_at = ?
		 WHERE kernel_id = ? AND state = ?`,
		string(managed.StateUnloading), now, kernelID, string(managed.StateLoaded))
	if err != nil {
		return fmt.Errorf("failed to mark unloading: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("program %d: %w", kernelID, store.ErrNotFound)
	}

	s.logger.Debug("marked unloading", "kernel_id", kernelID)
	return nil
}

// List returns all program metadata.
// Only returns programs with state=loaded.
func (s *Store) List(ctx context.Context) (map[uint32]managed.Program, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT kernel_id, metadata FROM managed_programs WHERE state = ?",
		string(managed.StateLoaded))
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
// Only returns programs with state=loaded.
func (s *Store) FindProgramByMetadata(ctx context.Context, key, value string) (managed.Program, uint32, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT m.kernel_id, m.metadata
		FROM managed_programs m
		JOIN program_metadata_index i ON m.kernel_id = i.kernel_id
		WHERE i.key = ? AND i.value = ? AND m.state = ?
		LIMIT 1
	`, key, value, string(managed.StateLoaded))

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
// Only returns programs with state=loaded.
func (s *Store) FindAllProgramsByMetadata(ctx context.Context, key, value string) ([]struct {
	KernelID uint32
	Metadata managed.Program
}, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT m.kernel_id, m.metadata
		FROM managed_programs m
		JOIN program_metadata_index i ON m.kernel_id = i.kernel_id
		WHERE i.key = ? AND i.value = ? AND m.state = ?
	`, key, value, string(managed.StateLoaded))
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

// Reserve creates a loading reservation keyed by UUID.
// The kernel_id is set to 0 (placeholder) since we don't know it yet.
func (s *Store) Reserve(ctx context.Context, uuid string, metadata managed.Program) error {
	// Ensure state is set to loading
	metadata.State = managed.StateLoading
	metadata.UpdatedAt = time.Now()

	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	now := time.Now().Format(time.RFC3339)

	// Use kernel_id = 0 as placeholder for reservations.
	// We'll update it when committing.
	stateLoading := string(managed.StateLoading)
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO managed_programs (kernel_id, uuid, metadata, created_at, state, updated_at, error_message)
		 VALUES (0, ?, ?, ?, ?, ?, '')
		 ON CONFLICT(kernel_id) DO UPDATE SET
		   uuid = excluded.uuid,
		   metadata = excluded.metadata,
		   state = ?,
		   updated_at = excluded.updated_at`,
		uuid, string(metadataJSON), now, stateLoading, now, stateLoading)
	if err != nil {
		return fmt.Errorf("failed to create reservation: %w", err)
	}

	s.logger.Debug("created reservation", "uuid", uuid)
	return nil
}

// CommitReservation transitions a reservation from loading to loaded,
// updating the kernel_id from placeholder to actual value.
func (s *Store) CommitReservation(ctx context.Context, uuid string, kernelID uint32) error {
	now := time.Now().Format(time.RFC3339)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Get the existing metadata
	var metadataJSON string
	err = tx.QueryRowContext(ctx,
		"SELECT metadata FROM managed_programs WHERE uuid = ? AND state = ?",
		uuid, string(managed.StateLoading)).Scan(&metadataJSON)
	if err == sql.ErrNoRows {
		return fmt.Errorf("reservation %s: %w", uuid, store.ErrNotFound)
	}
	if err != nil {
		return fmt.Errorf("failed to get reservation: %w", err)
	}

	var metadata managed.Program
	if err := json.Unmarshal([]byte(metadataJSON), &metadata); err != nil {
		return fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	// Update state to loaded
	metadata.State = managed.StateLoaded
	metadata.UpdatedAt = time.Now()

	updatedJSON, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal updated metadata: %w", err)
	}

	// Delete the placeholder row and insert with real kernel_id
	_, err = tx.ExecContext(ctx,
		"DELETE FROM managed_programs WHERE uuid = ? AND kernel_id = 0",
		uuid)
	if err != nil {
		return fmt.Errorf("failed to delete placeholder: %w", err)
	}

	_, err = tx.ExecContext(ctx,
		`INSERT INTO managed_programs (kernel_id, uuid, metadata, created_at, state, updated_at, error_message)
		 VALUES (?, ?, ?, ?, ?, ?, '')`,
		kernelID, uuid, string(updatedJSON), metadata.CreatedAt.Format(time.RFC3339), string(managed.StateLoaded), now)
	if err != nil {
		return fmt.Errorf("failed to insert committed program: %w", err)
	}

	// Insert metadata index entries
	for key, value := range metadata.UserMetadata {
		_, err = tx.ExecContext(ctx,
			"INSERT INTO program_metadata_index (kernel_id, key, value) VALUES (?, ?, ?)",
			kernelID, key, value)
		if err != nil {
			return fmt.Errorf("failed to insert metadata index: %w", err)
		}
	}

	if err := tx.Commit(); err != nil {
		return err
	}
	s.logger.Debug("committed reservation", "uuid", uuid, "kernel_id", kernelID)
	return nil
}

// MarkError transitions a reservation to error state.
func (s *Store) MarkError(ctx context.Context, uuid string, errMsg string) error {
	now := time.Now().Format(time.RFC3339)

	result, err := s.db.ExecContext(ctx,
		`UPDATE managed_programs
		 SET state = ?, error_message = ?, updated_at = ?
		 WHERE uuid = ?`,
		string(managed.StateError), errMsg, now, uuid)
	if err != nil {
		return fmt.Errorf("failed to mark error: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("reservation %s: %w", uuid, store.ErrNotFound)
	}

	s.logger.Debug("marked error", "uuid", uuid, "error", errMsg)
	return nil
}

// DeleteReservation removes a reservation by UUID.
func (s *Store) DeleteReservation(ctx context.Context, uuid string) error {
	_, err := s.db.ExecContext(ctx,
		"DELETE FROM managed_programs WHERE uuid = ?",
		uuid)
	if err == nil {
		s.logger.Debug("deleted reservation", "uuid", uuid)
	}
	return err
}

// ListByState returns all entries with the given state.
func (s *Store) ListByState(ctx context.Context, state managed.State) ([]interpreter.StateEntry, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT kernel_id, metadata FROM managed_programs WHERE state = ?",
		string(state))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []interpreter.StateEntry
	for rows.Next() {
		var kernelID uint32
		var metadataJSON string
		if err := rows.Scan(&kernelID, &metadataJSON); err != nil {
			return nil, err
		}

		var metadata managed.Program
		if err := json.Unmarshal([]byte(metadataJSON), &metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}

		result = append(result, interpreter.StateEntry{
			KernelID: kernelID,
			Metadata: metadata,
		})
	}

	return result, rows.Err()
}

// ----------------------------------------------------------------------------
// Link Registry Operations
// ----------------------------------------------------------------------------

// DeleteLink removes link metadata by UUID.
// Due to CASCADE, this also removes the corresponding detail table entry.
func (s *Store) DeleteLink(ctx context.Context, uuid string) error {
	result, err := s.db.ExecContext(ctx,
		"DELETE FROM link_registry WHERE uuid = ?",
		uuid)
	if err != nil {
		return fmt.Errorf("failed to delete link: %w", err)
	}

	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return fmt.Errorf("link %s: %w", uuid, store.ErrNotFound)
	}

	s.logger.Debug("deleted link", "uuid", uuid)
	return nil
}

// GetLink retrieves link metadata by UUID using two-phase lookup.
func (s *Store) GetLink(ctx context.Context, uuid string) (managed.LinkSummary, managed.LinkDetails, error) {
	// Phase 1: Get summary from registry
	summary, err := s.getLinkSummaryByUUID(ctx, uuid)
	if err != nil {
		return managed.LinkSummary{}, nil, err
	}

	// Phase 2: Get details based on link type
	details, err := s.getLinkDetails(ctx, summary.LinkType, uuid)
	if err != nil {
		return managed.LinkSummary{}, nil, err
	}

	return summary, details, nil
}

// GetLinkByKernelID retrieves link metadata by kernel link ID.
func (s *Store) GetLinkByKernelID(ctx context.Context, kernelLinkID uint32) (managed.LinkSummary, managed.LinkDetails, error) {
	// Phase 1: Get summary from registry
	row := s.db.QueryRowContext(ctx,
		`SELECT uuid, link_type, kernel_program_id, kernel_link_id, pin_path, created_at
		 FROM link_registry WHERE kernel_link_id = ?`, kernelLinkID)

	summary, err := s.scanLinkSummary(row)
	if err != nil {
		return managed.LinkSummary{}, nil, err
	}

	// Phase 2: Get details based on link type
	details, err := s.getLinkDetails(ctx, summary.LinkType, summary.UUID)
	if err != nil {
		return managed.LinkSummary{}, nil, err
	}

	return summary, details, nil
}

// ListLinks returns all links (summary only).
func (s *Store) ListLinks(ctx context.Context) ([]managed.LinkSummary, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT uuid, link_type, kernel_program_id, kernel_link_id, pin_path, created_at
		 FROM link_registry`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return s.scanLinkSummaries(rows)
}

// ListLinksByProgram returns all links for a given program kernel ID.
func (s *Store) ListLinksByProgram(ctx context.Context, programKernelID uint32) ([]managed.LinkSummary, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT uuid, link_type, kernel_program_id, kernel_link_id, pin_path, created_at
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

// SaveTracepointLink saves a tracepoint link atomically.
func (s *Store) SaveTracepointLink(ctx context.Context, summary managed.LinkSummary, details managed.TracepointDetails) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	if err := s.insertLinkRegistry(ctx, tx, summary); err != nil {
		return err
	}

	_, err = tx.ExecContext(ctx,
		`INSERT INTO tracepoint_link_details (uuid, tracepoint_group, tracepoint_name)
		 VALUES (?, ?, ?)`,
		summary.UUID, details.Group, details.Name)
	if err != nil {
		return fmt.Errorf("failed to insert tracepoint details: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	s.logger.Debug("saved tracepoint link", "uuid", summary.UUID, "group", details.Group, "name", details.Name)
	return nil
}

// SaveKprobeLink saves a kprobe/kretprobe link atomically.
func (s *Store) SaveKprobeLink(ctx context.Context, summary managed.LinkSummary, details managed.KprobeDetails) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	if err := s.insertLinkRegistry(ctx, tx, summary); err != nil {
		return err
	}

	retprobe := 0
	if details.Retprobe {
		retprobe = 1
	}

	_, err = tx.ExecContext(ctx,
		`INSERT INTO kprobe_link_details (uuid, fn_name, offset, retprobe)
		 VALUES (?, ?, ?, ?)`,
		summary.UUID, details.FnName, details.Offset, retprobe)
	if err != nil {
		return fmt.Errorf("failed to insert kprobe details: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	s.logger.Debug("saved kprobe link", "uuid", summary.UUID, "fn_name", details.FnName)
	return nil
}

// SaveUprobeLink saves a uprobe/uretprobe link atomically.
func (s *Store) SaveUprobeLink(ctx context.Context, summary managed.LinkSummary, details managed.UprobeDetails) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	if err := s.insertLinkRegistry(ctx, tx, summary); err != nil {
		return err
	}

	retprobe := 0
	if details.Retprobe {
		retprobe = 1
	}

	_, err = tx.ExecContext(ctx,
		`INSERT INTO uprobe_link_details (uuid, target, fn_name, offset, pid, retprobe)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		summary.UUID, details.Target, details.FnName, details.Offset, details.PID, retprobe)
	if err != nil {
		return fmt.Errorf("failed to insert uprobe details: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	s.logger.Debug("saved uprobe link", "uuid", summary.UUID, "target", details.Target)
	return nil
}

// SaveFentryLink saves a fentry link atomically.
func (s *Store) SaveFentryLink(ctx context.Context, summary managed.LinkSummary, details managed.FentryDetails) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	if err := s.insertLinkRegistry(ctx, tx, summary); err != nil {
		return err
	}

	_, err = tx.ExecContext(ctx,
		`INSERT INTO fentry_link_details (uuid, fn_name)
		 VALUES (?, ?)`,
		summary.UUID, details.FnName)
	if err != nil {
		return fmt.Errorf("failed to insert fentry details: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	s.logger.Debug("saved fentry link", "uuid", summary.UUID, "fn_name", details.FnName)
	return nil
}

// SaveFexitLink saves a fexit link atomically.
func (s *Store) SaveFexitLink(ctx context.Context, summary managed.LinkSummary, details managed.FexitDetails) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	if err := s.insertLinkRegistry(ctx, tx, summary); err != nil {
		return err
	}

	_, err = tx.ExecContext(ctx,
		`INSERT INTO fexit_link_details (uuid, fn_name)
		 VALUES (?, ?)`,
		summary.UUID, details.FnName)
	if err != nil {
		return fmt.Errorf("failed to insert fexit details: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	s.logger.Debug("saved fexit link", "uuid", summary.UUID, "fn_name", details.FnName)
	return nil
}

// SaveXDPLink saves an XDP link atomically.
func (s *Store) SaveXDPLink(ctx context.Context, summary managed.LinkSummary, details managed.XDPDetails) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	if err := s.insertLinkRegistry(ctx, tx, summary); err != nil {
		return err
	}

	proceedOnJSON, err := json.Marshal(details.ProceedOn)
	if err != nil {
		return fmt.Errorf("failed to marshal proceed_on: %w", err)
	}

	_, err = tx.ExecContext(ctx,
		`INSERT INTO xdp_link_details (uuid, interface, ifindex, priority, position, proceed_on, netns, nsid, dispatcher_id, revision)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		summary.UUID, details.Interface, details.Ifindex, details.Priority, details.Position,
		string(proceedOnJSON), details.Netns, details.Nsid, details.DispatcherID, details.Revision)
	if err != nil {
		return fmt.Errorf("failed to insert xdp details: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	s.logger.Debug("saved xdp link", "uuid", summary.UUID, "interface", details.Interface)
	return nil
}

// SaveTCLink saves a TC link atomically.
func (s *Store) SaveTCLink(ctx context.Context, summary managed.LinkSummary, details managed.TCDetails) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	if err := s.insertLinkRegistry(ctx, tx, summary); err != nil {
		return err
	}

	proceedOnJSON, err := json.Marshal(details.ProceedOn)
	if err != nil {
		return fmt.Errorf("failed to marshal proceed_on: %w", err)
	}

	_, err = tx.ExecContext(ctx,
		`INSERT INTO tc_link_details (uuid, interface, ifindex, direction, priority, position, proceed_on, netns, nsid, dispatcher_id, revision)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		summary.UUID, details.Interface, details.Ifindex, details.Direction, details.Priority, details.Position,
		string(proceedOnJSON), details.Netns, details.Nsid, details.DispatcherID, details.Revision)
	if err != nil {
		return fmt.Errorf("failed to insert tc details: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	s.logger.Debug("saved tc link", "uuid", summary.UUID, "interface", details.Interface, "direction", details.Direction)
	return nil
}

// SaveTCXLink saves a TCX link atomically.
func (s *Store) SaveTCXLink(ctx context.Context, summary managed.LinkSummary, details managed.TCXDetails) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback()

	if err := s.insertLinkRegistry(ctx, tx, summary); err != nil {
		return err
	}

	_, err = tx.ExecContext(ctx,
		`INSERT INTO tcx_link_details (uuid, interface, ifindex, direction, priority, netns, nsid)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		summary.UUID, details.Interface, details.Ifindex, details.Direction, details.Priority, details.Netns, details.Nsid)
	if err != nil {
		return fmt.Errorf("failed to insert tcx details: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return err
	}

	s.logger.Debug("saved tcx link", "uuid", summary.UUID, "interface", details.Interface, "direction", details.Direction)
	return nil
}

// ----------------------------------------------------------------------------
// Helper Functions
// ----------------------------------------------------------------------------

// insertLinkRegistry inserts a record into the link_registry table within a transaction.
func (s *Store) insertLinkRegistry(ctx context.Context, tx *sql.Tx, summary managed.LinkSummary) error {
	_, err := tx.ExecContext(ctx,
		`INSERT INTO link_registry (uuid, link_type, kernel_program_id, kernel_link_id, pin_path, created_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		summary.UUID, string(summary.LinkType), summary.KernelProgramID,
		summary.KernelLinkID, summary.PinPath, summary.CreatedAt.Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("failed to insert link registry: %w", err)
	}
	return nil
}

// getLinkSummaryByUUID retrieves a link summary by UUID.
func (s *Store) getLinkSummaryByUUID(ctx context.Context, uuid string) (managed.LinkSummary, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT uuid, link_type, kernel_program_id, kernel_link_id, pin_path, created_at
		 FROM link_registry WHERE uuid = ?`, uuid)
	return s.scanLinkSummary(row)
}

// scanLinkSummary scans a single row into a LinkSummary.
func (s *Store) scanLinkSummary(row *sql.Row) (managed.LinkSummary, error) {
	var summary managed.LinkSummary
	var linkType string
	var kernelLinkID sql.NullInt64
	var pinPath sql.NullString
	var createdAtStr string

	err := row.Scan(&summary.UUID, &linkType, &summary.KernelProgramID, &kernelLinkID, &pinPath, &createdAtStr)
	if err == sql.ErrNoRows {
		return managed.LinkSummary{}, fmt.Errorf("link: %w", store.ErrNotFound)
	}
	if err != nil {
		return managed.LinkSummary{}, err
	}

	summary.LinkType = managed.LinkType(linkType)
	if kernelLinkID.Valid {
		summary.KernelLinkID = uint32(kernelLinkID.Int64)
	}
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
		var kernelLinkID sql.NullInt64
		var pinPath sql.NullString
		var createdAtStr string

		err := rows.Scan(&summary.UUID, &linkType, &summary.KernelProgramID, &kernelLinkID, &pinPath, &createdAtStr)
		if err != nil {
			return nil, err
		}

		summary.LinkType = managed.LinkType(linkType)
		if kernelLinkID.Valid {
			summary.KernelLinkID = uint32(kernelLinkID.Int64)
		}
		if pinPath.Valid {
			summary.PinPath = pinPath.String
		}
		summary.CreatedAt, _ = time.Parse(time.RFC3339, createdAtStr)

		result = append(result, summary)
	}

	return result, rows.Err()
}

// getLinkDetails retrieves the type-specific details for a link.
func (s *Store) getLinkDetails(ctx context.Context, linkType managed.LinkType, uuid string) (managed.LinkDetails, error) {
	switch linkType {
	case managed.LinkTypeTracepoint:
		return s.getTracepointDetails(ctx, uuid)
	case managed.LinkTypeKprobe, managed.LinkTypeKretprobe:
		return s.getKprobeDetails(ctx, uuid)
	case managed.LinkTypeUprobe, managed.LinkTypeUretprobe:
		return s.getUprobeDetails(ctx, uuid)
	case managed.LinkTypeFentry:
		return s.getFentryDetails(ctx, uuid)
	case managed.LinkTypeFexit:
		return s.getFexitDetails(ctx, uuid)
	case managed.LinkTypeXDP:
		return s.getXDPDetails(ctx, uuid)
	case managed.LinkTypeTC:
		return s.getTCDetails(ctx, uuid)
	case managed.LinkTypeTCX:
		return s.getTCXDetails(ctx, uuid)
	default:
		return nil, fmt.Errorf("unknown link type: %s", linkType)
	}
}

func (s *Store) getTracepointDetails(ctx context.Context, uuid string) (managed.TracepointDetails, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT tracepoint_group, tracepoint_name FROM tracepoint_link_details WHERE uuid = ?`, uuid)

	var details managed.TracepointDetails
	err := row.Scan(&details.Group, &details.Name)
	if err == sql.ErrNoRows {
		return managed.TracepointDetails{}, fmt.Errorf("tracepoint details for %s: %w", uuid, store.ErrNotFound)
	}
	if err != nil {
		return managed.TracepointDetails{}, err
	}
	return details, nil
}

func (s *Store) getKprobeDetails(ctx context.Context, uuid string) (managed.KprobeDetails, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT fn_name, offset, retprobe FROM kprobe_link_details WHERE uuid = ?`, uuid)

	var details managed.KprobeDetails
	var retprobe int
	err := row.Scan(&details.FnName, &details.Offset, &retprobe)
	if err == sql.ErrNoRows {
		return managed.KprobeDetails{}, fmt.Errorf("kprobe details for %s: %w", uuid, store.ErrNotFound)
	}
	if err != nil {
		return managed.KprobeDetails{}, err
	}
	details.Retprobe = retprobe == 1
	return details, nil
}

func (s *Store) getUprobeDetails(ctx context.Context, uuid string) (managed.UprobeDetails, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT target, fn_name, offset, pid, retprobe FROM uprobe_link_details WHERE uuid = ?`, uuid)

	var details managed.UprobeDetails
	var fnName sql.NullString
	var pid sql.NullInt64
	var retprobe int
	err := row.Scan(&details.Target, &fnName, &details.Offset, &pid, &retprobe)
	if err == sql.ErrNoRows {
		return managed.UprobeDetails{}, fmt.Errorf("uprobe details for %s: %w", uuid, store.ErrNotFound)
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

func (s *Store) getFentryDetails(ctx context.Context, uuid string) (managed.FentryDetails, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT fn_name FROM fentry_link_details WHERE uuid = ?`, uuid)

	var details managed.FentryDetails
	err := row.Scan(&details.FnName)
	if err == sql.ErrNoRows {
		return managed.FentryDetails{}, fmt.Errorf("fentry details for %s: %w", uuid, store.ErrNotFound)
	}
	if err != nil {
		return managed.FentryDetails{}, err
	}
	return details, nil
}

func (s *Store) getFexitDetails(ctx context.Context, uuid string) (managed.FexitDetails, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT fn_name FROM fexit_link_details WHERE uuid = ?`, uuid)

	var details managed.FexitDetails
	err := row.Scan(&details.FnName)
	if err == sql.ErrNoRows {
		return managed.FexitDetails{}, fmt.Errorf("fexit details for %s: %w", uuid, store.ErrNotFound)
	}
	if err != nil {
		return managed.FexitDetails{}, err
	}
	return details, nil
}

func (s *Store) getXDPDetails(ctx context.Context, uuid string) (managed.XDPDetails, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT interface, ifindex, priority, position, proceed_on, netns, nsid, dispatcher_id, revision
		 FROM xdp_link_details WHERE uuid = ?`, uuid)

	var details managed.XDPDetails
	var proceedOnJSON string
	var netns sql.NullString
	err := row.Scan(&details.Interface, &details.Ifindex, &details.Priority, &details.Position,
		&proceedOnJSON, &netns, &details.Nsid, &details.DispatcherID, &details.Revision)
	if err == sql.ErrNoRows {
		return managed.XDPDetails{}, fmt.Errorf("xdp details for %s: %w", uuid, store.ErrNotFound)
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

func (s *Store) getTCDetails(ctx context.Context, uuid string) (managed.TCDetails, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT interface, ifindex, direction, priority, position, proceed_on, netns, nsid, dispatcher_id, revision
		 FROM tc_link_details WHERE uuid = ?`, uuid)

	var details managed.TCDetails
	var proceedOnJSON string
	var netns sql.NullString
	err := row.Scan(&details.Interface, &details.Ifindex, &details.Direction, &details.Priority, &details.Position,
		&proceedOnJSON, &netns, &details.Nsid, &details.DispatcherID, &details.Revision)
	if err == sql.ErrNoRows {
		return managed.TCDetails{}, fmt.Errorf("tc details for %s: %w", uuid, store.ErrNotFound)
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

func (s *Store) getTCXDetails(ctx context.Context, uuid string) (managed.TCXDetails, error) {
	row := s.db.QueryRowContext(ctx,
		`SELECT interface, ifindex, direction, priority, netns, nsid
		 FROM tcx_link_details WHERE uuid = ?`, uuid)

	var details managed.TCXDetails
	var netns sql.NullString
	var nsid sql.NullInt64
	err := row.Scan(&details.Interface, &details.Ifindex, &details.Direction, &details.Priority, &netns, &nsid)
	if err == sql.ErrNoRows {
		return managed.TCXDetails{}, fmt.Errorf("tcx details for %s: %w", uuid, store.ErrNotFound)
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
	row := s.db.QueryRowContext(ctx,
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

	_, err := s.db.ExecContext(ctx,
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
	result, err := s.db.ExecContext(ctx,
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
func (s *Store) IncrementRevision(ctx context.Context, dispType string, nsid uint64, ifindex uint32) (uint32, error) {
	now := time.Now().Format(time.RFC3339)

	// Use CASE to handle wrap-around at MaxUint32
	result, err := s.db.ExecContext(ctx,
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
	err = s.db.QueryRowContext(ctx,
		`SELECT revision FROM dispatchers WHERE type = ? AND nsid = ? AND ifindex = ?`,
		dispType, nsid, ifindex).Scan(&newRevision)
	if err != nil {
		return 0, fmt.Errorf("fetch new revision: %w", err)
	}

	s.logger.Debug("incremented dispatcher revision",
		"type", dispType, "nsid", nsid, "ifindex", ifindex, "new_revision", newRevision)
	return newRevision, nil
}
