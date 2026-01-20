// Package sqlite provides a SQLite implementation of the program store.
package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"

	"github.com/frobware/go-bpfman/pkg/bpfman/domain"
	"github.com/frobware/go-bpfman/pkg/bpfman/interpreter"
	"github.com/frobware/go-bpfman/pkg/bpfman/interpreter/store"
)

// Store implements interpreter.ProgramStore using SQLite.
type Store struct {
	db *sql.DB
}

// New creates a new SQLite store at the given path.
func New(dbPath string) (*Store, error) {
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create database directory: %w", err)
	}

	db, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to migrate database: %w", err)
	}

	return s, nil
}

// NewInMemory creates an in-memory SQLite store for testing.
func NewInMemory() (*Store, error) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return nil, fmt.Errorf("failed to open in-memory database: %w", err)
	}

	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to migrate database: %w", err)
	}

	return s, nil
}

// Close closes the database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) migrate() error {
	// Step 1: Create tables (without state-dependent indexes)
	schema := `
	CREATE TABLE IF NOT EXISTS managed_programs (
		kernel_id INTEGER PRIMARY KEY,
		uuid TEXT,
		metadata TEXT NOT NULL,
		created_at TEXT NOT NULL
	);

	CREATE INDEX IF NOT EXISTS idx_managed_programs_uuid ON managed_programs(uuid);

	-- Index table for fast metadata key/value lookups (used by CSI)
	CREATE TABLE IF NOT EXISTS program_metadata_index (
		kernel_id INTEGER NOT NULL,
		key TEXT NOT NULL,
		value TEXT NOT NULL,
		PRIMARY KEY (kernel_id, key),
		FOREIGN KEY (kernel_id) REFERENCES managed_programs(kernel_id) ON DELETE CASCADE
	);

	CREATE INDEX IF NOT EXISTS idx_program_metadata_key_value ON program_metadata_index(key, value);
	`
	if _, err := s.db.Exec(schema); err != nil {
		return err
	}

	// Step 2: Add state columns if missing (for existing databases)
	// SQLite doesn't support IF NOT EXISTS for ALTER TABLE, so we check first.
	var count int
	err := s.db.QueryRow(`
		SELECT COUNT(*) FROM pragma_table_info('managed_programs') WHERE name = 'state'
	`).Scan(&count)
	if err != nil {
		return err
	}
	if count == 0 {
		// Columns don't exist, add them
		migrations := []string{
			`ALTER TABLE managed_programs ADD COLUMN state TEXT NOT NULL DEFAULT 'loaded'`,
			`ALTER TABLE managed_programs ADD COLUMN updated_at TEXT NOT NULL DEFAULT ''`,
			`ALTER TABLE managed_programs ADD COLUMN error_message TEXT NOT NULL DEFAULT ''`,
		}
		for _, m := range migrations {
			if _, err := s.db.Exec(m); err != nil {
				return err
			}
		}
	}

	// Step 3: Create state index (now that column definitely exists)
	_, err = s.db.Exec(`CREATE INDEX IF NOT EXISTS idx_managed_programs_state ON managed_programs(state)`)
	if err != nil {
		return err
	}

	return nil
}

// Get retrieves program metadata by kernel ID.
// Returns store.ErrNotFound if the program does not exist.
// Only returns programs with state=loaded.
func (s *Store) Get(ctx context.Context, kernelID uint32) (domain.ProgramMetadata, error) {
	row := s.db.QueryRowContext(ctx,
		"SELECT metadata FROM managed_programs WHERE kernel_id = ? AND state = ?",
		kernelID, string(domain.StateLoaded))

	var metadataJSON string
	err := row.Scan(&metadataJSON)
	if err == sql.ErrNoRows {
		return domain.ProgramMetadata{}, fmt.Errorf("program %d: %w", kernelID, store.ErrNotFound)
	}
	if err != nil {
		return domain.ProgramMetadata{}, err
	}

	var metadata domain.ProgramMetadata
	if err := json.Unmarshal([]byte(metadataJSON), &metadata); err != nil {
		return domain.ProgramMetadata{}, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	return metadata, nil
}

// Save stores program metadata.
func (s *Store) Save(ctx context.Context, kernelID uint32, metadata domain.ProgramMetadata) error {
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

	return tx.Commit()
}

// GetByUUID retrieves program metadata by UUID.
// Returns store.ErrNotFound if the program does not exist.
// Only returns programs with state=loaded.
func (s *Store) GetByUUID(ctx context.Context, uuid string) (domain.ProgramMetadata, uint32, error) {
	row := s.db.QueryRowContext(ctx,
		"SELECT kernel_id, metadata FROM managed_programs WHERE uuid = ? AND state = ?",
		uuid, string(domain.StateLoaded))

	var kernelID uint32
	var metadataJSON string
	err := row.Scan(&kernelID, &metadataJSON)
	if err == sql.ErrNoRows {
		return domain.ProgramMetadata{}, 0, fmt.Errorf("uuid %s: %w", uuid, store.ErrNotFound)
	}
	if err != nil {
		return domain.ProgramMetadata{}, 0, err
	}

	var metadata domain.ProgramMetadata
	if err := json.Unmarshal([]byte(metadataJSON), &metadata); err != nil {
		return domain.ProgramMetadata{}, 0, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	return metadata, kernelID, nil
}

// Delete removes program metadata.
func (s *Store) Delete(ctx context.Context, kernelID uint32) error {
	_, err := s.db.ExecContext(ctx,
		"DELETE FROM managed_programs WHERE kernel_id = ?",
		kernelID)
	return err
}

// List returns all program metadata.
// Only returns programs with state=loaded.
func (s *Store) List(ctx context.Context) (map[uint32]domain.ProgramMetadata, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT kernel_id, metadata FROM managed_programs WHERE state = ?",
		string(domain.StateLoaded))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[uint32]domain.ProgramMetadata)
	for rows.Next() {
		var kernelID uint32
		var metadataJSON string
		if err := rows.Scan(&kernelID, &metadataJSON); err != nil {
			return nil, err
		}

		var metadata domain.ProgramMetadata
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
func (s *Store) FindProgramByMetadata(ctx context.Context, key, value string) (domain.ProgramMetadata, uint32, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT m.kernel_id, m.metadata
		FROM managed_programs m
		JOIN program_metadata_index i ON m.kernel_id = i.kernel_id
		WHERE i.key = ? AND i.value = ? AND m.state = ?
		LIMIT 1
	`, key, value, string(domain.StateLoaded))

	var kernelID uint32
	var metadataJSON string
	err := row.Scan(&kernelID, &metadataJSON)
	if err == sql.ErrNoRows {
		return domain.ProgramMetadata{}, 0, fmt.Errorf("program with %s=%s: %w", key, value, store.ErrNotFound)
	}
	if err != nil {
		return domain.ProgramMetadata{}, 0, err
	}

	var metadata domain.ProgramMetadata
	if err := json.Unmarshal([]byte(metadataJSON), &metadata); err != nil {
		return domain.ProgramMetadata{}, 0, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	return metadata, kernelID, nil
}

// FindAllProgramsByMetadata finds all programs with a specific metadata key/value pair.
// Only returns programs with state=loaded.
func (s *Store) FindAllProgramsByMetadata(ctx context.Context, key, value string) ([]struct {
	KernelID uint32
	Metadata domain.ProgramMetadata
}, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT m.kernel_id, m.metadata
		FROM managed_programs m
		JOIN program_metadata_index i ON m.kernel_id = i.kernel_id
		WHERE i.key = ? AND i.value = ? AND m.state = ?
	`, key, value, string(domain.StateLoaded))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []struct {
		KernelID uint32
		Metadata domain.ProgramMetadata
	}

	for rows.Next() {
		var kernelID uint32
		var metadataJSON string
		if err := rows.Scan(&kernelID, &metadataJSON); err != nil {
			return nil, err
		}

		var metadata domain.ProgramMetadata
		if err := json.Unmarshal([]byte(metadataJSON), &metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata for %d: %w", kernelID, err)
		}

		result = append(result, struct {
			KernelID uint32
			Metadata domain.ProgramMetadata
		}{KernelID: kernelID, Metadata: metadata})
	}

	return result, rows.Err()
}

// Reserve creates a loading reservation keyed by UUID.
// The kernel_id is set to 0 (placeholder) since we don't know it yet.
func (s *Store) Reserve(ctx context.Context, uuid string, metadata domain.ProgramMetadata) error {
	// Ensure state is set to loading
	metadata.State = domain.StateLoading
	metadata.UpdatedAt = time.Now()

	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	now := time.Now().Format(time.RFC3339)

	// Use kernel_id = 0 as placeholder for reservations.
	// We'll update it when committing.
	stateLoading := string(domain.StateLoading)
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
		uuid, string(domain.StateLoading)).Scan(&metadataJSON)
	if err == sql.ErrNoRows {
		return fmt.Errorf("reservation %s: %w", uuid, store.ErrNotFound)
	}
	if err != nil {
		return fmt.Errorf("failed to get reservation: %w", err)
	}

	var metadata domain.ProgramMetadata
	if err := json.Unmarshal([]byte(metadataJSON), &metadata); err != nil {
		return fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	// Update state to loaded
	metadata.State = domain.StateLoaded
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
		kernelID, uuid, string(updatedJSON), metadata.CreatedAt.Format(time.RFC3339), string(domain.StateLoaded), now)
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

	return tx.Commit()
}

// MarkError transitions a reservation to error state.
func (s *Store) MarkError(ctx context.Context, uuid string, errMsg string) error {
	now := time.Now().Format(time.RFC3339)

	result, err := s.db.ExecContext(ctx,
		`UPDATE managed_programs
		 SET state = ?, error_message = ?, updated_at = ?
		 WHERE uuid = ?`,
		string(domain.StateError), errMsg, now, uuid)
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

	return nil
}

// DeleteReservation removes a reservation by UUID.
func (s *Store) DeleteReservation(ctx context.Context, uuid string) error {
	_, err := s.db.ExecContext(ctx,
		"DELETE FROM managed_programs WHERE uuid = ?",
		uuid)
	return err
}

// ListByState returns all entries with the given state.
func (s *Store) ListByState(ctx context.Context, state domain.ProgramState) ([]interpreter.StateEntry, error) {
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

		var metadata domain.ProgramMetadata
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
