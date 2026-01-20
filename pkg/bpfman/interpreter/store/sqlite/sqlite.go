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

	_ "github.com/mattn/go-sqlite3"

	"github.com/frobware/go-bpfman/pkg/bpfman/domain"
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

	db, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL")
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
	db, err := sql.Open("sqlite3", ":memory:")
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
	schema := `
	CREATE TABLE IF NOT EXISTS managed_programs (
		kernel_id INTEGER PRIMARY KEY,
		uuid TEXT,
		metadata TEXT NOT NULL,
		created_at TEXT NOT NULL
	);

	CREATE INDEX IF NOT EXISTS idx_managed_programs_uuid ON managed_programs(uuid);
	`
	_, err := s.db.Exec(schema)
	return err
}

// Get retrieves program metadata by kernel ID.
// Returns store.ErrNotFound if the program does not exist.
func (s *Store) Get(ctx context.Context, kernelID uint32) (domain.ProgramMetadata, error) {
	row := s.db.QueryRowContext(ctx,
		"SELECT metadata FROM managed_programs WHERE kernel_id = ?",
		kernelID)

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

	_, err = s.db.ExecContext(ctx,
		"INSERT OR REPLACE INTO managed_programs (kernel_id, uuid, metadata, created_at) VALUES (?, ?, ?, ?)",
		kernelID, metadata.UUID, string(metadataJSON), time.Now().Format(time.RFC3339))
	return err
}

// GetByUUID retrieves program metadata by UUID.
// Returns store.ErrNotFound if the program does not exist.
func (s *Store) GetByUUID(ctx context.Context, uuid string) (domain.ProgramMetadata, uint32, error) {
	row := s.db.QueryRowContext(ctx,
		"SELECT kernel_id, metadata FROM managed_programs WHERE uuid = ?",
		uuid)

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
func (s *Store) List(ctx context.Context) (map[uint32]domain.ProgramMetadata, error) {
	rows, err := s.db.QueryContext(ctx,
		"SELECT kernel_id, metadata FROM managed_programs")
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
