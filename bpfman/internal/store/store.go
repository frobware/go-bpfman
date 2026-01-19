// Package store provides SQLite persistence for bpfman state.
package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

const (
	// DefaultDBPath is the default path for the SQLite database.
	DefaultDBPath = "/run/bpfman/state.db"
)

// ProgramRecord represents a persisted program.
type ProgramRecord struct {
	ID           uint32
	UUID         string
	Name         string
	FuncName     string
	ProgramType  uint32
	BytecodePath string
	PinPath      string
	MapPinPath   string
	Metadata     map[string]string
	GlobalData   map[string][]byte
	LoadedAt     time.Time
	MapIDs       []uint32
}

// LinkRecord represents a persisted link.
type LinkRecord struct {
	ID         uint32
	ProgramID  uint32
	AttachType int
	AttachInfo string // JSON blob
}

// Store provides SQLite-backed persistence for bpfman state.
type Store struct {
	db *sql.DB
}

// Open opens or creates a SQLite database at the given path.
func Open(dbPath string) (*Store, error) {
	// Ensure directory exists
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

// Close closes the database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS programs (
		id INTEGER PRIMARY KEY,
		uuid TEXT UNIQUE NOT NULL,
		name TEXT NOT NULL,
		func_name TEXT NOT NULL,
		program_type INTEGER NOT NULL,
		bytecode_path TEXT,
		pin_path TEXT NOT NULL,
		map_pin_path TEXT,
		metadata TEXT,
		global_data BLOB,
		loaded_at TEXT NOT NULL,
		map_ids TEXT
	);

	CREATE TABLE IF NOT EXISTS links (
		id INTEGER PRIMARY KEY,
		program_id INTEGER NOT NULL,
		attach_type INTEGER NOT NULL,
		attach_info TEXT,
		FOREIGN KEY (program_id) REFERENCES programs(id) ON DELETE CASCADE
	);

	CREATE INDEX IF NOT EXISTS idx_programs_uuid ON programs(uuid);
	CREATE INDEX IF NOT EXISTS idx_links_program_id ON links(program_id);
	`

	_, err := s.db.Exec(schema)
	return err
}

// SaveProgram persists a program record.
func (s *Store) SaveProgram(p *ProgramRecord) error {
	metadata, err := json.Marshal(p.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	globalData, err := json.Marshal(p.GlobalData)
	if err != nil {
		return fmt.Errorf("failed to marshal global data: %w", err)
	}

	mapIDs, err := json.Marshal(p.MapIDs)
	if err != nil {
		return fmt.Errorf("failed to marshal map IDs: %w", err)
	}

	_, err = s.db.Exec(`
		INSERT OR REPLACE INTO programs
		(id, uuid, name, func_name, program_type, bytecode_path, pin_path, map_pin_path, metadata, global_data, loaded_at, map_ids)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.ID, p.UUID, p.Name, p.FuncName, p.ProgramType, p.BytecodePath, p.PinPath, p.MapPinPath,
		string(metadata), globalData, p.LoadedAt.Format(time.RFC3339), string(mapIDs),
	)
	return err
}

// DeleteProgram removes a program record by ID.
func (s *Store) DeleteProgram(id uint32) error {
	_, err := s.db.Exec("DELETE FROM programs WHERE id = ?", id)
	return err
}

// GetProgram retrieves a program record by ID.
func (s *Store) GetProgram(id uint32) (*ProgramRecord, error) {
	row := s.db.QueryRow(`
		SELECT id, uuid, name, func_name, program_type, bytecode_path, pin_path, map_pin_path, metadata, global_data, loaded_at, map_ids
		FROM programs WHERE id = ?`, id)

	return s.scanProgram(row)
}

// GetProgramByUUID retrieves a program record by UUID.
func (s *Store) GetProgramByUUID(uuid string) (*ProgramRecord, error) {
	row := s.db.QueryRow(`
		SELECT id, uuid, name, func_name, program_type, bytecode_path, pin_path, map_pin_path, metadata, global_data, loaded_at, map_ids
		FROM programs WHERE uuid = ?`, uuid)

	return s.scanProgram(row)
}

// ListPrograms retrieves all program records.
func (s *Store) ListPrograms() ([]*ProgramRecord, error) {
	rows, err := s.db.Query(`
		SELECT id, uuid, name, func_name, program_type, bytecode_path, pin_path, map_pin_path, metadata, global_data, loaded_at, map_ids
		FROM programs`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var programs []*ProgramRecord
	for rows.Next() {
		p, err := s.scanProgramRows(rows)
		if err != nil {
			return nil, err
		}
		programs = append(programs, p)
	}

	return programs, rows.Err()
}

func (s *Store) scanProgram(row *sql.Row) (*ProgramRecord, error) {
	var p ProgramRecord
	var metadata, mapIDs string
	var globalData []byte
	var loadedAt string

	err := row.Scan(&p.ID, &p.UUID, &p.Name, &p.FuncName, &p.ProgramType, &p.BytecodePath,
		&p.PinPath, &p.MapPinPath, &metadata, &globalData, &loadedAt, &mapIDs)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	if err := json.Unmarshal([]byte(metadata), &p.Metadata); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	if len(globalData) > 0 {
		if err := json.Unmarshal(globalData, &p.GlobalData); err != nil {
			return nil, fmt.Errorf("failed to unmarshal global data: %w", err)
		}
	}

	if err := json.Unmarshal([]byte(mapIDs), &p.MapIDs); err != nil {
		return nil, fmt.Errorf("failed to unmarshal map IDs: %w", err)
	}

	p.LoadedAt, _ = time.Parse(time.RFC3339, loadedAt)

	return &p, nil
}

func (s *Store) scanProgramRows(rows *sql.Rows) (*ProgramRecord, error) {
	var p ProgramRecord
	var metadata, mapIDs string
	var globalData []byte
	var loadedAt string

	err := rows.Scan(&p.ID, &p.UUID, &p.Name, &p.FuncName, &p.ProgramType, &p.BytecodePath,
		&p.PinPath, &p.MapPinPath, &metadata, &globalData, &loadedAt, &mapIDs)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal([]byte(metadata), &p.Metadata); err != nil {
		return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
	}

	if len(globalData) > 0 {
		if err := json.Unmarshal(globalData, &p.GlobalData); err != nil {
			return nil, fmt.Errorf("failed to unmarshal global data: %w", err)
		}
	}

	if err := json.Unmarshal([]byte(mapIDs), &p.MapIDs); err != nil {
		return nil, fmt.Errorf("failed to unmarshal map IDs: %w", err)
	}

	p.LoadedAt, _ = time.Parse(time.RFC3339, loadedAt)

	return &p, nil
}

// SaveLink persists a link record.
func (s *Store) SaveLink(l *LinkRecord) error {
	_, err := s.db.Exec(`
		INSERT OR REPLACE INTO links (id, program_id, attach_type, attach_info)
		VALUES (?, ?, ?, ?)`,
		l.ID, l.ProgramID, l.AttachType, l.AttachInfo,
	)
	return err
}

// DeleteLink removes a link record by ID.
func (s *Store) DeleteLink(id uint32) error {
	_, err := s.db.Exec("DELETE FROM links WHERE id = ?", id)
	return err
}

// GetLink retrieves a link record by ID.
func (s *Store) GetLink(id uint32) (*LinkRecord, error) {
	row := s.db.QueryRow("SELECT id, program_id, attach_type, attach_info FROM links WHERE id = ?", id)

	var l LinkRecord
	err := row.Scan(&l.ID, &l.ProgramID, &l.AttachType, &l.AttachInfo)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return &l, nil
}

// ListLinksByProgram retrieves all links for a program.
func (s *Store) ListLinksByProgram(programID uint32) ([]*LinkRecord, error) {
	rows, err := s.db.Query("SELECT id, program_id, attach_type, attach_info FROM links WHERE program_id = ?", programID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var links []*LinkRecord
	for rows.Next() {
		var l LinkRecord
		if err := rows.Scan(&l.ID, &l.ProgramID, &l.AttachType, &l.AttachInfo); err != nil {
			return nil, err
		}
		links = append(links, &l)
	}

	return links, rows.Err()
}
