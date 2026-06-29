package sqlite

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/source"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

// migrationsFS holds the ordered SQL migrations applied to the store.
// Each migration is a pair of files, NNNNN_description.up.sql and
// NNNNN_description.down.sql; the numeric prefix is the schema version
// the up file advances the database to. The lowest is
// 00001_baseline.up.sql, the initial schema. Add a new pair with the
// next number to evolve the schema. The glob deliberately matches only
// *.sql, so the TEMPLATE_*.sql.tmpl scaffolding is not embedded and
// never runs.
//
//go:embed migrations/*.sql
var migrationsFS embed.FS

// errSchemaVersionMismatch reports that the on-disk schema version is
// not the version this build expects. The database is never deleted to
// resolve a mismatch: doing so would orphan the BPF programs, pins, and
// links the database is the only record of. A mismatch is surfaced to
// the caller, not silently repaired by wiping live state.
var errSchemaVersionMismatch = errors.New("schema version mismatch")

// migrate brings the database up to the latest schema version by
// applying every pending migration in order. A database already at the
// latest version is left untouched. A database newer than this build
// understands is refused, not downgraded and not wiped.
//
// golang-migrate's high-level API predates context, so ctx does not
// cancel the migration run itself; the migrations are local SQLite DDL
// executed under the writer lock, so there is nothing long-running to
// interrupt. ctx is honoured for the post-migration store work and
// logging.
func (s *sqliteStore) migrate(ctx context.Context) error {
	src, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("open embedded migrations: %w", err)
	}
	defer src.Close()

	target, err := latestMigrationVersion(src)
	if err != nil {
		return err
	}

	driver, err := newMigrateDriver(s.db)
	if err != nil {
		return fmt.Errorf("create migration driver: %w", err)
	}

	m, err := migrate.NewWithInstance("iofs", src, driverName, driver)
	if err != nil {
		return fmt.Errorf("create migrator: %w", err)
	}
	// Deliberately not calling m.Close(): it would close the shared
	// *sql.DB this store owns and continues to use. The source is
	// closed by the defer above; the database driver holds no
	// resources of its own beyond s.db.

	current, _, err := m.Version()
	if err != nil && !errors.Is(err, migrate.ErrNilVersion) {
		return fmt.Errorf("read schema version: %w", err)
	}

	if !errors.Is(err, migrate.ErrNilVersion) && current > target {
		return fmt.Errorf("%w: database is at version %d, newer than this build supports (%d); refusing to open", errSchemaVersionMismatch, current, target)
	}

	switch err := m.Up(); {
	case err == nil:
		s.logger.InfoContext(ctx, "applied schema migrations", "to", target)
	case errors.Is(err, migrate.ErrNoChange):
		// Already at the latest version; nothing to apply.
	default:
		return fmt.Errorf("apply migrations: %w", err)
	}

	return s.seedLinkIDSequence(ctx)
}

// checkSchemaVersion verifies, without writing, that the database is at
// the schema version this build expects. Read-oriented callers open the
// store without the writer lock, so this path must not create the
// version table or apply migrations. It queries golang-migrate's
// bookkeeping table directly: its absence or emptiness means the
// database was never initialised by this framework, and a dirty flag
// means a migration did not complete.
func (s *sqliteStore) checkSchemaVersion(ctx context.Context) error {
	src, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("open embedded migrations: %w", err)
	}
	defer src.Close()

	target, err := latestMigrationVersion(src)
	if err != nil {
		return err
	}

	const versionQuery = `SELECT version, dirty FROM schema_migrations LIMIT 1`
	var current uint
	var dirty bool
	if err := s.db.QueryRowContext(ctx, versionQuery).Scan(&current, &dirty); err != nil {
		return fmt.Errorf("%w: cannot read schema version (database not initialised?): %w", errSchemaVersionMismatch, err)
	}

	if dirty {
		return fmt.Errorf("%w: database is dirty at version %d (a migration did not complete)", errSchemaVersionMismatch, current)
	}

	if current != target {
		return fmt.Errorf("%w: have %d, want %d", errSchemaVersionMismatch, current, target)
	}
	return nil
}

// latestMigrationVersion returns the highest version among the embedded
// migrations, i.e. the schema version this build targets. It walks the
// source forward from the first version; the source reports the end of
// the chain with fs.ErrNotExist.
func latestMigrationVersion(src source.Driver) (uint, error) {
	v, err := src.First()
	if err != nil {
		return 0, fmt.Errorf("no embedded migrations: %w", err)
	}

	for {
		next, err := src.Next(v)
		if errors.Is(err, fs.ErrNotExist) {
			return v, nil
		}
		if err != nil {
			return 0, fmt.Errorf("walk embedded migrations: %w", err)
		}

		v = next
	}
}
