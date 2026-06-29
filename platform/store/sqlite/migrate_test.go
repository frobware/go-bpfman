package sqlite

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/stretchr/testify/require"

	"github.com/frobware/go-bpfman/lock"
)

// addNotesMigration is a synthetic second migration used to prove that
// a real schema change applied on top of the baseline preserves data.
const addNotesMigration = `ALTER TABLE map_sets ADD COLUMN notes TEXT;`

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// openStore opens (creating and migrating) a file store at dbPath under
// the writer lock and closes it, returning any error from New.
func openStore(ctx context.Context, dbPath, lockPath string) error {
	return lock.Run(ctx, lockPath, func(ctx context.Context, wl lock.WriterScope) error {
		store, err := New(ctx, dbPath, discardLogger(), wl)
		if err != nil {
			return err
		}
		return store.Close()
	})
}

// openRaw opens a bare connection to dbPath for test probes and
// closes it on cleanup.
func openRaw(t *testing.T, dbPath string) *sql.DB {
	t.Helper()
	db, err := sql.Open(driverName, dbPath)
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	return db
}

// latestKnownVersion is the highest version among the embedded
// migrations, i.e. the version a freshly opened store lands at.
func latestKnownVersion(t *testing.T) uint {
	t.Helper()
	src, err := iofs.New(migrationsFS, "migrations")
	require.NoError(t, err)
	defer src.Close()
	v, err := latestMigrationVersion(src)
	require.NoError(t, err)
	return v
}

// recordedVersion reads the version golang-migrate has recorded for the
// database, without writing.
func recordedVersion(t *testing.T, ctx context.Context, db *sql.DB) uint {
	t.Helper()
	var v uint
	var dirty bool
	require.NoError(t, db.QueryRowContext(ctx, "SELECT version, dirty FROM schema_migrations LIMIT 1").Scan(&v, &dirty))
	require.False(t, dirty, "database should not be dirty")
	return v
}

func tableExists(t *testing.T, ctx context.Context, db *sql.DB, name string) bool {
	t.Helper()
	var n int
	require.NoError(t, db.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = ?", name).Scan(&n))
	return n == 1
}

func countRows(t *testing.T, ctx context.Context, db *sql.DB, table string) int {
	t.Helper()
	var n int
	require.NoError(t, db.QueryRowContext(ctx, fmt.Sprintf("SELECT count(*) FROM %s", table)).Scan(&n))
	return n
}

// TestMigrateFreshDatabaseLandsAtLatest proves a brand-new database is
// migrated up to the latest schema version and carries the schema.
func TestMigrateFreshDatabaseLandsAtLatest(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "store.db")
	lockPath := filepath.Join(dir, ".lock")

	require.NoError(t, openStore(ctx, dbPath, lockPath))

	db := openRaw(t, dbPath)
	require.Equal(t, latestKnownVersion(t), recordedVersion(t, ctx, db))
	require.True(t, tableExists(t, ctx, db, "managed_programs"), "schema should be present")
}

// TestMigrateAdoptsExistingDatabaseWithoutWipe is the headline of this
// change: reopening a database that already carries the schema but has
// no golang-migrate bookkeeping (the shape every pre-migration database
// has on disk) adopts it in place. The data survives -- it is no longer
// deleted on a version change -- and golang-migrate takes over version
// tracking.
func TestMigrateAdoptsExistingDatabaseWithoutWipe(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "store.db")
	lockPath := filepath.Join(dir, ".lock")

	// Create a current-schema database and write a row.
	require.NoError(t, openStore(ctx, dbPath, lockPath))
	seed := openRaw(t, dbPath)
	_, err := seed.ExecContext(ctx, "INSERT INTO map_sets(id, pin_path, created_at) VALUES (1, '/pin', 'now')")
	require.NoError(t, err)

	// Strip golang-migrate's bookkeeping and stamp the legacy PRAGMA
	// user_version to mimic a database written by the pre-migration build.
	_, err = seed.ExecContext(ctx, "DROP TABLE schema_migrations")
	require.NoError(t, err)
	_, err = seed.ExecContext(ctx, "PRAGMA user_version = 16")
	require.NoError(t, err)
	require.NoError(t, seed.Close())

	// Reopening must adopt the existing schema rather than wipe it.
	require.NoError(t, openStore(ctx, dbPath, lockPath))

	db := openRaw(t, dbPath)
	require.Equal(t, 1, countRows(t, ctx, db, "map_sets"), "row must survive reopen")
	require.Equal(t, latestKnownVersion(t), recordedVersion(t, ctx, db))
}

// TestMigrateRefusesNewerDatabaseWithoutWipe proves a database recorded
// at a version newer than this build understands is refused, not
// downgraded and not deleted.
func TestMigrateRefusesNewerDatabaseWithoutWipe(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "store.db")
	lockPath := filepath.Join(dir, ".lock")

	require.NoError(t, openStore(ctx, dbPath, lockPath))
	seed := openRaw(t, dbPath)
	_, err := seed.ExecContext(ctx, "INSERT INTO map_sets(id, pin_path, created_at) VALUES (1, '/pin', 'now')")
	require.NoError(t, err)

	// Record a version far beyond any embedded migration.
	_, err = seed.ExecContext(ctx, "DELETE FROM schema_migrations")
	require.NoError(t, err)
	_, err = seed.ExecContext(ctx, "INSERT INTO schema_migrations(version, dirty) VALUES (9999, 0)")
	require.NoError(t, err)
	require.NoError(t, seed.Close())

	err = openStore(ctx, dbPath, lockPath)
	require.Error(t, err)
	require.ErrorIs(t, err, errSchemaVersionMismatch)

	db := openRaw(t, dbPath)
	require.Equal(t, 1, countRows(t, ctx, db, "map_sets"), "data must be left intact on refusal")
}

// TestForwardMigrationPreservesData proves the framework supports real
// future migrations: a schema change applied on top of the baseline
// advances the version and leaves existing rows in place.
func TestForwardMigrationPreservesData(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	dir := t.TempDir()

	// Assemble a migrations directory: the real baseline plus a
	// synthetic follow-up that adds a column.
	migDir := filepath.Join(dir, "migrations")
	require.NoError(t, os.MkdirAll(migDir, 0o755))
	for _, name := range []string{"00001_baseline.up.sql", "00001_baseline.down.sql"} {
		body, err := migrationsFS.ReadFile("migrations/" + name)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(migDir, name), body, 0o644))
	}
	require.NoError(t, os.WriteFile(filepath.Join(migDir, "00002_add_notes.up.sql"), []byte(addNotesMigration), 0o644))
	require.NoError(t, os.WriteFile(filepath.Join(migDir, "00002_add_notes.down.sql"), []byte("ALTER TABLE map_sets DROP COLUMN notes;"), 0o644))

	dbPath := filepath.Join(dir, "store.db")
	db, err := sql.Open(driverName, dbPath)
	require.NoError(t, err)
	defer db.Close()

	src, err := iofs.New(os.DirFS(migDir), ".")
	require.NoError(t, err)
	driver, err := newMigrateDriver(db)
	require.NoError(t, err)
	m, err := migrate.NewWithInstance("iofs", src, driverName, driver)
	require.NoError(t, err)

	// Apply only the baseline, then write a row.
	require.NoError(t, m.Steps(1))
	_, err = db.ExecContext(ctx, "INSERT INTO map_sets(id, pin_path, created_at) VALUES (1, '/pin', 'now')")
	require.NoError(t, err)

	// Apply the follow-up migration.
	require.NoError(t, m.Up())

	version, _, err := m.Version()
	require.NoError(t, err)
	require.Equal(t, uint(2), version)

	require.Equal(t, 1, countRows(t, ctx, db, "map_sets"), "row must survive the migration")

	// The new column must exist and be writable.
	_, err = db.ExecContext(ctx, "UPDATE map_sets SET notes = 'hello' WHERE id = 1")
	require.NoError(t, err)
}
