package sqlite

import (
	"database/sql"

	"github.com/golang-migrate/migrate/v4/database"
	migratesqlite3 "github.com/golang-migrate/migrate/v4/database/sqlite3"
)

// newMigrateDriver wraps the store's database handle in golang-migrate's
// mattn/go-sqlite3 database driver, the only SQLite driver the store
// uses. NoTxWrap is set because migrations manage their own transactions
// where they need one: a SQLite table rebuild must toggle PRAGMA
// foreign_keys, which is a no-op inside a transaction, so the framework
// must not open one around the migration. Simpler migrations are written
// to be idempotent instead. See the migration template for the rebuild
// pattern.
func newMigrateDriver(db *sql.DB) (database.Driver, error) {
	return migratesqlite3.WithInstance(db, &migratesqlite3.Config{NoTxWrap: true})
}
