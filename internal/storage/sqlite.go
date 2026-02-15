package storage

import (
	"database/sql"
	"fmt"

	_ "modernc.org/sqlite"
)

// DB wraps a sql.DB connection to a SQLite database.
type DB struct {
	db *sql.DB
}

// NewDB opens (or creates) a SQLite database at path and runs schema migrations.
func NewDB(path string) (*DB, error) {
	dsn := path + "?_journal_mode=WAL&_busy_timeout=5000"
	sqlDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	if err := sqlDB.Ping(); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("ping db: %w", err)
	}

	// Enable foreign keys.
	if _, err := sqlDB.Exec("PRAGMA foreign_keys = ON"); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("enable foreign keys: %w", err)
	}

	d := &DB{db: sqlDB}
	if err := d.migrate(); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return d, nil
}

// Close closes the underlying database connection.
func (d *DB) Close() error {
	return d.db.Close()
}

// migrate creates all required tables if they do not already exist.
func (d *DB) migrate() error {
	schema := `
CREATE TABLE IF NOT EXISTS recovery_keys (
    id TEXT PRIMARY KEY,
    hex_key TEXT NOT NULL,
    mnemonic TEXT,
    escrow_blob BLOB NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS files (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    size INTEGER NOT NULL,
    mime_type TEXT,
    cipher TEXT NOT NULL,
    salt BLOB NOT NULL,
    nonce BLOB NOT NULL,
    blob BLOB NOT NULL,
    recovery_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (recovery_id) REFERENCES recovery_keys(id)
);

CREATE TABLE IF NOT EXISTS links (
    id TEXT PRIMARY KEY,
    file_id TEXT NOT NULL,
    mode TEXT NOT NULL,
    password_hash BLOB NOT NULL,
    expires_at INTEGER,
    burned INTEGER DEFAULT 0,
    downloads INTEGER DEFAULT 0,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (file_id) REFERENCES files(id)
);

CREATE TABLE IF NOT EXISTS nodes (
    id TEXT PRIMARY KEY,
    public_key BLOB NOT NULL,
    address TEXT NOT NULL,
    max_storage INTEGER NOT NULL,
    used_storage INTEGER DEFAULT 0,
    last_seen INTEGER NOT NULL,
    online INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS shards (
    id TEXT PRIMARY KEY,
    file_id TEXT NOT NULL,
    shard_index INTEGER NOT NULL,
    node_id TEXT NOT NULL,
    size INTEGER NOT NULL,
    checksum TEXT NOT NULL,
    FOREIGN KEY (file_id) REFERENCES files(id),
    FOREIGN KEY (node_id) REFERENCES nodes(id)
);`
	_, err := d.db.Exec(schema)
	return err
}
