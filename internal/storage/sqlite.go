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

// --- Recovery Key CRUD ---

// CreateRecoveryKey inserts a new recovery key record.
func (d *DB) CreateRecoveryKey(rk *RecoveryKey) error {
	_, err := d.db.Exec(
		`INSERT INTO recovery_keys (id, hex_key, mnemonic, escrow_blob, created_at)
		 VALUES (?, ?, ?, ?, ?)`,
		rk.ID, rk.HexKey, rk.Mnemonic, rk.EscrowBlob, rk.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("create recovery key: %w", err)
	}
	return nil
}

// GetRecoveryKey retrieves a recovery key by ID.
func (d *DB) GetRecoveryKey(id string) (*RecoveryKey, error) {
	rk := &RecoveryKey{}
	err := d.db.QueryRow(
		`SELECT id, hex_key, mnemonic, escrow_blob, created_at
		 FROM recovery_keys WHERE id = ?`, id,
	).Scan(&rk.ID, &rk.HexKey, &rk.Mnemonic, &rk.EscrowBlob, &rk.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("get recovery key: %w", err)
	}
	return rk, nil
}

// ListRecoveryKeys returns all recovery keys.
func (d *DB) ListRecoveryKeys() ([]RecoveryKey, error) {
	rows, err := d.db.Query(
		`SELECT id, hex_key, mnemonic, escrow_blob, created_at FROM recovery_keys`,
	)
	if err != nil {
		return nil, fmt.Errorf("list recovery keys: %w", err)
	}
	defer rows.Close()

	var keys []RecoveryKey
	for rows.Next() {
		var rk RecoveryKey
		if err := rows.Scan(&rk.ID, &rk.HexKey, &rk.Mnemonic, &rk.EscrowBlob, &rk.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan recovery key: %w", err)
		}
		keys = append(keys, rk)
	}
	return keys, rows.Err()
}

// --- File CRUD ---

// CreateFile inserts a new file record.
func (d *DB) CreateFile(f *File) error {
	_, err := d.db.Exec(
		`INSERT INTO files (id, name, size, mime_type, cipher, salt, nonce, blob, recovery_id, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		f.ID, f.Name, f.Size, f.MimeType, f.Cipher, f.Salt, f.Nonce, f.Blob, f.RecoveryID, f.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	return nil
}

// GetFile retrieves a file by ID, including the blob.
func (d *DB) GetFile(id string) (*File, error) {
	f := &File{}
	err := d.db.QueryRow(
		`SELECT id, name, size, mime_type, cipher, salt, nonce, blob, recovery_id, created_at
		 FROM files WHERE id = ?`, id,
	).Scan(&f.ID, &f.Name, &f.Size, &f.MimeType, &f.Cipher, &f.Salt, &f.Nonce, &f.Blob, &f.RecoveryID, &f.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("get file: %w", err)
	}
	return f, nil
}

// ListFiles returns all files without their blob data (for listing).
func (d *DB) ListFiles() ([]File, error) {
	rows, err := d.db.Query(
		`SELECT id, name, size, mime_type, cipher, salt, nonce, recovery_id, created_at FROM files`,
	)
	if err != nil {
		return nil, fmt.Errorf("list files: %w", err)
	}
	defer rows.Close()

	var files []File
	for rows.Next() {
		var f File
		if err := rows.Scan(&f.ID, &f.Name, &f.Size, &f.MimeType, &f.Cipher, &f.Salt, &f.Nonce, &f.RecoveryID, &f.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan file: %w", err)
		}
		files = append(files, f)
	}
	return files, rows.Err()
}

// DeleteFile removes a file by ID.
func (d *DB) DeleteFile(id string) error {
	res, err := d.db.Exec(`DELETE FROM files WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete file: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete file rows affected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("delete file: %w", sql.ErrNoRows)
	}
	return nil
}
