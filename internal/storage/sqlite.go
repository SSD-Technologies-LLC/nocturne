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
//
// Deprecated: Agent tables (operators, agent_keys, knowledge, compute_tasks,
// votes, provenance, awareness, anomaly_logs) are superseded by the distributed
// DHT layer. These tables remain for backward compatibility with centralized mode.
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
);

CREATE TABLE IF NOT EXISTS operators (
    id TEXT PRIMARY KEY,
    public_key BLOB NOT NULL,
    label TEXT NOT NULL,
    approved_by TEXT NOT NULL,
    reputation REAL DEFAULT 0.0,
    quarantined INTEGER DEFAULT 0,
    max_agents INTEGER DEFAULT 5,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS agent_keys (
    id TEXT PRIMARY KEY,
    operator_id TEXT NOT NULL,
    public_key BLOB NOT NULL,
    label TEXT,
    last_seen INTEGER,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (operator_id) REFERENCES operators(id)
);

CREATE TABLE IF NOT EXISTS knowledge (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    operator_id TEXT NOT NULL,
    type TEXT NOT NULL,
    domain TEXT NOT NULL,
    content TEXT NOT NULL,
    confidence REAL DEFAULT 0.5,
    sources TEXT,
    supersedes TEXT,
    votes_up INTEGER DEFAULT 0,
    votes_down INTEGER DEFAULT 0,
    verified_by TEXT,
    ttl INTEGER,
    created_at INTEGER NOT NULL,
    signature TEXT NOT NULL,
    FOREIGN KEY (agent_id) REFERENCES agent_keys(id),
    FOREIGN KEY (operator_id) REFERENCES operators(id)
);

CREATE TABLE IF NOT EXISTS compute_tasks (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    domain TEXT,
    description TEXT NOT NULL,
    priority INTEGER DEFAULT 5,
    claimed_by TEXT,
    claimed_at INTEGER,
    completed INTEGER DEFAULT 0,
    result_id TEXT,
    verified_by TEXT,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS votes (
    id TEXT PRIMARY KEY,
    entry_id TEXT NOT NULL,
    operator_id TEXT NOT NULL,
    commitment TEXT,
    vote INTEGER,
    nonce TEXT,
    reason TEXT,
    phase TEXT DEFAULT 'commit',
    committed_at INTEGER NOT NULL,
    revealed_at INTEGER,
    UNIQUE(entry_id, operator_id)
);

CREATE TABLE IF NOT EXISTS provenance (
    entry_id TEXT NOT NULL,
    source_id TEXT NOT NULL,
    PRIMARY KEY (entry_id, source_id)
);

CREATE TABLE IF NOT EXISTS awareness (
    id TEXT PRIMARY KEY,
    snapshot TEXT NOT NULL,
    generated_by TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS anomaly_logs (
    id TEXT PRIMARY KEY,
    operator_id TEXT NOT NULL,
    type TEXT NOT NULL,
    evidence TEXT NOT NULL,
    action_taken TEXT,
    created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_knowledge_domain ON knowledge(domain);
CREATE INDEX IF NOT EXISTS idx_knowledge_type ON knowledge(type);
CREATE INDEX IF NOT EXISTS idx_knowledge_confidence ON knowledge(confidence);
CREATE INDEX IF NOT EXISTS idx_knowledge_created ON knowledge(created_at);
CREATE INDEX IF NOT EXISTS idx_compute_tasks_priority ON compute_tasks(priority DESC);
CREATE INDEX IF NOT EXISTS idx_compute_tasks_claimed ON compute_tasks(claimed_by);
CREATE INDEX IF NOT EXISTS idx_votes_entry ON votes(entry_id);
CREATE INDEX IF NOT EXISTS idx_votes_phase ON votes(phase);
CREATE INDEX IF NOT EXISTS idx_anomaly_operator ON anomaly_logs(operator_id);
CREATE INDEX IF NOT EXISTS idx_agent_keys_operator ON agent_keys(operator_id);`
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

// --- Link CRUD ---

// boolToInt converts a bool to an integer (0 or 1) for SQLite storage.
func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// CreateLink inserts a new link record.
func (d *DB) CreateLink(l *Link) error {
	var expiresAt sql.NullInt64
	if l.ExpiresAt != nil {
		expiresAt = sql.NullInt64{Int64: *l.ExpiresAt, Valid: true}
	}
	_, err := d.db.Exec(
		`INSERT INTO links (id, file_id, mode, password_hash, expires_at, burned, downloads, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		l.ID, l.FileID, l.Mode, l.PasswordHash, expiresAt, boolToInt(l.Burned), l.Downloads, l.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("create link: %w", err)
	}
	return nil
}

// GetLink retrieves a link by ID.
func (d *DB) GetLink(id string) (*Link, error) {
	l := &Link{}
	var expiresAt sql.NullInt64
	var burned int
	err := d.db.QueryRow(
		`SELECT id, file_id, mode, password_hash, expires_at, burned, downloads, created_at
		 FROM links WHERE id = ?`, id,
	).Scan(&l.ID, &l.FileID, &l.Mode, &l.PasswordHash, &expiresAt, &burned, &l.Downloads, &l.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("get link: %w", err)
	}
	if expiresAt.Valid {
		l.ExpiresAt = &expiresAt.Int64
	}
	l.Burned = burned != 0
	return l, nil
}

// ListLinksForFile returns all links associated with a file.
func (d *DB) ListLinksForFile(fileID string) ([]Link, error) {
	rows, err := d.db.Query(
		`SELECT id, file_id, mode, password_hash, expires_at, burned, downloads, created_at
		 FROM links WHERE file_id = ?`, fileID,
	)
	if err != nil {
		return nil, fmt.Errorf("list links for file: %w", err)
	}
	defer rows.Close()

	var links []Link
	for rows.Next() {
		var l Link
		var expiresAt sql.NullInt64
		var burned int
		if err := rows.Scan(&l.ID, &l.FileID, &l.Mode, &l.PasswordHash, &expiresAt, &burned, &l.Downloads, &l.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan link: %w", err)
		}
		if expiresAt.Valid {
			l.ExpiresAt = &expiresAt.Int64
		}
		l.Burned = burned != 0
		links = append(links, l)
	}
	return links, rows.Err()
}

// BurnLink sets burned=1 and increments downloads for a link.
func (d *DB) BurnLink(id string) error {
	res, err := d.db.Exec(
		`UPDATE links SET burned = 1, downloads = downloads + 1 WHERE id = ?`, id,
	)
	if err != nil {
		return fmt.Errorf("burn link: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("burn link rows affected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("burn link: %w", sql.ErrNoRows)
	}
	return nil
}

// IncrementDownloads increments the download counter for a link.
func (d *DB) IncrementDownloads(id string) error {
	res, err := d.db.Exec(
		`UPDATE links SET downloads = downloads + 1 WHERE id = ?`, id,
	)
	if err != nil {
		return fmt.Errorf("increment downloads: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("increment downloads rows affected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("increment downloads: %w", sql.ErrNoRows)
	}
	return nil
}

// DeleteLink removes a link by ID.
func (d *DB) DeleteLink(id string) error {
	res, err := d.db.Exec(`DELETE FROM links WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete link: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete link rows affected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("delete link: %w", sql.ErrNoRows)
	}
	return nil
}
