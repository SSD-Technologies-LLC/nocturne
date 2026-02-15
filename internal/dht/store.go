package dht

import (
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	_ "modernc.org/sqlite"
)

// LocalStore manages DHT key-value entries stored on this node using SQLite.
type LocalStore struct {
	db *sql.DB
}

// NewLocalStore opens (or creates) a SQLite database at the given path.
// Pass ":memory:" for an in-memory database (useful for tests).
func NewLocalStore(dbPath string) (*LocalStore, error) {
	dsn := dbPath + "?_journal_mode=WAL&_busy_timeout=5000"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open store: %w", err)
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("ping store: %w", err)
	}

	// Create table for DHT entries.
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS dht_entries (
		key_hex TEXT PRIMARY KEY,
		value BLOB NOT NULL,
		expires_at INTEGER NOT NULL
	)`)
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("create table: %w", err)
	}

	return &LocalStore{db: db}, nil
}

// Put stores a key-value pair with a TTL. If the key already exists, it is
// overwritten with the new value and expiration time. The expiration is stored
// with millisecond precision.
func (s *LocalStore) Put(key NodeID, value []byte, ttl time.Duration) error {
	keyHex := hex.EncodeToString(key[:])
	expiresAt := time.Now().Add(ttl).UnixMilli()
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO dht_entries (key_hex, value, expires_at) VALUES (?, ?, ?)`,
		keyHex, value, expiresAt,
	)
	return err
}

// Get retrieves a value by key. Returns (nil, false, nil) if the key is not
// found or has expired. Expired entries are cleaned up on read.
func (s *LocalStore) Get(key NodeID) ([]byte, bool, error) {
	keyHex := hex.EncodeToString(key[:])
	var value []byte
	var expiresAt int64
	err := s.db.QueryRow(
		`SELECT value, expires_at FROM dht_entries WHERE key_hex = ?`,
		keyHex,
	).Scan(&value, &expiresAt)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if time.Now().UnixMilli() > expiresAt {
		// Expired — clean up and return not found.
		s.Delete(key)
		return nil, false, nil
	}
	return value, true, nil
}

// Delete removes an entry by key.
func (s *LocalStore) Delete(key NodeID) error {
	keyHex := hex.EncodeToString(key[:])
	_, err := s.db.Exec(`DELETE FROM dht_entries WHERE key_hex = ?`, keyHex)
	return err
}

// PruneExpired removes all expired entries and returns the count removed.
func (s *LocalStore) PruneExpired() (int, error) {
	now := time.Now().UnixMilli()
	res, err := s.db.Exec(`DELETE FROM dht_entries WHERE expires_at < ?`, now)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

// ListKeys returns all non-expired keys currently in the store.
func (s *LocalStore) ListKeys() ([]NodeID, error) {
	now := time.Now().UnixMilli()
	rows, err := s.db.Query(`SELECT key_hex FROM dht_entries WHERE expires_at >= ?`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []NodeID
	for rows.Next() {
		var keyHex string
		if err := rows.Scan(&keyHex); err != nil {
			return nil, err
		}
		b, err := hex.DecodeString(keyHex)
		if err != nil || len(b) != IDLength {
			continue
		}
		var id NodeID
		copy(id[:], b)
		keys = append(keys, id)
	}
	return keys, rows.Err()
}

// Close closes the underlying SQLite database.
func (s *LocalStore) Close() error {
	return s.db.Close()
}
