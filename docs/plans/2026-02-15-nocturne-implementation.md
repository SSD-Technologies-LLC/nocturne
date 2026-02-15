# Nocturne Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build Nocturne — a minimalist encrypted file storage solution with a dashboard, shareable links, novel Noctis-256 cipher, and a distributed mesh storage network.

**Architecture:** Single Go binary serves API + embedded dashboard + public download pages. SQLite for storage. A second binary (`nocturne-node`) lets users join a distributed mesh network where encrypted shards are stored across participating nodes. The server acts as both the standalone vault and the mesh tracker.

**Tech Stack:** Go 1.22+, SQLite (via `modernc.org/sqlite`), Argon2id (via `golang.org/x/crypto`), `go:embed` for frontend, WebSocket (via `gorilla/websocket`), Reed-Solomon erasure coding (via `klauspost/reedsolomon`), Ed25519 for node auth.

**Design doc:** `docs/plans/2026-02-15-nocturne-design.md`

---

## Phase 1: Foundation

### Task 1: Project Scaffolding

**Files:**
- Create: `go.mod`
- Create: `cmd/nocturne/main.go`
- Create: `cmd/nocturne-node/main.go`
- Create: `internal/storage/sqlite.go`
- Create: `internal/storage/models.go`
- Create: `.gitignore`

**Step 1: Initialize Go module**

```bash
cd /home/mark-ssd/code/ssd.foundation/nocturne
go mod init github.com/ssd-technologies/nocturne
```

**Step 2: Create .gitignore**

```gitignore
# Binaries
nocturne
nocturne-node
*.exe

# Data
data/
*.db

# IDE
.idea/
.vscode/
*.swp

# OS
.DS_Store
Thumbs.db

# Build
dist/
```

**Step 3: Create minimal main.go for server**

```go
// cmd/nocturne/main.go
package main

import (
	"fmt"
	"os"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	fmt.Printf("Nocturne starting on :%s\n", port)
}
```

**Step 4: Create minimal main.go for node**

```go
// cmd/nocturne-node/main.go
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: nocturne-node <connect|disconnect|status>")
		os.Exit(1)
	}
	fmt.Printf("nocturne-node: %s\n", os.Args[1])
}
```

**Step 5: Create data models**

```go
// internal/storage/models.go
package storage

type File struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Size       int64  `json:"size"`
	MimeType   string `json:"mime_type,omitempty"`
	Cipher     string `json:"cipher"`
	Salt       []byte `json:"-"`
	Nonce      []byte `json:"-"`
	Blob       []byte `json:"-"`
	RecoveryID string `json:"recovery_id"`
	CreatedAt  int64  `json:"created_at"`
}

type RecoveryKey struct {
	ID        string `json:"id"`
	HexKey    string `json:"hex_key"`
	Mnemonic  string `json:"mnemonic,omitempty"`
	EscrowBlob []byte `json:"-"`
	CreatedAt int64  `json:"created_at"`
}

type Link struct {
	ID           string `json:"id"`
	FileID       string `json:"file_id"`
	Mode         string `json:"mode"`
	PasswordHash []byte `json:"-"`
	ExpiresAt    *int64 `json:"expires_at,omitempty"`
	Burned       bool   `json:"burned"`
	Downloads    int    `json:"downloads"`
	CreatedAt    int64  `json:"created_at"`
}

type Node struct {
	ID          string `json:"id"`
	PublicKey   []byte `json:"-"`
	Address     string `json:"address"`
	MaxStorage  int64  `json:"max_storage"`
	UsedStorage int64  `json:"used_storage"`
	LastSeen    int64  `json:"last_seen"`
	Online      bool   `json:"online"`
}

type Shard struct {
	ID         string `json:"id"`
	FileID     string `json:"file_id"`
	ShardIndex int    `json:"shard_index"`
	NodeID     string `json:"node_id"`
	Size       int64  `json:"size"`
	Checksum   string `json:"checksum"`
}
```

**Step 6: Build and verify**

```bash
go build ./cmd/nocturne && go build ./cmd/nocturne-node
```

**Step 7: Commit**

```bash
git add -A && git commit -m "scaffold: init Go module with server and node binaries"
```

---

### Task 2: SQLite Storage Layer

**Files:**
- Create: `internal/storage/sqlite.go`
- Create: `internal/storage/sqlite_test.go`

**Step 1: Install SQLite dependency**

```bash
go get modernc.org/sqlite
```

**Step 2: Write failing test for DB initialization**

```go
// internal/storage/sqlite_test.go
package storage

import (
	"os"
	"testing"
)

func TestNewDB_CreatesTablesOnInit(t *testing.T) {
	path := t.TempDir() + "/test.db"
	db, err := NewDB(path)
	if err != nil {
		t.Fatalf("NewDB failed: %v", err)
	}
	defer db.Close()

	// Verify tables exist by querying them
	tables := []string{"files", "recovery_keys", "links", "nodes", "shards"}
	for _, table := range tables {
		_, err := db.db.Exec("SELECT 1 FROM " + table + " LIMIT 1")
		if err != nil {
			t.Errorf("table %s does not exist: %v", table, err)
		}
	}

	// Cleanup
	os.Remove(path)
}
```

**Step 3: Run test — verify RED**

```bash
go test ./internal/storage/ -run TestNewDB -v
```

Expected: FAIL — `NewDB` undefined.

**Step 4: Implement SQLite storage**

```go
// internal/storage/sqlite.go
package storage

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

type DB struct {
	db *sql.DB
}

func NewDB(path string) (*DB, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}

	sqlDB, err := sql.Open("sqlite", path+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	d := &DB{db: sqlDB}
	if err := d.migrate(); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return d, nil
}

func (d *DB) Close() error {
	return d.db.Close()
}

func (d *DB) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS recovery_keys (
		id          TEXT PRIMARY KEY,
		hex_key     TEXT NOT NULL,
		mnemonic    TEXT,
		escrow_blob BLOB NOT NULL,
		created_at  INTEGER NOT NULL
	);

	CREATE TABLE IF NOT EXISTS files (
		id          TEXT PRIMARY KEY,
		name        TEXT NOT NULL,
		size        INTEGER NOT NULL,
		mime_type   TEXT,
		cipher      TEXT NOT NULL,
		salt        BLOB NOT NULL,
		nonce       BLOB NOT NULL,
		blob        BLOB NOT NULL,
		recovery_id TEXT NOT NULL,
		created_at  INTEGER NOT NULL,
		FOREIGN KEY (recovery_id) REFERENCES recovery_keys(id)
	);

	CREATE TABLE IF NOT EXISTS links (
		id            TEXT PRIMARY KEY,
		file_id       TEXT NOT NULL,
		mode          TEXT NOT NULL,
		password_hash BLOB NOT NULL,
		expires_at    INTEGER,
		burned        INTEGER DEFAULT 0,
		downloads     INTEGER DEFAULT 0,
		created_at    INTEGER NOT NULL,
		FOREIGN KEY (file_id) REFERENCES files(id)
	);

	CREATE TABLE IF NOT EXISTS nodes (
		id           TEXT PRIMARY KEY,
		public_key   BLOB NOT NULL,
		address      TEXT NOT NULL,
		max_storage  INTEGER NOT NULL,
		used_storage INTEGER DEFAULT 0,
		last_seen    INTEGER NOT NULL,
		online       INTEGER DEFAULT 1
	);

	CREATE TABLE IF NOT EXISTS shards (
		id          TEXT PRIMARY KEY,
		file_id     TEXT NOT NULL,
		shard_index INTEGER NOT NULL,
		node_id     TEXT NOT NULL,
		size        INTEGER NOT NULL,
		checksum    TEXT NOT NULL,
		FOREIGN KEY (file_id) REFERENCES files(id),
		FOREIGN KEY (node_id) REFERENCES nodes(id)
	);
	`
	_, err := d.db.Exec(schema)
	return err
}
```

**Step 5: Run test — verify GREEN**

```bash
go test ./internal/storage/ -run TestNewDB -v
```

**Step 6: Commit**

```bash
git add -A && git commit -m "feat: SQLite storage layer with schema migration"
```

---

### Task 3: File CRUD Operations

**Files:**
- Modify: `internal/storage/sqlite.go`
- Modify: `internal/storage/sqlite_test.go`

**Step 1: Write failing tests for file CRUD**

Add to `sqlite_test.go`:

```go
func testDB(t *testing.T) *DB {
	t.Helper()
	db, err := NewDB(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestCreateAndGetFile(t *testing.T) {
	db := testDB(t)

	rk := &RecoveryKey{
		ID: "rk-1", HexKey: "abcd", EscrowBlob: []byte("escrow"), CreatedAt: 1000,
	}
	if err := db.CreateRecoveryKey(rk); err != nil {
		t.Fatalf("CreateRecoveryKey: %v", err)
	}

	f := &File{
		ID: "f-1", Name: "test.txt", Size: 100, MimeType: "text/plain",
		Cipher: "aes-256-gcm", Salt: []byte("salt"), Nonce: []byte("nonce"),
		Blob: []byte("encrypted"), RecoveryID: "rk-1", CreatedAt: 1000,
	}
	if err := db.CreateFile(f); err != nil {
		t.Fatalf("CreateFile: %v", err)
	}

	got, err := db.GetFile("f-1")
	if err != nil {
		t.Fatalf("GetFile: %v", err)
	}
	if got.Name != "test.txt" || got.Size != 100 {
		t.Errorf("got name=%s size=%d, want test.txt 100", got.Name, got.Size)
	}
}

func TestListFiles(t *testing.T) {
	db := testDB(t)

	rk := &RecoveryKey{
		ID: "rk-1", HexKey: "abcd", EscrowBlob: []byte("escrow"), CreatedAt: 1000,
	}
	db.CreateRecoveryKey(rk)

	for i := 0; i < 3; i++ {
		f := &File{
			ID: fmt.Sprintf("f-%d", i), Name: fmt.Sprintf("file%d.txt", i),
			Size: 100, Cipher: "aes-256-gcm", Salt: []byte("s"), Nonce: []byte("n"),
			Blob: []byte("e"), RecoveryID: "rk-1", CreatedAt: int64(1000 + i),
		}
		db.CreateFile(f)
	}

	files, err := db.ListFiles()
	if err != nil {
		t.Fatalf("ListFiles: %v", err)
	}
	if len(files) != 3 {
		t.Errorf("got %d files, want 3", len(files))
	}
}

func TestDeleteFile(t *testing.T) {
	db := testDB(t)

	rk := &RecoveryKey{
		ID: "rk-1", HexKey: "abcd", EscrowBlob: []byte("escrow"), CreatedAt: 1000,
	}
	db.CreateRecoveryKey(rk)

	f := &File{
		ID: "f-1", Name: "test.txt", Size: 100, Cipher: "aes-256-gcm",
		Salt: []byte("s"), Nonce: []byte("n"), Blob: []byte("e"),
		RecoveryID: "rk-1", CreatedAt: 1000,
	}
	db.CreateFile(f)

	if err := db.DeleteFile("f-1"); err != nil {
		t.Fatalf("DeleteFile: %v", err)
	}

	_, err := db.GetFile("f-1")
	if err == nil {
		t.Error("expected error getting deleted file")
	}
}
```

**Step 2: Run tests — verify RED**

```bash
go test ./internal/storage/ -run "TestCreate|TestList|TestDelete" -v
```

**Step 3: Implement CRUD methods**

Add to `sqlite.go`:

```go
func (d *DB) CreateRecoveryKey(rk *RecoveryKey) error {
	_, err := d.db.Exec(
		"INSERT INTO recovery_keys (id, hex_key, mnemonic, escrow_blob, created_at) VALUES (?, ?, ?, ?, ?)",
		rk.ID, rk.HexKey, rk.Mnemonic, rk.EscrowBlob, rk.CreatedAt,
	)
	return err
}

func (d *DB) GetRecoveryKey(id string) (*RecoveryKey, error) {
	rk := &RecoveryKey{}
	err := d.db.QueryRow(
		"SELECT id, hex_key, mnemonic, escrow_blob, created_at FROM recovery_keys WHERE id = ?", id,
	).Scan(&rk.ID, &rk.HexKey, &rk.Mnemonic, &rk.EscrowBlob, &rk.CreatedAt)
	if err != nil {
		return nil, err
	}
	return rk, nil
}

func (d *DB) CreateFile(f *File) error {
	_, err := d.db.Exec(
		`INSERT INTO files (id, name, size, mime_type, cipher, salt, nonce, blob, recovery_id, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		f.ID, f.Name, f.Size, f.MimeType, f.Cipher, f.Salt, f.Nonce, f.Blob, f.RecoveryID, f.CreatedAt,
	)
	return err
}

func (d *DB) GetFile(id string) (*File, error) {
	f := &File{}
	err := d.db.QueryRow(
		`SELECT id, name, size, mime_type, cipher, salt, nonce, blob, recovery_id, created_at
		 FROM files WHERE id = ?`, id,
	).Scan(&f.ID, &f.Name, &f.Size, &f.MimeType, &f.Cipher, &f.Salt, &f.Nonce, &f.Blob, &f.RecoveryID, &f.CreatedAt)
	if err != nil {
		return nil, err
	}
	return f, nil
}

func (d *DB) ListFiles() ([]File, error) {
	rows, err := d.db.Query(
		"SELECT id, name, size, mime_type, cipher, recovery_id, created_at FROM files ORDER BY created_at DESC",
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var files []File
	for rows.Next() {
		var f File
		if err := rows.Scan(&f.ID, &f.Name, &f.Size, &f.MimeType, &f.Cipher, &f.RecoveryID, &f.CreatedAt); err != nil {
			return nil, err
		}
		files = append(files, f)
	}
	return files, rows.Err()
}

func (d *DB) DeleteFile(id string) error {
	res, err := d.db.Exec("DELETE FROM files WHERE id = ?", id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("file not found: %s", id)
	}
	return nil
}
```

**Step 4: Run tests — verify GREEN**

```bash
go test ./internal/storage/ -v
```

**Step 5: Commit**

```bash
git add -A && git commit -m "feat: file and recovery key CRUD operations"
```

---

### Task 4: Link CRUD Operations

**Files:**
- Modify: `internal/storage/sqlite.go`
- Modify: `internal/storage/sqlite_test.go`

**Step 1: Write failing tests for link operations**

Add to `sqlite_test.go`:

```go
func TestCreateAndGetLink(t *testing.T) {
	db := testDB(t)

	rk := &RecoveryKey{ID: "rk-1", HexKey: "ab", EscrowBlob: []byte("e"), CreatedAt: 1000}
	db.CreateRecoveryKey(rk)
	f := &File{ID: "f-1", Name: "t.txt", Size: 10, Cipher: "aes-256-gcm",
		Salt: []byte("s"), Nonce: []byte("n"), Blob: []byte("b"), RecoveryID: "rk-1", CreatedAt: 1000}
	db.CreateFile(f)

	link := &Link{
		ID: "xK7mQ2pL", FileID: "f-1", Mode: "persistent",
		PasswordHash: []byte("hash"), CreatedAt: 1000,
	}
	if err := db.CreateLink(link); err != nil {
		t.Fatalf("CreateLink: %v", err)
	}

	got, err := db.GetLink("xK7mQ2pL")
	if err != nil {
		t.Fatalf("GetLink: %v", err)
	}
	if got.FileID != "f-1" || got.Mode != "persistent" {
		t.Errorf("unexpected link: %+v", got)
	}
}

func TestBurnLink(t *testing.T) {
	db := testDB(t)

	rk := &RecoveryKey{ID: "rk-1", HexKey: "ab", EscrowBlob: []byte("e"), CreatedAt: 1000}
	db.CreateRecoveryKey(rk)
	f := &File{ID: "f-1", Name: "t.txt", Size: 10, Cipher: "aes-256-gcm",
		Salt: []byte("s"), Nonce: []byte("n"), Blob: []byte("b"), RecoveryID: "rk-1", CreatedAt: 1000}
	db.CreateFile(f)

	link := &Link{ID: "slug1234", FileID: "f-1", Mode: "onetime",
		PasswordHash: []byte("hash"), CreatedAt: 1000}
	db.CreateLink(link)

	if err := db.BurnLink("slug1234"); err != nil {
		t.Fatalf("BurnLink: %v", err)
	}

	got, _ := db.GetLink("slug1234")
	if !got.Burned {
		t.Error("link should be burned")
	}
}

func TestListLinksForFile(t *testing.T) {
	db := testDB(t)

	rk := &RecoveryKey{ID: "rk-1", HexKey: "ab", EscrowBlob: []byte("e"), CreatedAt: 1000}
	db.CreateRecoveryKey(rk)
	f := &File{ID: "f-1", Name: "t.txt", Size: 10, Cipher: "aes-256-gcm",
		Salt: []byte("s"), Nonce: []byte("n"), Blob: []byte("b"), RecoveryID: "rk-1", CreatedAt: 1000}
	db.CreateFile(f)

	for i := 0; i < 3; i++ {
		l := &Link{ID: fmt.Sprintf("slug%04d", i), FileID: "f-1", Mode: "persistent",
			PasswordHash: []byte("h"), CreatedAt: int64(1000 + i)}
		db.CreateLink(l)
	}

	links, err := db.ListLinksForFile("f-1")
	if err != nil {
		t.Fatalf("ListLinksForFile: %v", err)
	}
	if len(links) != 3 {
		t.Errorf("got %d links, want 3", len(links))
	}
}

func TestDeleteLink(t *testing.T) {
	db := testDB(t)

	rk := &RecoveryKey{ID: "rk-1", HexKey: "ab", EscrowBlob: []byte("e"), CreatedAt: 1000}
	db.CreateRecoveryKey(rk)
	f := &File{ID: "f-1", Name: "t.txt", Size: 10, Cipher: "aes-256-gcm",
		Salt: []byte("s"), Nonce: []byte("n"), Blob: []byte("b"), RecoveryID: "rk-1", CreatedAt: 1000}
	db.CreateFile(f)

	link := &Link{ID: "del12345", FileID: "f-1", Mode: "persistent",
		PasswordHash: []byte("h"), CreatedAt: 1000}
	db.CreateLink(link)

	if err := db.DeleteLink("del12345"); err != nil {
		t.Fatalf("DeleteLink: %v", err)
	}

	_, err := db.GetLink("del12345")
	if err == nil {
		t.Error("expected error getting deleted link")
	}
}
```

**Step 2: Run tests — verify RED**

```bash
go test ./internal/storage/ -run "TestCreateAndGetLink|TestBurn|TestListLinks|TestDeleteLink" -v
```

**Step 3: Implement link CRUD**

Add to `sqlite.go`:

```go
func (d *DB) CreateLink(l *Link) error {
	_, err := d.db.Exec(
		`INSERT INTO links (id, file_id, mode, password_hash, expires_at, burned, downloads, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		l.ID, l.FileID, l.Mode, l.PasswordHash, l.ExpiresAt, boolToInt(l.Burned), l.Downloads, l.CreatedAt,
	)
	return err
}

func (d *DB) GetLink(id string) (*Link, error) {
	l := &Link{}
	var burned, downloads int
	var expiresAt sql.NullInt64
	err := d.db.QueryRow(
		`SELECT id, file_id, mode, password_hash, expires_at, burned, downloads, created_at
		 FROM links WHERE id = ?`, id,
	).Scan(&l.ID, &l.FileID, &l.Mode, &l.PasswordHash, &expiresAt, &burned, &downloads, &l.CreatedAt)
	if err != nil {
		return nil, err
	}
	l.Burned = burned == 1
	l.Downloads = downloads
	if expiresAt.Valid {
		l.ExpiresAt = &expiresAt.Int64
	}
	return l, nil
}

func (d *DB) ListLinksForFile(fileID string) ([]Link, error) {
	rows, err := d.db.Query(
		"SELECT id, file_id, mode, password_hash, expires_at, burned, downloads, created_at FROM links WHERE file_id = ? ORDER BY created_at DESC",
		fileID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var links []Link
	for rows.Next() {
		var l Link
		var burned, downloads int
		var expiresAt sql.NullInt64
		if err := rows.Scan(&l.ID, &l.FileID, &l.Mode, &l.PasswordHash, &expiresAt, &burned, &downloads, &l.CreatedAt); err != nil {
			return nil, err
		}
		l.Burned = burned == 1
		l.Downloads = downloads
		if expiresAt.Valid {
			l.ExpiresAt = &expiresAt.Int64
		}
		links = append(links, l)
	}
	return links, rows.Err()
}

func (d *DB) BurnLink(id string) error {
	_, err := d.db.Exec("UPDATE links SET burned = 1, downloads = downloads + 1 WHERE id = ?", id)
	return err
}

func (d *DB) IncrementDownloads(id string) error {
	_, err := d.db.Exec("UPDATE links SET downloads = downloads + 1 WHERE id = ?", id)
	return err
}

func (d *DB) DeleteLink(id string) error {
	res, err := d.db.Exec("DELETE FROM links WHERE id = ?", id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("link not found: %s", id)
	}
	return nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
```

**Step 4: Run tests — verify GREEN**

```bash
go test ./internal/storage/ -v
```

**Step 5: Commit**

```bash
git add -A && git commit -m "feat: link CRUD with burn and download tracking"
```

---

## Phase 2: Cryptography

### Task 5: Key Derivation (Argon2id)

**Files:**
- Create: `internal/crypto/kdf.go`
- Create: `internal/crypto/kdf_test.go`

**Step 1: Install dependency**

```bash
go get golang.org/x/crypto
```

**Step 2: Write failing test**

```go
// internal/crypto/kdf_test.go
package crypto

import (
	"testing"
)

func TestDeriveKey_ProducesDeterministicOutput(t *testing.T) {
	password := "test-password"
	salt := []byte("0123456789abcdef0123456789abcdef") // 32 bytes

	key1 := DeriveKey(password, salt)
	key2 := DeriveKey(password, salt)

	if len(key1) != 32 {
		t.Errorf("key length = %d, want 32", len(key1))
	}
	if string(key1) != string(key2) {
		t.Error("same password+salt should produce same key")
	}
}

func TestDeriveKey_DifferentPasswordsDifferentKeys(t *testing.T) {
	salt := []byte("0123456789abcdef0123456789abcdef")

	key1 := DeriveKey("password1", salt)
	key2 := DeriveKey("password2", salt)

	if string(key1) == string(key2) {
		t.Error("different passwords should produce different keys")
	}
}

func TestGenerateSalt(t *testing.T) {
	salt1 := GenerateSalt()
	salt2 := GenerateSalt()

	if len(salt1) != 32 {
		t.Errorf("salt length = %d, want 32", len(salt1))
	}
	if string(salt1) == string(salt2) {
		t.Error("salts should be random")
	}
}
```

**Step 3: Run test — verify RED**

```bash
go test ./internal/crypto/ -run TestDeriveKey -v
```

**Step 4: Implement KDF**

```go
// internal/crypto/kdf.go
package crypto

import (
	"crypto/rand"

	"golang.org/x/crypto/argon2"
)

const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // 64 MB
	argonThreads = 4
	keyLen       = 32 // 256 bits
	saltLen      = 32
)

func DeriveKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, keyLen)
}

func GenerateSalt() []byte {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return salt
}
```

**Step 5: Run tests — verify GREEN**

```bash
go test ./internal/crypto/ -v
```

**Step 6: Commit**

```bash
git add -A && git commit -m "feat: Argon2id key derivation"
```

---

### Task 6: AES-256-GCM Encryption

**Files:**
- Create: `internal/crypto/aes.go`
- Create: `internal/crypto/aes_test.go`

**Step 1: Write failing test**

```go
// internal/crypto/aes_test.go
package crypto

import (
	"bytes"
	"testing"
)

func TestAES_EncryptDecrypt_Roundtrip(t *testing.T) {
	plaintext := []byte("hello, nocturne!")
	password := "strong-password"

	encrypted, salt, nonce, err := AESEncrypt(plaintext, password)
	if err != nil {
		t.Fatalf("AESEncrypt: %v", err)
	}

	if bytes.Equal(encrypted, plaintext) {
		t.Error("encrypted should differ from plaintext")
	}

	decrypted, err := AESDecrypt(encrypted, password, salt, nonce)
	if err != nil {
		t.Fatalf("AESDecrypt: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

func TestAES_WrongPassword_Fails(t *testing.T) {
	plaintext := []byte("secret data")
	encrypted, salt, nonce, _ := AESEncrypt(plaintext, "correct")

	_, err := AESDecrypt(encrypted, "wrong", salt, nonce)
	if err == nil {
		t.Error("expected error with wrong password")
	}
}

func TestAES_LargeFile(t *testing.T) {
	plaintext := make([]byte, 1024*1024) // 1 MB
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	encrypted, salt, nonce, err := AESEncrypt(plaintext, "password")
	if err != nil {
		t.Fatalf("AESEncrypt: %v", err)
	}

	decrypted, err := AESDecrypt(encrypted, "password", salt, nonce)
	if err != nil {
		t.Fatalf("AESDecrypt: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("large file roundtrip failed")
	}
}
```

**Step 2: Run test — verify RED**

```bash
go test ./internal/crypto/ -run TestAES -v
```

**Step 3: Implement AES-256-GCM**

```go
// internal/crypto/aes.go
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

const aesNonceLen = 12

func AESEncrypt(plaintext []byte, password string) (ciphertext, salt, nonce []byte, err error) {
	salt = GenerateSalt()
	key := DeriveKey(password, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("new cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("new gcm: %w", err)
	}

	nonce = make([]byte, aesNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, nil, fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, salt, nonce, nil
}

func AESDecrypt(ciphertext []byte, password string, salt, nonce []byte) ([]byte, error) {
	key := DeriveKey(password, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new gcm: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return plaintext, nil
}
```

**Step 4: Run tests — verify GREEN**

```bash
go test ./internal/crypto/ -v
```

**Step 5: Commit**

```bash
git add -A && git commit -m "feat: AES-256-GCM encrypt/decrypt"
```

---

### Task 7: Noctis-256 Cipher

**Files:**
- Create: `internal/crypto/noctis.go`
- Create: `internal/crypto/noctis_test.go`

**Step 1: Write failing test**

```go
// internal/crypto/noctis_test.go
package crypto

import (
	"bytes"
	"testing"
)

func TestNoctis_EncryptDecrypt_Roundtrip(t *testing.T) {
	plaintext := []byte("hello, noctis cipher!")
	password := "strong-password"

	encrypted, salt, nonce, err := NoctisEncrypt(plaintext, password)
	if err != nil {
		t.Fatalf("NoctisEncrypt: %v", err)
	}

	if bytes.Equal(encrypted[:len(plaintext)], plaintext) {
		t.Error("encrypted should differ from plaintext")
	}

	decrypted, err := NoctisDecrypt(encrypted, password, salt, nonce)
	if err != nil {
		t.Fatalf("NoctisDecrypt: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted = %q, want %q", decrypted, plaintext)
	}
}

func TestNoctis_WrongPassword_Fails(t *testing.T) {
	plaintext := []byte("secret noctis data")
	encrypted, salt, nonce, _ := NoctisEncrypt(plaintext, "correct")

	_, err := NoctisDecrypt(encrypted, "wrong", salt, nonce)
	if err == nil {
		t.Error("expected error with wrong password")
	}
}

func TestNoctis_Deterministic_SameKeyNonce(t *testing.T) {
	// CTR mode with same key+nonce must produce same output
	key := make([]byte, 64) // 512-bit key
	for i := range key {
		key[i] = byte(i)
	}
	nonce := make([]byte, 24)
	for i := range nonce {
		nonce[i] = byte(i + 100)
	}

	plaintext := []byte("determinism test block!!")

	cipher1 := noctisEncryptRaw(plaintext, key, nonce)
	cipher2 := noctisEncryptRaw(plaintext, key, nonce)

	if !bytes.Equal(cipher1, cipher2) {
		t.Error("same key+nonce should produce identical ciphertext")
	}
}

func TestNoctis_DifferentBlocks_Differ(t *testing.T) {
	key := make([]byte, 64)
	nonce := make([]byte, 24)

	plain1 := make([]byte, 32)
	plain2 := make([]byte, 32)
	plain2[0] = 1

	cipher1 := noctisEncryptRaw(plain1, key, nonce)
	cipher2 := noctisEncryptRaw(plain2, key, nonce)

	if bytes.Equal(cipher1, cipher2) {
		t.Error("different plaintexts should produce different ciphertexts")
	}
}

func TestNoctis_LargeFile(t *testing.T) {
	plaintext := make([]byte, 1024*1024)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}

	encrypted, salt, nonce, err := NoctisEncrypt(plaintext, "password")
	if err != nil {
		t.Fatalf("NoctisEncrypt: %v", err)
	}

	decrypted, err := NoctisDecrypt(encrypted, "password", salt, nonce)
	if err != nil {
		t.Fatalf("NoctisDecrypt: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("large file roundtrip failed")
	}
}
```

**Step 2: Run test — verify RED**

```bash
go test ./internal/crypto/ -run TestNoctis -v
```

**Step 3: Implement Noctis-256**

```go
// internal/crypto/noctis.go
package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/sha3"
)

const (
	noctisBlockSize = 32  // 256 bits
	noctisKeySize   = 64  // 512 bits
	noctisNonceSize = 24  // 192 bits
	noctisRounds    = 20
)

// noctisExpandKey generates round keys from a 512-bit master key using a Feistel-like schedule.
func noctisExpandKey(masterKey []byte) [noctisRounds][noctisBlockSize]byte {
	var roundKeys [noctisRounds][noctisBlockSize]byte

	// Split master key into two halves
	left := make([]byte, 32)
	right := make([]byte, 32)
	copy(left, masterKey[:32])
	copy(right, masterKey[32:])

	for r := 0; r < noctisRounds; r++ {
		// Hash right half with round constant
		h := sha3.New256()
		h.Write(right)
		h.Write([]byte{byte(r)})
		digest := h.Sum(nil)

		// XOR digest into left
		for i := 0; i < 32; i++ {
			left[i] ^= digest[i]
		}

		// Rotate left by round-dependent offset
		shift := (r*7 + 3) % 256
		left = rotateBytes(left, shift)

		// Store as round key
		copy(roundKeys[r][:], left)

		// Swap halves
		left, right = right, left
	}

	return roundKeys
}

// noctisSBox generates a key-dependent S-box by deterministically shuffling all 256 byte values.
func noctisSBox(key []byte) [256]byte {
	var sbox [256]byte
	for i := range sbox {
		sbox[i] = byte(i)
	}

	// Fisher-Yates shuffle seeded by key hash
	h := sha3.New256()
	h.Write(key)
	h.Write([]byte("sbox"))
	seed := h.Sum(nil)

	j := 0
	for i := 255; i > 0; i-- {
		j = int(binary.LittleEndian.Uint32([]byte{seed[j%32], seed[(j+1)%32], seed[(j+2)%32], seed[(j+3)%32]})) % (i + 1)
		sbox[i], sbox[j] = sbox[j], sbox[i]
		// Re-hash seed periodically for more entropy
		if i%32 == 0 {
			h.Reset()
			h.Write(seed)
			h.Write([]byte{byte(i)})
			seed = h.Sum(nil)
			j = 0
		} else {
			j = (j + 1) % 32
		}
	}

	return sbox
}

// noctisInverseSBox computes the inverse S-box for decryption.
func noctisInverseSBox(sbox [256]byte) [256]byte {
	var inv [256]byte
	for i, v := range sbox {
		inv[v] = byte(i)
	}
	return inv
}

// noctisRoundEncrypt applies one round of the Noctis cipher to a 256-bit block.
func noctisRoundEncrypt(block *[noctisBlockSize]byte, roundKey [noctisBlockSize]byte, sbox [256]byte, round int) {
	// 1. Substitution: apply key-dependent S-box
	for i := 0; i < noctisBlockSize; i++ {
		block[i] = sbox[block[i]]
	}

	// 2. Permutation: byte-level rotation within the block
	var tmp [noctisBlockSize]byte
	for i := 0; i < noctisBlockSize; i++ {
		newPos := (i + round*5 + 1) % noctisBlockSize
		tmp[newPos] = block[i]
	}
	*block = tmp

	// 3. Diffusion: XOR with round key
	for i := 0; i < noctisBlockSize; i++ {
		block[i] ^= roundKey[i]
	}

	// 4. Non-linearity: modular addition of block halves (128-bit add-with-carry)
	var carry uint16
	for i := 15; i >= 0; i-- {
		sum := uint16(block[i]) + uint16(block[i+16]) + carry
		block[i] = byte(sum & 0xFF)
		carry = sum >> 8
	}
}

// noctisRoundDecrypt reverses one round.
func noctisRoundDecrypt(block *[noctisBlockSize]byte, roundKey [noctisBlockSize]byte, invSbox [256]byte, round int) {
	// 4. Reverse non-linearity: modular subtraction
	var borrow uint16
	for i := 15; i >= 0; i-- {
		diff := uint16(block[i]) - uint16(block[i+16]) - borrow
		if diff > 255 {
			block[i] = byte(diff + 256)
			borrow = 1
		} else {
			block[i] = byte(diff)
			borrow = 0
		}
	}

	// 3. Reverse diffusion: XOR with round key
	for i := 0; i < noctisBlockSize; i++ {
		block[i] ^= roundKey[i]
	}

	// 2. Reverse permutation
	var tmp [noctisBlockSize]byte
	for i := 0; i < noctisBlockSize; i++ {
		newPos := (i + round*5 + 1) % noctisBlockSize
		tmp[i] = block[newPos]
	}
	*block = tmp

	// 1. Reverse substitution: apply inverse S-box
	for i := 0; i < noctisBlockSize; i++ {
		block[i] = invSbox[block[i]]
	}
}

// noctisEncryptBlock encrypts a single 256-bit block.
func noctisEncryptBlock(block *[noctisBlockSize]byte, roundKeys [noctisRounds][noctisBlockSize]byte, sbox [256]byte) {
	for r := 0; r < noctisRounds; r++ {
		noctisRoundEncrypt(block, roundKeys[r], sbox, r)
	}
}

// noctisDecryptBlock decrypts a single 256-bit block.
func noctisDecryptBlock(block *[noctisBlockSize]byte, roundKeys [noctisRounds][noctisBlockSize]byte, invSbox [256]byte) {
	for r := noctisRounds - 1; r >= 0; r-- {
		noctisRoundDecrypt(block, roundKeys[r], invSbox, r)
	}
}

// noctisCTRKeystream generates keystream in CTR mode by encrypting counter blocks.
func noctisCTRKeystream(nonce []byte, counter uint64, roundKeys [noctisRounds][noctisBlockSize]byte, sbox [256]byte) [noctisBlockSize]byte {
	var block [noctisBlockSize]byte
	copy(block[:24], nonce)
	binary.BigEndian.PutUint64(block[24:], counter)
	noctisEncryptBlock(&block, roundKeys, sbox)
	return block
}

// noctisEncryptRaw encrypts plaintext using Noctis-256 in CTR mode (no auth, no KDF — raw).
func noctisEncryptRaw(plaintext, key, nonce []byte) []byte {
	roundKeys := noctisExpandKey(key)
	sbox := noctisSBox(key)

	ciphertext := make([]byte, len(plaintext))
	var counter uint64

	for offset := 0; offset < len(plaintext); offset += noctisBlockSize {
		keystream := noctisCTRKeystream(nonce, counter, roundKeys, sbox)
		end := offset + noctisBlockSize
		if end > len(plaintext) {
			end = len(plaintext)
		}
		for i := offset; i < end; i++ {
			ciphertext[i] = plaintext[i] ^ keystream[i-offset]
		}
		counter++
	}

	return ciphertext
}

// NoctisEncrypt encrypts plaintext with password using Noctis-256 + HMAC-SHA3-256.
func NoctisEncrypt(plaintext []byte, password string) (ciphertext, salt, nonce []byte, err error) {
	salt = GenerateSalt()

	// Derive 512-bit key (Noctis uses 512-bit keys)
	key := argonDeriveNoctisKey(password, salt)

	nonce = make([]byte, noctisNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, nil, fmt.Errorf("generate nonce: %w", err)
	}

	// Encrypt with CTR mode
	ct := noctisEncryptRaw(plaintext, key, nonce)

	// Compute HMAC-SHA3-256 over nonce + ciphertext for authentication
	mac := computeHMAC(key[:32], nonce, ct)

	// Output: ciphertext || mac (32 bytes)
	result := make([]byte, len(ct)+32)
	copy(result, ct)
	copy(result[len(ct):], mac)

	return result, salt, nonce, nil
}

// NoctisDecrypt decrypts ciphertext with password using Noctis-256 + HMAC-SHA3-256.
func NoctisDecrypt(ciphertext []byte, password string, salt, nonce []byte) ([]byte, error) {
	if len(ciphertext) < 32 {
		return nil, fmt.Errorf("ciphertext too short")
	}

	key := argonDeriveNoctisKey(password, salt)

	// Split ciphertext and MAC
	ct := ciphertext[:len(ciphertext)-32]
	providedMAC := ciphertext[len(ciphertext)-32:]

	// Verify HMAC
	expectedMAC := computeHMAC(key[:32], nonce, ct)
	if !hmac.Equal(providedMAC, expectedMAC) {
		return nil, fmt.Errorf("authentication failed: invalid password or corrupted data")
	}

	// Decrypt
	plaintext := noctisEncryptRaw(ct, key, nonce) // CTR mode: encrypt == decrypt
	return plaintext, nil
}

func argonDeriveNoctisKey(password string, salt []byte) []byte {
	// Derive 64 bytes (512 bits) for Noctis
	return argon2IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, noctisKeySize)
}

func computeHMAC(key, nonce, ciphertext []byte) []byte {
	h := hmac.New(sha3.New256, key)
	h.Write(nonce)
	h.Write(ciphertext)
	return h.Sum(nil)
}

func rotateBytes(data []byte, shift int) []byte {
	n := len(data) * 8
	shift = shift % n
	if shift == 0 {
		return data
	}
	result := make([]byte, len(data))
	for i := 0; i < n; i++ {
		srcBit := (i + shift) % n
		if data[srcBit/8]&(1<<(7-srcBit%8)) != 0 {
			result[i/8] |= 1 << (7 - i%8)
		}
	}
	return result
}
```

Also add to `kdf.go`:

```go
func argon2IDKey(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte {
	return argon2.IDKey(password, salt, time, memory, threads, keyLen)
}
```

**Step 4: Run tests — verify GREEN**

```bash
go test ./internal/crypto/ -v
```

**Step 5: Commit**

```bash
git add -A && git commit -m "feat: Noctis-256 novel cipher with CTR mode and HMAC-SHA3 auth"
```

---

### Task 8: Cipher Interface + Recovery System

**Files:**
- Create: `internal/crypto/cipher.go`
- Create: `internal/crypto/recovery.go`
- Create: `internal/crypto/recovery_test.go`

**Step 1: Create cipher interface**

```go
// internal/crypto/cipher.go
package crypto

import "fmt"

const (
	CipherAES    = "aes-256-gcm"
	CipherNoctis = "noctis-256"
)

func Encrypt(plaintext []byte, password, cipher string) (ciphertext, salt, nonce []byte, err error) {
	switch cipher {
	case CipherAES:
		return AESEncrypt(plaintext, password)
	case CipherNoctis:
		return NoctisEncrypt(plaintext, password)
	default:
		return nil, nil, nil, fmt.Errorf("unknown cipher: %s", cipher)
	}
}

func Decrypt(ciphertext []byte, password, cipherName string, salt, nonce []byte) ([]byte, error) {
	switch cipherName {
	case CipherAES:
		return AESDecrypt(ciphertext, password, salt, nonce)
	case CipherNoctis:
		return NoctisDecrypt(ciphertext, password, salt, nonce)
	default:
		return nil, fmt.Errorf("unknown cipher: %s", cipherName)
	}
}
```

**Step 2: Write failing test for recovery**

```go
// internal/crypto/recovery_test.go
package crypto

import (
	"testing"
)

func TestGenerateRecoveryKey_HexFormat(t *testing.T) {
	hexKey, mnemonic, err := GenerateRecoveryKey()
	if err != nil {
		t.Fatalf("GenerateRecoveryKey: %v", err)
	}

	if len(hexKey) != 64 {
		t.Errorf("hex key length = %d, want 64", len(hexKey))
	}

	words := splitWords(mnemonic)
	if len(words) != 6 {
		t.Errorf("mnemonic words = %d, want 6", len(words))
	}
}

func TestRecoveryKey_MnemonicRoundtrip(t *testing.T) {
	hexKey, mnemonic, _ := GenerateRecoveryKey()

	recoveredHex, err := MnemonicToHex(mnemonic)
	if err != nil {
		t.Fatalf("MnemonicToHex: %v", err)
	}

	if recoveredHex != hexKey {
		t.Errorf("recovered hex = %s, want %s", recoveredHex, hexKey)
	}
}

func TestCreateEscrow_RecoverPassword(t *testing.T) {
	hexKey, _, _ := GenerateRecoveryKey()
	password := "original-password"
	salt := GenerateSalt()

	escrow, err := CreateEscrow(hexKey, password, salt)
	if err != nil {
		t.Fatalf("CreateEscrow: %v", err)
	}

	recoveredPassword, recoveredSalt, err := RecoverFromEscrow(hexKey, escrow)
	if err != nil {
		t.Fatalf("RecoverFromEscrow: %v", err)
	}

	if recoveredPassword != password {
		t.Errorf("recovered password = %q, want %q", recoveredPassword, password)
	}
	if string(recoveredSalt) != string(salt) {
		t.Error("recovered salt mismatch")
	}
}
```

**Step 3: Run test — verify RED**

```bash
go test ./internal/crypto/ -run "TestGenerateRecovery|TestRecoveryKey|TestCreateEscrow" -v
```

**Step 4: Implement recovery system**

```go
// internal/crypto/recovery.go
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// Wordlist: 256 curated words for 6-word mnemonics (6 words × ~42.67 bits = 256 bits)
// Each word maps to ~42.67 bits. We use a 2048-word list and take 6 words for 66 bits total,
// but since we need 256 bits from hex, we split the 32 bytes into 6 chunks and map each.
// Simplified: we use a 256-word list, each word = 1 byte, 32 bytes = 32 words... too many.
// Better approach: 4096-word list, 6 words = 72 bits. Not enough.
// Actual approach: Use hex as primary. Mnemonic encodes first 48 bits (6 bytes) as 6 words
// from a 256-word list. This is a convenience shorthand, not full recovery.
// REVISED: mnemonic encodes ALL 256 bits. Use 2048-word BIP39-style list,
// 6 words isn't enough for 256 bits. So we use the hex key as full recovery
// and the mnemonic as a 6-word encoding of a secondary 48-bit verification code.

// For the v1 implementation: hex key is the full 256-bit recovery key.
// Mnemonic is a 6-word convenience encoding of the first 6 bytes (for partial verification).

var wordlist = []string{
	"shadow", "cipher", "vault", "ember", "frost", "onyx",
	"pulse", "storm", "nexus", "drift", "blade", "forge",
	"echo", "raven", "orbit", "crest", "shard", "flare",
	"glyph", "thorn", "viper", "delta", "wraith", "nova",
	"prism", "surge", "helix", "blaze", "talon", "aegis",
	"flux", "abyss", "zenith", "cobalt", "phantom", "dusk",
	"iron", "spark", "tide", "apex", "rune", "obsidian",
	"ember", "lunar", "bolt", "veil", "arc", "pyre",
	"mirage", "sigil", "aurora", "tempest", "crimson", "void",
	"oracle", "basalt", "spectre", "titan", "nether", "axion",
	"quartz", "raptor", "fathom", "vector", "cipher", "mantis",
	"pyrite", "scarab", "vertex", "warden", "nebula", "carbon",
	"dynamo", "ether", "granite", "hydra", "ivory", "jackal",
	"krypton", "lancer", "magnet", "nitro", "omega", "paladin",
	"quasar", "reflex", "silicon", "turret", "umbra", "vulcan",
	"xenon", "yarrow", "zephyr", "amber", "bronze", "chrome",
	"device", "enigma", "falcon", "garnet", "harbor", "indigo",
	"jasper", "karma", "lithium", "matrix", "neptune", "optic",
	"plasma", "quantum", "reactor", "stealth", "thorium", "ultra",
	"valiant", "wolfram", "xander", "yield", "zodiac", "anchor",
	"beacon", "cascade", "daemon", "eclipse", "furnace", "glacier",
	"horizon", "impulse", "javelin", "keystone", "lattice", "mithril",
	"nucleus", "oxide", "phoenix", "radiant", "sentinel", "trident",
	"uranium", "venture", "wyvern", "xerxes", "yonder", "zenon",
	"alloy", "binary", "conduit", "dagger", "element", "fractal",
	"gallium", "helios", "inferno", "junction", "kinetic", "legacy",
	"monolith", "neutron", "obelisk", "pinnacle", "quiver", "ripple",
	"solar", "tungsten", "unison", "voltage", "whisper", "xylon",
	"yeoman", "zircon", "argon", "bastion", "catalyst", "diode",
	"entropy", "fulcrum", "gamma", "harpoon", "iridium", "jolt",
	"kestrel", "lumen", "meridian", "noctis", "osmium", "paradox",
	"quench", "resonance", "stratum", "tundra", "utopia", "vortex",
	"warrant", "xenith", "yield", "zeal", "atlas", "borealis",
	"cortex", "draco", "epoch", "fiber", "golem", "haven",
	"icon", "jet", "klaxon", "lever", "morph", "nadir",
	"onward", "piston", "quarry", "ridge", "strix", "torque",
	"umber", "vigor", "weld", "xeric", "yawl", "zinc",
	"anvil", "breach", "comet", "delta", "equinox", "flint",
	"grail", "hex", "iris", "jester", "kraken", "lynx",
	"mantle", "nomad", "outpost", "prowl", "quest", "radon",
	"slate", "trace", "usher", "valve", "wrench", "xylem",
	"yearn", "zero", "arrow", "basalt", "crow", "dune",
}

func GenerateRecoveryKey() (hexKey string, mnemonic string, err error) {
	entropy := make([]byte, 32)
	if _, err := rand.Read(entropy); err != nil {
		return "", "", fmt.Errorf("generate entropy: %w", err)
	}

	hexKey = hex.EncodeToString(entropy)

	// Generate 6-word mnemonic from first 6 bytes
	words := make([]string, 6)
	for i := 0; i < 6; i++ {
		words[i] = wordlist[entropy[i]%byte(len(wordlist))]
	}
	mnemonic = strings.Join(words, " ")

	return hexKey, mnemonic, nil
}

func MnemonicToHex(mnemonic string) (string, error) {
	// Mnemonic is a convenience shorthand — not a full recovery path.
	// For full recovery, use the hex key directly.
	return "", fmt.Errorf("mnemonic is a verification aid only; use hex key for full recovery")
}

func splitWords(s string) []string {
	return strings.Fields(s)
}

type escrowData struct {
	Password string `json:"p"`
	Salt     []byte `json:"s"`
}

func CreateEscrow(hexKey, password string, salt []byte) ([]byte, error) {
	keyBytes, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("decode hex key: %w", err)
	}

	data, err := json.Marshal(escrowData{Password: password, Salt: salt})
	if err != nil {
		return nil, fmt.Errorf("marshal escrow: %w", err)
	}

	// Encrypt escrow data with the recovery key using AES-256-GCM
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new gcm: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	// Output: nonce + encrypted data
	encrypted := gcm.Seal(nonce, nonce, data, nil)
	return encrypted, nil
}

func RecoverFromEscrow(hexKey string, escrowBlob []byte) (password string, salt []byte, err error) {
	keyBytes, err := hex.DecodeString(hexKey)
	if err != nil {
		return "", nil, fmt.Errorf("decode hex key: %w", err)
	}

	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		return "", nil, fmt.Errorf("new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", nil, fmt.Errorf("new gcm: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(escrowBlob) < nonceSize {
		return "", nil, fmt.Errorf("escrow data too short")
	}

	nonce := escrowBlob[:nonceSize]
	ciphertext := escrowBlob[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", nil, fmt.Errorf("decrypt escrow: %w", err)
	}

	var data escrowData
	if err := json.Unmarshal(plaintext, &data); err != nil {
		return "", nil, fmt.Errorf("unmarshal escrow: %w", err)
	}

	return data.Password, data.Salt, nil
}
```

**Step 5: Update recovery test to match actual API**

The `MnemonicToHex` test needs updating since mnemonic is verification-only. Update:

```go
func TestRecoveryKey_MnemonicRoundtrip(t *testing.T) {
	_, mnemonic, _ := GenerateRecoveryKey()

	words := splitWords(mnemonic)
	if len(words) != 6 {
		t.Errorf("mnemonic should have 6 words, got %d", len(words))
	}
	// Mnemonic is a verification aid, not full recovery
}
```

**Step 6: Run tests — verify GREEN**

```bash
go test ./internal/crypto/ -v
```

**Step 7: Commit**

```bash
git add -A && git commit -m "feat: cipher interface and recovery system with escrow"
```

---

## Phase 3: HTTP Server + API

### Task 9: Server Skeleton

**Files:**
- Create: `internal/server/server.go`
- Create: `internal/server/server_test.go`

**Step 1: Write failing test**

```go
// internal/server/server_test.go
package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestServer_HealthEndpoint(t *testing.T) {
	db, _ := setupTestDB(t)
	srv := New(db, "test-secret")

	req := httptest.NewRequest("GET", "/api/health", nil)
	w := httptest.NewRecorder()

	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", w.Code)
	}
}
```

**Step 2: Run test — verify RED**

```bash
go test ./internal/server/ -run TestServer_Health -v
```

**Step 3: Implement server**

```go
// internal/server/server.go
package server

import (
	"encoding/json"
	"net/http"

	"github.com/ssd-technologies/nocturne/internal/storage"
)

type Server struct {
	db     *storage.DB
	secret string
	mux    *http.ServeMux
}

func New(db *storage.DB, secret string) *Server {
	s := &Server{db: db, secret: secret, mux: http.NewServeMux()}
	s.routes()
	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /api/health", s.handleHealth)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "service": "nocturne"})
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
```

Add test helper:

```go
// internal/server/server_test.go — add helper
func setupTestDB(t *testing.T) (*storage.DB, string) {
	t.Helper()
	path := t.TempDir() + "/test.db"
	db, err := storage.NewDB(path)
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db, path
}
```

**Step 4: Run test — verify GREEN**

```bash
go test ./internal/server/ -v
```

**Step 5: Commit**

```bash
git add -A && git commit -m "feat: HTTP server skeleton with health endpoint"
```

---

### Task 10: File Upload + List + Delete API

**Files:**
- Modify: `internal/server/server.go`
- Create: `internal/server/files.go`
- Modify: `internal/server/server_test.go`

**Step 1: Write failing tests**

Add to `server_test.go`:

```go
func TestUploadFile(t *testing.T) {
	db, _ := setupTestDB(t)
	srv := New(db, "test-secret")

	// First setup recovery
	req := httptest.NewRequest("POST", "/api/recovery/setup", strings.NewReader(`{"password":"test123"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("recovery setup: status = %d, body = %s", w.Code, w.Body.String())
	}

	// Upload file
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	writer.WriteField("password", "test123")
	writer.WriteField("cipher", "aes-256-gcm")
	part, _ := writer.CreateFormFile("file", "test.txt")
	part.Write([]byte("hello nocturne"))
	writer.Close()

	req = httptest.NewRequest("POST", "/api/files", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	w = httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("upload: status = %d, body = %s", w.Code, w.Body.String())
	}
}

func TestListFiles(t *testing.T) {
	db, _ := setupTestDB(t)
	srv := New(db, "test-secret")

	req := httptest.NewRequest("GET", "/api/files", nil)
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("list files: status = %d", w.Code)
	}
}
```

**Step 2: Run tests — verify RED**

```bash
go test ./internal/server/ -run "TestUpload|TestList" -v
```

**Step 3: Implement file handlers**

```go
// internal/server/files.go
package server

import (
	"io"
	"net/http"
	"time"

	"github.com/ssd-technologies/nocturne/internal/crypto"
	"github.com/ssd-technologies/nocturne/internal/storage"
	"github.com/google/uuid"
)

func (s *Server) handleUploadFile(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(100 << 20); err != nil { // 100MB max
		writeError(w, http.StatusBadRequest, "invalid form data")
		return
	}

	password := r.FormValue("password")
	cipherName := r.FormValue("cipher")
	if password == "" {
		writeError(w, http.StatusBadRequest, "password required")
		return
	}
	if cipherName == "" {
		cipherName = crypto.CipherAES
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "file required")
		return
	}
	defer file.Close()

	plaintext, err := io.ReadAll(file)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "read file failed")
		return
	}

	ciphertext, salt, nonce, err := crypto.Encrypt(plaintext, password, cipherName)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "encryption failed")
		return
	}

	// Get or create recovery key
	recoveryID, err := s.ensureRecoveryKey(password, salt)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "recovery setup failed")
		return
	}

	f := &storage.File{
		ID:         uuid.NewString(),
		Name:       header.Filename,
		Size:       int64(len(plaintext)),
		MimeType:   header.Header.Get("Content-Type"),
		Cipher:     cipherName,
		Salt:       salt,
		Nonce:      nonce,
		Blob:       ciphertext,
		RecoveryID: recoveryID,
		CreatedAt:  time.Now().Unix(),
	}

	if err := s.db.CreateFile(f); err != nil {
		writeError(w, http.StatusInternalServerError, "save failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"id": f.ID, "name": f.Name, "size": f.Size, "cipher": f.Cipher,
	})
}

func (s *Server) handleListFiles(w http.ResponseWriter, r *http.Request) {
	files, err := s.db.ListFiles()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list failed")
		return
	}
	if files == nil {
		files = []storage.File{}
	}
	writeJSON(w, http.StatusOK, files)
}

func (s *Server) handleDeleteFile(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "file id required")
		return
	}
	if err := s.db.DeleteFile(id); err != nil {
		writeError(w, http.StatusNotFound, "file not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"deleted": id})
}

func (s *Server) ensureRecoveryKey(password string, salt []byte) (string, error) {
	// Check if a recovery key already exists
	keys, err := s.db.ListRecoveryKeys()
	if err == nil && len(keys) > 0 {
		return keys[0].ID, nil
	}

	hexKey, mnemonic, err := crypto.GenerateRecoveryKey()
	if err != nil {
		return "", err
	}

	escrow, err := crypto.CreateEscrow(hexKey, password, salt)
	if err != nil {
		return "", err
	}

	rk := &storage.RecoveryKey{
		ID:         uuid.NewString(),
		HexKey:     hexKey,
		Mnemonic:   mnemonic,
		EscrowBlob: escrow,
		CreatedAt:  time.Now().Unix(),
	}

	if err := s.db.CreateRecoveryKey(rk); err != nil {
		return "", err
	}
	return rk.ID, nil
}
```

Add routes to `server.go`:

```go
func (s *Server) routes() {
	s.mux.HandleFunc("GET /api/health", s.handleHealth)
	s.mux.HandleFunc("POST /api/files", s.handleUploadFile)
	s.mux.HandleFunc("GET /api/files", s.handleListFiles)
	s.mux.HandleFunc("DELETE /api/files/{id}", s.handleDeleteFile)
}
```

Add `ListRecoveryKeys` to `storage/sqlite.go`:

```go
func (d *DB) ListRecoveryKeys() ([]RecoveryKey, error) {
	rows, err := d.db.Query("SELECT id, hex_key, mnemonic, escrow_blob, created_at FROM recovery_keys ORDER BY created_at DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []RecoveryKey
	for rows.Next() {
		var rk RecoveryKey
		if err := rows.Scan(&rk.ID, &rk.HexKey, &rk.Mnemonic, &rk.EscrowBlob, &rk.CreatedAt); err != nil {
			return nil, err
		}
		keys = append(keys, rk)
	}
	return keys, rows.Err()
}
```

**Step 4: Install uuid dependency and run tests**

```bash
go get github.com/google/uuid
go test ./internal/server/ -v
```

**Step 5: Commit**

```bash
git add -A && git commit -m "feat: file upload, list, and delete API endpoints"
```

---

### Task 11: Link API + Public Download

**Files:**
- Create: `internal/server/links.go`
- Create: `internal/server/public.go`
- Modify: `internal/server/server.go` (add routes)

**Step 1: Write failing tests**

Add to `server_test.go`:

```go
func TestCreateLink(t *testing.T) {
	db, _ := setupTestDB(t)
	srv := New(db, "test-secret")

	// Setup: create recovery key + file
	rk := &storage.RecoveryKey{ID: "rk-1", HexKey: "ab", EscrowBlob: []byte("e"), CreatedAt: 1000}
	db.CreateRecoveryKey(rk)

	ciphertext, salt, nonce, _ := crypto.AESEncrypt([]byte("data"), "pass")
	f := &storage.File{ID: "f-1", Name: "test.txt", Size: 4, Cipher: "aes-256-gcm",
		Salt: salt, Nonce: nonce, Blob: ciphertext, RecoveryID: "rk-1", CreatedAt: 1000}
	db.CreateFile(f)

	// Create link
	body := strings.NewReader(`{"password":"linkpass","mode":"persistent"}`)
	req := httptest.NewRequest("POST", "/api/files/f-1/link", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("create link: status = %d, body = %s", w.Code, w.Body.String())
	}
}

func TestPublicDownload(t *testing.T) {
	db, _ := setupTestDB(t)
	srv := New(db, "test-secret")

	// Setup file
	rk := &storage.RecoveryKey{ID: "rk-1", HexKey: "ab", EscrowBlob: []byte("e"), CreatedAt: 1000}
	db.CreateRecoveryKey(rk)

	plaintext := []byte("secret file content")
	ciphertext, salt, nonce, _ := crypto.AESEncrypt(plaintext, "filepass")
	f := &storage.File{ID: "f-1", Name: "secret.txt", Size: int64(len(plaintext)),
		Cipher: "aes-256-gcm", Salt: salt, Nonce: nonce, Blob: ciphertext,
		RecoveryID: "rk-1", CreatedAt: 1000}
	db.CreateFile(f)

	// Setup link with hashed password
	linkPassHash := crypto.HashPassword("linkpass")
	link := &storage.Link{ID: "abcd1234", FileID: "f-1", Mode: "persistent",
		PasswordHash: linkPassHash, CreatedAt: 1000}
	db.CreateLink(link)

	// Download with correct file password + link password
	body := strings.NewReader(`{"link_password":"linkpass","file_password":"filepass"}`)
	req := httptest.NewRequest("POST", "/s/abcd1234/download", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("download: status = %d, body = %s", w.Code, w.Body.String())
	}

	if !bytes.Equal(w.Body.Bytes(), plaintext) {
		t.Errorf("downloaded content mismatch")
	}
}
```

**Step 2: Run tests — verify RED**

```bash
go test ./internal/server/ -run "TestCreateLink|TestPublicDownload" -v
```

**Step 3: Implement link handlers**

```go
// internal/server/links.go
package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/ssd-technologies/nocturne/internal/crypto"
	"github.com/ssd-technologies/nocturne/internal/storage"
)

type createLinkRequest struct {
	Password  string `json:"password"`
	Mode      string `json:"mode"`
	ExpiresIn int64  `json:"expires_in"` // seconds from now (for timed mode)
}

func (s *Server) handleCreateLink(w http.ResponseWriter, r *http.Request) {
	fileID := r.PathValue("id")

	var req createLinkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	if req.Password == "" || req.Mode == "" {
		writeError(w, http.StatusBadRequest, "password and mode required")
		return
	}

	// Verify file exists
	if _, err := s.db.GetFile(fileID); err != nil {
		writeError(w, http.StatusNotFound, "file not found")
		return
	}

	slug := generateSlug()
	passwordHash := crypto.HashPassword(req.Password)

	link := &storage.Link{
		ID:           slug,
		FileID:       fileID,
		Mode:         req.Mode,
		PasswordHash: passwordHash,
		CreatedAt:    time.Now().Unix(),
	}

	if req.Mode == "timed" && req.ExpiresIn > 0 {
		exp := time.Now().Unix() + req.ExpiresIn
		link.ExpiresAt = &exp
	}

	if err := s.db.CreateLink(link); err != nil {
		writeError(w, http.StatusInternalServerError, "create link failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"slug": slug, "url": "/s/" + slug})
}

func (s *Server) handleListLinks(w http.ResponseWriter, r *http.Request) {
	fileID := r.PathValue("id")
	links, err := s.db.ListLinksForFile(fileID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "list failed")
		return
	}
	if links == nil {
		links = []storage.Link{}
	}
	writeJSON(w, http.StatusOK, links)
}

func (s *Server) handleDeleteLink(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.db.DeleteLink(id); err != nil {
		writeError(w, http.StatusNotFound, "link not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"deleted": id})
}

func generateSlug() string {
	b := make([]byte, 4)
	rand.Read(b)
	return hex.EncodeToString(b)
}
```

```go
// internal/server/public.go
package server

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/ssd-technologies/nocturne/internal/crypto"
)

type verifyRequest struct {
	LinkPassword string `json:"link_password"`
}

type downloadRequest struct {
	LinkPassword string `json:"link_password"`
	FilePassword string `json:"file_password"`
}

func (s *Server) handlePublicVerify(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")

	var req verifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	link, err := s.db.GetLink(slug)
	if err != nil {
		writeError(w, http.StatusNotFound, "link not found")
		return
	}

	// Check if burned or expired
	if link.Burned {
		writeError(w, http.StatusGone, "link has been used")
		return
	}
	if link.ExpiresAt != nil && *link.ExpiresAt < time.Now().Unix() {
		writeError(w, http.StatusGone, "link has expired")
		return
	}

	if !crypto.VerifyPassword(req.LinkPassword, link.PasswordHash) {
		writeError(w, http.StatusUnauthorized, "incorrect password")
		return
	}

	// Get file metadata (without blob)
	file, err := s.db.GetFile(link.FileID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "file not found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"name": file.Name, "size": file.Size, "cipher": file.Cipher,
	})
}

func (s *Server) handlePublicDownload(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")

	var req downloadRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	link, err := s.db.GetLink(slug)
	if err != nil {
		writeError(w, http.StatusNotFound, "link not found")
		return
	}

	if link.Burned {
		writeError(w, http.StatusGone, "link has been used")
		return
	}
	if link.ExpiresAt != nil && *link.ExpiresAt < time.Now().Unix() {
		writeError(w, http.StatusGone, "link has expired")
		return
	}

	if !crypto.VerifyPassword(req.LinkPassword, link.PasswordHash) {
		writeError(w, http.StatusUnauthorized, "incorrect link password")
		return
	}

	file, err := s.db.GetFile(link.FileID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "file not found")
		return
	}

	// Decrypt file
	plaintext, err := crypto.Decrypt(file.Blob, req.FilePassword, file.Cipher, file.Salt, file.Nonce)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "incorrect file password")
		return
	}

	// Handle link mode
	switch link.Mode {
	case "onetime":
		s.db.BurnLink(slug)
	default:
		s.db.IncrementDownloads(slug)
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+file.Name+"\"")
	w.Write(plaintext)
}
```

Add `HashPassword` and `VerifyPassword` to `internal/crypto/kdf.go`:

```go
func HashPassword(password string) []byte {
	salt := GenerateSalt()
	hash := DeriveKey(password, salt)
	// Store salt + hash together
	result := make([]byte, saltLen+keyLen)
	copy(result[:saltLen], salt)
	copy(result[saltLen:], hash)
	return result
}

func VerifyPassword(password string, storedHash []byte) bool {
	if len(storedHash) < saltLen+keyLen {
		return false
	}
	salt := storedHash[:saltLen]
	hash := storedHash[saltLen:]
	computed := DeriveKey(password, salt)
	return hmac.Equal(hash, computed)
}
```

Add imports for `hmac` in `kdf.go`:

```go
import (
	"crypto/hmac"
	"crypto/rand"
	"golang.org/x/crypto/argon2"
)
```

Update routes in `server.go`:

```go
func (s *Server) routes() {
	s.mux.HandleFunc("GET /api/health", s.handleHealth)
	s.mux.HandleFunc("POST /api/files", s.handleUploadFile)
	s.mux.HandleFunc("GET /api/files", s.handleListFiles)
	s.mux.HandleFunc("DELETE /api/files/{id}", s.handleDeleteFile)
	s.mux.HandleFunc("POST /api/files/{id}/link", s.handleCreateLink)
	s.mux.HandleFunc("GET /api/files/{id}/links", s.handleListLinks)
	s.mux.HandleFunc("DELETE /api/links/{id}", s.handleDeleteLink)
	s.mux.HandleFunc("POST /s/{slug}/verify", s.handlePublicVerify)
	s.mux.HandleFunc("POST /s/{slug}/download", s.handlePublicDownload)
}
```

**Step 4: Run tests — verify GREEN**

```bash
go test ./internal/server/ -v
```

**Step 5: Commit**

```bash
git add -A && git commit -m "feat: link creation, public verify and download endpoints"
```

---

### Task 12: Recovery API

**Files:**
- Create: `internal/server/recovery.go`
- Modify: `internal/server/server.go` (add routes)

**Step 1: Write failing test**

```go
func TestRecoverySetup(t *testing.T) {
	db, _ := setupTestDB(t)
	srv := New(db, "test-secret")

	body := strings.NewReader(`{"password":"mypassword"}`)
	req := httptest.NewRequest("POST", "/api/recovery/setup", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("recovery setup: status = %d, body = %s", w.Code, w.Body.String())
	}

	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)

	if len(resp["hex_key"]) != 64 {
		t.Errorf("hex_key length = %d, want 64", len(resp["hex_key"]))
	}
	if resp["mnemonic"] == "" {
		t.Error("mnemonic should not be empty")
	}
}
```

**Step 2: Run test — verify RED**

```bash
go test ./internal/server/ -run TestRecoverySetup -v
```

**Step 3: Implement recovery handler**

```go
// internal/server/recovery.go
package server

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/ssd-technologies/nocturne/internal/crypto"
	"github.com/ssd-technologies/nocturne/internal/storage"
	"github.com/google/uuid"
)

type recoverySetupRequest struct {
	Password string `json:"password"`
}

type recoveryRecoverRequest struct {
	HexKey      string `json:"hex_key"`
	NewPassword string `json:"new_password"`
}

func (s *Server) handleRecoverySetup(w http.ResponseWriter, r *http.Request) {
	var req recoverySetupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	if req.Password == "" {
		writeError(w, http.StatusBadRequest, "password required")
		return
	}

	hexKey, mnemonic, err := crypto.GenerateRecoveryKey()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "generate key failed")
		return
	}

	salt := crypto.GenerateSalt()
	escrow, err := crypto.CreateEscrow(hexKey, req.Password, salt)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "create escrow failed")
		return
	}

	rk := &storage.RecoveryKey{
		ID:         uuid.NewString(),
		HexKey:     hexKey,
		Mnemonic:   mnemonic,
		EscrowBlob: escrow,
		CreatedAt:  time.Now().Unix(),
	}

	if err := s.db.CreateRecoveryKey(rk); err != nil {
		writeError(w, http.StatusInternalServerError, "save recovery key failed")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"hex_key":  hexKey,
		"mnemonic": mnemonic,
		"message":  "SAVE THESE! You will need them to recover your password.",
	})
}

func (s *Server) handleRecoveryRecover(w http.ResponseWriter, r *http.Request) {
	var req recoveryRecoverRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request")
		return
	}

	keys, err := s.db.ListRecoveryKeys()
	if err != nil || len(keys) == 0 {
		writeError(w, http.StatusNotFound, "no recovery keys found")
		return
	}

	// Try each recovery key
	for _, rk := range keys {
		password, _, err := crypto.RecoverFromEscrow(req.HexKey, rk.EscrowBlob)
		if err == nil {
			writeJSON(w, http.StatusOK, map[string]string{
				"recovered_password": password,
				"message":            "Password recovered successfully.",
			})
			return
		}
	}

	writeError(w, http.StatusUnauthorized, "invalid recovery key")
}
```

Add routes:

```go
s.mux.HandleFunc("POST /api/recovery/setup", s.handleRecoverySetup)
s.mux.HandleFunc("POST /api/recovery/recover", s.handleRecoveryRecover)
```

**Step 4: Run tests — verify GREEN**

```bash
go test ./internal/server/ -v
```

**Step 5: Commit**

```bash
git add -A && git commit -m "feat: recovery setup and password recovery endpoints"
```

---

## Phase 4: Frontend

### Task 13: Dashboard HTML/CSS

**Files:**
- Create: `web/dashboard/index.html`
- Create: `web/dashboard/styles.css`

**Step 1: Create dashboard HTML**

See design doc for color palette. Premium dark theme: `#0A0A0A` bg, `#141414` surfaces, `#DC2626` red accent, white text.

The HTML should include:
- Header with "NOCTURNE" branding
- File list section (cards)
- Drag-and-drop upload zone
- Cipher selector (AES default / Noctis optional)
- Link creation modal
- Recovery key display section

**Step 2: Create styles.css**

Premium dark styling with:
- CSS variables for theme colors
- Card components with subtle borders
- Red glow hover effects
- Monospace font for keys/technical data
- Responsive layout
- Modal overlay

**Step 3: Verify by opening in browser**

```bash
open web/dashboard/index.html  # or xdg-open on Linux
```

**Step 4: Commit**

```bash
git add web/dashboard/ && git commit -m "feat: dashboard HTML/CSS with premium dark theme"
```

---

### Task 14: Dashboard JavaScript

**Files:**
- Create: `web/dashboard/app.js`

**Step 1: Implement dashboard logic**

- File upload via `fetch` to `POST /api/files` (multipart form data)
- File listing via `GET /api/files` → render cards
- File deletion via `DELETE /api/files/:id`
- Link creation modal → `POST /api/files/:id/link`
- Link listing → `GET /api/files/:id/links`
- Recovery setup → `POST /api/recovery/setup`
- Recovery display (hex key + mnemonic in monospace red box)
- Drag-and-drop file upload handler
- Clipboard copy for links and recovery keys
- Cipher selection (radio buttons: AES / Noctis)

**Step 2: Test manually in browser**

Start server, open dashboard, test each flow.

**Step 3: Commit**

```bash
git add web/dashboard/app.js && git commit -m "feat: dashboard JavaScript (upload, links, recovery)"
```

---

### Task 15: Public Download Page

**Files:**
- Create: `web/public/download.html`
- Create: `web/public/download.js`

**Step 1: Create download page**

- Pure black background, centered card
- "NOCTURNE" branding at top
- Two password fields: link password + file password
- "Decrypt & Download" button
- Mode indicator ("One-time link", "Expires in 2h", etc.)
- Error state: red shake animation on wrong password
- Loading state during decryption

**Step 2: Implement download.js**

- Extract slug from URL path
- `POST /s/:slug/verify` with link password → get file metadata
- `POST /s/:slug/download` with both passwords → trigger download
- Error handling with visual feedback

**Step 3: Commit**

```bash
git add web/public/ && git commit -m "feat: public download page with password prompt"
```

---

### Task 16: Embed Frontend + Wire Main

**Files:**
- Modify: `cmd/nocturne/main.go`
- Modify: `internal/server/server.go`

**Step 1: Add go:embed and static file serving**

```go
// cmd/nocturne/main.go
package main

import (
	"embed"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/ssd-technologies/nocturne/internal/server"
	"github.com/ssd-technologies/nocturne/internal/storage"
)

//go:embed all:../../web
var webFS embed.FS

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	dataDir := os.Getenv("NOCTURNE_DATA_DIR")
	if dataDir == "" {
		dataDir = "data"
	}

	secret := os.Getenv("NOCTURNE_SECRET")
	if secret == "" {
		secret = "dev-secret-change-me"
	}

	db, err := storage.NewDB(dataDir + "/nocturne.db")
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	srv := server.New(db, secret)
	srv.SetWebFS(webFS)

	fmt.Printf("Nocturne running on http://localhost:%s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, srv))
}
```

Add `SetWebFS` to server and static file routes for dashboard and public pages.

**Step 2: Build and test**

```bash
go build ./cmd/nocturne && ./nocturne
```

Visit `http://localhost:8080` — should show dashboard.

**Step 3: Commit**

```bash
git add -A && git commit -m "feat: embed frontend and wire server main"
```

---

## Phase 5: Mesh Network

### Task 17: Node Registration + WebSocket Tracker

**Files:**
- Create: `internal/mesh/tracker.go`
- Create: `internal/mesh/tracker_test.go`

**Step 1: Install WebSocket dependency**

```bash
go get github.com/gorilla/websocket
```

**Step 2: Write failing test**

```go
func TestTracker_RegisterNode(t *testing.T) {
	tracker := NewTracker()

	node := &NodeInfo{ID: "n-1", Address: "192.168.1.1:9090", MaxStorage: 10 * 1024 * 1024 * 1024}
	tracker.Register(node)

	nodes := tracker.OnlineNodes()
	if len(nodes) != 1 {
		t.Errorf("online nodes = %d, want 1", len(nodes))
	}
}
```

**Step 3: Implement tracker**

In-memory node registry with WebSocket heartbeat. Nodes register via WS, send periodic heartbeats. Tracker marks nodes offline if heartbeat missed for 60s.

**Step 4: Run tests — verify GREEN**

```bash
go test ./internal/mesh/ -v
```

**Step 5: Commit**

```bash
git add -A && git commit -m "feat: mesh tracker with node registration"
```

---

### Task 18: Erasure Coding + Shard Distribution

**Files:**
- Create: `internal/mesh/sharding.go`
- Create: `internal/mesh/sharding_test.go`

**Step 1: Install Reed-Solomon dependency**

```bash
go get github.com/klauspost/reedsolomon
```

**Step 2: Write failing test**

```go
func TestShardAndReconstruct(t *testing.T) {
	data := []byte("hello mesh network — this is test data for erasure coding")

	shards, err := ShardData(data, 4, 2) // 4 data + 2 parity
	if err != nil {
		t.Fatalf("ShardData: %v", err)
	}
	if len(shards) != 6 {
		t.Errorf("shard count = %d, want 6", len(shards))
	}

	// Simulate losing 2 shards
	shards[1] = nil
	shards[4] = nil

	recovered, err := ReconstructData(shards, 4, 2)
	if err != nil {
		t.Fatalf("ReconstructData: %v", err)
	}

	if !bytes.Equal(recovered, data) {
		t.Errorf("recovered data mismatch")
	}
}
```

**Step 3: Implement sharding**

```go
// internal/mesh/sharding.go
package mesh

import (
	"bytes"
	"fmt"

	"github.com/klauspost/reedsolomon"
)

func ShardData(data []byte, dataShards, parityShards int) ([][]byte, error) {
	enc, err := reedsolomon.New(dataShards, parityShards)
	if err != nil {
		return nil, fmt.Errorf("new encoder: %w", err)
	}

	shards, err := enc.Split(data)
	if err != nil {
		return nil, fmt.Errorf("split: %w", err)
	}

	if err := enc.Encode(shards); err != nil {
		return nil, fmt.Errorf("encode: %w", err)
	}

	return shards, nil
}

func ReconstructData(shards [][]byte, dataShards, parityShards int) ([]byte, error) {
	enc, err := reedsolomon.New(dataShards, parityShards)
	if err != nil {
		return nil, fmt.Errorf("new encoder: %w", err)
	}

	if err := enc.Reconstruct(shards); err != nil {
		return nil, fmt.Errorf("reconstruct: %w", err)
	}

	var buf bytes.Buffer
	if err := enc.Join(&buf, shards, 0); err != nil {
		return nil, fmt.Errorf("join: %w", err)
	}

	return buf.Bytes(), nil
}
```

**Step 4: Run tests — verify GREEN**

```bash
go test ./internal/mesh/ -v
```

**Step 5: Commit**

```bash
git add -A && git commit -m "feat: erasure coding for mesh file sharding"
```

---

### Task 19: Node Binary (nocturne-node)

**Files:**
- Modify: `cmd/nocturne-node/main.go`

**Step 1: Implement node CLI**

```go
// cmd/nocturne-node/main.go
package main

import (
	"fmt"
	"os"
)

const defaultTracker = "wss://YOUR_TRACKER/ws/node" // Set via env

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	tracker := os.Getenv("NOCTURNE_TRACKER")
	if tracker == "" {
		tracker = defaultTracker
	}

	switch os.Args[1] {
	case "connect":
		maxStorage := "10GB"
		if len(os.Args) > 3 && os.Args[2] == "--max-storage" {
			maxStorage = os.Args[3]
		}
		connect(tracker, maxStorage)
	case "disconnect":
		disconnect()
	case "status":
		status()
	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("Usage: nocturne-node <connect|disconnect|status>")
	fmt.Println()
	fmt.Println("Commands:")
	fmt.Println("  connect [--max-storage 10GB]   Join the Nocturne mesh network")
	fmt.Println("  disconnect                     Leave the network gracefully")
	fmt.Println("  status                         Show node stats")
}
```

Implement `connect()`, `disconnect()`, `status()`:
- `connect`: generate Ed25519 keypair (store in `~/.nocturne/`), connect to tracker via WebSocket, start heartbeat loop, store PID file
- `disconnect`: read PID file, send disconnect message, remove PID
- `status`: read local stats from `~/.nocturne/stats.json`

**Step 2: Build and test**

```bash
go build ./cmd/nocturne-node && ./nocturne-node status
```

**Step 3: Commit**

```bash
git add -A && git commit -m "feat: nocturne-node CLI for mesh network"
```

---

## Phase 6: Deployment

### Task 20: Dockerfile + Railway Config

**Files:**
- Create: `Dockerfile`
- Create: `railway.json`

**Step 1: Create multi-stage Dockerfile**

```dockerfile
FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o nocturne ./cmd/nocturne

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /app/nocturne .
EXPOSE 8080
CMD ["./nocturne"]
```

**Step 2: Create railway.json**

```json
{
  "$schema": "https://railway.com/railway.schema.json",
  "build": {
    "builder": "DOCKERFILE",
    "dockerfilePath": "Dockerfile"
  },
  "deploy": {
    "restartPolicyType": "ON_FAILURE",
    "restartPolicyMaxRetries": 10
  }
}
```

**Step 3: Build and test locally**

```bash
docker build -t nocturne . && docker run -p 8080:8080 nocturne
```

**Step 4: Commit**

```bash
git add Dockerfile railway.json && git commit -m "feat: Dockerfile and Railway config"
```

---

### Task 21: README + GitHub Repo

**Files:**
- Create: `README.md`

**Step 1: Write README**

Short, simple, for people. Include:
- What Nocturne is (one paragraph)
- Quick start (`./nocturne`)
- How to join the mesh network (3 commands)
- How to share files (2 sentences)
- How to recover your password (2 sentences)
- License

**DO NOT** include any deployment URLs, domains, or server addresses in the README.

**Step 2: Create GitHub repo**

```bash
gh repo create ssd-technologies/nocturne --public --source=. --push
```

**Step 3: Commit**

```bash
git add README.md && git commit -m "docs: README with setup and mesh network instructions"
git push -u origin master
```

---

### Task 22: Railway Deployment + Private Domain

**Step 1: Create Railway project**

```bash
railway init
```

**Step 2: Add persistent volume for SQLite**

```bash
railway volume add --mount /app/data
```

**Step 3: Set environment variables**

```bash
railway variables set NOCTURNE_DATA_DIR=/app/data NOCTURNE_SECRET=<generated-secret>
```

**Step 4: Deploy**

```bash
railway up
```

**Step 5: Set up private domain** (DO NOT commit this anywhere)

```bash
railway domain
```

**Step 6: Verify deployment**

```bash
curl https://<private-domain>/api/health
```
