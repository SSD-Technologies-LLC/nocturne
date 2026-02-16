# Phase 10: Remaining Security Fixes Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix the 6 remaining high-priority security issues from the code review.

**Architecture:** Each fix is an independent commit. Fixes 1-2 are trivial middleware/header changes. Fix 3 adds SQL transactions for multi-step deletes. Fix 4 adds CASCADE to FK constraints with a schema migration. Fix 5 adds versioned CAS to the DHT local store. Fix 6 adds per-peer rate limiting to WebSocket transport and mesh tracker, plus gossip fan-out limiting.

**Tech Stack:** Go 1.24, SQLite (modernc.org/sqlite), gorilla/websocket, stdlib `net/http`

---

### Task 1: Content-Disposition Header Injection Fix

**Files:**
- Modify: `internal/server/public.go:136-137`
- Test: `internal/server/server_test.go`

**Step 1: Write the failing test**

Add to `internal/server/server_test.go`:

```go
func TestPublicDownload_SanitizesFilename(t *testing.T) {
	srv := setupTestServer(t)

	// Upload a file with a malicious filename containing quotes and path traversal.
	result := uploadTestFile(t, srv, "../../etc/passwd\"\r\nX-Injected: true", "content", "filepass")
	fileID := result["id"].(string)

	linkResult := createTestLink(t, srv, fileID, "linkpass", "persistent")
	slug := linkResult["slug"].(string)

	body, _ := json.Marshal(map[string]string{
		"link_password": "linkpass",
		"file_password": "filepass",
	})
	req := httptest.NewRequest(http.MethodPost, "/s/"+slug+"/download", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	cd := rec.Header().Get("Content-Disposition")
	// Must not contain path traversal, quotes, or injected headers.
	if strings.Contains(cd, "..") {
		t.Errorf("Content-Disposition contains path traversal: %q", cd)
	}
	if strings.Contains(cd, "\r") || strings.Contains(cd, "\n") {
		t.Errorf("Content-Disposition contains newlines: %q", cd)
	}
	// The filename should be sanitized to just the base name without dangerous chars.
	if strings.Contains(cd, "etc/passwd") {
		t.Errorf("Content-Disposition contains unsanitized path: %q", cd)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `cd /home/mark-ssd/code/ssd.foundation/nocturne && go test ./internal/server/ -run TestPublicDownload_SanitizesFilename -v`
Expected: FAIL — Content-Disposition contains `../` and `\r\n`

**Step 3: Write minimal implementation**

In `internal/server/public.go`, add import `"path/filepath"` and `"strings"`, then add a `sanitizeFilename` function and use it:

```go
// sanitizeFilename removes path traversal, quotes, and control characters
// from a filename for safe use in Content-Disposition headers.
func sanitizeFilename(name string) string {
	// Strip directory traversal.
	name = filepath.Base(name)
	// Remove characters dangerous in HTTP headers.
	name = strings.NewReplacer(
		"\"", "",
		"\r", "",
		"\n", "",
	).Replace(name)
	if name == "" || name == "." {
		name = "download"
	}
	return name
}
```

Replace line 137:
```go
w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, sanitizeFilename(file.Name)))
```

**Step 4: Run test to verify it passes**

Run: `cd /home/mark-ssd/code/ssd.foundation/nocturne && go test ./internal/server/ -run TestPublicDownload -v`
Expected: ALL PASS (both existing and new test)

**Step 5: Run full test suite**

Run: `cd /home/mark-ssd/code/ssd.foundation/nocturne && go test ./...`
Expected: ALL PASS

**Step 6: Commit**

```bash
cd /home/mark-ssd/code/ssd.foundation/nocturne
git add internal/server/public.go internal/server/server_test.go
git commit -m "fix(server): sanitize Content-Disposition filename to prevent header injection"
```

---

### Task 2: Security Headers Middleware

**Files:**
- Modify: `internal/server/server.go:37-39` (ServeHTTP method)
- Test: `internal/server/server_test.go`

**Step 1: Write the failing test**

Add to `internal/server/server_test.go`:

```go
func TestSecurityHeaders(t *testing.T) {
	srv := setupTestServer(t)

	// Test on an unauthenticated endpoint (health).
	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	headers := map[string]string{
		"X-Frame-Options":        "DENY",
		"X-Content-Type-Options": "nosniff",
		"Referrer-Policy":        "strict-origin-when-cross-origin",
	}

	for name, want := range headers {
		got := rec.Header().Get(name)
		if got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}

	// CSP and HSTS should be present (exact values may vary).
	if csp := rec.Header().Get("Content-Security-Policy"); csp == "" {
		t.Error("Content-Security-Policy header is missing")
	}
	if hsts := rec.Header().Get("Strict-Transport-Security"); hsts == "" {
		t.Error("Strict-Transport-Security header is missing")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `cd /home/mark-ssd/code/ssd.foundation/nocturne && go test ./internal/server/ -run TestSecurityHeaders -v`
Expected: FAIL — headers are missing

**Step 3: Write minimal implementation**

In `internal/server/server.go`, modify `ServeHTTP`:

```go
// ServeHTTP implements http.Handler, injecting security headers on every response.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'self'")
	w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	s.mux.ServeHTTP(w, r)
}
```

**Step 4: Run test to verify it passes**

Run: `cd /home/mark-ssd/code/ssd.foundation/nocturne && go test ./internal/server/ -run TestSecurityHeaders -v`
Expected: PASS

**Step 5: Run full test suite**

Run: `cd /home/mark-ssd/code/ssd.foundation/nocturne && go test ./...`
Expected: ALL PASS

**Step 6: Commit**

```bash
cd /home/mark-ssd/code/ssd.foundation/nocturne
git add internal/server/server.go internal/server/server_test.go
git commit -m "fix(server): add security headers to all responses"
```

---

### Task 3: Transactional File & Operator Deletion

**Files:**
- Modify: `internal/storage/sqlite.go` (add `DeleteFileWithLinks`)
- Modify: `internal/storage/agent_store.go` (add `DeleteOperatorCascade`)
- Modify: `internal/server/files.go:158-185` (use transactional method)
- Test: `internal/server/server_test.go`
- Test: `internal/storage/sqlite_test.go`

**Step 1: Write the failing test for transactional file deletion**

Add to `internal/storage/sqlite_test.go`:

```go
func TestDeleteFileWithLinks(t *testing.T) {
	db := setupTestDB(t)

	// Create a recovery key, file, and two links.
	rk := &RecoveryKey{
		ID: "rk-tx-1", HexKey: "aabb", EscrowBlob: []byte("blob"), CreatedAt: 1,
	}
	if err := db.CreateRecoveryKey(rk); err != nil {
		t.Fatal(err)
	}

	f := &File{
		ID: "file-tx-1", Name: "test.txt", Size: 10, Cipher: "aes-256-gcm",
		Salt: []byte("s"), Nonce: []byte("n"), Blob: []byte("b"),
		RecoveryID: "rk-tx-1", CreatedAt: 1,
	}
	if err := db.CreateFile(f); err != nil {
		t.Fatal(err)
	}

	l1 := &Link{
		ID: "link-tx-1", FileID: "file-tx-1", Mode: "persistent",
		PasswordHash: []byte("h"), CreatedAt: 1,
	}
	l2 := &Link{
		ID: "link-tx-2", FileID: "file-tx-1", Mode: "onetime",
		PasswordHash: []byte("h"), CreatedAt: 1,
	}
	if err := db.CreateLink(l1); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateLink(l2); err != nil {
		t.Fatal(err)
	}

	// Delete file with links transactionally.
	if err := db.DeleteFileWithLinks("file-tx-1"); err != nil {
		t.Fatalf("DeleteFileWithLinks: %v", err)
	}

	// Verify file is gone.
	_, err := db.GetFile("file-tx-1")
	if err == nil {
		t.Fatal("expected error getting deleted file")
	}

	// Verify links are gone.
	links, err := db.ListLinksForFile("file-tx-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(links) != 0 {
		t.Fatalf("expected 0 links, got %d", len(links))
	}
}
```

Read the existing `sqlite_test.go` first to find the `setupTestDB` helper name. It may be named differently — check the file. If it doesn't exist, add one matching the pattern from `server_test.go`.

**Step 2: Run test to verify it fails**

Run: `cd /home/mark-ssd/code/ssd.foundation/nocturne && go test ./internal/storage/ -run TestDeleteFileWithLinks -v`
Expected: FAIL — `DeleteFileWithLinks` method doesn't exist

**Step 3: Implement `DeleteFileWithLinks`**

Add to `internal/storage/sqlite.go`:

```go
// DeleteFileWithLinks removes a file and all its associated links in a single
// transaction. Returns sql.ErrNoRows if the file doesn't exist.
func (d *DB) DeleteFileWithLinks(fileID string) error {
	tx, err := d.db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	// Delete links first (child rows).
	if _, err := tx.Exec(`DELETE FROM links WHERE file_id = ?`, fileID); err != nil {
		return fmt.Errorf("delete links: %w", err)
	}

	// Delete the file.
	res, err := tx.Exec(`DELETE FROM files WHERE id = ?`, fileID)
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

	return tx.Commit()
}
```

**Step 4: Run test to verify it passes**

Run: `cd /home/mark-ssd/code/ssd.foundation/nocturne && go test ./internal/storage/ -run TestDeleteFileWithLinks -v`
Expected: PASS

**Step 5: Implement `DeleteOperatorCascade`**

Add to `internal/storage/agent_store.go`:

```go
// DeleteOperatorCascade removes an operator and its agent keys in a single transaction.
func (d *DB) DeleteOperatorCascade(id string) error {
	tx, err := d.db.Begin()
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`DELETE FROM agent_keys WHERE operator_id = ?`, id); err != nil {
		return fmt.Errorf("delete agent keys: %w", err)
	}

	res, err := tx.Exec(`DELETE FROM operators WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete operator: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("delete operator rows affected: %w", err)
	}
	if n == 0 {
		return fmt.Errorf("delete operator: %w", sql.ErrNoRows)
	}

	return tx.Commit()
}
```

**Step 6: Update `handleDeleteFile` to use the transactional method**

Replace `internal/server/files.go:158-185` (`handleDeleteFile` body):

```go
func (s *Server) handleDeleteFile(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "file id is required")
		return
	}

	if err := s.db.DeleteFileWithLinks(id); err != nil {
		writeError(w, http.StatusNotFound, "file not found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
```

**Step 7: Run full test suite**

Run: `cd /home/mark-ssd/code/ssd.foundation/nocturne && go test ./...`
Expected: ALL PASS

**Step 8: Commit**

```bash
cd /home/mark-ssd/code/ssd.foundation/nocturne
git add internal/storage/sqlite.go internal/storage/agent_store.go internal/server/files.go internal/storage/sqlite_test.go
git commit -m "fix(storage): wrap file and operator deletion in transactions"
```

---

### Task 4: FK CASCADE in Schema

**Files:**
- Modify: `internal/storage/sqlite.go:51-210` (schema + migration)
- Test: `internal/storage/sqlite_test.go`

**Step 1: Write the failing test**

Add to `internal/storage/sqlite_test.go`:

```go
func TestFKCascadeDeleteFile(t *testing.T) {
	db := setupTestDB(t)

	rk := &RecoveryKey{
		ID: "rk-cascade-1", HexKey: "cc", EscrowBlob: []byte("b"), CreatedAt: 1,
	}
	if err := db.CreateRecoveryKey(rk); err != nil {
		t.Fatal(err)
	}

	f := &File{
		ID: "file-cascade-1", Name: "cascade.txt", Size: 5, Cipher: "aes-256-gcm",
		Salt: []byte("s"), Nonce: []byte("n"), Blob: []byte("b"),
		RecoveryID: "rk-cascade-1", CreatedAt: 1,
	}
	if err := db.CreateFile(f); err != nil {
		t.Fatal(err)
	}

	l := &Link{
		ID: "link-cascade-1", FileID: "file-cascade-1", Mode: "persistent",
		PasswordHash: []byte("h"), CreatedAt: 1,
	}
	if err := db.CreateLink(l); err != nil {
		t.Fatal(err)
	}

	// Delete the file directly (not via DeleteFileWithLinks).
	// With CASCADE, the link should be automatically deleted.
	if err := db.DeleteFile("file-cascade-1"); err != nil {
		t.Fatalf("DeleteFile: %v", err)
	}

	links, err := db.ListLinksForFile("file-cascade-1")
	if err != nil {
		t.Fatal(err)
	}
	if len(links) != 0 {
		t.Fatalf("expected 0 links after cascade delete, got %d", len(links))
	}
}
```

**Step 2: Run test to verify it fails**

Run: `cd /home/mark-ssd/code/ssd.foundation/nocturne && go test ./internal/storage/ -run TestFKCascadeDeleteFile -v`
Expected: FAIL — FK constraint violation (links reference files.id, no CASCADE)

**Step 3: Update schema with CASCADE**

In `internal/storage/sqlite.go`, update the `migrate()` schema string. Replace all FK declarations:

```sql
-- files table
FOREIGN KEY (recovery_id) REFERENCES recovery_keys(id) ON DELETE CASCADE

-- links table
FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE

-- shards table
FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE,
FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE

-- agent_keys table
FOREIGN KEY (operator_id) REFERENCES operators(id) ON DELETE CASCADE

-- knowledge table
FOREIGN KEY (agent_id) REFERENCES agent_keys(id) ON DELETE CASCADE,
FOREIGN KEY (operator_id) REFERENCES operators(id) ON DELETE CASCADE
```

Since `CREATE TABLE IF NOT EXISTS` won't update existing tables, add a migration function. Add this inside `migrate()` after the schema exec, or as a separate step:

```go
// Migrate existing tables to add ON DELETE CASCADE.
// SQLite doesn't support ALTER TABLE to add CASCADE, so we use the
// rename-and-recreate pattern. Only runs if CASCADE is missing.
if err := d.migrateCascade(); err != nil {
	return fmt.Errorf("migrate cascade: %w", err)
}
```

Add the `migrateCascade` method:

```go
func (d *DB) migrateCascade() error {
	// Check if links table already has CASCADE by reading the schema SQL.
	var sql string
	err := d.db.QueryRow(`SELECT sql FROM sqlite_master WHERE type='table' AND name='links'`).Scan(&sql)
	if err != nil {
		return nil // table doesn't exist yet (fresh DB), schema already has CASCADE
	}
	if strings.Contains(sql, "ON DELETE CASCADE") {
		return nil // already migrated
	}

	// Migrate tables that have foreign keys. Order matters: children first.
	migrations := []struct {
		table  string
		create string
	}{
		{"knowledge", `CREATE TABLE knowledge_new (
			id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, operator_id TEXT NOT NULL,
			type TEXT NOT NULL, domain TEXT NOT NULL, content TEXT NOT NULL,
			confidence REAL DEFAULT 0.5, sources TEXT, supersedes TEXT,
			votes_up INTEGER DEFAULT 0, votes_down INTEGER DEFAULT 0,
			verified_by TEXT, ttl INTEGER, created_at INTEGER NOT NULL,
			signature TEXT NOT NULL,
			FOREIGN KEY (agent_id) REFERENCES agent_keys(id) ON DELETE CASCADE,
			FOREIGN KEY (operator_id) REFERENCES operators(id) ON DELETE CASCADE
		)`},
		{"agent_keys", `CREATE TABLE agent_keys_new (
			id TEXT PRIMARY KEY, operator_id TEXT NOT NULL, public_key BLOB NOT NULL,
			label TEXT, last_seen INTEGER, created_at INTEGER NOT NULL,
			FOREIGN KEY (operator_id) REFERENCES operators(id) ON DELETE CASCADE
		)`},
		{"shards", `CREATE TABLE shards_new (
			id TEXT PRIMARY KEY, file_id TEXT NOT NULL, shard_index INTEGER NOT NULL,
			node_id TEXT NOT NULL, size INTEGER NOT NULL, checksum TEXT NOT NULL,
			FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE,
			FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE
		)`},
		{"links", `CREATE TABLE links_new (
			id TEXT PRIMARY KEY, file_id TEXT NOT NULL, mode TEXT NOT NULL,
			password_hash BLOB NOT NULL, expires_at INTEGER,
			burned INTEGER DEFAULT 0, downloads INTEGER DEFAULT 0,
			created_at INTEGER NOT NULL,
			FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE
		)`},
		{"files", `CREATE TABLE files_new (
			id TEXT PRIMARY KEY, name TEXT NOT NULL, size INTEGER NOT NULL,
			mime_type TEXT, cipher TEXT NOT NULL, salt BLOB NOT NULL,
			nonce BLOB NOT NULL, blob BLOB NOT NULL,
			recovery_id TEXT NOT NULL, created_at INTEGER NOT NULL,
			FOREIGN KEY (recovery_id) REFERENCES recovery_keys(id) ON DELETE CASCADE
		)`},
	}

	for _, m := range migrations {
		// Check if the old table exists.
		var exists int
		err := d.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, m.table).Scan(&exists)
		if err != nil || exists == 0 {
			continue
		}

		if _, err := d.db.Exec(m.create); err != nil {
			return fmt.Errorf("create %s_new: %w", m.table, err)
		}
		if _, err := d.db.Exec(fmt.Sprintf(`INSERT INTO %s_new SELECT * FROM %s`, m.table, m.table)); err != nil {
			d.db.Exec(fmt.Sprintf(`DROP TABLE IF EXISTS %s_new`, m.table))
			return fmt.Errorf("copy %s: %w", m.table, err)
		}
		if _, err := d.db.Exec(fmt.Sprintf(`DROP TABLE %s`, m.table)); err != nil {
			return fmt.Errorf("drop old %s: %w", m.table, err)
		}
		if _, err := d.db.Exec(fmt.Sprintf(`ALTER TABLE %s_new RENAME TO %s`, m.table, m.table)); err != nil {
			return fmt.Errorf("rename %s_new: %w", m.table, err)
		}
	}

	return nil
}
```

Add `"strings"` to imports if not already present.

**Step 4: Run test to verify it passes**

Run: `cd /home/mark-ssd/code/ssd.foundation/nocturne && go test ./internal/storage/ -run TestFKCascade -v`
Expected: PASS

**Step 5: Run full test suite**

Run: `cd /home/mark-ssd/code/ssd.foundation/nocturne && go test ./...`
Expected: ALL PASS

**Step 6: Commit**

```bash
cd /home/mark-ssd/code/ssd.foundation/nocturne
git add internal/storage/sqlite.go internal/storage/sqlite_test.go
git commit -m "fix(storage): add ON DELETE CASCADE to all foreign keys with migration"
```

---

### Task 5: DHT Vote/Task Compare-And-Swap

**Files:**
- Modify: `internal/dht/store.go` (add version column + CAS methods)
- Modify: `internal/dht/tasks.go` (use CAS for ClaimTask, SubmitTaskResult)
- Modify: `internal/dht/voting.go` (use CAS for SubmitVoteCommitment, SubmitVoteReveal, TallyVotes)
- Test: `internal/dht/store_test.go`
- Test: `internal/dht/tasks_test.go`

**Step 1: Write the failing test for versioned store**

Add to `internal/dht/store_test.go`:

```go
func TestLocalStorePutVersioned(t *testing.T) {
	s, err := NewLocalStore(":memory:")
	if err != nil {
		t.Fatalf("NewLocalStore: %v", err)
	}
	defer s.Close()

	key := ContentKey("test", "versioned")
	v1 := []byte(`{"v":1}`)
	v2 := []byte(`{"v":2}`)

	// First put should return version 1.
	ver1, err := s.PutVersioned(key, v1, 1*time.Hour)
	if err != nil {
		t.Fatalf("PutVersioned v1: %v", err)
	}
	if ver1 != 1 {
		t.Fatalf("expected version 1, got %d", ver1)
	}

	// CAS with correct version should succeed.
	ver2, err := s.CompareAndSwap(key, v2, ver1, 1*time.Hour)
	if err != nil {
		t.Fatalf("CompareAndSwap: %v", err)
	}
	if ver2 != 2 {
		t.Fatalf("expected version 2, got %d", ver2)
	}

	// CAS with stale version should fail.
	_, err = s.CompareAndSwap(key, []byte(`{"v":3}`), ver1, 1*time.Hour)
	if err == nil {
		t.Fatal("expected error for stale version CAS")
	}

	// Verify the value is still v2.
	got, _, _, err := s.GetVersioned(key)
	if err != nil {
		t.Fatalf("GetVersioned: %v", err)
	}
	if string(got) != string(v2) {
		t.Fatalf("expected %q, got %q", v2, got)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `cd /home/mark-ssd/code/ssd.foundation/nocturne && go test ./internal/dht/ -run TestLocalStorePutVersioned -v`
Expected: FAIL — methods don't exist

**Step 3: Add version column and CAS methods to LocalStore**

In `internal/dht/store.go`:

1. Add a `version` column to the schema (with migration for existing DBs):

```go
func NewLocalStore(dbPath string) (*LocalStore, error) {
	// ... existing code until after CREATE TABLE ...

	// Add version column if missing (migration for existing stores).
	_, _ = db.Exec(`ALTER TABLE dht_entries ADD COLUMN version INTEGER DEFAULT 0`)

	return &LocalStore{db: db}, nil
}
```

2. Add new methods:

```go
// ErrVersionConflict is returned when a CompareAndSwap fails due to version mismatch.
var ErrVersionConflict = fmt.Errorf("version conflict")

// PutVersioned stores a key-value pair and returns the new version number.
// If the key doesn't exist, version starts at 1. If it exists, version increments.
func (s *LocalStore) PutVersioned(key NodeID, value []byte, ttl time.Duration) (uint64, error) {
	keyHex := hex.EncodeToString(key[:])
	expiresAt := time.Now().Add(ttl).UnixMilli()

	// Use INSERT OR REPLACE with version increment.
	var currentVersion uint64
	err := s.db.QueryRow(`SELECT version FROM dht_entries WHERE key_hex = ?`, keyHex).Scan(&currentVersion)
	if err == sql.ErrNoRows {
		currentVersion = 0
	} else if err != nil {
		return 0, err
	}

	newVersion := currentVersion + 1
	_, err = s.db.Exec(
		`INSERT OR REPLACE INTO dht_entries (key_hex, value, expires_at, version) VALUES (?, ?, ?, ?)`,
		keyHex, value, expiresAt, newVersion,
	)
	if err != nil {
		return 0, err
	}
	return newVersion, nil
}

// GetVersioned retrieves a value and its version. Returns (nil, 0, false, nil) if not found.
func (s *LocalStore) GetVersioned(key NodeID) ([]byte, uint64, bool, error) {
	keyHex := hex.EncodeToString(key[:])
	var value []byte
	var expiresAt int64
	var version uint64
	err := s.db.QueryRow(
		`SELECT value, expires_at, version FROM dht_entries WHERE key_hex = ?`,
		keyHex,
	).Scan(&value, &expiresAt, &version)
	if err == sql.ErrNoRows {
		return nil, 0, false, nil
	}
	if err != nil {
		return nil, 0, false, err
	}
	if time.Now().UnixMilli() > expiresAt {
		s.Delete(key)
		return nil, 0, false, nil
	}
	return value, version, true, nil
}

// CompareAndSwap atomically updates a value only if the current version matches
// expectedVersion. Returns the new version on success or ErrVersionConflict.
func (s *LocalStore) CompareAndSwap(key NodeID, value []byte, expectedVersion uint64, ttl time.Duration) (uint64, error) {
	keyHex := hex.EncodeToString(key[:])
	expiresAt := time.Now().Add(ttl).UnixMilli()
	newVersion := expectedVersion + 1

	res, err := s.db.Exec(
		`UPDATE dht_entries SET value = ?, expires_at = ?, version = ? WHERE key_hex = ? AND version = ?`,
		value, expiresAt, newVersion, keyHex, expectedVersion,
	)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	if n == 0 {
		return 0, ErrVersionConflict
	}
	return newVersion, nil
}
```

**Step 4: Run test to verify it passes**

Run: `cd /home/mark-ssd/code/ssd.foundation/nocturne && go test ./internal/dht/ -run TestLocalStorePutVersioned -v`
Expected: PASS

**Step 5: Add CAS helpers to Node**

Add to `internal/dht/node.go` (after the existing `Store` method):

```go
// StoreLocal stores a value in the local store only (no replication),
// returning the new version. Used by vote/task operations that need CAS.
func (n *Node) StoreLocal(key NodeID, value []byte) (uint64, error) {
	return n.store.PutVersioned(key, value, defaultStoreTTL)
}

// FindValueVersioned retrieves a value from the local store with its version.
// Returns (nil, 0, nil) if not found locally.
func (n *Node) FindValueVersioned(key NodeID) ([]byte, uint64, error) {
	value, version, found, err := n.store.GetVersioned(key)
	if err != nil {
		return nil, 0, err
	}
	if !found {
		return nil, 0, nil
	}
	return value, version, nil
}

// CompareAndSwapLocal atomically updates a local store entry if the version matches.
func (n *Node) CompareAndSwapLocal(key NodeID, value []byte, expectedVersion uint64) (uint64, error) {
	return n.store.CompareAndSwap(key, value, expectedVersion, defaultStoreTTL)
}
```

**Step 6: Update ClaimTask to use CAS**

Replace `internal/dht/tasks.go` `ClaimTask` method:

```go
func (n *Node) ClaimTask(taskID, agentID string) (*ComputeTask, error) {
	key := PrefixKey(taskKeyPrefix, taskID)

	const maxRetries = 3
	for attempt := 0; attempt < maxRetries; attempt++ {
		data, version, err := n.FindValueVersioned(key)
		if err != nil {
			return nil, fmt.Errorf("find task: %w", err)
		}
		if data == nil {
			// Fall back to network lookup on first attempt.
			if attempt == 0 {
				netData, netErr := n.FindValue(key)
				if netErr != nil {
					return nil, fmt.Errorf("find task: %w", netErr)
				}
				if netData == nil {
					return nil, fmt.Errorf("task %s not found", taskID)
				}
				// Store locally and retry with version.
				if _, err := n.StoreLocal(key, netData); err != nil {
					return nil, fmt.Errorf("store task locally: %w", err)
				}
				continue
			}
			return nil, fmt.Errorf("task %s not found", taskID)
		}

		var task ComputeTask
		if err := json.Unmarshal(data, &task); err != nil {
			return nil, fmt.Errorf("unmarshal task: %w", err)
		}

		if task.ClaimedBy != "" && !task.Completed {
			claimAge := time.Since(time.Unix(task.ClaimedAt, 0))
			if claimAge < claimTimeout {
				return nil, fmt.Errorf("task %s already claimed by %s", taskID, task.ClaimedBy)
			}
		}

		task.ClaimedBy = agentID
		task.ClaimedAt = time.Now().Unix()

		updatedData, err := json.Marshal(task)
		if err != nil {
			return nil, err
		}

		_, casErr := n.CompareAndSwapLocal(key, updatedData, version)
		if casErr == ErrVersionConflict {
			continue // retry
		}
		if casErr != nil {
			return nil, fmt.Errorf("store claimed task: %w", casErr)
		}

		// Replicate to network (best-effort).
		go n.Store(key, updatedData)

		return &task, nil
	}
	return nil, fmt.Errorf("task %s: too many concurrent modifications", taskID)
}
```

Note: Import `ErrVersionConflict` is in the same package so it works directly.

**Step 7: Update SubmitVoteCommitment to use CAS**

Replace `internal/dht/voting.go` `SubmitVoteCommitment`:

```go
func (n *Node) SubmitVoteCommitment(entryKey NodeID, operatorID, commitment string) error {
	key := voteRecordKey(entryKey)

	const maxRetries = 3
	for attempt := 0; attempt < maxRetries; attempt++ {
		data, version, err := n.FindValueVersioned(key)
		if err != nil {
			return err
		}

		now := time.Now().Unix()
		var record *VoteRecord

		if data == nil {
			if attempt > 0 {
				return fmt.Errorf("vote record disappeared during retry")
			}
			record = &VoteRecord{
				EntryKey:  entryKey,
				CommitEnd: now + int64(defaultCommitWindow.Seconds()),
				RevealEnd: now + int64((defaultCommitWindow + defaultRevealWindow).Seconds()),
			}
		} else {
			record = &VoteRecord{}
			if err := json.Unmarshal(data, record); err != nil {
				return fmt.Errorf("unmarshal vote record: %w", err)
			}
		}

		if now > record.CommitEnd {
			return fmt.Errorf("commit window has ended")
		}

		for _, c := range record.Commitments {
			if c.OperatorID == operatorID {
				return fmt.Errorf("operator %s already committed", operatorID)
			}
		}

		record.Commitments = append(record.Commitments, VoteCommitment{
			OperatorID:  operatorID,
			Commitment:  commitment,
			CommittedAt: now,
		})

		recordData, err := json.Marshal(record)
		if err != nil {
			return err
		}

		if data == nil {
			// New record — use StoreLocal (no version to check).
			if _, err := n.StoreLocal(key, recordData); err != nil {
				return err
			}
			go n.Store(key, recordData)
			return nil
		}

		_, casErr := n.CompareAndSwapLocal(key, recordData, version)
		if casErr == ErrVersionConflict {
			continue
		}
		if casErr != nil {
			return casErr
		}
		go n.Store(key, recordData)
		return nil
	}
	return fmt.Errorf("too many concurrent modifications to vote record")
}
```

**Step 8: Update SubmitVoteReveal to use CAS**

Same pattern as SubmitVoteCommitment — replace the body of `SubmitVoteReveal` with a retry loop that uses `FindValueVersioned` and `CompareAndSwapLocal`. The business logic (window checks, commitment matching, duplicate detection) stays the same, just wrapped in a CAS retry loop.

**Step 9: Update TallyVotes and SubmitTaskResult similarly**

Apply the same CAS pattern to `TallyVotes` (marks finalized) and `SubmitTaskResult` (marks completed). These are lower contention but should still be safe.

**Step 10: Run tests**

Run: `cd /home/mark-ssd/code/ssd.foundation/nocturne && go test ./internal/dht/ -v`
Expected: ALL PASS (existing tests should still work since CAS is backward compatible)

**Step 11: Run full suite**

Run: `cd /home/mark-ssd/code/ssd.foundation/nocturne && go test ./...`
Expected: ALL PASS

**Step 12: Commit**

```bash
cd /home/mark-ssd/code/ssd.foundation/nocturne
git add internal/dht/store.go internal/dht/node.go internal/dht/tasks.go internal/dht/voting.go internal/dht/store_test.go
git commit -m "fix(dht): add compare-and-swap to prevent vote/task claim race conditions"
```

---

### Task 6: Per-Peer Rate Limiting + Gossip Fan-Out

**Files:**
- Create: `internal/ratelimit/ratelimit.go` (shared rate limiter)
- Modify: `internal/dht/transport.go` (per-peer limiter in peerConn + readLoop)
- Modify: `internal/dht/gossip.go` (limit fan-out to 3 random peers)
- Modify: `internal/mesh/ws.go` (per-connection rate limiting)
- Modify: `internal/server/ratelimit.go` (import shared implementation OR keep as-is)
- Test: `internal/ratelimit/ratelimit_test.go`
- Test: `internal/dht/transport_test.go`
- Test: `internal/mesh/ws_test.go` (if exists, otherwise test via tracker_test.go)

**Step 1: Write the failing test for shared rate limiter**

Create `internal/ratelimit/ratelimit_test.go`:

```go
package ratelimit

import (
	"testing"
	"time"
)

func TestLimiter_AllowsUpToRate(t *testing.T) {
	l := New(5, time.Minute)
	for i := 0; i < 5; i++ {
		if !l.Allow() {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}
	if l.Allow() {
		t.Fatal("6th request should be denied")
	}
}

func TestLimiter_ResetsAfterWindow(t *testing.T) {
	l := New(2, 50*time.Millisecond)
	l.Allow()
	l.Allow()
	if l.Allow() {
		t.Fatal("3rd request should be denied")
	}
	time.Sleep(60 * time.Millisecond)
	if !l.Allow() {
		t.Fatal("request after window reset should be allowed")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `cd /home/mark-ssd/code/ssd.foundation/nocturne && go test ./internal/ratelimit/ -v`
Expected: FAIL — package doesn't exist

**Step 3: Create the shared rate limiter package**

Create `internal/ratelimit/ratelimit.go`:

```go
package ratelimit

import (
	"sync"
	"time"
)

// Limiter is a simple fixed-window rate limiter for a single entity.
type Limiter struct {
	mu          sync.Mutex
	count       int
	windowStart time.Time
	rate        int
	window      time.Duration
}

// New creates a Limiter that allows rate requests per window.
func New(rate int, window time.Duration) *Limiter {
	return &Limiter{
		rate:        rate,
		window:      window,
		windowStart: time.Now(),
	}
}

// Allow returns true if the request is within the rate limit.
func (l *Limiter) Allow() bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	if now.Sub(l.windowStart) > l.window {
		l.count = 0
		l.windowStart = now
	}
	l.count++
	return l.count <= l.rate
}
```

**Step 4: Run test to verify it passes**

Run: `cd /home/mark-ssd/code/ssd.foundation/nocturne && go test ./internal/ratelimit/ -v`
Expected: PASS

**Step 5: Add per-peer rate limiting to DHT transport**

In `internal/dht/transport.go`:

1. Add import: `"github.com/ssd-technologies/nocturne/internal/ratelimit"`

2. Add limiter to `peerConn`:
```go
type peerConn struct {
	conn    *websocket.Conn
	wmu     sync.Mutex
	pubKey  ed25519.PublicKey
	limiter *ratelimit.Limiter
}
```

3. Initialize in `handleWS` and `Connect`:
```go
// In handleWS:
pc := &peerConn{conn: conn, limiter: ratelimit.New(100, time.Minute)}

// In Connect:
pc := &peerConn{conn: conn, limiter: ratelimit.New(100, time.Minute)}
```

4. Check in `readLoop` before dispatch:
```go
// In readLoop, after ReadJSON succeeds:
if !pc.limiter.Allow() {
	continue // silently drop — peer is flooding
}
```

**Step 6: Limit gossip fan-out to 3 random peers**

In `internal/dht/gossip.go`, modify `forward()`:

Add import `"math/rand"` (crypto/rand is for key generation; math/rand is fine for peer selection).

Replace the peer loop:
```go
func (g *Gossiper) forward(gmsg *GossipMessage) error {
	data, err := json.Marshal(gmsg)
	if err != nil {
		return err
	}

	peers := g.node.transport.ConnectedPeers()

	// Filter out origin.
	var eligible []NodeID
	for _, peerID := range peers {
		if peerID != gmsg.Origin {
			eligible = append(eligible, peerID)
		}
	}

	// Limit fan-out to 3 peers to prevent amplification.
	const maxFanOut = 3
	if len(eligible) > maxFanOut {
		rand.Shuffle(len(eligible), func(i, j int) {
			eligible[i], eligible[j] = eligible[j], eligible[i]
		})
		eligible = eligible[:maxFanOut]
	}

	for _, peerID := range eligible {
		msg := &Message{
			Type:    MsgGossip,
			ID:      randomMsgID(),
			Payload: json.RawMessage(data),
			Sender: SenderInfo{
				NodeID:  g.node.id,
				Address: g.node.Addr(),
			},
		}
		g.node.transport.Send(peerID, msg)
	}
	return nil
}
```

**Step 7: Add per-connection rate limiting to mesh WebSocket**

In `internal/mesh/ws.go`:

1. Add import: `"github.com/ssd-technologies/nocturne/internal/ratelimit"` and `"time"`

2. Add limiter after connection setup:
```go
func HandleWebSocket(tracker *Tracker) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Printf("websocket upgrade error: %v", err)
			return
		}
		defer conn.Close()

		limiter := ratelimit.New(60, time.Minute)
		var nodeID string
		// ... rest unchanged, but add before the switch:
```

3. Add check inside the for loop, before `switch msg.Type`:
```go
if !limiter.Allow() {
	writeError(conn, "rate limit exceeded")
	continue
}
```

**Step 8: Run full test suite**

Run: `cd /home/mark-ssd/code/ssd.foundation/nocturne && go test ./...`
Expected: ALL PASS

**Step 9: Commit**

```bash
cd /home/mark-ssd/code/ssd.foundation/nocturne
git add internal/ratelimit/ratelimit.go internal/ratelimit/ratelimit_test.go internal/dht/transport.go internal/dht/gossip.go internal/mesh/ws.go
git commit -m "fix(net): add per-peer rate limiting and gossip fan-out cap"
```

---

## Verification

After all 6 tasks, run the full suite:

```bash
cd /home/mark-ssd/code/ssd.foundation/nocturne && go test ./... -count=1
```

Expected: ALL PASS, 0 failures. Check `git log --oneline -8` to verify 6 new commits + 1 plan doc commit.
