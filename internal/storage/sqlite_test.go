package storage

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// testDB creates a temporary SQLite database for testing.
func testDB(t *testing.T) *DB {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	db, err := NewDB(dbPath)
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestNewDB_CreatesFile(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	db, err := NewDB(dbPath)
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	defer db.Close()

	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Fatal("database file was not created")
	}
}

func TestNewDB_AllTablesExist(t *testing.T) {
	db := testDB(t)

	expected := []string{"files", "recovery_keys", "links", "nodes", "shards"}
	for _, table := range expected {
		var name string
		err := db.db.QueryRow(
			"SELECT name FROM sqlite_master WHERE type='table' AND name=?", table,
		).Scan(&name)
		if err != nil {
			t.Errorf("table %q not found: %v", table, err)
		}
	}
}

func TestDB_Close(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	db, err := NewDB(dbPath)
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// After close, queries should fail.
	var name string
	err = db.db.QueryRow("SELECT 1").Scan(&name)
	if err == nil {
		t.Fatal("expected error after Close, got nil")
	}
}

// --- Task 3: File CRUD tests ---

func seedRecoveryKey(t *testing.T, db *DB) *RecoveryKey {
	t.Helper()
	rk := &RecoveryKey{
		ID:         "rk-001",
		HexKey:     "abcdef0123456789",
		Mnemonic:   "word1 word2 word3",
		EscrowBlob: []byte("escrow-data"),
		CreatedAt:  time.Now().Unix(),
	}
	if err := db.CreateRecoveryKey(rk); err != nil {
		t.Fatalf("CreateRecoveryKey: %v", err)
	}
	return rk
}

func TestCreateAndGetRecoveryKey(t *testing.T) {
	db := testDB(t)
	rk := seedRecoveryKey(t, db)

	got, err := db.GetRecoveryKey(rk.ID)
	if err != nil {
		t.Fatalf("GetRecoveryKey: %v", err)
	}
	if got.ID != rk.ID {
		t.Errorf("ID = %q, want %q", got.ID, rk.ID)
	}
	if got.HexKey != rk.HexKey {
		t.Errorf("HexKey = %q, want %q", got.HexKey, rk.HexKey)
	}
	if got.Mnemonic != rk.Mnemonic {
		t.Errorf("Mnemonic = %q, want %q", got.Mnemonic, rk.Mnemonic)
	}
	if string(got.EscrowBlob) != string(rk.EscrowBlob) {
		t.Errorf("EscrowBlob mismatch")
	}
}

func TestListRecoveryKeys(t *testing.T) {
	db := testDB(t)
	seedRecoveryKey(t, db)

	rk2 := &RecoveryKey{
		ID:         "rk-002",
		HexKey:     "1111111111111111",
		EscrowBlob: []byte("escrow2"),
		CreatedAt:  time.Now().Unix(),
	}
	if err := db.CreateRecoveryKey(rk2); err != nil {
		t.Fatalf("CreateRecoveryKey: %v", err)
	}

	keys, err := db.ListRecoveryKeys()
	if err != nil {
		t.Fatalf("ListRecoveryKeys: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("len = %d, want 2", len(keys))
	}
}

func TestCreateAndGetFile(t *testing.T) {
	db := testDB(t)
	rk := seedRecoveryKey(t, db)

	f := &File{
		ID:         "file-001",
		Name:       "secret.txt",
		Size:       1024,
		MimeType:   "text/plain",
		Cipher:     "aes-256-gcm",
		Salt:       []byte("salt-bytes"),
		Nonce:      []byte("nonce-bytes"),
		Blob:       []byte("encrypted-blob-data"),
		RecoveryID: rk.ID,
		CreatedAt:  time.Now().Unix(),
	}
	if err := db.CreateFile(f); err != nil {
		t.Fatalf("CreateFile: %v", err)
	}

	got, err := db.GetFile(f.ID)
	if err != nil {
		t.Fatalf("GetFile: %v", err)
	}
	if got.Name != f.Name {
		t.Errorf("Name = %q, want %q", got.Name, f.Name)
	}
	if got.Size != f.Size {
		t.Errorf("Size = %d, want %d", got.Size, f.Size)
	}
	if got.MimeType != f.MimeType {
		t.Errorf("MimeType = %q, want %q", got.MimeType, f.MimeType)
	}
	if string(got.Blob) != string(f.Blob) {
		t.Errorf("Blob mismatch")
	}
	if got.RecoveryID != f.RecoveryID {
		t.Errorf("RecoveryID = %q, want %q", got.RecoveryID, f.RecoveryID)
	}
}

func TestListFiles(t *testing.T) {
	db := testDB(t)
	rk := seedRecoveryKey(t, db)

	for i := 0; i < 3; i++ {
		f := &File{
			ID:         fmt.Sprintf("file-%03d", i),
			Name:       fmt.Sprintf("file%d.txt", i),
			Size:       int64(100 * (i + 1)),
			Cipher:     "aes-256-gcm",
			Salt:       []byte("salt"),
			Nonce:      []byte("nonce"),
			Blob:       []byte("blob-data"),
			RecoveryID: rk.ID,
			CreatedAt:  time.Now().Unix(),
		}
		if err := db.CreateFile(f); err != nil {
			t.Fatalf("CreateFile[%d]: %v", i, err)
		}
	}

	files, err := db.ListFiles()
	if err != nil {
		t.Fatalf("ListFiles: %v", err)
	}
	if len(files) != 3 {
		t.Fatalf("len = %d, want 3", len(files))
	}
	// ListFiles should NOT include blob data.
	for _, f := range files {
		if len(f.Blob) != 0 {
			t.Errorf("ListFiles should not populate Blob, got %d bytes", len(f.Blob))
		}
	}
}

func TestDeleteFile(t *testing.T) {
	db := testDB(t)
	rk := seedRecoveryKey(t, db)

	f := &File{
		ID:         "file-del",
		Name:       "todelete.txt",
		Size:       512,
		Cipher:     "aes-256-gcm",
		Salt:       []byte("s"),
		Nonce:      []byte("n"),
		Blob:       []byte("b"),
		RecoveryID: rk.ID,
		CreatedAt:  time.Now().Unix(),
	}
	if err := db.CreateFile(f); err != nil {
		t.Fatalf("CreateFile: %v", err)
	}

	if err := db.DeleteFile(f.ID); err != nil {
		t.Fatalf("DeleteFile: %v", err)
	}

	_, err := db.GetFile(f.ID)
	if err == nil {
		t.Fatal("expected error after delete, got nil")
	}
}
