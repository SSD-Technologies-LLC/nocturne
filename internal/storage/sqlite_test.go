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

// --- Task 4: Link CRUD tests ---

// seedFile creates a recovery key and file for link tests.
func seedFile(t *testing.T, db *DB) *File {
	t.Helper()
	rk := seedRecoveryKey(t, db)
	f := &File{
		ID:         "file-link-test",
		Name:       "linked.txt",
		Size:       256,
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
	return f
}

func TestCreateAndGetLink(t *testing.T) {
	db := testDB(t)
	f := seedFile(t, db)

	exp := time.Now().Add(24 * time.Hour).Unix()
	l := &Link{
		ID:           "link-001",
		FileID:       f.ID,
		Mode:         "password",
		PasswordHash: []byte("hashed-pw"),
		ExpiresAt:    &exp,
		Burned:       false,
		Downloads:    0,
		CreatedAt:    time.Now().Unix(),
	}
	if err := db.CreateLink(l); err != nil {
		t.Fatalf("CreateLink: %v", err)
	}

	got, err := db.GetLink(l.ID)
	if err != nil {
		t.Fatalf("GetLink: %v", err)
	}
	if got.ID != l.ID {
		t.Errorf("ID = %q, want %q", got.ID, l.ID)
	}
	if got.FileID != l.FileID {
		t.Errorf("FileID = %q, want %q", got.FileID, l.FileID)
	}
	if got.Mode != l.Mode {
		t.Errorf("Mode = %q, want %q", got.Mode, l.Mode)
	}
	if string(got.PasswordHash) != string(l.PasswordHash) {
		t.Errorf("PasswordHash mismatch")
	}
	if got.ExpiresAt == nil {
		t.Fatal("ExpiresAt is nil, expected non-nil")
	}
	if *got.ExpiresAt != *l.ExpiresAt {
		t.Errorf("ExpiresAt = %d, want %d", *got.ExpiresAt, *l.ExpiresAt)
	}
	if got.Burned {
		t.Error("Burned = true, want false")
	}
	if got.Downloads != 0 {
		t.Errorf("Downloads = %d, want 0", got.Downloads)
	}
}

func TestCreateAndGetLink_NilExpiry(t *testing.T) {
	db := testDB(t)
	f := seedFile(t, db)

	l := &Link{
		ID:           "link-noexp",
		FileID:       f.ID,
		Mode:         "open",
		PasswordHash: []byte("h"),
		ExpiresAt:    nil,
		CreatedAt:    time.Now().Unix(),
	}
	if err := db.CreateLink(l); err != nil {
		t.Fatalf("CreateLink: %v", err)
	}

	got, err := db.GetLink(l.ID)
	if err != nil {
		t.Fatalf("GetLink: %v", err)
	}
	if got.ExpiresAt != nil {
		t.Errorf("ExpiresAt = %v, want nil", got.ExpiresAt)
	}
}

func TestBurnLink(t *testing.T) {
	db := testDB(t)
	f := seedFile(t, db)

	l := &Link{
		ID:           "link-burn",
		FileID:       f.ID,
		Mode:         "burn",
		PasswordHash: []byte("h"),
		CreatedAt:    time.Now().Unix(),
	}
	if err := db.CreateLink(l); err != nil {
		t.Fatalf("CreateLink: %v", err)
	}

	if err := db.BurnLink(l.ID); err != nil {
		t.Fatalf("BurnLink: %v", err)
	}

	got, err := db.GetLink(l.ID)
	if err != nil {
		t.Fatalf("GetLink after burn: %v", err)
	}
	if !got.Burned {
		t.Error("Burned = false after BurnLink, want true")
	}
	if got.Downloads != 1 {
		t.Errorf("Downloads = %d after BurnLink, want 1", got.Downloads)
	}
}

func TestIncrementDownloads(t *testing.T) {
	db := testDB(t)
	f := seedFile(t, db)

	l := &Link{
		ID:           "link-dl",
		FileID:       f.ID,
		Mode:         "open",
		PasswordHash: []byte("h"),
		CreatedAt:    time.Now().Unix(),
	}
	if err := db.CreateLink(l); err != nil {
		t.Fatalf("CreateLink: %v", err)
	}

	for i := 0; i < 3; i++ {
		if err := db.IncrementDownloads(l.ID); err != nil {
			t.Fatalf("IncrementDownloads[%d]: %v", i, err)
		}
	}

	got, err := db.GetLink(l.ID)
	if err != nil {
		t.Fatalf("GetLink: %v", err)
	}
	if got.Downloads != 3 {
		t.Errorf("Downloads = %d, want 3", got.Downloads)
	}
}

func TestListLinksForFile(t *testing.T) {
	db := testDB(t)
	f := seedFile(t, db)

	for i := 0; i < 3; i++ {
		l := &Link{
			ID:           fmt.Sprintf("link-%03d", i),
			FileID:       f.ID,
			Mode:         "open",
			PasswordHash: []byte("h"),
			CreatedAt:    time.Now().Unix(),
		}
		if err := db.CreateLink(l); err != nil {
			t.Fatalf("CreateLink[%d]: %v", i, err)
		}
	}

	links, err := db.ListLinksForFile(f.ID)
	if err != nil {
		t.Fatalf("ListLinksForFile: %v", err)
	}
	if len(links) != 3 {
		t.Fatalf("len = %d, want 3", len(links))
	}

	// Links for a non-existent file should return empty.
	empty, err := db.ListLinksForFile("no-such-file")
	if err != nil {
		t.Fatalf("ListLinksForFile(missing): %v", err)
	}
	if len(empty) != 0 {
		t.Errorf("expected 0 links for missing file, got %d", len(empty))
	}
}

func TestDeleteLink(t *testing.T) {
	db := testDB(t)
	f := seedFile(t, db)

	l := &Link{
		ID:           "link-del",
		FileID:       f.ID,
		Mode:         "open",
		PasswordHash: []byte("h"),
		CreatedAt:    time.Now().Unix(),
	}
	if err := db.CreateLink(l); err != nil {
		t.Fatalf("CreateLink: %v", err)
	}

	if err := db.DeleteLink(l.ID); err != nil {
		t.Fatalf("DeleteLink: %v", err)
	}

	_, err := db.GetLink(l.ID)
	if err == nil {
		t.Fatal("expected error after delete, got nil")
	}
}
