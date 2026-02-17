package dht

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"
)

func TestStoreShard(t *testing.T) {
	a, b, _ := testCluster(t)

	shardData := []byte("shard-data-for-testing-purposes-here")
	checksum := sha256.Sum256(shardData)
	checksumHex := hex.EncodeToString(checksum[:])

	err := a.StoreShard("file-001", 0, shardData)
	if err != nil {
		t.Fatalf("StoreShard: %v", err)
	}

	time.Sleep(300 * time.Millisecond)

	// Retrieve from different node.
	got, err := b.RetrieveShard("file-001", 0)
	if err != nil {
		t.Fatalf("RetrieveShard: %v", err)
	}
	if string(got) != string(shardData) {
		t.Fatalf("shard data mismatch")
	}

	// Verify checksum.
	gotChecksum := sha256.Sum256(got)
	if hex.EncodeToString(gotChecksum[:]) != checksumHex {
		t.Fatal("checksum mismatch")
	}
}

func TestStoreAndRetrieveManifest(t *testing.T) {
	a, b, _ := testCluster(t)

	manifest := &ShardManifest{
		FileID:       "file-002",
		FileName:     "test.txt",
		FileSize:     1000,
		Cipher:       "aes-256-gcm",
		Salt:         []byte("0123456789abcdef0123456789abcdef"),
		Nonce:        []byte("0123456789ab"),
		DataShards:   4,
		ParityShards: 2,
		Shards: []ShardInfo{
			{Index: 0, Size: 250, Checksum: "aaa"},
			{Index: 1, Size: 250, Checksum: "bbb"},
			{Index: 2, Size: 250, Checksum: "ccc"},
			{Index: 3, Size: 250, Checksum: "ddd"},
			{Index: 4, Size: 250, Checksum: "eee"},
			{Index: 5, Size: 250, Checksum: "fff"},
		},
		UploadedBy: "op-1",
		CreatedAt:  1700000000,
	}

	err := a.StoreManifest(manifest)
	if err != nil {
		t.Fatalf("StoreManifest: %v", err)
	}

	time.Sleep(300 * time.Millisecond)

	got, err := b.RetrieveManifest("file-002")
	if err != nil {
		t.Fatalf("RetrieveManifest: %v", err)
	}
	if got.FileID != "file-002" {
		t.Fatalf("expected file-002, got %s", got.FileID)
	}
	if len(got.Shards) != 6 {
		t.Fatalf("expected 6 shards, got %d", len(got.Shards))
	}
}

func TestUpdateFileIndex(t *testing.T) {
	a, b, _ := testCluster(t)

	// Add two files to operator's index.
	if err := a.AddToFileIndex("op-1", "file-001"); err != nil {
		t.Fatalf("AddToFileIndex: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	if err := a.AddToFileIndex("op-1", "file-002"); err != nil {
		t.Fatalf("AddToFileIndex: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	// List from another node.
	index, err := b.GetFileIndex("op-1")
	if err != nil {
		t.Fatalf("GetFileIndex: %v", err)
	}
	if len(index.FileIDs) != 2 {
		t.Fatalf("expected 2 files, got %d", len(index.FileIDs))
	}

	// Remove a file.
	if err := a.RemoveFromFileIndex("op-1", "file-001"); err != nil {
		t.Fatalf("RemoveFromFileIndex: %v", err)
	}
	time.Sleep(200 * time.Millisecond)

	index, err = b.GetFileIndex("op-1")
	if err != nil {
		t.Fatalf("GetFileIndex after remove: %v", err)
	}
	if len(index.FileIDs) != 1 {
		t.Fatalf("expected 1 file, got %d", len(index.FileIDs))
	}
}
