package dht

import (
	"bytes"
	"testing"
	"time"
)

func TestDistributeAndReconstructFile(t *testing.T) {
	// 5-node cluster for shard distribution.
	nodes := testNodes(t, 5)
	for i := 1; i < len(nodes); i++ {
		if _, err := nodes[i-1].Ping(nodes[i].Addr()); err != nil {
			t.Fatalf("ping %d→%d: %v", i-1, i, err)
		}
	}
	time.Sleep(500 * time.Millisecond)

	// Simulate a pre-encrypted ciphertext (could be any bytes).
	ciphertext := bytes.Repeat([]byte("ENCRYPTED-DATA-"), 100) // 1500 bytes

	manifest, err := nodes[0].DistributeFile(DistributeFileParams{
		FileID:       "file-dist-001",
		FileName:     "secret.pdf",
		FileSize:     int64(len(ciphertext)),
		Cipher:       "aes-256-gcm",
		Salt:         []byte("0123456789abcdef0123456789abcdef"),
		Nonce:        []byte("0123456789ab"),
		Ciphertext:   ciphertext,
		DataShards:   4,
		ParityShards: 2,
		OperatorID:   "op-1",
	})
	if err != nil {
		t.Fatalf("DistributeFile: %v", err)
	}

	if manifest.FileID != "file-dist-001" {
		t.Fatalf("manifest file ID mismatch")
	}
	if len(manifest.Shards) != 6 {
		t.Fatalf("expected 6 shards, got %d", len(manifest.Shards))
	}

	time.Sleep(500 * time.Millisecond)

	// Reconstruct from a different node.
	got, err := nodes[2].ReconstructFile("file-dist-001")
	if err != nil {
		t.Fatalf("ReconstructFile: %v", err)
	}

	if !bytes.Equal(got, ciphertext) {
		t.Fatalf("reconstructed ciphertext mismatch: got %d bytes, want %d", len(got), len(ciphertext))
	}
}

func TestReconstructFileWithMissingShards(t *testing.T) {
	nodes := testNodes(t, 5)
	for i := 1; i < len(nodes); i++ {
		if _, err := nodes[i-1].Ping(nodes[i].Addr()); err != nil {
			t.Fatalf("ping %d→%d: %v", i-1, i, err)
		}
	}
	time.Sleep(500 * time.Millisecond)

	ciphertext := bytes.Repeat([]byte("IMPORTANT-FILE-"), 100)

	_, err := nodes[0].DistributeFile(DistributeFileParams{
		FileID:       "file-missing-001",
		FileName:     "important.doc",
		FileSize:     int64(len(ciphertext)),
		Cipher:       "aes-256-gcm",
		Salt:         []byte("0123456789abcdef0123456789abcdef"),
		Nonce:        []byte("0123456789ab"),
		Ciphertext:   ciphertext,
		DataShards:   4,
		ParityShards: 2,
		OperatorID:   "op-1",
	})
	if err != nil {
		t.Fatalf("DistributeFile: %v", err)
	}
	time.Sleep(500 * time.Millisecond)

	// Delete 2 shards from ALL nodes (within parity tolerance).
	// Shards are replicated across the DHT, so we must remove from every node's
	// local store to truly simulate shard loss.
	for _, nd := range nodes {
		nd.store.Delete(ShardKey("file-missing-001", 0))
		nd.store.Delete(ShardKey("file-missing-001", 1))
	}

	// Should still reconstruct (4 of 6 shards remain, need 4 data shards).
	got, err := nodes[3].ReconstructFile("file-missing-001")
	if err != nil {
		t.Fatalf("ReconstructFile with missing shards: %v", err)
	}

	if !bytes.Equal(got, ciphertext) {
		t.Fatalf("reconstructed data mismatch")
	}
}
