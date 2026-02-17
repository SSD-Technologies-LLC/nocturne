package dht

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/ssd-technologies/nocturne/internal/crypto"
)

// TestP2PFileStorageIntegration tests the complete P2P file storage flow
// across a 5-node cluster: encrypt -> distribute -> reconstruct -> degrade -> repair -> delete.
func TestP2PFileStorageIntegration(t *testing.T) {
	// 1. Set up a 5-node DHT cluster.
	nodes := testNodes(t, 5)
	a, e := nodes[0], nodes[4]

	// Bootstrap all nodes to each other.
	for i := 1; i < len(nodes); i++ {
		if _, err := nodes[0].Ping(nodes[i].Addr()); err != nil {
			t.Fatalf("bootstrap ping %d: %v", i, err)
		}
	}
	for i := 1; i < len(nodes); i++ {
		for j := i + 1; j < len(nodes); j++ {
			if _, err := nodes[i].Ping(nodes[j].Addr()); err != nil {
				t.Fatalf("cross-ping %d->%d: %v", i, j, err)
			}
		}
	}
	time.Sleep(200 * time.Millisecond)

	// 2. Simulate client-side encryption using Go crypto (same as browser would use).
	plaintext := []byte("This is a secret file for the P2P integration test — it must survive erasure coding and reconstruction!")
	password := "integration-test-password"
	ciphertext, salt, nonce, err := crypto.Encrypt(plaintext, password, crypto.CipherAES)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// 3. Distribute file on node A.
	manifest, err := a.DistributeFile(DistributeFileParams{
		FileID:       "integration-file-1",
		FileName:     "secret.txt",
		FileSize:     int64(len(ciphertext)),
		Cipher:       crypto.CipherAES,
		Salt:         salt,
		Nonce:        nonce,
		Ciphertext:   ciphertext,
		DataShards:   4,
		ParityShards: 2,
		OperatorID:   "test-operator",
	})
	if err != nil {
		t.Fatalf("distribute: %v", err)
	}

	if manifest.TotalShards() != 6 {
		t.Fatalf("expected 6 total shards, got %d", manifest.TotalShards())
	}
	if manifest.FileID != "integration-file-1" {
		t.Fatalf("manifest file ID mismatch: %s", manifest.FileID)
	}

	// 4. Reconstruct file on node E (different node).
	reconstructed, err := e.ReconstructFile("integration-file-1")
	if err != nil {
		t.Fatalf("reconstruct on node E: %v", err)
	}
	if string(reconstructed) != string(ciphertext) {
		t.Fatalf("reconstructed ciphertext mismatch: got %d bytes, want %d bytes", len(reconstructed), len(ciphertext))
	}

	// 5. Decrypt the reconstructed ciphertext to verify end-to-end integrity.
	decrypted, err := crypto.Decrypt(reconstructed, password, crypto.CipherAES, salt, nonce)
	if err != nil {
		t.Fatalf("decrypt reconstructed: %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Fatalf("decrypted plaintext mismatch")
	}

	// 6. Delete 2 shards (within 4+2 parity tolerance) and reconstruct again.
	shard0Key := ShardKey("integration-file-1", 0)
	shard1Key := ShardKey("integration-file-1", 1)
	for _, n := range nodes {
		n.store.Delete(shard0Key)
		n.store.Delete(shard1Key)
	}

	degraded, err := e.ReconstructFile("integration-file-1")
	if err != nil {
		t.Fatalf("reconstruct after shard loss: %v", err)
	}
	if string(degraded) != string(ciphertext) {
		t.Fatalf("degraded reconstruction mismatch")
	}

	// 7. Repair the missing shards.
	rl := NewRepairLoop(a, time.Hour, func() []string {
		return []string{"integration-file-1"}
	})
	result := rl.repairCycle()
	if result.ShardsRepaired < 2 {
		t.Fatalf("expected at least 2 shards repaired, got %d", result.ShardsRepaired)
	}

	// 8. Verify all shards are healthy after repair.
	for i := 0; i < 6; i++ {
		if _, err := a.RetrieveShard("integration-file-1", i); err != nil {
			t.Fatalf("shard %d missing after repair: %v", i, err)
		}
	}

	// 9. Verify file index.
	index, err := a.GetFileIndex("test-operator")
	if err != nil {
		t.Fatalf("get file index: %v", err)
	}
	found := false
	for _, id := range index.FileIDs {
		if id == "integration-file-1" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("file not in operator's file index")
	}

	// 10. Delete the distributed file from all nodes (simulates cluster-wide cleanup).
	for _, n := range nodes {
		n.DeleteDistributedFile("integration-file-1", "test-operator")
	}

	// 11. Verify manifest is gone from the local store of the originating node.
	manifestKey := ManifestKey("integration-file-1")
	_, manifestFound, _ := a.store.Get(manifestKey)
	if manifestFound {
		t.Fatal("expected manifest to be deleted from local store")
	}

	// 12. Verify file index is updated.
	index, err = a.GetFileIndex("test-operator")
	if err != nil {
		t.Fatalf("get file index after delete: %v", err)
	}
	for _, id := range index.FileIDs {
		if id == "integration-file-1" {
			t.Fatal("file should be removed from index after delete")
		}
	}
}

// TestP2PDirectMessagingIntegration tests agent-to-agent messaging across a cluster.
func TestP2PDirectMessagingIntegration(t *testing.T) {
	nodes := testNodes(t, 5)

	// Bootstrap chain: 0-1-2-3-4.
	for i := 0; i < len(nodes)-1; i++ {
		if _, err := nodes[i].Ping(nodes[i+1].Addr()); err != nil {
			t.Fatalf("ping %d->%d: %v", i, i+1, err)
		}
	}
	time.Sleep(200 * time.Millisecond)

	// Test: node 0 sends to node 4 (must relay through intermediaries).
	var received json.RawMessage
	done := make(chan struct{})

	nodes[4].OnDirectMessage(func(from NodeID, content json.RawMessage) {
		received = content
		close(done)
	})

	msg := json.RawMessage(`{"type":"task","data":"process this"}`)
	if err := nodes[0].SendDirectMessage(nodes[4].ID(), msg); err != nil {
		t.Fatalf("send: %v", err)
	}

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for relayed message")
	}

	if string(received) != `{"type":"task","data":"process this"}` {
		t.Fatalf("unexpected content: %s", received)
	}
}
