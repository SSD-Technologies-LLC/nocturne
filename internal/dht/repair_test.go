package dht

import (
	"bytes"
	"testing"
	"time"
)

func TestRepairLoop_DetectsAndRepairsShards(t *testing.T) {
	// Set up a 5-node cluster for shard distribution.
	nodes := testNodes(t, 5)
	for i := 1; i < len(nodes); i++ {
		if _, err := nodes[i-1].Ping(nodes[i].Addr()); err != nil {
			t.Fatalf("ping %d->%d: %v", i-1, i, err)
		}
	}
	time.Sleep(500 * time.Millisecond)

	// Simulate a pre-encrypted ciphertext (needs enough bytes for 4+2 RS).
	ciphertext := bytes.Repeat([]byte("REPAIR-TEST-DATA"), 100) // 1600 bytes

	_, err := nodes[0].DistributeFile(DistributeFileParams{
		FileID:       "repair-file-1",
		FileName:     "test.bin",
		FileSize:     int64(len(ciphertext)),
		Cipher:       "aes-256-gcm",
		Salt:         []byte("0123456789abcdef0123456789abcdef"),
		Nonce:        []byte("0123456789ab"),
		Ciphertext:   ciphertext,
		DataShards:   4,
		ParityShards: 2,
		OperatorID:   "test-op",
	})
	if err != nil {
		t.Fatalf("distribute: %v", err)
	}
	time.Sleep(500 * time.Millisecond)

	// Delete shard 0 from ALL nodes (DHT replicates, so must remove everywhere).
	shardKey := ShardKey("repair-file-1", 0)
	for _, nd := range nodes {
		nd.store.Delete(shardKey)
	}

	// Verify shard 0 is now missing.
	_, err = nodes[0].RetrieveShard("repair-file-1", 0)
	if err == nil {
		t.Fatal("expected shard 0 to be missing after delete")
	}

	// Run a single repair cycle (no need to start the background goroutine).
	rl := NewRepairLoop(nodes[0], time.Hour, func() []string {
		return []string{"repair-file-1"}
	})

	result := rl.repairCycle()
	if result.FilesChecked != 1 {
		t.Fatalf("expected 1 file checked, got %d", result.FilesChecked)
	}
	if result.ShardsRepaired < 1 {
		t.Fatalf("expected at least 1 shard repaired, got %d", result.ShardsRepaired)
	}
	if len(result.Errors) != 0 {
		t.Fatalf("expected no errors, got %v", result.Errors)
	}

	// Verify shard 0 is restored.
	_, err = nodes[0].RetrieveShard("repair-file-1", 0)
	if err != nil {
		t.Fatalf("shard 0 should be restored after repair: %v", err)
	}

	// Verify full file can still be reconstructed.
	data, err := nodes[0].ReconstructFile("repair-file-1")
	if err != nil {
		t.Fatalf("reconstruct after repair: %v", err)
	}
	if !bytes.Equal(data, ciphertext) {
		t.Fatalf("data mismatch after repair: got %d bytes, want %d", len(data), len(ciphertext))
	}
}

func TestRepairLoop_NoMissingShards(t *testing.T) {
	nodes := testNodes(t, 5)
	for i := 1; i < len(nodes); i++ {
		if _, err := nodes[i-1].Ping(nodes[i].Addr()); err != nil {
			t.Fatalf("ping %d->%d: %v", i-1, i, err)
		}
	}
	time.Sleep(500 * time.Millisecond)

	ciphertext := bytes.Repeat([]byte("HEALTHY-FILE-YAY"), 100)

	_, err := nodes[0].DistributeFile(DistributeFileParams{
		FileID:       "healthy-file",
		FileName:     "ok.bin",
		FileSize:     int64(len(ciphertext)),
		Cipher:       "aes-256-gcm",
		Salt:         []byte("0123456789abcdef0123456789abcdef"),
		Nonce:        []byte("0123456789ab"),
		Ciphertext:   ciphertext,
		DataShards:   4,
		ParityShards: 2,
		OperatorID:   "test-op",
	})
	if err != nil {
		t.Fatalf("distribute: %v", err)
	}
	time.Sleep(500 * time.Millisecond)

	rl := NewRepairLoop(nodes[0], time.Hour, func() []string {
		return []string{"healthy-file"}
	})

	result := rl.repairCycle()
	if result.ShardsRepaired != 0 {
		t.Fatalf("expected 0 shards repaired for healthy file, got %d", result.ShardsRepaired)
	}
	if len(result.Errors) != 0 {
		t.Fatalf("expected no errors, got %v", result.Errors)
	}
	if result.ShardsChecked != 6 {
		t.Fatalf("expected 6 shards checked, got %d", result.ShardsChecked)
	}
}

func TestRepairLoop_InsufficientShards(t *testing.T) {
	nodes := testNodes(t, 5)
	for i := 1; i < len(nodes); i++ {
		if _, err := nodes[i-1].Ping(nodes[i].Addr()); err != nil {
			t.Fatalf("ping %d->%d: %v", i-1, i, err)
		}
	}
	time.Sleep(500 * time.Millisecond)

	ciphertext := bytes.Repeat([]byte("DOOMED-FILE-DATA"), 100)

	_, err := nodes[0].DistributeFile(DistributeFileParams{
		FileID:       "doomed-file",
		FileName:     "doomed.bin",
		FileSize:     int64(len(ciphertext)),
		Cipher:       "aes-256-gcm",
		Salt:         []byte("0123456789abcdef0123456789abcdef"),
		Nonce:        []byte("0123456789ab"),
		Ciphertext:   ciphertext,
		DataShards:   4,
		ParityShards: 2,
		OperatorID:   "test-op",
	})
	if err != nil {
		t.Fatalf("distribute: %v", err)
	}
	time.Sleep(500 * time.Millisecond)

	// Delete 3 shards from ALL nodes (exceeds parity tolerance of 2).
	for _, nd := range nodes {
		nd.store.Delete(ShardKey("doomed-file", 0))
		nd.store.Delete(ShardKey("doomed-file", 1))
		nd.store.Delete(ShardKey("doomed-file", 2))
	}

	rl := NewRepairLoop(nodes[0], time.Hour, func() []string {
		return []string{"doomed-file"}
	})

	result := rl.repairCycle()
	if result.ShardsRepaired != 0 {
		t.Fatalf("expected 0 shards repaired when insufficient, got %d", result.ShardsRepaired)
	}
	if len(result.Errors) != 1 {
		t.Fatalf("expected 1 error, got %d: %v", len(result.Errors), result.Errors)
	}
}

func TestRepairLoop_StartStop(t *testing.T) {
	nodes := testNodes(t, 3)
	for i := 1; i < len(nodes); i++ {
		if _, err := nodes[i-1].Ping(nodes[i].Addr()); err != nil {
			t.Fatalf("ping %d->%d: %v", i-1, i, err)
		}
	}

	rl := NewRepairLoop(nodes[0], 100*time.Millisecond, func() []string {
		return nil
	})
	rl.Start()
	// Starting again should be a no-op (no panic).
	rl.Start()
	time.Sleep(250 * time.Millisecond)
	rl.Stop()
	// Stopping again should be a no-op (no panic).
	rl.Stop()
}

func TestRepairLoop_EmptyFileList(t *testing.T) {
	nodes := testNodes(t, 3)
	for i := 1; i < len(nodes); i++ {
		if _, err := nodes[i-1].Ping(nodes[i].Addr()); err != nil {
			t.Fatalf("ping %d->%d: %v", i-1, i, err)
		}
	}

	rl := NewRepairLoop(nodes[0], time.Hour, func() []string {
		return nil
	})

	result := rl.repairCycle()
	if result.FilesChecked != 0 {
		t.Fatalf("expected 0 files checked, got %d", result.FilesChecked)
	}
	if result.ShardsRepaired != 0 {
		t.Fatalf("expected 0 shards repaired, got %d", result.ShardsRepaired)
	}
	if len(result.Errors) != 0 {
		t.Fatalf("expected no errors, got %v", result.Errors)
	}
}
