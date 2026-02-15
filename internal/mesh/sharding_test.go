package mesh

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestShardAndReconstruct(t *testing.T) {
	data := []byte("Hello, Nocturne mesh network! This is a test of erasure coding.")
	dataShards := 4
	parityShards := 2

	shards, err := ShardData(data, dataShards, parityShards)
	if err != nil {
		t.Fatalf("ShardData failed: %v", err)
	}

	if len(shards) != dataShards+parityShards {
		t.Fatalf("expected %d shards, got %d", dataShards+parityShards, len(shards))
	}

	// Reconstruct with all shards present.
	reconstructed, err := ReconstructData(shards, dataShards, parityShards, len(data))
	if err != nil {
		t.Fatalf("ReconstructData failed: %v", err)
	}

	if !bytes.Equal(data, reconstructed) {
		t.Fatalf("reconstructed data does not match original")
	}
}

func TestShardAndReconstruct_WithLoss(t *testing.T) {
	data := []byte("Hello, Nocturne mesh network! This is a test of erasure coding with loss.")
	dataShards := 4
	parityShards := 2

	shards, err := ShardData(data, dataShards, parityShards)
	if err != nil {
		t.Fatalf("ShardData failed: %v", err)
	}

	// Lose 2 parity shards (indices 4 and 5).
	shards[4] = nil
	shards[5] = nil

	reconstructed, err := ReconstructData(shards, dataShards, parityShards, len(data))
	if err != nil {
		t.Fatalf("ReconstructData failed: %v", err)
	}

	if !bytes.Equal(data, reconstructed) {
		t.Fatalf("reconstructed data does not match original after parity loss")
	}
}

func TestShardAndReconstruct_DataShardLoss(t *testing.T) {
	data := []byte("Testing reconstruction after losing data shards, not just parity.")
	dataShards := 4
	parityShards := 2

	shards, err := ShardData(data, dataShards, parityShards)
	if err != nil {
		t.Fatalf("ShardData failed: %v", err)
	}

	// Lose 1 data shard and 1 parity shard.
	shards[0] = nil
	shards[5] = nil

	reconstructed, err := ReconstructData(shards, dataShards, parityShards, len(data))
	if err != nil {
		t.Fatalf("ReconstructData failed: %v", err)
	}

	if !bytes.Equal(data, reconstructed) {
		t.Fatalf("reconstructed data does not match original after mixed loss")
	}
}

func TestShardAndReconstruct_TooMuchLoss(t *testing.T) {
	data := []byte("This test should fail because too many shards are lost.")
	dataShards := 4
	parityShards := 2

	shards, err := ShardData(data, dataShards, parityShards)
	if err != nil {
		t.Fatalf("ShardData failed: %v", err)
	}

	// Lose 3 shards (more than parityShards).
	shards[0] = nil
	shards[1] = nil
	shards[4] = nil

	_, err = ReconstructData(shards, dataShards, parityShards, len(data))
	if err == nil {
		t.Fatal("expected error when too many shards are lost, got nil")
	}
}

func TestShardData_SmallPayload(t *testing.T) {
	data := []byte("hi")
	dataShards := 4
	parityShards := 2

	shards, err := ShardData(data, dataShards, parityShards)
	if err != nil {
		t.Fatalf("ShardData failed for small data: %v", err)
	}

	if len(shards) != dataShards+parityShards {
		t.Fatalf("expected %d shards, got %d", dataShards+parityShards, len(shards))
	}

	reconstructed, err := ReconstructData(shards, dataShards, parityShards, len(data))
	if err != nil {
		t.Fatalf("ReconstructData failed for small data: %v", err)
	}

	if !bytes.Equal(data, reconstructed) {
		t.Fatalf("reconstructed small data does not match original")
	}
}

func TestShardData_LargePayload(t *testing.T) {
	// 1MB of random data.
	data := make([]byte, 1024*1024)
	if _, err := rand.Read(data); err != nil {
		t.Fatalf("failed to generate random data: %v", err)
	}

	dataShards := 4
	parityShards := 2

	shards, err := ShardData(data, dataShards, parityShards)
	if err != nil {
		t.Fatalf("ShardData failed for large data: %v", err)
	}

	if len(shards) != dataShards+parityShards {
		t.Fatalf("expected %d shards, got %d", dataShards+parityShards, len(shards))
	}

	// Lose 1 shard and still reconstruct.
	shards[3] = nil

	reconstructed, err := ReconstructData(shards, dataShards, parityShards, len(data))
	if err != nil {
		t.Fatalf("ReconstructData failed for large data: %v", err)
	}

	if !bytes.Equal(data, reconstructed) {
		t.Fatalf("reconstructed large data does not match original")
	}
}
