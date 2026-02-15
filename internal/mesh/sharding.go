package mesh

import (
	"fmt"

	"github.com/klauspost/reedsolomon"
)

// ShardData splits data into dataShards + parityShards using Reed-Solomon erasure coding.
// Returns a slice of shards where the first dataShards are data and the rest are parity.
func ShardData(data []byte, dataShards, parityShards int) ([][]byte, error) {
	enc, err := reedsolomon.New(dataShards, parityShards)
	if err != nil {
		return nil, fmt.Errorf("creating reed-solomon encoder: %w", err)
	}

	shards, err := enc.Split(data)
	if err != nil {
		return nil, fmt.Errorf("splitting data into shards: %w", err)
	}

	if err := enc.Encode(shards); err != nil {
		return nil, fmt.Errorf("encoding parity shards: %w", err)
	}

	return shards, nil
}

// ReconstructData reconstructs the original data from available shards.
// Some shards may be nil (lost). The number of non-nil shards must be >= dataShards.
// The result is trimmed to originalSize since Reed-Solomon pads data.
func ReconstructData(shards [][]byte, dataShards, parityShards int, originalSize int) ([]byte, error) {
	enc, err := reedsolomon.New(dataShards, parityShards)
	if err != nil {
		return nil, fmt.Errorf("creating reed-solomon encoder: %w", err)
	}

	if err := enc.Reconstruct(shards); err != nil {
		return nil, fmt.Errorf("reconstructing shards: %w", err)
	}

	ok, err := enc.Verify(shards)
	if err != nil {
		return nil, fmt.Errorf("verifying shards: %w", err)
	}
	if !ok {
		return nil, fmt.Errorf("shard verification failed after reconstruction")
	}

	// Join the data shards back together.
	var result []byte
	for i := 0; i < dataShards; i++ {
		result = append(result, shards[i]...)
	}

	// Trim to original size since RS pads.
	if originalSize > len(result) {
		return nil, fmt.Errorf("original size %d exceeds reconstructed data length %d", originalSize, len(result))
	}

	return result[:originalSize], nil
}
