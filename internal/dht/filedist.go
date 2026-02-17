package dht

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/ssd-technologies/nocturne/internal/mesh"
)

// DistributeFileParams holds the parameters for distributing a file.
type DistributeFileParams struct {
	FileID       string
	FileName     string
	FileSize     int64
	Cipher       string
	Salt         []byte
	Nonce        []byte
	Ciphertext   []byte
	DataShards   int
	ParityShards int
	OperatorID   string
}

// DistributeFile erasure-codes ciphertext, stores shards in DHT, creates manifest.
func (n *Node) DistributeFile(p DistributeFileParams) (*ShardManifest, error) {
	// 1. Erasure-code the ciphertext.
	shards, err := mesh.ShardData(p.Ciphertext, p.DataShards, p.ParityShards)
	if err != nil {
		return nil, fmt.Errorf("shard data: %w", err)
	}

	// 2. Store each shard in the DHT.
	var shardInfos []ShardInfo
	for i, shard := range shards {
		checksum := sha256.Sum256(shard)
		checksumHex := hex.EncodeToString(checksum[:])

		if err := n.StoreShard(p.FileID, i, shard); err != nil {
			return nil, fmt.Errorf("store shard %d: %w", i, err)
		}

		shardInfos = append(shardInfos, ShardInfo{
			Index:    i,
			Size:     len(shard),
			Checksum: checksumHex,
		})
	}

	// 3. Build and store the manifest.
	manifest := &ShardManifest{
		FileID:       p.FileID,
		FileName:     p.FileName,
		FileSize:     p.FileSize,
		Cipher:       p.Cipher,
		Salt:         p.Salt,
		Nonce:        p.Nonce,
		DataShards:   p.DataShards,
		ParityShards: p.ParityShards,
		Shards:       shardInfos,
		UploadedBy:   p.OperatorID,
		CreatedAt:    time.Now().Unix(),
	}

	if err := n.StoreManifest(manifest); err != nil {
		return nil, fmt.Errorf("store manifest: %w", err)
	}

	// 4. Update file index.
	if p.OperatorID != "" {
		if err := n.AddToFileIndex(p.OperatorID, p.FileID); err != nil {
			return nil, fmt.Errorf("update file index: %w", err)
		}
	}

	return manifest, nil
}

// ReconstructFile fetches manifest and shards from DHT, reconstructs ciphertext.
func (n *Node) ReconstructFile(fileID string) ([]byte, error) {
	// 1. Fetch manifest.
	manifest, err := n.RetrieveManifest(fileID)
	if err != nil {
		return nil, fmt.Errorf("retrieve manifest: %w", err)
	}

	totalShards := manifest.DataShards + manifest.ParityShards
	shards := make([][]byte, totalShards)

	// 2. Fetch each shard (some may be missing).
	available := 0
	for i := 0; i < totalShards; i++ {
		data, err := n.RetrieveShard(fileID, i)
		if err != nil {
			shards[i] = nil // mark as missing
			continue
		}

		// Verify checksum if we have manifest info.
		if i < len(manifest.Shards) {
			checksum := sha256.Sum256(data)
			if hex.EncodeToString(checksum[:]) != manifest.Shards[i].Checksum {
				shards[i] = nil // corrupted
				continue
			}
		}

		shards[i] = data
		available++
	}

	if available < manifest.DataShards {
		return nil, fmt.Errorf("insufficient shards: have %d, need %d", available, manifest.DataShards)
	}

	// 3. Reconstruct using Reed-Solomon.
	result, err := mesh.ReconstructData(shards, manifest.DataShards, manifest.ParityShards, int(manifest.FileSize))
	if err != nil {
		return nil, fmt.Errorf("reconstruct: %w", err)
	}

	return result, nil
}

// DeleteDistributedFile removes all shards, manifest, and file index entry.
func (n *Node) DeleteDistributedFile(fileID, operatorID string) error {
	// Fetch manifest to know shard count.
	manifest, err := n.RetrieveManifest(fileID)
	if err != nil {
		// If manifest gone, still try to clean up index.
		if operatorID != "" {
			_ = n.RemoveFromFileIndex(operatorID, fileID)
		}
		return nil
	}

	// Delete each shard from local store.
	for i := 0; i < manifest.TotalShards(); i++ {
		key := ShardKey(fileID, i)
		if err := n.store.Delete(key); err != nil {
			return fmt.Errorf("delete shard %d: %w", i, err)
		}
	}

	// Delete manifest from local store.
	key := ManifestKey(fileID)
	if err := n.store.Delete(key); err != nil {
		return fmt.Errorf("delete manifest: %w", err)
	}

	// Update file index.
	if operatorID != "" {
		if err := n.RemoveFromFileIndex(operatorID, fileID); err != nil {
			return fmt.Errorf("remove from file index: %w", err)
		}
	}

	return nil
}
