package dht

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
)

// Sentinel errors for not-found conditions.
var (
	ErrShardNotFound    = errors.New("shard not found")
	ErrManifestNotFound = errors.New("manifest not found")
)

// fileIndexMu protects the read-modify-write cycle in updateFileIndex.
var fileIndexMu sync.Mutex

// StoreShard stores a raw shard byte slice at the DHT key for fileID:shardIndex.
// The data is JSON-encoded (base64) before storage so it survives the DHT's
// JSON-based network replication protocol.
func (n *Node) StoreShard(fileID string, shardIndex int, data []byte) error {
	key := ShardKey(fileID, shardIndex)
	encoded, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("encode shard: %w", err)
	}
	return n.Store(key, encoded)
}

// RetrieveShard fetches a shard from the DHT by fileID and shardIndex.
func (n *Node) RetrieveShard(fileID string, shardIndex int) ([]byte, error) {
	key := ShardKey(fileID, shardIndex)
	data, err := n.FindValue(key)
	if err != nil {
		return nil, fmt.Errorf("find shard %s:%d: %w", fileID, shardIndex, err)
	}
	if data == nil {
		return nil, fmt.Errorf("shard %s:%d: %w", fileID, shardIndex, ErrShardNotFound)
	}
	var decoded []byte
	if err := json.Unmarshal(data, &decoded); err != nil {
		return nil, fmt.Errorf("decode shard %s:%d: %w", fileID, shardIndex, err)
	}
	return decoded, nil
}

// StoreManifest stores a ShardManifest as JSON in the DHT.
func (n *Node) StoreManifest(m *ShardManifest) error {
	data, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("marshal manifest: %w", err)
	}
	key := ManifestKey(m.FileID)
	return n.Store(key, data)
}

// RetrieveManifest fetches a ShardManifest from the DHT.
func (n *Node) RetrieveManifest(fileID string) (*ShardManifest, error) {
	key := ManifestKey(fileID)
	data, err := n.FindValue(key)
	if err != nil {
		return nil, fmt.Errorf("find manifest %s: %w", fileID, err)
	}
	if data == nil {
		return nil, fmt.Errorf("manifest %s: %w", fileID, ErrManifestNotFound)
	}
	var m ShardManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("unmarshal manifest: %w", err)
	}
	return &m, nil
}

// AddToFileIndex adds a file ID to the operator's file index in the DHT.
func (n *Node) AddToFileIndex(operatorID, fileID string) error {
	return n.updateFileIndex(operatorID, fileID, true)
}

// RemoveFromFileIndex removes a file ID from the operator's file index.
func (n *Node) RemoveFromFileIndex(operatorID, fileID string) error {
	return n.updateFileIndex(operatorID, fileID, false)
}

// GetFileIndex retrieves the file index for an operator.
func (n *Node) GetFileIndex(operatorID string) (*FileIndex, error) {
	key := FileIndexKey(operatorID)
	data, err := n.FindValue(key)
	if err != nil {
		return nil, fmt.Errorf("find file index: %w", err)
	}
	if data == nil {
		return &FileIndex{OperatorID: operatorID}, nil
	}
	var index FileIndex
	if err := json.Unmarshal(data, &index); err != nil {
		return nil, fmt.Errorf("unmarshal file index: %w", err)
	}
	return &index, nil
}

func (n *Node) updateFileIndex(operatorID, fileID string, add bool) error {
	fileIndexMu.Lock()
	defer fileIndexMu.Unlock()

	key := FileIndexKey(operatorID)
	data, err := n.FindValue(key)
	if err != nil {
		return fmt.Errorf("find file index for %s: %w", operatorID, err)
	}

	var index FileIndex
	if data != nil {
		if err := json.Unmarshal(data, &index); err != nil {
			return fmt.Errorf("unmarshal file index for %s: %w", operatorID, err)
		}
	}
	index.OperatorID = operatorID

	if add {
		for _, id := range index.FileIDs {
			if id == fileID {
				return nil // already present
			}
		}
		index.FileIDs = append(index.FileIDs, fileID)
	} else {
		filtered := index.FileIDs[:0]
		for _, id := range index.FileIDs {
			if id != fileID {
				filtered = append(filtered, id)
			}
		}
		index.FileIDs = filtered
	}

	indexData, err := json.Marshal(index)
	if err != nil {
		return err
	}
	return n.Store(key, indexData)
}
