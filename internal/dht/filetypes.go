package dht

import "fmt"

// ShardManifest describes a file distributed across DHT peers via erasure coding.
// It contains all metadata needed to locate and reassemble the file's shards.
type ShardManifest struct {
	FileID       string      `json:"file_id"`
	FileName     string      `json:"file_name"`
	FileSize     int64       `json:"file_size"`
	Cipher       string      `json:"cipher"`
	Salt         []byte      `json:"salt"`
	Nonce        []byte      `json:"nonce"`
	DataShards   int         `json:"data_shards"`
	ParityShards int         `json:"parity_shards"`
	Shards       []ShardInfo `json:"shards"`
	UploadedBy   string      `json:"uploaded_by"`
	CreatedAt    int64       `json:"created_at"`
}

// TotalShards returns the total number of shards (data + parity).
func (m *ShardManifest) TotalShards() int {
	return m.DataShards + m.ParityShards
}

// ShardInfo describes a single erasure-coded shard of a distributed file.
type ShardInfo struct {
	Index    int    `json:"index"`
	Size     int    `json:"size"`
	Checksum string `json:"checksum"` // SHA-256 hex
}

// FileIndex stores the list of file IDs belonging to an operator.
// It is stored in the DHT keyed by FileIndexKey(operatorID).
type FileIndex struct {
	OperatorID string   `json:"operator_id"`
	FileIDs    []string `json:"file_ids"`
}

// ShardKey computes the DHT key for a specific shard of a file.
// The key is derived as SHA-256("shard:" + fileID + ":" + shardIndex).
func ShardKey(fileID string, shardIndex int) NodeID {
	return PrefixKey("shard", fmt.Sprintf("%s:%d", fileID, shardIndex))
}

// ManifestKey computes the DHT key for a file's shard manifest.
// The key is derived as SHA-256("manifest:" + fileID).
func ManifestKey(fileID string) NodeID {
	return PrefixKey("manifest", fileID)
}

// FileIndexKey computes the DHT key for an operator's file index.
// The key is derived as SHA-256("file_index:" + operatorID).
func FileIndexKey(operatorID string) NodeID {
	return PrefixKey("file_index", operatorID)
}
