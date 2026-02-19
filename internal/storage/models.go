// internal/storage/models.go
package storage

type File struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Size       int64  `json:"size"`
	MimeType   string `json:"mime_type,omitempty"`
	Cipher     string `json:"cipher"`
	Salt       []byte `json:"-"`
	Nonce      []byte `json:"-"`
	Blob       []byte `json:"-"`
	RecoveryID string `json:"recovery_id"`
	CreatedAt  int64  `json:"created_at"`
	BlobLen    int64  `json:"-"` // populated by ListFiles via length(blob), avoids loading full blob
}

type RecoveryKey struct {
	ID         string `json:"id"`
	HexKey     string `json:"hex_key"`
	Mnemonic   string `json:"mnemonic,omitempty"`
	EscrowBlob []byte `json:"-"`
	CreatedAt  int64  `json:"created_at"`
}

type Link struct {
	ID           string `json:"id"`
	FileID       string `json:"file_id"`
	Mode         string `json:"mode"`
	PasswordHash []byte `json:"-"`
	ExpiresAt    *int64 `json:"expires_at,omitempty"`
	Burned       bool   `json:"burned"`
	Downloads    int    `json:"downloads"`
	CreatedAt    int64  `json:"created_at"`
}

type Node struct {
	ID          string `json:"id"`
	PublicKey   []byte `json:"-"`
	Address     string `json:"address"`
	MaxStorage  int64  `json:"max_storage"`
	UsedStorage int64  `json:"used_storage"`
	LastSeen    int64  `json:"last_seen"`
	Online      bool   `json:"online"`
}

type Shard struct {
	ID         string `json:"id"`
	FileID     string `json:"file_id"`
	ShardIndex int    `json:"shard_index"`
	NodeID     string `json:"node_id"`
	Size       int64  `json:"size"`
	Checksum   string `json:"checksum"`
}
