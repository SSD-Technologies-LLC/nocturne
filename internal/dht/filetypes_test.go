package dht

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func TestShardManifestSerialization(t *testing.T) {
	now := time.Now().Unix()
	m := ShardManifest{
		FileID:       "file-abc-123",
		FileName:     "secret-plans.pdf",
		FileSize:     1048576,
		Cipher:       "noctis-256",
		Salt:         []byte{0x01, 0x02, 0x03, 0x04},
		Nonce:        []byte{0xaa, 0xbb, 0xcc},
		DataShards:   4,
		ParityShards: 2,
		Shards: []ShardInfo{
			{Index: 0, Size: 262144, Checksum: "aabbccdd"},
			{Index: 1, Size: 262144, Checksum: "eeff0011"},
			{Index: 2, Size: 262144, Checksum: "22334455"},
			{Index: 3, Size: 262144, Checksum: "66778899"},
			{Index: 4, Size: 131072, Checksum: "aabb0011"},
			{Index: 5, Size: 131072, Checksum: "ccdd2233"},
		},
		UploadedBy: "operator-xyz",
		CreatedAt:  now,
	}

	// Verify fields.
	if m.FileID != "file-abc-123" {
		t.Errorf("FileID = %q, want %q", m.FileID, "file-abc-123")
	}
	if m.FileName != "secret-plans.pdf" {
		t.Errorf("FileName = %q, want %q", m.FileName, "secret-plans.pdf")
	}
	if m.FileSize != 1048576 {
		t.Errorf("FileSize = %d, want %d", m.FileSize, 1048576)
	}
	if m.Cipher != "noctis-256" {
		t.Errorf("Cipher = %q, want %q", m.Cipher, "noctis-256")
	}
	if m.DataShards != 4 {
		t.Errorf("DataShards = %d, want %d", m.DataShards, 4)
	}
	if m.ParityShards != 2 {
		t.Errorf("ParityShards = %d, want %d", m.ParityShards, 2)
	}
	if len(m.Shards) != 6 {
		t.Fatalf("len(Shards) = %d, want %d", len(m.Shards), 6)
	}

	// Verify TotalShards method.
	if total := m.TotalShards(); total != 6 {
		t.Errorf("TotalShards() = %d, want %d", total, 6)
	}

	// Verify JSON round-trip.
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	var decoded ShardManifest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}

	if decoded.FileID != m.FileID {
		t.Errorf("decoded FileID = %q, want %q", decoded.FileID, m.FileID)
	}
	if decoded.FileName != m.FileName {
		t.Errorf("decoded FileName = %q, want %q", decoded.FileName, m.FileName)
	}
	if decoded.FileSize != m.FileSize {
		t.Errorf("decoded FileSize = %d, want %d", decoded.FileSize, m.FileSize)
	}
	if decoded.TotalShards() != m.TotalShards() {
		t.Errorf("decoded TotalShards() = %d, want %d", decoded.TotalShards(), m.TotalShards())
	}
	if decoded.CreatedAt != m.CreatedAt {
		t.Errorf("decoded CreatedAt = %d, want %d", decoded.CreatedAt, m.CreatedAt)
	}
	if decoded.UploadedBy != m.UploadedBy {
		t.Errorf("decoded UploadedBy = %q, want %q", decoded.UploadedBy, m.UploadedBy)
	}
	if len(decoded.Shards) != len(m.Shards) {
		t.Fatalf("decoded len(Shards) = %d, want %d", len(decoded.Shards), len(m.Shards))
	}
	for i, s := range decoded.Shards {
		if s.Index != m.Shards[i].Index {
			t.Errorf("Shard[%d].Index = %d, want %d", i, s.Index, m.Shards[i].Index)
		}
		if s.Size != m.Shards[i].Size {
			t.Errorf("Shard[%d].Size = %d, want %d", i, s.Size, m.Shards[i].Size)
		}
		if s.Checksum != m.Shards[i].Checksum {
			t.Errorf("Shard[%d].Checksum = %q, want %q", i, s.Checksum, m.Shards[i].Checksum)
		}
	}
}

func TestShardKeySerialization(t *testing.T) {
	// ShardKey must be deterministic: same inputs yield the same NodeID.
	k1 := ShardKey("file-abc", 0)
	k2 := ShardKey("file-abc", 0)
	if k1 != k2 {
		t.Error("ShardKey is not deterministic: same inputs produced different keys")
	}

	// Different shard indices must produce different keys.
	k3 := ShardKey("file-abc", 1)
	if k1 == k3 {
		t.Error("ShardKey returned same key for different shard indices")
	}

	// Different file IDs must produce different keys.
	k4 := ShardKey("file-xyz", 0)
	if k1 == k4 {
		t.Error("ShardKey returned same key for different file IDs")
	}

	// Verify the key matches what PrefixKey would produce directly.
	expected := PrefixKey("shard", fmt.Sprintf("%s:%d", "file-abc", 0))
	if k1 != expected {
		t.Errorf("ShardKey does not match PrefixKey(\"shard\", \"file-abc:0\")")
	}
}

func TestManifestKeyDerivation(t *testing.T) {
	// ManifestKey must be deterministic.
	k1 := ManifestKey("file-abc")
	k2 := ManifestKey("file-abc")
	if k1 != k2 {
		t.Error("ManifestKey is not deterministic: same inputs produced different keys")
	}

	// Different file IDs must produce different keys.
	k3 := ManifestKey("file-xyz")
	if k1 == k3 {
		t.Error("ManifestKey returned same key for different file IDs")
	}

	// ManifestKey and ShardKey for the same file must differ.
	sk := ShardKey("file-abc", 0)
	if k1 == sk {
		t.Error("ManifestKey collides with ShardKey for the same file")
	}

	// Verify the key matches what PrefixKey would produce directly.
	expected := PrefixKey("manifest", "file-abc")
	if k1 != expected {
		t.Errorf("ManifestKey does not match PrefixKey(\"manifest\", \"file-abc\")")
	}
}

func TestFileIndexKeyDerivation(t *testing.T) {
	// FileIndexKey must be deterministic.
	k1 := FileIndexKey("operator-abc")
	k2 := FileIndexKey("operator-abc")
	if k1 != k2 {
		t.Error("FileIndexKey is not deterministic: same inputs produced different keys")
	}

	// Different operator IDs must produce different keys.
	k3 := FileIndexKey("operator-xyz")
	if k1 == k3 {
		t.Error("FileIndexKey returned same key for different operator IDs")
	}

	// FileIndexKey must differ from ManifestKey and ShardKey.
	mk := ManifestKey("operator-abc")
	if k1 == mk {
		t.Error("FileIndexKey collides with ManifestKey for the same ID string")
	}

	sk := ShardKey("operator-abc", 0)
	if k1 == sk {
		t.Error("FileIndexKey collides with ShardKey for the same ID string")
	}

	// Verify the key matches what PrefixKey would produce directly.
	expected := PrefixKey("file_index", "operator-abc")
	if k1 != expected {
		t.Errorf("FileIndexKey does not match PrefixKey(\"file_index\", \"operator-abc\")")
	}
}
