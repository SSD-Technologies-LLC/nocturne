package dht

import (
	"crypto/ed25519"
	"crypto/sha256"
	"testing"
)

func TestNodeIDFromPublicKey(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key: %v", err)
	}

	id := NodeIDFromPublicKey(pub)

	if len(id) != IDLength {
		t.Fatalf("expected NodeID length %d, got %d", IDLength, len(id))
	}

	expected := sha256.Sum256(pub)
	if id != expected {
		t.Fatal("NodeID should equal SHA-256 of public key")
	}

	// Same key should produce the same ID.
	id2 := NodeIDFromPublicKey(pub)
	if id != id2 {
		t.Fatal("same public key should produce the same NodeID")
	}

	// Different key should produce a different ID.
	pub2, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("failed to generate second ed25519 key: %v", err)
	}
	id3 := NodeIDFromPublicKey(pub2)
	if id == id3 {
		t.Fatal("different public keys should produce different NodeIDs")
	}
}

func TestXORDistance(t *testing.T) {
	var a, b NodeID
	a[0] = 0xFF
	b[0] = 0x0F

	result := XOR(a, b)

	if result[0] != 0xF0 {
		t.Fatalf("expected XOR first byte 0xF0, got 0x%02X", result[0])
	}

	// All other bytes should be zero.
	for i := 1; i < IDLength; i++ {
		if result[i] != 0x00 {
			t.Fatalf("expected XOR byte %d to be 0x00, got 0x%02X", i, result[i])
		}
	}
}

func TestXORDistance_SameID(t *testing.T) {
	var a NodeID
	a[0] = 0xAB
	a[15] = 0xCD

	result := XOR(a, a)

	for i := 0; i < IDLength; i++ {
		if result[i] != 0x00 {
			t.Fatalf("XOR of identical IDs should be zero, byte %d = 0x%02X", i, result[i])
		}
	}
}

func TestXORDistance_Symmetry(t *testing.T) {
	var a, b NodeID
	a[0] = 0x12
	a[5] = 0x34
	b[0] = 0x56
	b[5] = 0x78

	if XOR(a, b) != XOR(b, a) {
		t.Fatal("XOR distance should be symmetric: d(a,b) == d(b,a)")
	}
}

func TestDistanceLess(t *testing.T) {
	var target, closer, farther NodeID
	target[0] = 0x00
	closer[0] = 0x01  // distance = 0x01
	farther[0] = 0x80 // distance = 0x80

	if !DistanceLess(target, closer, farther) {
		t.Fatal("closer node should be less than farther node")
	}

	if DistanceLess(target, farther, closer) {
		t.Fatal("farther node should not be less than closer node")
	}
}

func TestDistanceLessEqual(t *testing.T) {
	var target, a NodeID
	target[0] = 0x00
	a[0] = 0x42

	// Same distance should return false (not strictly less).
	if DistanceLess(target, a, a) {
		t.Fatal("equal distance should return false")
	}
}

func TestDistanceLess_MultiByteComparison(t *testing.T) {
	var target, a, b NodeID
	// Both have the same first byte distance, differ in second byte.
	target[0] = 0x00
	a[0] = 0x10
	a[1] = 0x01 // distance byte 0 = 0x10, byte 1 = 0x01
	b[0] = 0x10
	b[1] = 0xFF // distance byte 0 = 0x10, byte 1 = 0xFF

	if !DistanceLess(target, a, b) {
		t.Fatal("a should be closer when first bytes tie and second byte is smaller")
	}
}

func TestBucketIndex_HighBitDiffers(t *testing.T) {
	var self, other NodeID
	other[0] = 0x80 // highest bit set → bucket 0 (most distant)

	bucket := BucketIndex(self, other)
	if bucket != 0 {
		t.Fatalf("expected bucket 0 for 0x80 prefix, got %d", bucket)
	}
}

func TestBucketIndex_LowBitDiffers(t *testing.T) {
	var self, other NodeID
	other[IDLength-1] = 0x01 // only lowest bit set → bucket 255 (closest)

	bucket := BucketIndex(self, other)
	if bucket != 255 {
		t.Fatalf("expected bucket 255 for lowest bit difference, got %d", bucket)
	}
}

func TestBucketIndex_SameID(t *testing.T) {
	var self NodeID
	self[0] = 0xAA
	self[15] = 0xBB

	bucket := BucketIndex(self, self)
	if bucket != 255 {
		t.Fatalf("expected bucket 255 for identical IDs, got %d", bucket)
	}
}

func TestBucketIndex_VariousPositions(t *testing.T) {
	tests := []struct {
		name    string
		byteIdx int
		bitVal  byte
		want    int
	}{
		{"byte0_bit7", 0, 0x80, 0},   // bit 0 from MSB
		{"byte0_bit6", 0, 0x40, 1},   // bit 1 from MSB
		{"byte0_bit0", 0, 0x01, 7},   // bit 7 from MSB
		{"byte1_bit7", 1, 0x80, 8},   // bit 8 from MSB
		{"byte31_bit0", 31, 0x01, 255}, // last bit
		{"byte15_bit4", 15, 0x10, 123}, // 15*8 + 3 leading zeros of 0x10
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var self, other NodeID
			other[tt.byteIdx] = tt.bitVal

			got := BucketIndex(self, other)
			if got != tt.want {
				t.Fatalf("expected bucket %d, got %d", tt.want, got)
			}
		})
	}
}

func TestContentKey(t *testing.T) {
	k1 := ContentKey("security", "vuln-001")
	k2 := ContentKey("security", "vuln-001")

	if k1 != k2 {
		t.Fatal("same inputs should produce the same content key")
	}

	k3 := ContentKey("security", "vuln-002")
	if k1 == k3 {
		t.Fatal("different entry IDs should produce different content keys")
	}

	k4 := ContentKey("finance", "vuln-001")
	if k1 == k4 {
		t.Fatal("different domains should produce different content keys")
	}

	// Verify it matches SHA-256(domain + ":" + entryID).
	expected := sha256.Sum256([]byte("security:vuln-001"))
	if k1 != expected {
		t.Fatal("ContentKey should equal SHA-256 of domain:entryID")
	}
}

func TestDomainIndexKey(t *testing.T) {
	k1 := DomainIndexKey("security")
	k2 := DomainIndexKey("security")

	if k1 != k2 {
		t.Fatal("same domain should produce the same index key")
	}

	k3 := DomainIndexKey("finance")
	if k1 == k3 {
		t.Fatal("different domains should produce different index keys")
	}

	// Verify it uses the "domain_index:" prefix.
	expected := sha256.Sum256([]byte("domain_index:security"))
	if k1 != expected {
		t.Fatal("DomainIndexKey should equal SHA-256 of domain_index:domain")
	}
}

func TestPrefixKey(t *testing.T) {
	k1 := PrefixKey("task", "abc-123")
	k2 := PrefixKey("task", "abc-123")

	if k1 != k2 {
		t.Fatal("same prefix and ID should produce the same key")
	}

	k3 := PrefixKey("vote", "abc-123")
	if k1 == k3 {
		t.Fatal("different prefixes should produce different keys")
	}

	k4 := PrefixKey("task", "xyz-789")
	if k1 == k4 {
		t.Fatal("different IDs should produce different keys")
	}

	// Verify it uses the given prefix.
	expected := sha256.Sum256([]byte("task:abc-123"))
	if k1 != expected {
		t.Fatal("PrefixKey should equal SHA-256 of prefix:id")
	}
}

func TestPrefixKey_MatchesDomainIndexKey(t *testing.T) {
	// DomainIndexKey is a special case of PrefixKey with prefix "domain_index".
	pk := PrefixKey("domain_index", "security")
	dk := DomainIndexKey("security")

	if pk != dk {
		t.Fatal("PrefixKey with 'domain_index' prefix should match DomainIndexKey")
	}
}
