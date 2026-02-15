// Package dht provides distributed hash table primitives for the Nocturne P2P
// agent mesh network. It defines 256-bit node identifiers, XOR distance metrics,
// and content key derivation used by the Kademlia-style routing layer.
package dht

import (
	"crypto/ed25519"
	"crypto/sha256"
	"math/bits"
)

// IDLength is the byte length of a NodeID (256 bits).
const IDLength = 32

// NodeID is a 256-bit identifier in the DHT key space.
type NodeID [IDLength]byte

// NodeIDFromPublicKey computes SHA-256 of an Ed25519 public key to produce a
// uniformly distributed NodeID. This ensures the DHT key space is populated
// evenly regardless of key generation patterns.
func NodeIDFromPublicKey(pub ed25519.PublicKey) NodeID {
	return sha256.Sum256(pub)
}

// ContentKey computes the DHT key for a knowledge entry: SHA-256(domain + ":" + entryID).
// This determines which nodes are responsible for storing a given piece of knowledge.
func ContentKey(domain, entryID string) NodeID {
	return sha256.Sum256([]byte(domain + ":" + entryID))
}

// DomainIndexKey computes the DHT key for a domain index: SHA-256("domain_index:" + domain).
// Each domain has a single index key that points to the set of entries in that domain.
func DomainIndexKey(domain string) NodeID {
	return sha256.Sum256([]byte("domain_index:" + domain))
}

// PrefixKey computes a DHT key with a typed prefix: SHA-256(prefix + ":" + id).
// This is the general form used for any typed key derivation in the DHT.
func PrefixKey(prefix, id string) NodeID {
	return sha256.Sum256([]byte(prefix + ":" + id))
}

// XOR returns the XOR distance between two node IDs. In Kademlia, XOR distance
// defines the metric space: d(a,b) = a XOR b. The result is itself a valid
// NodeID-sized value where each byte is the XOR of the corresponding input bytes.
func XOR(a, b NodeID) NodeID {
	var result NodeID
	for i := 0; i < IDLength; i++ {
		result[i] = a[i] ^ b[i]
	}
	return result
}

// DistanceLess returns true if a is strictly closer to target than b by XOR
// distance. Comparison is done byte-by-byte from the most significant byte.
func DistanceLess(target, a, b NodeID) bool {
	da := XOR(target, a)
	db := XOR(target, b)
	for i := 0; i < IDLength; i++ {
		if da[i] != db[i] {
			return da[i] < db[i]
		}
	}
	return false // equal distance
}

// BucketIndex returns the k-bucket index for a peer relative to self.
// The bucket index is defined as 255 minus the position of the highest set bit
// in XOR(self, other). Bucket 0 is the most distant (highest bit differs),
// bucket 255 is the closest (only the lowest bit differs).
// If self and other are identical, BucketIndex returns 255.
func BucketIndex(self, other NodeID) int {
	dist := XOR(self, other)
	for i := 0; i < IDLength; i++ {
		if dist[i] != 0 {
			// bits.LeadingZeros8 returns how many leading zeros in this byte.
			// The global bit position of the highest set bit is i*8 + lz,
			// counting from the most significant bit as position 0.
			lz := bits.LeadingZeros8(dist[i])
			return i*8 + lz
		}
	}
	// IDs are identical; place in the closest bucket.
	return 255
}
