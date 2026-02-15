// Package dht — routing table for the Kademlia-style DHT.
//
// A RoutingTable maintains 256 k-buckets, one for each possible bit position
// where the local node's ID and a remote node's ID first differ. Each bucket
// holds at most k peers. Standard Kademlia eviction rules apply: long-lived
// contacts are preferred, and new contacts are dropped when a bucket is full.
package dht

import (
	"sort"
	"sync"
	"time"
)

// NumBuckets is the number of k-buckets in the routing table (one per bit of
// the 256-bit ID space).
const NumBuckets = 256

// PeerInfo describes a known peer in the DHT.
type PeerInfo struct {
	ID         NodeID
	Address    string
	PublicKey  []byte
	OperatorID string
	LastSeen   time.Time
}

// bucket is a single k-bucket in the routing table.
type bucket struct {
	peers       []PeerInfo
	lastRefresh time.Time
}

// RoutingTable is a Kademlia routing table with 256 k-buckets.
type RoutingTable struct {
	mu      sync.RWMutex
	self    NodeID
	k       int
	buckets [NumBuckets]*bucket
}

// NewRoutingTable creates a routing table for the given local node ID with
// bucket capacity k. Each bucket starts with an empty peer list and the
// current time as last refresh.
func NewRoutingTable(self NodeID, k int) *RoutingTable {
	rt := &RoutingTable{
		self: self,
		k:    k,
	}
	now := time.Now()
	for i := 0; i < NumBuckets; i++ {
		rt.buckets[i] = &bucket{
			peers:       make([]PeerInfo, 0),
			lastRefresh: now,
		}
	}
	return rt
}

// Self returns the local node's ID.
func (rt *RoutingTable) Self() NodeID {
	return rt.self
}

// Add inserts a peer into the appropriate k-bucket.
//
// Kademlia rules:
//   - If the peer's ID equals our own, it is silently ignored.
//   - If the peer already exists in the bucket, it is moved to the tail
//     (most recently seen position) and its metadata is updated.
//   - If the bucket is not full, the peer is appended to the tail.
//   - If the bucket is full, the new peer is DROPPED (existing long-lived
//     contacts are preferred).
func (rt *RoutingTable) Add(peer PeerInfo) {
	if peer.ID == rt.self {
		return
	}

	idx := BucketIndex(rt.self, peer.ID)

	rt.mu.Lock()
	defer rt.mu.Unlock()

	b := rt.buckets[idx]

	// Check if the peer already exists in this bucket.
	for i, p := range b.peers {
		if p.ID == peer.ID {
			// Remove from current position.
			b.peers = append(b.peers[:i], b.peers[i+1:]...)
			// Append to tail (most recently seen).
			b.peers = append(b.peers, peer)
			b.lastRefresh = time.Now()
			return
		}
	}

	// Peer not in bucket. Add only if bucket has room.
	if len(b.peers) < rt.k {
		b.peers = append(b.peers, peer)
		b.lastRefresh = time.Now()
	}
	// Otherwise, drop the new peer (prefer existing long-lived contacts).
}

// Remove deletes a peer by its NodeID from the routing table.
func (rt *RoutingTable) Remove(id NodeID) {
	idx := BucketIndex(rt.self, id)

	rt.mu.Lock()
	defer rt.mu.Unlock()

	b := rt.buckets[idx]
	for i, p := range b.peers {
		if p.ID == id {
			b.peers = append(b.peers[:i], b.peers[i+1:]...)
			return
		}
	}
}

// ClosestN returns up to n peers closest to the target NodeID, sorted by
// ascending XOR distance.
func (rt *RoutingTable) ClosestN(target NodeID, n int) []PeerInfo {
	rt.mu.RLock()
	// Collect all peers.
	var all []PeerInfo
	for _, b := range rt.buckets {
		all = append(all, b.peers...)
	}
	rt.mu.RUnlock()

	// Sort by XOR distance to target.
	sort.Slice(all, func(i, j int) bool {
		return DistanceLess(target, all[i].ID, all[j].ID)
	})

	if len(all) > n {
		all = all[:n]
	}
	return all
}

// StaleBuckets returns the indices of all buckets that have not been refreshed
// within the given maxAge duration.
func (rt *RoutingTable) StaleBuckets(maxAge time.Duration) []int {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	cutoff := time.Now().Add(-maxAge)
	var stale []int
	for i, b := range rt.buckets {
		if b.lastRefresh.Before(cutoff) {
			stale = append(stale, i)
		}
	}
	return stale
}

// Size returns the total number of peers across all buckets.
func (rt *RoutingTable) Size() int {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	total := 0
	for _, b := range rt.buckets {
		total += len(b.peers)
	}
	return total
}
