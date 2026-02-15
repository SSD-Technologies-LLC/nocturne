package dht

import (
	"sync"
	"testing"
	"time"
)

// makePeer creates a PeerInfo with a deterministic NodeID built from a single
// non-zero byte at position byteIdx with value val. The address is set to the
// given string and LastSeen to time.Now().
func makePeer(byteIdx int, val byte, addr string) PeerInfo {
	var id NodeID
	id[byteIdx] = val
	return PeerInfo{
		ID:       id,
		Address:  addr,
		LastSeen: time.Now(),
	}
}

// TestRoutingTableAddAndFind adds a peer and verifies it appears in ClosestN.
func TestRoutingTableAddAndFind(t *testing.T) {
	var self NodeID
	rt := NewRoutingTable(self, 20)

	peer := makePeer(0, 0x80, "10.0.0.1:4000")
	rt.Add(peer)

	closest := rt.ClosestN(peer.ID, 5)
	if len(closest) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(closest))
	}
	if closest[0].ID != peer.ID {
		t.Fatal("closest peer should be the one we added")
	}
	if closest[0].Address != "10.0.0.1:4000" {
		t.Fatalf("expected address 10.0.0.1:4000, got %s", closest[0].Address)
	}
}

// TestRoutingTableBucketFull fills a bucket to k and verifies that additional
// peers targeting the same bucket are dropped.
func TestRoutingTableBucketFull(t *testing.T) {
	var self NodeID
	k := 3
	rt := NewRoutingTable(self, k)

	// All peers differ in byte 0 with the high bit set, so they all land in
	// bucket 0 (BucketIndex = 0 when the highest bit of XOR is bit 0).
	// We use 0x80 | low nibble to keep them all in bucket 0.
	peers := make([]PeerInfo, k+2)
	for i := 0; i < k+2; i++ {
		var id NodeID
		id[0] = 0x80 // high bit set → bucket 0
		id[1] = byte(i + 1)
		peers[i] = PeerInfo{
			ID:       id,
			Address:  "peer",
			LastSeen: time.Now(),
		}
	}

	for _, p := range peers {
		rt.Add(p)
	}

	if rt.Size() != k {
		t.Fatalf("expected size %d after overfilling bucket, got %d", k, rt.Size())
	}

	// The first k peers should be present; the extras should be dropped.
	all := rt.ClosestN(self, k+2)
	for i := 0; i < k; i++ {
		found := false
		for _, p := range all {
			if p.ID == peers[i].ID {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("expected peer %d to be in table (first k), but it was missing", i)
		}
	}

	// Verify the excess peers are NOT present.
	for i := k; i < k+2; i++ {
		for _, p := range all {
			if p.ID == peers[i].ID {
				t.Fatalf("peer %d should have been dropped (bucket full), but it was found", i)
			}
		}
	}
}

// TestRoutingTableExistingPeerMovesToTail verifies that re-adding an existing
// peer updates its LastSeen and moves it to the tail of the bucket.
func TestRoutingTableExistingPeerMovesToTail(t *testing.T) {
	var self NodeID
	rt := NewRoutingTable(self, 20)

	// Add three peers to the same bucket (bucket 0).
	p1 := makePeer(0, 0x80, "peer1")
	p1.ID[1] = 0x01
	p2 := makePeer(0, 0x80, "peer2")
	p2.ID[1] = 0x02
	p3 := makePeer(0, 0x80, "peer3")
	p3.ID[1] = 0x03

	rt.Add(p1)
	rt.Add(p2)
	rt.Add(p3)

	// Re-add p1 with updated address and later LastSeen.
	updated := PeerInfo{
		ID:       p1.ID,
		Address:  "peer1-updated",
		LastSeen: time.Now().Add(time.Hour),
	}
	rt.Add(updated)

	// Inspect the bucket directly (we are in the same package).
	idx := BucketIndex(self, p1.ID)
	rt.mu.RLock()
	b := rt.buckets[idx]
	lastPeer := b.peers[len(b.peers)-1]
	rt.mu.RUnlock()

	if lastPeer.ID != p1.ID {
		t.Fatal("re-added peer should be at the tail of the bucket")
	}
	if lastPeer.Address != "peer1-updated" {
		t.Fatalf("expected updated address, got %s", lastPeer.Address)
	}
}

// TestRoutingTableClosestNOrdering verifies that ClosestN returns peers
// sorted by ascending XOR distance to the target.
func TestRoutingTableClosestNOrdering(t *testing.T) {
	var self NodeID
	rt := NewRoutingTable(self, 20)

	// Add peers at various distances from a target.
	var target NodeID
	target[0] = 0x40

	// Peer A: distance to target = XOR(0x40, 0x80) = 0xC0 in byte 0
	peerA := makePeer(0, 0x80, "far")
	// Peer B: distance to target = XOR(0x40, 0x41) = 0x01 in byte 0
	peerB := makePeer(0, 0x41, "close")
	// Peer C: distance to target = XOR(0x40, 0x60) = 0x20 in byte 0
	peerC := makePeer(0, 0x60, "mid")

	rt.Add(peerA)
	rt.Add(peerB)
	rt.Add(peerC)

	closest := rt.ClosestN(target, 3)
	if len(closest) != 3 {
		t.Fatalf("expected 3 peers, got %d", len(closest))
	}

	// Expected order: B (0x01), C (0x20), A (0xC0)
	if closest[0].ID != peerB.ID {
		t.Fatal("closest[0] should be peerB (distance 0x01)")
	}
	if closest[1].ID != peerC.ID {
		t.Fatal("closest[1] should be peerC (distance 0x20)")
	}
	if closest[2].ID != peerA.ID {
		t.Fatal("closest[2] should be peerA (distance 0xC0)")
	}

	// Also verify ClosestN with n < total returns only n peers.
	top1 := rt.ClosestN(target, 1)
	if len(top1) != 1 {
		t.Fatalf("expected 1 peer, got %d", len(top1))
	}
	if top1[0].ID != peerB.ID {
		t.Fatal("top-1 closest should be peerB")
	}
}

// TestRoutingTableRemove adds a peer, removes it, and verifies it is gone.
func TestRoutingTableRemove(t *testing.T) {
	var self NodeID
	rt := NewRoutingTable(self, 20)

	peer := makePeer(0, 0x80, "10.0.0.1:4000")
	rt.Add(peer)

	if rt.Size() != 1 {
		t.Fatalf("expected size 1 after add, got %d", rt.Size())
	}

	rt.Remove(peer.ID)

	if rt.Size() != 0 {
		t.Fatalf("expected size 0 after remove, got %d", rt.Size())
	}

	closest := rt.ClosestN(peer.ID, 5)
	if len(closest) != 0 {
		t.Fatal("removed peer should not appear in ClosestN")
	}
}

// TestRoutingTableStaleBuckets verifies that buckets not refreshed within
// maxAge are reported as stale.
func TestRoutingTableStaleBuckets(t *testing.T) {
	var self NodeID
	rt := NewRoutingTable(self, 20)

	// Artificially age all buckets by setting lastRefresh in the past.
	rt.mu.Lock()
	past := time.Now().Add(-2 * time.Hour)
	for i := 0; i < NumBuckets; i++ {
		rt.buckets[i].lastRefresh = past
	}
	rt.mu.Unlock()

	stale := rt.StaleBuckets(1 * time.Hour)
	if len(stale) != NumBuckets {
		t.Fatalf("expected all %d buckets to be stale, got %d", NumBuckets, len(stale))
	}

	// Now add a peer to bucket 0. This should refresh that bucket.
	peer := makePeer(0, 0x80, "refresh")
	rt.Add(peer)

	stale = rt.StaleBuckets(1 * time.Hour)
	if len(stale) != NumBuckets-1 {
		t.Fatalf("expected %d stale buckets after refreshing one, got %d", NumBuckets-1, len(stale))
	}

	// Bucket 0 should NOT be in the stale list.
	for _, idx := range stale {
		if idx == 0 {
			t.Fatal("bucket 0 was refreshed but still reported as stale")
		}
	}
}

// TestRoutingTableSize verifies the Size method reflects adds and removes.
func TestRoutingTableSize(t *testing.T) {
	var self NodeID
	rt := NewRoutingTable(self, 20)

	if rt.Size() != 0 {
		t.Fatalf("expected size 0 for empty table, got %d", rt.Size())
	}

	// Add peers in different buckets.
	p1 := makePeer(0, 0x80, "a") // bucket 0
	p2 := makePeer(0, 0x40, "b") // bucket 1
	p3 := makePeer(0, 0x01, "c") // bucket 7

	rt.Add(p1)
	rt.Add(p2)
	rt.Add(p3)

	if rt.Size() != 3 {
		t.Fatalf("expected size 3, got %d", rt.Size())
	}

	rt.Remove(p2.ID)
	if rt.Size() != 2 {
		t.Fatalf("expected size 2 after remove, got %d", rt.Size())
	}
}

// TestRoutingTableSelfNotAdded verifies that the table ignores attempts to
// add the local node's own ID.
func TestRoutingTableSelfNotAdded(t *testing.T) {
	var self NodeID
	self[0] = 0xAA
	rt := NewRoutingTable(self, 20)

	selfPeer := PeerInfo{
		ID:       self,
		Address:  "localhost:4000",
		LastSeen: time.Now(),
	}
	rt.Add(selfPeer)

	if rt.Size() != 0 {
		t.Fatalf("self should not be added to routing table, but size is %d", rt.Size())
	}
}

// TestRoutingTableConcurrency exercises concurrent Add and ClosestN calls to
// verify there are no data races. Run with -race to detect issues.
func TestRoutingTableConcurrency(t *testing.T) {
	var self NodeID
	rt := NewRoutingTable(self, 20)

	var wg sync.WaitGroup
	const goroutines = 50
	const opsPerGoroutine = 100

	// Half the goroutines add peers, the other half call ClosestN.
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(gid int) {
			defer wg.Done()
			for i := 0; i < opsPerGoroutine; i++ {
				var id NodeID
				id[0] = byte(gid)
				id[1] = byte(i)
				p := PeerInfo{
					ID:       id,
					Address:  "concurrent",
					LastSeen: time.Now(),
				}
				rt.Add(p)
				rt.ClosestN(id, 10)
				rt.Size()
				rt.Remove(id)
			}
		}(g)
	}
	wg.Wait()

	// If we reach this point without a panic or race detector complaint,
	// the concurrency test passes.
}

// TestRoutingTableRemoveNonexistent verifies that removing a peer that does
// not exist is a no-op and does not panic.
func TestRoutingTableRemoveNonexistent(t *testing.T) {
	var self NodeID
	rt := NewRoutingTable(self, 20)

	var unknown NodeID
	unknown[0] = 0xFF

	// Should not panic.
	rt.Remove(unknown)

	if rt.Size() != 0 {
		t.Fatal("size should remain 0 after removing nonexistent peer")
	}
}

// TestRoutingTableClosestNEmpty verifies ClosestN on an empty table returns nil/empty.
func TestRoutingTableClosestNEmpty(t *testing.T) {
	var self NodeID
	rt := NewRoutingTable(self, 20)

	closest := rt.ClosestN(self, 10)
	if len(closest) != 0 {
		t.Fatalf("expected 0 peers from empty table, got %d", len(closest))
	}
}
