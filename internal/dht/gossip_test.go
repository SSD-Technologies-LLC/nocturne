package dht

import (
	"encoding/json"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// setupGossipCluster creates n nodes, each with a gossiper, and connects them
// according to the provided adjacency list. adj[i] contains the indices of
// nodes that node i should be connected to (via Ping).
func setupGossipCluster(t *testing.T, n int, adj map[int][]int) ([]*Node, []*Gossiper) {
	t.Helper()
	nodes := testNodes(t, n)
	gossipers := make([]*Gossiper, n)

	for i, node := range nodes {
		g := NewGossiper(node)
		node.SetGossiper(g)
		gossipers[i] = g
	}

	// Connect nodes according to adjacency list.
	for from, targets := range adj {
		for _, to := range targets {
			if _, err := nodes[from].Ping(nodes[to].Addr()); err != nil {
				t.Fatalf("ping %d->%d: %v", from, to, err)
			}
		}
	}

	// Wait for all connections to establish.
	time.Sleep(100 * time.Millisecond)

	return nodes, gossipers
}

func TestGossipBroadcastReachesAll(t *testing.T) {
	// 4-node chain: A(0) <-> B(1) <-> C(2) <-> D(3)
	adj := map[int][]int{
		0: {1},
		1: {2},
		2: {3},
	}
	nodes, gossipers := setupGossipCluster(t, 4, adj)
	_ = nodes

	// Track which nodes received the gossip.
	var mu sync.Mutex
	received := make(map[int]bool)

	for i := 1; i < 4; i++ {
		idx := i
		gossipers[idx].OnGossip(GossipTrustCert, func(msg *GossipMessage) {
			mu.Lock()
			received[idx] = true
			mu.Unlock()
		})
	}

	// Node A broadcasts a trust cert gossip.
	data, _ := json.Marshal(map[string]string{"cert": "test-trust-cert"})
	if err := gossipers[0].Broadcast(GossipTrustCert, data); err != nil {
		t.Fatalf("broadcast: %v", err)
	}

	// Wait for propagation through the chain.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		allReceived := received[1] && received[2] && received[3]
		mu.Unlock()
		if allReceived {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()
	t.Fatalf("not all nodes received gossip: B=%v C=%v D=%v",
		received[1], received[2], received[3])
}

func TestGossipDeduplication(t *testing.T) {
	// 3-node triangle: A(0) <-> B(1), A(0) <-> C(2), B(1) <-> C(2)
	adj := map[int][]int{
		0: {1, 2},
		1: {2},
	}
	_, gossipers := setupGossipCluster(t, 3, adj)

	// Count how many times each node receives the gossip.
	var countB, countC atomic.Int32

	gossipers[1].OnGossip(GossipRevocation, func(msg *GossipMessage) {
		countB.Add(1)
	})
	gossipers[2].OnGossip(GossipRevocation, func(msg *GossipMessage) {
		countC.Add(1)
	})

	// A broadcasts.
	data, _ := json.Marshal(map[string]string{"revoke": "agent-123"})
	if err := gossipers[0].Broadcast(GossipRevocation, data); err != nil {
		t.Fatalf("broadcast: %v", err)
	}

	// Wait for propagation.
	time.Sleep(2 * time.Second)

	// Each node should receive the gossip exactly once.
	if got := countB.Load(); got != 1 {
		t.Errorf("B received gossip %d times, want 1", got)
	}
	if got := countC.Load(); got != 1 {
		t.Errorf("C received gossip %d times, want 1", got)
	}
}

func TestGossipMaxHops(t *testing.T) {
	// 5-node chain: A(0) <-> B(1) <-> C(2) <-> D(3) <-> E(4)
	adj := map[int][]int{
		0: {1},
		1: {2},
		2: {3},
		3: {4},
	}
	_, gossipers := setupGossipCluster(t, 5, adj)

	// Set max hops to 2 on the originating gossiper.
	gossipers[0].maxHops = 2

	var mu sync.Mutex
	received := make(map[int]bool)

	for i := 1; i < 5; i++ {
		idx := i
		gossipers[idx].OnGossip(GossipQuarantine, func(msg *GossipMessage) {
			mu.Lock()
			received[idx] = true
			mu.Unlock()
		})
	}

	// A broadcasts with maxHops=2.
	data, _ := json.Marshal(map[string]string{"quarantine": "node-x"})
	if err := gossipers[0].Broadcast(GossipQuarantine, data); err != nil {
		t.Fatalf("broadcast: %v", err)
	}

	// Wait for propagation.
	time.Sleep(2 * time.Second)

	mu.Lock()
	defer mu.Unlock()

	// B (hop 1) and C (hop 2) should receive it.
	if !received[1] {
		t.Error("B (hop 1) did not receive gossip, expected it to")
	}
	if !received[2] {
		t.Error("C (hop 2) did not receive gossip, expected it to")
	}
	// D (hop 3) and E (hop 4) should NOT receive it.
	if received[3] {
		t.Error("D (hop 3) received gossip, expected it NOT to")
	}
	if received[4] {
		t.Error("E (hop 4) received gossip, expected it NOT to")
	}
}

func TestGossipHandler(t *testing.T) {
	// 2 nodes: A(0) <-> B(1)
	adj := map[int][]int{
		0: {1},
	}
	_, gossipers := setupGossipCluster(t, 2, adj)

	// Register a handler for GossipTrustCert on B.
	var receivedData json.RawMessage
	var receivedType GossipType
	done := make(chan struct{})

	gossipers[1].OnGossip(GossipTrustCert, func(msg *GossipMessage) {
		receivedData = msg.Data
		receivedType = msg.GossipType
		close(done)
	})

	// A broadcasts a trust cert.
	cert := map[string]string{
		"subject":  "agent-456",
		"issuer":   "operator-1",
		"trust":    "high",
	}
	data, _ := json.Marshal(cert)
	if err := gossipers[0].Broadcast(GossipTrustCert, data); err != nil {
		t.Fatalf("broadcast: %v", err)
	}

	// Wait for handler to fire.
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("handler not called within timeout")
	}

	// Verify the received data.
	if receivedType != GossipTrustCert {
		t.Errorf("received type = %q, want %q", receivedType, GossipTrustCert)
	}

	var got map[string]string
	if err := json.Unmarshal(receivedData, &got); err != nil {
		t.Fatalf("unmarshal received data: %v", err)
	}
	if got["subject"] != "agent-456" {
		t.Errorf("subject = %q, want %q", got["subject"], "agent-456")
	}
	if got["issuer"] != "operator-1" {
		t.Errorf("issuer = %q, want %q", got["issuer"], "operator-1")
	}
}

func TestGossipPruneSeen(t *testing.T) {
	// Create a single node with a gossiper.
	nodes := testNodes(t, 1)
	g := NewGossiper(nodes[0])

	// Set a very short TTL for testing.
	g.seenTTL = 50 * time.Millisecond

	// Add some entries to the seen set.
	g.markSeen("msg-1")
	g.markSeen("msg-2")
	g.markSeen("msg-3")

	// They should all be seen.
	if !g.hasSeen("msg-1") || !g.hasSeen("msg-2") || !g.hasSeen("msg-3") {
		t.Fatal("entries should be seen before TTL expires")
	}

	// Wait for TTL to expire.
	time.Sleep(100 * time.Millisecond)

	// Prune should remove all 3.
	count := g.PruneSeen()
	if count != 3 {
		t.Errorf("PruneSeen returned %d, want 3", count)
	}

	// Verify they are gone.
	if g.hasSeen("msg-1") || g.hasSeen("msg-2") || g.hasSeen("msg-3") {
		t.Error("entries should not be seen after prune")
	}
}

func TestGossipDoesNotSendBackToOrigin(t *testing.T) {
	// 3-node chain: A(0) <-> B(1) <-> C(2)
	// A broadcasts. B should forward to C but NOT back to A.
	// We verify A's handler is never called (since A is the origin).
	adj := map[int][]int{
		0: {1},
		1: {2},
	}
	_, gossipers := setupGossipCluster(t, 3, adj)

	var originReceived atomic.Int32
	var cReceived atomic.Int32

	gossipers[0].OnGossip(GossipAnomalyReport, func(msg *GossipMessage) {
		originReceived.Add(1)
	})
	gossipers[2].OnGossip(GossipAnomalyReport, func(msg *GossipMessage) {
		cReceived.Add(1)
	})

	// A broadcasts.
	data, _ := json.Marshal(map[string]string{"anomaly": "suspicious-pattern"})
	if err := gossipers[0].Broadcast(GossipAnomalyReport, data); err != nil {
		t.Fatalf("broadcast: %v", err)
	}

	// Wait for propagation.
	time.Sleep(2 * time.Second)

	// C should have received it (via B).
	if got := cReceived.Load(); got != 1 {
		t.Errorf("C received gossip %d times, want 1", got)
	}

	// A (origin) should NOT have received it via its handler, because:
	// 1. A marked the message as seen before broadcasting.
	// 2. B should skip forwarding back to origin.
	if got := originReceived.Load(); got != 0 {
		t.Errorf("origin (A) received gossip %d times via handler, want 0", got)
	}
}
