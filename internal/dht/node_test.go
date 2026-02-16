package dht

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"
)

// testNodes creates n DHT nodes, each listening on a random port.
// All nodes are cleaned up when the test finishes.
func testNodes(t *testing.T, n int) []*Node {
	t.Helper()
	nodes := make([]*Node, n)
	for i := range nodes {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generate key %d: %v", i, err)
		}
		cfg := Config{
			PrivateKey: priv,
			PublicKey:  pub,
			K:          20,
			Alpha:      3,
			Port:       0, // random port
			BindAddr:   "127.0.0.1",
		}
		node, err := NewNode(cfg)
		if err != nil {
			t.Fatalf("create node %d: %v", i, err)
		}
		if err := node.Start(); err != nil {
			t.Fatalf("start node %d: %v", i, err)
		}
		nodes[i] = node
		t.Cleanup(func() { node.Close() })
	}
	return nodes
}

// waitForTableSize polls until the routing table reaches the expected size,
// or fails after a timeout.
func waitForTableSize(t *testing.T, n *Node, expected int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if n.Table().Size() >= expected {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	id := n.ID()
	t.Fatalf("node %x table size = %d, want >= %d (timed out)",
		id[:4], n.Table().Size(), expected)
}

func TestNodePing(t *testing.T) {
	nodes := testNodes(t, 2)
	a, b := nodes[0], nodes[1]

	// A pings B.
	info, err := a.Ping(b.Addr())
	if err != nil {
		t.Fatalf("ping: %v", err)
	}

	// Verify returned PeerInfo.
	bID := b.ID()
	if info.ID != bID {
		t.Fatalf("ping returned ID = %x, want %x", info.ID[:4], bID[:4])
	}
	if info.Address != b.Addr() {
		t.Fatalf("ping returned address = %q, want %q", info.Address, b.Addr())
	}

	// A should have B in its routing table.
	waitForTableSize(t, a, 1, 2*time.Second)

	// B should have A in its routing table (from the hello/ping messages).
	waitForTableSize(t, b, 1, 2*time.Second)

	// Verify A's table contains B.
	closest := a.Table().ClosestN(b.ID(), 1)
	if len(closest) == 0 || closest[0].ID != b.ID() {
		t.Fatal("A's routing table does not contain B")
	}

	// Verify B's table contains A.
	closest = b.Table().ClosestN(a.ID(), 1)
	if len(closest) == 0 || closest[0].ID != a.ID() {
		t.Fatal("B's routing table does not contain A")
	}
}

func TestNodePingTimeout(t *testing.T) {
	nodes := testNodes(t, 1)
	a := nodes[0]

	// Ping a non-existent address. Should return an error (connection refused).
	_, err := a.Ping("127.0.0.1:19999")
	if err == nil {
		t.Fatal("expected error pinging non-existent address")
	}
}

func TestNodeFindNodeDirect(t *testing.T) {
	// Setup: A knows B, B knows C. A calls FindNode(C.ID).
	nodes := testNodes(t, 3)
	a, b, c := nodes[0], nodes[1], nodes[2]

	// A pings B.
	if _, err := a.Ping(b.Addr()); err != nil {
		t.Fatalf("A ping B: %v", err)
	}
	// B pings C.
	if _, err := b.Ping(c.Addr()); err != nil {
		t.Fatalf("B ping C: %v", err)
	}

	// Wait for routing tables to stabilize.
	waitForTableSize(t, a, 1, 2*time.Second)
	waitForTableSize(t, b, 2, 2*time.Second)

	// A calls FindNode(C.ID). A only knows B, so it should ask B, who knows C.
	peers, err := a.FindNode(c.ID())
	if err != nil {
		t.Fatalf("FindNode: %v", err)
	}

	// Should find C.
	found := false
	for _, p := range peers {
		if p.ID == c.ID() {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("FindNode did not find C. Got %d peers", len(peers))
	}
}

func TestNodeFindNodeIterative(t *testing.T) {
	// Create 5 nodes in a chain: A->B->C->D->E.
	// Only adjacent nodes know each other.
	nodes := testNodes(t, 5)

	// Connect chain: 0->1->2->3->4
	for i := 0; i < len(nodes)-1; i++ {
		if _, err := nodes[i].Ping(nodes[i+1].Addr()); err != nil {
			t.Fatalf("ping %d->%d: %v", i, i+1, err)
		}
	}

	// Wait for all routing tables to have their adjacent peers.
	for i := 0; i < len(nodes); i++ {
		expected := 1
		if i > 0 && i < len(nodes)-1 {
			expected = 2 // middle nodes know two peers
		}
		waitForTableSize(t, nodes[i], expected, 2*time.Second)
	}

	// Node 0 (A) calls FindNode for Node 4 (E).
	target := nodes[4].ID()
	peers, err := nodes[0].FindNode(target)
	if err != nil {
		t.Fatalf("FindNode: %v", err)
	}

	// Should find E through iterative lookup: A->B->C->D->E.
	found := false
	for _, p := range peers {
		if p.ID == target {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("iterative FindNode did not find E. Got %d peers:", len(peers))
	}
}

func TestNodeBootstrap(t *testing.T) {
	nodes := testNodes(t, 2)
	a := nodes[0]

	// Create a new node that bootstraps using A's address.
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		PrivateKey:     priv,
		PublicKey:      pub,
		K:              20,
		Alpha:          3,
		Port:           0,
		BindAddr:       "127.0.0.1",
		BootstrapPeers: []string{a.Addr()},
	}
	b, err := NewNode(cfg)
	if err != nil {
		t.Fatalf("create bootstrap node: %v", err)
	}
	if err := b.Start(); err != nil {
		t.Fatalf("start bootstrap node: %v", err)
	}
	t.Cleanup(func() { b.Close() })

	// After bootstrapping, both should know each other.
	waitForTableSize(t, b, 1, 3*time.Second)
	waitForTableSize(t, a, 1, 3*time.Second)

	// Verify A is in B's table.
	closest := b.Table().ClosestN(a.ID(), 1)
	if len(closest) == 0 || closest[0].ID != a.ID() {
		t.Fatal("B's table does not contain A after bootstrap")
	}

	// Verify B is in A's table.
	closest = a.Table().ClosestN(b.ID(), 1)
	if len(closest) == 0 || closest[0].ID != b.ID() {
		t.Fatal("A's table does not contain B after bootstrap")
	}
}

func TestNodeHandleMessageUpdatesTable(t *testing.T) {
	nodes := testNodes(t, 2)
	a, b := nodes[0], nodes[1]

	// Initially, A's table should be empty.
	if a.Table().Size() != 0 {
		t.Fatalf("A's table should be empty initially, got %d", a.Table().Size())
	}

	// A pings B — B sends messages back. After the exchange, A should have B
	// in its routing table (updated by handleMessage when PONG arrives).
	if _, err := a.Ping(b.Addr()); err != nil {
		t.Fatalf("ping: %v", err)
	}

	waitForTableSize(t, a, 1, 2*time.Second)

	// Verify B is in A's table.
	bID2 := b.ID()
	closest := a.Table().ClosestN(bID2, 1)
	if len(closest) == 0 {
		t.Fatal("A's table is empty after receiving messages from B")
	}
	if closest[0].ID != bID2 {
		t.Fatalf("A's table contains %x, want %x", closest[0].ID[:4], bID2[:4])
	}
}

func TestHandleMessage_RejectsForgedSignature(t *testing.T) {
	// Create a single node to receive the forged message.
	nodes := testNodes(t, 1)
	a := nodes[0]

	// Generate two keypairs: one for the claimed sender, one for the actual signer.
	claimedPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, wrongPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	claimedID := NodeIDFromPublicKey(claimedPub)

	// Build a message that claims to be from claimedPub but signed by wrongPriv.
	msg := &Message{
		Type:      MsgPing,
		ID:        "forged-msg",
		Timestamp: time.Now().Unix(),
		Payload:   json.RawMessage(`{}`),
		Sender: SenderInfo{
			NodeID:    claimedID,
			Address:   "127.0.0.1:9999",
			PublicKey: hex.EncodeToString(claimedPub),
		},
	}
	// Sign with the WRONG key — signature won't verify against claimedPub.
	msg.Sign(wrongPriv)

	initialSize := a.Table().Size()

	// Directly invoke handleMessage to simulate receiving this message.
	a.handleMessage(msg, claimedID)

	// The routing table should NOT have grown because the signature is invalid.
	if a.Table().Size() != initialSize {
		t.Fatalf("routing table grew after forged message: got %d, want %d",
			a.Table().Size(), initialSize)
	}
}

func TestHandleMessage_RejectsStaleTimestamp(t *testing.T) {
	// Create a single node to receive the stale message.
	nodes := testNodes(t, 1)
	a := nodes[0]

	// Generate a valid keypair for the sender.
	senderPub, senderPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	senderID := NodeIDFromPublicKey(senderPub)

	// Build a correctly signed message, but with a timestamp 10 minutes ago.
	msg := &Message{
		Type:      MsgPing,
		ID:        "stale-msg",
		Timestamp: time.Now().Unix() - 600, // 10 minutes old
		Payload:   json.RawMessage(`{}`),
		Sender: SenderInfo{
			NodeID:    senderID,
			Address:   "127.0.0.1:9999",
			PublicKey: hex.EncodeToString(senderPub),
		},
	}
	// Sign correctly with the real key.
	sig := ed25519.Sign(senderPriv, msg.signable())
	msg.Signature = hex.EncodeToString(sig)

	initialSize := a.Table().Size()

	// Directly invoke handleMessage.
	a.handleMessage(msg, senderID)

	// The routing table should NOT have grown because the timestamp is stale.
	if a.Table().Size() != initialSize {
		t.Fatalf("routing table grew after stale message: got %d, want %d",
			a.Table().Size(), initialSize)
	}
}

func TestHandleMessage_AcceptsValidMessage(t *testing.T) {
	// Create a single node to receive the valid message.
	nodes := testNodes(t, 1)
	a := nodes[0]

	// Generate a valid keypair for the sender.
	senderPub, senderPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	senderID := NodeIDFromPublicKey(senderPub)

	// Build a correctly signed message with a current timestamp.
	msg := &Message{
		Type:      MsgPing,
		ID:        "valid-msg",
		Timestamp: time.Now().Unix(),
		Payload:   json.RawMessage(`{}`),
		Sender: SenderInfo{
			NodeID:    senderID,
			Address:   "127.0.0.1:9999",
			PublicKey: hex.EncodeToString(senderPub),
		},
	}
	// Sign correctly with the real key.
	sig := ed25519.Sign(senderPriv, msg.signable())
	msg.Signature = hex.EncodeToString(sig)

	initialSize := a.Table().Size()

	// Directly invoke handleMessage.
	a.handleMessage(msg, senderID)

	// The routing table SHOULD have grown because the message is valid.
	if a.Table().Size() != initialSize+1 {
		t.Fatalf("routing table did not grow after valid message: got %d, want %d",
			a.Table().Size(), initialSize+1)
	}

	// Verify the sender is in the routing table.
	closest := a.Table().ClosestN(senderID, 1)
	if len(closest) == 0 || closest[0].ID != senderID {
		t.Fatal("sender not found in routing table after valid message")
	}

	// Verify the public key was stored in the PeerInfo.
	if closest[0].PublicKey == nil {
		t.Fatal("sender's public key not stored in PeerInfo")
	}
	if hex.EncodeToString(closest[0].PublicKey) != hex.EncodeToString(senderPub) {
		t.Fatal("stored public key does not match sender's public key")
	}
}
