package dht

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"sync"
	"testing"
	"time"
)

// testTransport creates a Transport with a random Ed25519 key, listening on a
// random port. It registers a cleanup function to close the transport.
func testTransport(t *testing.T) *Transport {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	nodeID := NodeIDFromPublicKey(pub)
	tr := NewTransport(nodeID, priv)
	if err := tr.Listen(0); err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { tr.Close() })
	return tr
}

func TestTransportListenAndConnect(t *testing.T) {
	a := testTransport(t)
	b := testTransport(t)

	if err := b.Connect(a.Addr(), a.self); err != nil {
		t.Fatalf("connect: %v", err)
	}

	// Give the server a moment to accept and register the inbound connection.
	time.Sleep(100 * time.Millisecond)

	// B should see A in its connected peers.
	peersB := b.ConnectedPeers()
	if len(peersB) != 1 {
		t.Fatalf("B connected peers = %d, want 1", len(peersB))
	}
	if peersB[0] != a.self {
		t.Fatalf("B peer = %x, want %x", peersB[0][:4], a.self[:4])
	}

	// A should see B in its connected peers (via the inbound connection).
	peersA := a.ConnectedPeers()
	if len(peersA) != 1 {
		t.Fatalf("A connected peers = %d, want 1", len(peersA))
	}
	if peersA[0] != b.self {
		t.Fatalf("A peer = %x, want %x", peersA[0][:4], b.self[:4])
	}
}

func TestTransportSendReceive(t *testing.T) {
	a := testTransport(t)
	b := testTransport(t)

	var (
		mu       sync.Mutex
		received *Message
		senderID NodeID
	)

	b.OnMessage(func(msg *Message, from NodeID) {
		mu.Lock()
		received = msg
		senderID = from
		mu.Unlock()
	})

	if err := a.Connect(b.Addr(), b.self); err != nil {
		t.Fatalf("connect: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	msg := &Message{
		Type:    MsgPing,
		ID:      "ping-1",
		Payload: json.RawMessage(`{}`),
	}

	if err := a.Send(b.self, msg); err != nil {
		t.Fatalf("send: %v", err)
	}

	// Wait for delivery.
	time.Sleep(200 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	if received == nil {
		t.Fatal("B did not receive message")
	}
	if received.Type != MsgPing {
		t.Fatalf("type = %q, want %q", received.Type, MsgPing)
	}
	if received.ID != "ping-1" {
		t.Fatalf("id = %q, want %q", received.ID, "ping-1")
	}
	if senderID != a.self {
		t.Fatalf("sender = %x, want %x", senderID[:4], a.self[:4])
	}

	// The message should have been auto-signed.
	if received.Signature == "" {
		t.Fatal("message was not auto-signed")
	}
	if received.Sender.NodeID != a.self {
		t.Fatalf("sender.NodeID = %x, want %x", received.Sender.NodeID[:4], a.self[:4])
	}
	if received.Timestamp == 0 {
		t.Fatal("timestamp was not set")
	}
}

func TestTransportBidirectional(t *testing.T) {
	a := testTransport(t)
	b := testTransport(t)

	var (
		muA      sync.Mutex
		recvByA  *Message
		muB      sync.Mutex
		recvByB  *Message
	)

	a.OnMessage(func(msg *Message, from NodeID) {
		muA.Lock()
		recvByA = msg
		muA.Unlock()
	})
	b.OnMessage(func(msg *Message, from NodeID) {
		muB.Lock()
		recvByB = msg
		muB.Unlock()
	})

	if err := a.Connect(b.Addr(), b.self); err != nil {
		t.Fatalf("connect: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	// A sends to B.
	msgAB := &Message{
		Type:    MsgPing,
		ID:      "a-to-b",
		Payload: json.RawMessage(`{}`),
	}
	if err := a.Send(b.self, msgAB); err != nil {
		t.Fatalf("send A->B: %v", err)
	}

	// B sends to A.
	msgBA := &Message{
		Type:    MsgPong,
		ID:      "b-to-a",
		Payload: json.RawMessage(`{}`),
	}
	if err := b.Send(a.self, msgBA); err != nil {
		t.Fatalf("send B->A: %v", err)
	}

	time.Sleep(200 * time.Millisecond)

	muB.Lock()
	if recvByB == nil {
		t.Fatal("B did not receive message from A")
	}
	if recvByB.ID != "a-to-b" {
		t.Fatalf("B got id = %q, want %q", recvByB.ID, "a-to-b")
	}
	muB.Unlock()

	muA.Lock()
	if recvByA == nil {
		t.Fatal("A did not receive message from B")
	}
	if recvByA.ID != "b-to-a" {
		t.Fatalf("A got id = %q, want %q", recvByA.ID, "b-to-a")
	}
	muA.Unlock()
}

func TestTransportDisconnect(t *testing.T) {
	a := testTransport(t)
	b := testTransport(t)

	if err := a.Connect(b.Addr(), b.self); err != nil {
		t.Fatalf("connect: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	if len(a.ConnectedPeers()) != 1 {
		t.Fatalf("before disconnect: peers = %d, want 1", len(a.ConnectedPeers()))
	}

	a.Disconnect(b.self)

	if peers := a.ConnectedPeers(); len(peers) != 0 {
		t.Fatalf("after disconnect: peers = %d, want 0", len(peers))
	}
}

func TestTransportConnectedPeers(t *testing.T) {
	a := testTransport(t)
	b := testTransport(t)
	c := testTransport(t)
	d := testTransport(t)

	if err := a.Connect(b.Addr(), b.self); err != nil {
		t.Fatalf("connect B: %v", err)
	}
	if err := a.Connect(c.Addr(), c.self); err != nil {
		t.Fatalf("connect C: %v", err)
	}
	if err := a.Connect(d.Addr(), d.self); err != nil {
		t.Fatalf("connect D: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	peers := a.ConnectedPeers()
	if len(peers) != 3 {
		t.Fatalf("connected peers = %d, want 3", len(peers))
	}

	// Verify all three are present.
	peerSet := make(map[NodeID]bool)
	for _, p := range peers {
		peerSet[p] = true
	}
	for _, expected := range []NodeID{b.self, c.self, d.self} {
		if !peerSet[expected] {
			t.Fatalf("peer %x not found in connected peers", expected[:4])
		}
	}
}

func TestTransportClose(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	nodeID := NodeIDFromPublicKey(pub)
	a := NewTransport(nodeID, priv)
	if err := a.Listen(0); err != nil {
		t.Fatalf("listen: %v", err)
	}

	b := testTransport(t)

	if err := a.Connect(b.Addr(), b.self); err != nil {
		t.Fatalf("connect: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	a.Close()

	// After close, connected peers should be empty.
	if peers := a.ConnectedPeers(); len(peers) != 0 {
		t.Fatalf("after close: peers = %d, want 0", len(peers))
	}

	// Attempting to connect to the closed transport's address should fail.
	c := testTransport(t)
	err := c.Connect(a.Addr(), a.self)
	if err == nil {
		t.Fatal("expected error connecting to closed transport")
	}
}
