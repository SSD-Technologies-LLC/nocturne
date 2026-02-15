# P2P Agent Mesh Network Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Replace the centralized agent mesh with a fully decentralized P2P network using Kademlia DHT, Web of Trust enrollment, and distributed commit-reveal voting.

**Architecture:** Every agent node becomes a full DHT peer. Knowledge, trust certificates, and votes are stored across k=20 responsible nodes. The Go binary (`nocturne-agent`) implements the full DHT peer. The npm MCP server (`nocturne-mesh`) spawns the Go binary as a child process and communicates via localhost HTTP — one DHT implementation, not two.

**Tech Stack:** Go 1.24, gorilla/websocket (existing), Ed25519 (existing), SQLite (existing), TypeScript/MCP SDK (existing)

**Design doc:** `docs/plans/2026-02-15-nocturne-p2p-agent-mesh-design.md`

**Pragmatic decision:** The npm package will NOT reimplement Kademlia in TypeScript. Instead, `nocturne-mesh` spawns the `nocturne-agent` Go binary as a local subprocess. The Go binary runs the DHT peer and exposes a localhost HTTP API. The TypeScript MCP server translates MCP tool calls into localhost HTTP calls to the Go binary. This means one DHT implementation (Go), and the npm package ships or downloads a prebuilt Go binary.

---

## Phase 1: DHT Core (Pure Data Structures)

No I/O, no networking. Pure algorithmic code with full test coverage.

### Task 1: XOR Distance & Node ID

**Files:**
- Create: `internal/dht/id.go`
- Test: `internal/dht/id_test.go`

**Step 1: Write failing tests**

```go
// internal/dht/id_test.go
package dht

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"testing"
)

func TestNodeIDFromPublicKey(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	id := NodeIDFromPublicKey(pub)
	if len(id) != IDLength {
		t.Fatalf("len = %d, want %d", len(id), IDLength)
	}
	// Should be SHA-256 of the public key
	expected := sha256.Sum256(pub)
	if id != NodeID(expected) {
		t.Fatal("NodeID does not match SHA-256 of public key")
	}
}

func TestXORDistance(t *testing.T) {
	a := NodeID{}
	b := NodeID{}
	a[0] = 0xFF
	b[0] = 0x0F

	dist := XOR(a, b)
	if dist[0] != 0xF0 {
		t.Fatalf("dist[0] = %02x, want 0xf0", dist[0])
	}
}

func TestDistanceLess(t *testing.T) {
	target := NodeID{}
	closer := NodeID{}
	farther := NodeID{}
	closer[31] = 0x01
	farther[31] = 0x02

	if !DistanceLess(target, closer, farther) {
		t.Fatal("closer should be less than farther")
	}
	if DistanceLess(target, farther, closer) {
		t.Fatal("farther should not be less than closer")
	}
}

func TestBucketIndex(t *testing.T) {
	self := NodeID{}
	other := NodeID{}
	other[0] = 0x80 // highest bit set → bucket 0

	idx := BucketIndex(self, other)
	if idx != 0 {
		t.Fatalf("bucket = %d, want 0", idx)
	}

	other2 := NodeID{}
	other2[31] = 0x01 // lowest bit set → bucket 255
	idx2 := BucketIndex(self, other2)
	if idx2 != 255 {
		t.Fatalf("bucket = %d, want 255", idx2)
	}
}

func TestContentKey(t *testing.T) {
	key := ContentKey("go/concurrency", "entry-123")
	if len(key) != IDLength {
		t.Fatalf("len = %d, want %d", len(key), IDLength)
	}
	// Same inputs should produce same key
	key2 := ContentKey("go/concurrency", "entry-123")
	if key != key2 {
		t.Fatal("same inputs should produce same key")
	}
	// Different inputs should produce different key
	key3 := ContentKey("go/concurrency", "entry-456")
	if key == key3 {
		t.Fatal("different inputs should produce different key")
	}
}
```

**Step 2: Run tests to verify they fail**

Run: `cd /home/mark-ssd/code/ssd.foundation/nocturne && go test ./internal/dht/ -v -run TestNodeID`
Expected: Compilation error — package doesn't exist yet

**Step 3: Implement**

```go
// internal/dht/id.go
package dht

import (
	"crypto/ed25519"
	"crypto/sha256"
)

const IDLength = 32 // 256-bit

// NodeID is a 256-bit identifier in the DHT key space.
type NodeID [IDLength]byte

// NodeIDFromPublicKey computes SHA-256 of an Ed25519 public key.
func NodeIDFromPublicKey(pub ed25519.PublicKey) NodeID {
	return NodeID(sha256.Sum256(pub))
}

// ContentKey computes the DHT key for a knowledge entry.
func ContentKey(domain, entryID string) NodeID {
	return NodeID(sha256.Sum256([]byte(domain + ":" + entryID)))
}

// DomainIndexKey computes the DHT key for a domain index.
func DomainIndexKey(domain string) NodeID {
	return NodeID(sha256.Sum256([]byte("domain_index:" + domain)))
}

// PrefixKey computes a DHT key with a typed prefix.
func PrefixKey(prefix, id string) NodeID {
	return NodeID(sha256.Sum256([]byte(prefix + ":" + id)))
}

// XOR returns the XOR distance between two node IDs.
func XOR(a, b NodeID) NodeID {
	var result NodeID
	for i := range result {
		result[i] = a[i] ^ b[i]
	}
	return result
}

// DistanceLess returns true if a is closer to target than b.
func DistanceLess(target, a, b NodeID) bool {
	da := XOR(target, a)
	db := XOR(target, b)
	for i := range da {
		if da[i] < db[i] {
			return true
		}
		if da[i] > db[i] {
			return false
		}
	}
	return false
}

// BucketIndex returns the k-bucket index for a peer relative to self.
// Bucket 0 = most distant (highest bit differs), bucket 255 = closest.
func BucketIndex(self, other NodeID) int {
	dist := XOR(self, other)
	for i := 0; i < IDLength; i++ {
		if dist[i] != 0 {
			// Find highest set bit in this byte
			for bit := 7; bit >= 0; bit-- {
				if dist[i]&(1<<uint(bit)) != 0 {
					return i*8 + (7 - bit)
				}
			}
		}
	}
	return 255 // same ID
}
```

**Step 4: Run tests**

Run: `cd /home/mark-ssd/code/ssd.foundation/nocturne && go test ./internal/dht/ -v`
Expected: All PASS

**Step 5: Commit**

```bash
git add internal/dht/id.go internal/dht/id_test.go
git commit -m "feat(dht): add node ID, XOR distance, and content key primitives"
```

---

### Task 2: K-Bucket Routing Table

**Files:**
- Create: `internal/dht/table.go`
- Test: `internal/dht/table_test.go`

**Step 1: Write failing tests**

```go
// internal/dht/table_test.go
package dht

import (
	"testing"
	"time"
)

func TestRoutingTableAddAndFind(t *testing.T) {
	self := NodeID{}
	rt := NewRoutingTable(self, 20)

	peer := PeerInfo{
		ID:      NodeID{0: 0x80}, // bucket 0
		Address: "wss://peer1:9090",
	}
	rt.Add(peer)

	closest := rt.ClosestN(peer.ID, 1)
	if len(closest) != 1 {
		t.Fatalf("got %d peers, want 1", len(closest))
	}
	if closest[0].ID != peer.ID {
		t.Fatal("returned wrong peer")
	}
}

func TestRoutingTableBucketFull(t *testing.T) {
	self := NodeID{}
	k := 3 // small k for testing
	rt := NewRoutingTable(self, k)

	// Fill bucket 0 with k peers
	for i := 0; i < k; i++ {
		id := NodeID{0: 0x80, 1: byte(i)}
		rt.Add(PeerInfo{ID: id, Address: "wss://peer:9090"})
	}

	// Adding one more to same bucket should not evict (Kademlia prefers old)
	newPeer := PeerInfo{ID: NodeID{0: 0x80, 1: byte(k)}, Address: "wss://new:9090"}
	rt.Add(newPeer)

	closest := rt.ClosestN(NodeID{0: 0x80}, k+1)
	// Should still have only k peers in that bucket region
	if len(closest) != k {
		t.Fatalf("got %d peers, want %d", len(closest), k)
	}
}

func TestRoutingTableClosestNOrdering(t *testing.T) {
	self := NodeID{}
	rt := NewRoutingTable(self, 20)

	// Add peers at various distances
	p1 := PeerInfo{ID: NodeID{31: 0x01}, Address: "wss://close:9090"}   // very close
	p2 := PeerInfo{ID: NodeID{0: 0x80}, Address: "wss://far:9090"}      // very far
	p3 := PeerInfo{ID: NodeID{15: 0x01}, Address: "wss://mid:9090"}     // middle

	rt.Add(p1)
	rt.Add(p2)
	rt.Add(p3)

	target := NodeID{} // same as self
	closest := rt.ClosestN(target, 3)
	if len(closest) != 3 {
		t.Fatalf("got %d peers, want 3", len(closest))
	}
	// Closest first
	if closest[0].ID != p1.ID {
		t.Fatal("first peer should be closest")
	}
}

func TestRoutingTableRemove(t *testing.T) {
	self := NodeID{}
	rt := NewRoutingTable(self, 20)

	peer := PeerInfo{ID: NodeID{0: 0x80}, Address: "wss://peer:9090"}
	rt.Add(peer)
	rt.Remove(peer.ID)

	closest := rt.ClosestN(peer.ID, 1)
	if len(closest) != 0 {
		t.Fatal("peer should have been removed")
	}
}

func TestRoutingTableStaleBuckets(t *testing.T) {
	self := NodeID{}
	rt := NewRoutingTable(self, 20)

	peer := PeerInfo{ID: NodeID{0: 0x80}, Address: "wss://peer:9090"}
	rt.Add(peer)

	stale := rt.StaleBuckets(1 * time.Millisecond)
	time.Sleep(2 * time.Millisecond)
	stale = rt.StaleBuckets(1 * time.Millisecond)
	if len(stale) == 0 {
		t.Fatal("should have stale buckets")
	}
}

func TestRoutingTableSize(t *testing.T) {
	self := NodeID{}
	rt := NewRoutingTable(self, 20)
	if rt.Size() != 0 {
		t.Fatalf("size = %d, want 0", rt.Size())
	}
	rt.Add(PeerInfo{ID: NodeID{0: 0x80}, Address: "wss://peer:9090"})
	if rt.Size() != 1 {
		t.Fatalf("size = %d, want 1", rt.Size())
	}
}
```

**Step 2: Run tests to verify they fail**

Run: `cd /home/mark-ssd/code/ssd.foundation/nocturne && go test ./internal/dht/ -v -run TestRoutingTable`
Expected: Compilation error — types not defined yet

**Step 3: Implement**

```go
// internal/dht/table.go
package dht

import (
	"sort"
	"sync"
	"time"
)

const NumBuckets = 256 // one per bit in 256-bit key space

// PeerInfo describes a known peer in the DHT.
type PeerInfo struct {
	ID         NodeID
	Address    string
	PublicKey  []byte
	OperatorID string
	LastSeen   time.Time
}

// bucket holds up to k peers.
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

// NewRoutingTable creates a routing table for the given node ID.
func NewRoutingTable(self NodeID, k int) *RoutingTable {
	rt := &RoutingTable{self: self, k: k}
	now := time.Now()
	for i := range rt.buckets {
		rt.buckets[i] = &bucket{lastRefresh: now}
	}
	return rt
}

// Add inserts a peer into the appropriate k-bucket.
// If the bucket is full, the new peer is dropped (Kademlia prefers long-lived peers).
func (rt *RoutingTable) Add(peer PeerInfo) {
	if peer.ID == rt.self {
		return
	}
	idx := BucketIndex(rt.self, peer.ID)

	rt.mu.Lock()
	defer rt.mu.Unlock()

	b := rt.buckets[idx]

	// Check if peer already exists — update it
	for i, p := range b.peers {
		if p.ID == peer.ID {
			b.peers[i].Address = peer.Address
			b.peers[i].LastSeen = time.Now()
			b.peers[i].PublicKey = peer.PublicKey
			b.peers[i].OperatorID = peer.OperatorID
			// Move to tail (most recently seen)
			entry := b.peers[i]
			b.peers = append(b.peers[:i], b.peers[i+1:]...)
			b.peers = append(b.peers, entry)
			b.lastRefresh = time.Now()
			return
		}
	}

	// Bucket not full — add
	if len(b.peers) < rt.k {
		peer.LastSeen = time.Now()
		b.peers = append(b.peers, peer)
		b.lastRefresh = time.Now()
	}
	// Bucket full — drop new peer (prefer old contacts)
}

// Remove deletes a peer from the routing table.
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

// ClosestN returns up to n peers closest to the target, sorted by XOR distance.
func (rt *RoutingTable) ClosestN(target NodeID, n int) []PeerInfo {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	var all []PeerInfo
	for _, b := range rt.buckets {
		all = append(all, b.peers...)
	}

	sort.Slice(all, func(i, j int) bool {
		return DistanceLess(target, all[i].ID, all[j].ID)
	})

	if len(all) > n {
		return all[:n]
	}
	return all
}

// StaleBuckets returns bucket indices that haven't been refreshed within the given duration.
func (rt *RoutingTable) StaleBuckets(maxAge time.Duration) []int {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	now := time.Now()
	var stale []int
	for i, b := range rt.buckets {
		if now.Sub(b.lastRefresh) > maxAge {
			stale = append(stale, i)
		}
	}
	return stale
}

// Size returns the total number of peers in the routing table.
func (rt *RoutingTable) Size() int {
	rt.mu.RLock()
	defer rt.mu.RUnlock()

	count := 0
	for _, b := range rt.buckets {
		count += len(b.peers)
	}
	return count
}

// Self returns this node's ID.
func (rt *RoutingTable) Self() NodeID {
	return rt.self
}
```

**Step 4: Run tests**

Run: `cd /home/mark-ssd/code/ssd.foundation/nocturne && go test ./internal/dht/ -v`
Expected: All PASS

**Step 5: Commit**

```bash
git add internal/dht/table.go internal/dht/table_test.go
git commit -m "feat(dht): add k-bucket routing table with add, remove, closest-n"
```

---

## Phase 2: Wire Protocol & Transport

### Task 3: Message Types & Serialization

**Files:**
- Create: `internal/dht/message.go`
- Test: `internal/dht/message_test.go`

**Step 1: Write failing tests**

```go
// internal/dht/message_test.go
package dht

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"testing"
)

func TestMessageMarshalRoundTrip(t *testing.T) {
	msg := &Message{
		Type: MsgPing,
		ID:   "test-123",
		Sender: SenderInfo{
			NodeID:     NodeID{0: 0x80},
			AgentID:    "a1b2c3d4",
			OperatorID: "op123456",
			Address:    "wss://peer:9090",
		},
		Timestamp: 1739635200,
		Payload:   json.RawMessage(`{}`),
	}

	data, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded Message
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded.Type != MsgPing {
		t.Fatalf("type = %q, want %q", decoded.Type, MsgPing)
	}
	if decoded.Sender.Address != "wss://peer:9090" {
		t.Fatalf("address = %q, want %q", decoded.Sender.Address, "wss://peer:9090")
	}
}

func TestMessageSignAndVerify(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	msg := &Message{
		Type:      MsgPing,
		ID:        "test-456",
		Timestamp: 1739635200,
		Payload:   json.RawMessage(`{}`),
	}

	msg.Sign(priv)
	if msg.Signature == "" {
		t.Fatal("signature should be set")
	}

	if err := msg.Verify(pub); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestMessageVerifyRejectsTampered(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	msg := &Message{
		Type:      MsgPing,
		ID:        "test-789",
		Timestamp: 1739635200,
		Payload:   json.RawMessage(`{}`),
	}

	msg.Sign(priv)
	msg.Timestamp = 9999999999 // tamper

	if err := msg.Verify(pub); err == nil {
		t.Fatal("should reject tampered message")
	}
}

func TestFindNodePayload(t *testing.T) {
	target := NodeID{0: 0xAB}
	payload := FindNodePayload{Target: target}
	data, _ := json.Marshal(payload)

	var decoded FindNodePayload
	json.Unmarshal(data, &decoded)
	if decoded.Target != target {
		t.Fatal("target mismatch")
	}
}

func TestStorePayload(t *testing.T) {
	payload := StorePayload{
		Key:   NodeID{0: 0xCD},
		Value: json.RawMessage(`{"content":"hello"}`),
	}
	data, _ := json.Marshal(payload)

	var decoded StorePayload
	json.Unmarshal(data, &decoded)
	if decoded.Key != payload.Key {
		t.Fatal("key mismatch")
	}
}
```

**Step 2: Run tests to verify they fail**

Run: `cd /home/mark-ssd/code/ssd.foundation/nocturne && go test ./internal/dht/ -v -run TestMessage`
Expected: Compilation error

**Step 3: Implement**

```go
// internal/dht/message.go
package dht

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
)

// Message types
const (
	MsgPing      = "PING"
	MsgPong      = "PONG"
	MsgFindNode  = "FIND_NODE"
	MsgFindValue = "FIND_VALUE"
	MsgStore     = "STORE"
	MsgVote      = "VOTE"
	MsgQuery     = "QUERY"
	MsgResponse  = "RESPONSE"
	MsgError     = "ERROR"
)

// SenderInfo identifies the message sender.
type SenderInfo struct {
	NodeID     NodeID `json:"node_id"`
	AgentID    string `json:"agent_id"`
	OperatorID string `json:"operator_id"`
	Address    string `json:"address"`
}

// Message is the common envelope for all DHT messages.
type Message struct {
	Type      string          `json:"type"`
	ID        string          `json:"id"`
	Sender    SenderInfo      `json:"sender"`
	Timestamp int64           `json:"timestamp"`
	Payload   json.RawMessage `json:"payload"`
	Signature string          `json:"signature,omitempty"`
}

// signable returns the bytes that are signed.
func (m *Message) signable() []byte {
	return []byte(m.Type + m.ID + strconv.FormatInt(m.Timestamp, 10) + string(m.Payload))
}

// Sign signs the message with the given private key.
func (m *Message) Sign(priv ed25519.PrivateKey) {
	sig := ed25519.Sign(priv, m.signable())
	m.Signature = hex.EncodeToString(sig)
}

// Verify checks the message signature against the given public key.
func (m *Message) Verify(pub ed25519.PublicKey) error {
	if m.Signature == "" {
		return fmt.Errorf("message has no signature")
	}
	sig, err := hex.DecodeString(m.Signature)
	if err != nil {
		return fmt.Errorf("invalid signature hex: %w", err)
	}
	if !ed25519.Verify(pub, m.signable(), sig) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

// Payload types for each RPC

type FindNodePayload struct {
	Target NodeID `json:"target"`
}

type FindNodeResponse struct {
	Peers []PeerInfo `json:"peers"`
}

type FindValuePayload struct {
	Key NodeID `json:"key"`
}

type FindValueResponse struct {
	Found bool            `json:"found"`
	Value json.RawMessage `json:"value,omitempty"`
	Peers []PeerInfo      `json:"peers,omitempty"` // if not found, return closest peers
}

type StorePayload struct {
	Key   NodeID          `json:"key"`
	Value json.RawMessage `json:"value"`
}

type StoreResponse struct {
	Stored bool `json:"stored"`
}

type VotePayload struct {
	EntryKey   NodeID `json:"entry_key"`
	Phase      string `json:"phase"` // "commit" or "reveal"
	Commitment string `json:"commitment,omitempty"`
	Vote       *int   `json:"vote,omitempty"`
	Nonce      string `json:"nonce,omitempty"`
	Reason     string `json:"reason,omitempty"`
	OperatorID string `json:"operator_id"`
}

type QueryPayload struct {
	Domain        string  `json:"domain,omitempty"`
	Text          string  `json:"text,omitempty"`
	MinConfidence float64 `json:"min_confidence,omitempty"`
	Limit         int     `json:"limit,omitempty"`
}

type ErrorPayload struct {
	Error string `json:"error"`
}
```

**Step 4: Run tests**

Run: `cd /home/mark-ssd/code/ssd.foundation/nocturne && go test ./internal/dht/ -v`
Expected: All PASS

**Step 5: Commit**

```bash
git add internal/dht/message.go internal/dht/message_test.go
git commit -m "feat(dht): add wire protocol message types with Ed25519 signing"
```

---

### Task 4: WebSocket Transport Layer

**Files:**
- Create: `internal/dht/transport.go`
- Test: `internal/dht/transport_test.go`

**Step 1: Write failing tests**

Tests should verify:
- `Transport.Listen(port)` starts a WebSocket server
- `Transport.Connect(address)` establishes a WebSocket connection to a peer
- `Transport.Send(nodeID, message)` sends a message to a connected peer
- `Transport.OnMessage(handler)` registers a callback for incoming messages
- `Transport.Disconnect(nodeID)` closes a connection
- Messages sent between two transports are received correctly
- Invalid signatures are rejected at the transport level

Use `httptest.Server` to test without real network.

**Step 2: Run tests to verify they fail**

Run: `cd /home/mark-ssd/code/ssd.foundation/nocturne && go test ./internal/dht/ -v -run TestTransport`
Expected: Compilation error

**Step 3: Implement**

The `Transport` struct manages WebSocket connections:

```go
// internal/dht/transport.go
package dht

// Transport manages WebSocket connections to DHT peers.
type Transport struct {
	mu       sync.RWMutex
	self     NodeID
	privKey  ed25519.PrivateKey
	conns    map[NodeID]*websocket.Conn
	handler  func(*Message, NodeID)
	listener net.Listener
	server   *http.Server
}

// Key methods:
// NewTransport(self NodeID, privKey ed25519.PrivateKey) *Transport
// Listen(port int) error — starts WSS listener, accepts incoming conns
// Connect(address string, peerID NodeID) error — outbound WSS connection
// Send(target NodeID, msg *Message) error — signs and sends message
// OnMessage(handler func(*Message, NodeID)) — register incoming message handler
// Disconnect(id NodeID) — close connection
// ConnectedPeers() []NodeID — list connected peers
// Close() — shutdown listener and all connections
```

Each incoming WebSocket connection runs a read loop goroutine. Messages are deserialized and passed to the handler. The transport auto-signs outbound messages and the handler can access the sender's NodeID.

**Step 4: Run tests**

Run: `cd /home/mark-ssd/code/ssd.foundation/nocturne && go test ./internal/dht/ -v -run TestTransport`
Expected: All PASS

**Step 5: Commit**

```bash
git add internal/dht/transport.go internal/dht/transport_test.go
git commit -m "feat(dht): add WebSocket transport layer with auto-signing"
```

---

### Task 5: DHT Node — PING and FIND_NODE RPCs

**Files:**
- Create: `internal/dht/node.go`
- Test: `internal/dht/node_test.go`

**Step 1: Write failing tests**

Tests should verify:
- `Node.Ping(peerAddress)` sends PING, receives PONG, adds peer to routing table
- `Node.FindNode(target)` performs iterative Kademlia lookup with α=3 concurrency
- Two nodes can discover each other via PING
- Three nodes: A knows B, B knows C → A can find C via `FindNode`

Create a test helper that spins up N in-memory DHT nodes on random ports:

```go
func testNodes(t *testing.T, n int) []*Node {
	t.Helper()
	nodes := make([]*Node, n)
	for i := range nodes {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		cfg := Config{
			PrivateKey: priv,
			PublicKey:  pub,
			K:          20,
			Alpha:      3,
			Port:       0, // random port
		}
		nodes[i] = NewNode(cfg)
		t.Cleanup(func() { nodes[i].Close() })
	}
	return nodes
}
```

**Step 2: Run tests to verify they fail**

**Step 3: Implement**

```go
// internal/dht/node.go
package dht

// Config holds DHT node configuration.
type Config struct {
	PrivateKey    ed25519.PrivateKey
	PublicKey     ed25519.PublicKey
	K             int    // bucket size (default 20)
	Alpha         int    // concurrency (default 3)
	Port          int    // listen port (0 = random)
	BootstrapPeers []string // initial peer addresses
}

// Node is a Kademlia DHT peer.
type Node struct {
	id        NodeID
	config    Config
	table     *RoutingTable
	transport *Transport
	store     *LocalStore    // (Task 6)
}

// Key methods:
// NewNode(cfg Config) *Node
// Start() error — listen + bootstrap
// Ping(address string) (*PeerInfo, error) — send PING, get PONG, add to table
// FindNode(target NodeID) ([]PeerInfo, error) — iterative Kademlia lookup
// Bootstrap(addresses []string) error — ping bootstrap nodes, then FindNode(self)
// handleMessage(msg *Message, from NodeID) — route incoming messages
// Close() error
```

The `FindNode` implements standard iterative Kademlia lookup:
1. Seed shortlist from routing table's closest-k to target
2. In parallel (α=3), send FIND_NODE to closest unqueried peers
3. Merge returned peers into shortlist
4. Repeat until no closer peers found
5. Return k closest

**Step 4: Run tests**

Run: `cd /home/mark-ssd/code/ssd.foundation/nocturne && go test ./internal/dht/ -v -run TestNode`
Expected: All PASS

**Step 5: Commit**

```bash
git add internal/dht/node.go internal/dht/node_test.go
git commit -m "feat(dht): add DHT node with PING, FIND_NODE, iterative lookup"
```

---

### Task 6: Local Store & STORE/FIND_VALUE RPCs

**Files:**
- Create: `internal/dht/store.go`
- Test: `internal/dht/store_test.go`
- Modify: `internal/dht/node.go` — add Store and FindValue methods

**Step 1: Write failing tests**

Tests should verify:
- `Node.Store(key, value)` stores at responsible nodes (the k closest)
- `Node.FindValue(key)` retrieves stored value
- Value stored on node A can be retrieved via node B (multi-hop)
- Entries have TTL and expire
- Node only accepts STORE if it's responsible (within k closest)

**Step 2: Run tests to verify they fail**

**Step 3: Implement**

`LocalStore` is a SQLite database at `~/.nocturne/dht/entries.db` that stores key-value pairs this node is responsible for. Reuses the existing SQLite patterns from `internal/storage/`.

```go
// internal/dht/store.go
package dht

// LocalStore manages DHT entries stored on this node.
type LocalStore struct {
	db *sql.DB
}

// Key methods:
// NewLocalStore(dbPath string) (*LocalStore, error)
// Put(key NodeID, value []byte, ttl time.Duration) error
// Get(key NodeID) ([]byte, bool, error)
// Delete(key NodeID) error
// PruneExpired() (int, error)
// ListKeys() ([]NodeID, error)
// Close() error
```

Add to `Node`:
- `Store(key NodeID, value []byte)` — find k closest, send STORE to each
- `FindValue(key NodeID)` — iterative lookup: FIND_VALUE to closest, returns value or closer peers

**Step 4: Run tests**

Run: `cd /home/mark-ssd/code/ssd.foundation/nocturne && go test ./internal/dht/ -v`
Expected: All PASS

**Step 5: Commit**

```bash
git add internal/dht/store.go internal/dht/store_test.go internal/dht/node.go internal/dht/node_test.go
git commit -m "feat(dht): add local store with STORE/FIND_VALUE RPCs"
```

---

## Phase 3: Web of Trust

### Task 7: Genesis Configuration & Trust Certificate Types

**Files:**
- Create: `internal/agent/trust.go`
- Test: `internal/agent/trust_test.go`

**Step 1: Write failing tests**

```go
// internal/agent/trust_test.go
package agent

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestLoadGenesis(t *testing.T) {
	genesis := DefaultGenesis()
	if genesis.Version != 1 {
		t.Fatalf("version = %d, want 1", genesis.Version)
	}
	if genesis.MinEndorsements != 3 {
		t.Fatalf("min_endorsements = %d, want 3", genesis.MinEndorsements)
	}
}

func TestCreateEndorsement(t *testing.T) {
	_, endorserPriv, _ := ed25519.GenerateKey(rand.Reader)
	newOpPub, _, _ := ed25519.GenerateKey(rand.Reader)

	endorsement, err := CreateEndorsement(endorserPriv, newOpPub, 1739635200)
	if err != nil {
		t.Fatalf("create endorsement: %v", err)
	}
	if endorsement.Signature == "" {
		t.Fatal("signature should be set")
	}
}

func TestVerifyEndorsement(t *testing.T) {
	endorserPub, endorserPriv, _ := ed25519.GenerateKey(rand.Reader)
	newOpPub, _, _ := ed25519.GenerateKey(rand.Reader)

	endorsement, _ := CreateEndorsement(endorserPriv, newOpPub, 1739635200)

	if err := VerifyEndorsement(endorsement, endorserPub, newOpPub); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestVerifyEndorsementRejectsTampered(t *testing.T) {
	_, endorserPriv, _ := ed25519.GenerateKey(rand.Reader)
	newOpPub, _, _ := ed25519.GenerateKey(rand.Reader)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)

	endorsement, _ := CreateEndorsement(endorserPriv, newOpPub, 1739635200)

	// Verify against wrong public key
	if err := VerifyEndorsement(endorsement, otherPub, newOpPub); err == nil {
		t.Fatal("should reject wrong endorser key")
	}
}

func TestTrustCertificateValidation(t *testing.T) {
	// Create a genesis operator
	genPub, genPriv, _ := ed25519.GenerateKey(rand.Reader)
	genPub2, genPriv2, _ := ed25519.GenerateKey(rand.Reader)
	genPub3, genPriv3, _ := ed25519.GenerateKey(rand.Reader)

	genesis := &Genesis{
		Version:            1,
		MinEndorsements:    3,
		RevocationThreshold: 3,
		Operators: []GenesisOperator{
			{PublicKey: genPub, Label: "gen1"},
			{PublicKey: genPub2, Label: "gen2"},
			{PublicKey: genPub3, Label: "gen3"},
		},
	}

	// Create new operator with 3 endorsements
	newPub, _, _ := ed25519.GenerateKey(rand.Reader)
	e1, _ := CreateEndorsement(genPriv, newPub, 1739635200)
	e2, _ := CreateEndorsement(genPriv2, newPub, 1739635200)
	e3, _ := CreateEndorsement(genPriv3, newPub, 1739635200)

	cert := &TrustCertificate{
		OperatorID:   AgentIDFromPublicKey(newPub),
		PublicKey:    newPub,
		Label:        "new-op",
		Endorsements: []Endorsement{*e1, *e2, *e3},
		MaxAgents:    5,
		CreatedAt:    1739635200,
	}

	validator := NewTrustValidator(genesis)
	if err := validator.ValidateCertificate(cert); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func TestTrustCertificateRejectsInsufficientEndorsements(t *testing.T) {
	genPub, genPriv, _ := ed25519.GenerateKey(rand.Reader)

	genesis := &Genesis{
		Version:         1,
		MinEndorsements: 3,
		Operators:       []GenesisOperator{{PublicKey: genPub, Label: "gen1"}},
	}

	newPub, _, _ := ed25519.GenerateKey(rand.Reader)
	e1, _ := CreateEndorsement(genPriv, newPub, 1739635200)

	cert := &TrustCertificate{
		OperatorID:   AgentIDFromPublicKey(newPub),
		PublicKey:    newPub,
		Label:        "new-op",
		Endorsements: []Endorsement{*e1}, // only 1, need 3
	}

	validator := NewTrustValidator(genesis)
	if err := validator.ValidateCertificate(cert); err == nil {
		t.Fatal("should reject insufficient endorsements")
	}
}
```

**Step 2: Run tests to verify they fail**

**Step 3: Implement**

```go
// internal/agent/trust.go
package agent

// Types:
// Genesis — embedded genesis configuration
// GenesisOperator — a founding operator
// Endorsement — signed endorsement of a new operator
// TrustCertificate — operator's proof of membership
// RevocationCertificate — operator removal proof
// TrustValidator — validates certificates against genesis + known operators

// Key functions:
// DefaultGenesis() *Genesis — returns the embedded genesis config
// CreateEndorsement(privKey, targetPubKey, timestamp) (*Endorsement, error)
// VerifyEndorsement(e *Endorsement, endorserPub, targetPub) error
// NewTrustValidator(genesis *Genesis) *TrustValidator
// (v *TrustValidator) ValidateCertificate(cert *TrustCertificate) error
// (v *TrustValidator) AddTrustedOperator(cert *TrustCertificate)
// (v *TrustValidator) IsRevoked(operatorID string) bool
// (v *TrustValidator) ValidateRevocation(rev *RevocationCertificate) error
```

The endorsement message format: `"ENDORSE:" + hex(new_operator_public_key) + ":" + timestamp`

The validator:
1. Checks each endorsement signature
2. Checks each endorser is trusted (genesis or previously validated cert, max depth 3)
3. Counts valid endorsements >= `min_endorsements`

**Step 4: Run tests**

Run: `cd /home/mark-ssd/code/ssd.foundation/nocturne && go test ./internal/agent/ -v`
Expected: All PASS (including existing auth tests)

**Step 5: Commit**

```bash
git add internal/agent/trust.go internal/agent/trust_test.go
git commit -m "feat(agent): add Web of Trust with genesis, endorsements, and certificate validation"
```

---

### Task 8: Revocation Certificates

**Files:**
- Modify: `internal/agent/trust.go`
- Modify: `internal/agent/trust_test.go`

**Step 1: Write failing tests**

Tests for:
- `CreateRevocation(targetOperatorID, reason, signerPrivKeys...)` creates a revocation certificate
- `ValidateRevocation` accepts valid revocations with N signatures
- `ValidateRevocation` rejects insufficient signatures
- `IsRevoked` returns true after valid revocation applied
- Revoked operators can't endorse new operators

**Step 2–5: Implement, test, commit**

```bash
git commit -m "feat(agent): add operator revocation certificates"
```

---

## Phase 4: Knowledge on DHT

### Task 9: Knowledge Entry DHT Storage

**Files:**
- Create: `internal/dht/knowledge.go`
- Test: `internal/dht/knowledge_test.go`

This wraps the lower-level DHT `Store`/`FindValue` with knowledge-specific logic:

- `PublishKnowledge(entry)` — stores entry at `ContentKey(domain, id)` and updates domain index at `DomainIndexKey(domain)`
- `QueryKnowledge(domain, text, filters)` — fetches domain index, then fetches individual entries, applies text search and confidence filter
- `DeleteKnowledge(entryID, domain)` — removes from DHT and domain index

Uses the existing `storage.KnowledgeEntry` model (no new types needed).

**Step 1: Write failing tests**

Test with 3-node DHT cluster:
- Publish entry on node A → query on node B returns it
- Domain index query returns correct entries
- Delete removes from both content key and domain index
- Entries with TTL expire
- Entries wrapped with untrusted markers on return

**Step 2–5: Implement, test, commit**

```bash
git commit -m "feat(dht): add knowledge entry publish, query, and delete over DHT"
```

---

### Task 10: Distributed Voting (VOTE RPC)

**Files:**
- Create: `internal/dht/voting.go`
- Test: `internal/dht/voting_test.go`

Implements the VOTE RPC on responsible nodes:

- `SubmitVoteCommitment(entryKey, commitment, operatorSig)` — sends to responsible nodes
- `SubmitVoteReveal(entryKey, vote, nonce, reason, operatorSig)` — reveals vote
- Responsible nodes store votes locally, sync with each other
- `TallyVotes(entryKey)` — computes tally when reveal window closes
- Tally valid when ceil(k/2+1) responsible nodes agree

**Step 1: Write failing tests**

Test with 5-node cluster (small k=5 for testing):
- Commit phase: 3 operators submit commitments
- Reveal phase: 3 operators reveal votes
- Tally: correct result with BFT threshold
- Reject duplicate votes from same operator
- Reject reveal that doesn't match commitment

**Step 2–5: Implement, test, commit**

```bash
git commit -m "feat(dht): add distributed commit-reveal voting on responsible nodes"
```

---

### Task 11: Compute Task Distribution

**Files:**
- Create: `internal/dht/tasks.go`
- Test: `internal/dht/tasks_test.go`

Implements distributed compute task lifecycle:

- Task generation triggers (domain index responsible nodes detect conditions)
- `PublishTask(task)` — stores at task key, updates task index
- `ClaimTask(taskID, agentID)` — distributed lock via first-writer-wins on responsible nodes
- `SubmitTaskResult(taskID, resultID)` — marks task complete
- Claim expiry after 1 hour

**Step 1: Write failing tests**

Test task lifecycle: publish → claim → submit result. Test claim contention (two agents try to claim simultaneously). Test claim expiry.

**Step 2–5: Implement, test, commit**

```bash
git commit -m "feat(dht): add distributed compute task publish, claim, and completion"
```

---

## Phase 5: Gossip & Anomaly Detection

### Task 12: Gossip Layer

**Files:**
- Create: `internal/dht/gossip.go`
- Test: `internal/dht/gossip_test.go`

Implements eager gossip for safety-critical messages:

- `Gossip(msg)` — send to all connected peers, who forward to their peers
- Deduplication by message ID (seen-set with TTL)
- Priority levels: revocations > quarantine > trust certs > anomaly reports
- Rate limiting on gossip forwarding

Used for:
- Trust certificate propagation
- Revocation propagation (highest priority)
- Quarantine certificates
- Anomaly reports

**Step 1: Write failing tests**

Test with 4-node chain: A↔B↔C↔D. Gossip from A reaches D. Dedup prevents infinite forwarding. Priority ordering.

**Step 2–5: Implement, test, commit**

```bash
git commit -m "feat(dht): add gossip layer for trust certs, revocations, and anomaly reports"
```

---

### Task 13: Distributed Anomaly Detection

**Files:**
- Create: `internal/dht/anomaly.go`
- Test: `internal/dht/anomaly_test.go`

Each node monitors locally:
- Vote burst detection (>20 votes/min from one operator)
- Domain flooding (>50 entries/hour from one operator)
- Accuracy dropoff tracking

When anomaly detected:
1. Publish anomaly report to DHT
2. Gossip the report
3. Quarantine vote can be initiated

Reuses anomaly detection patterns from existing `internal/server/anomaly.go`.

**Step 1: Write failing tests**

**Step 2–5: Implement, test, commit**

```bash
git commit -m "feat(dht): add distributed anomaly detection and quarantine voting"
```

---

## Phase 6: DHT Peer Binary

### Task 14: `nocturne-agent` CLI — Full DHT Peer

**Files:**
- Create: `cmd/nocturne-agent/main.go`
- Modify: `internal/dht/node.go` — add localhost HTTP API for MCP server communication

The `nocturne-agent` binary:
1. Starts a full DHT peer
2. Listens for P2P connections on `--port 9090`
3. Exposes a localhost HTTP API on `--api-port 9091` (for the MCP server)
4. Reads config from `~/.nocturne/`

Localhost API endpoints (same interface as the old central server, but backed by DHT):

```
POST /local/knowledge     → PublishKnowledge via DHT
GET  /local/knowledge     → QueryKnowledge via DHT
DELETE /local/knowledge/{id} → DeleteKnowledge via DHT
POST /local/knowledge/{id}/vote → SubmitVote via DHT
GET  /local/compute       → ClaimTask via DHT
POST /local/compute/{id}/result → SubmitTaskResult via DHT
GET  /local/awareness     → FindValue(awareness:latest) via DHT
POST /local/reflect       → Store awareness snapshot via DHT
GET  /local/peers         → RoutingTable stats
GET  /local/health        → Node health check
```

**Step 1: Write failing tests**

Integration test: start `nocturne-agent`, hit `/local/health`, verify it returns OK.

**Step 2–5: Implement, test, commit**

```bash
git commit -m "feat: add nocturne-agent CLI with DHT peer and localhost API"
```

---

### Task 15: `nocturne-agent` CLI — Setup, Endorse, Enroll Commands

**Files:**
- Modify: `cmd/nocturne-agent/main.go`

Add subcommands:

```bash
nocturne-agent start [--port 9090] [--api-port 9091] [--bootstrap wss://...]
nocturne-agent setup --label "my-org"
nocturne-agent endorse --operator <pubkey-hex> --key <path-to-private-key>
nocturne-agent enroll --endorsements e1.sig,e2.sig,e3.sig
nocturne-agent status
nocturne-agent stop
```

**Step 1–5: Implement, test, commit**

```bash
git commit -m "feat: add setup, endorse, enroll commands to nocturne-agent"
```

---

## Phase 7: MCP Server Update

### Task 16: Update `nocturne-mesh` npm Package

**Files:**
- Modify: `nocturne-mesh/src/index.ts`

Replace the HTTPS client with localhost HTTP calls to the co-running `nocturne-agent` binary:

1. On startup, `nocturne-mesh` spawns `nocturne-agent start` as a child process
2. Waits for `/local/health` to return OK
3. All MCP tool calls become `fetch("http://localhost:9091/local/...")` instead of `fetch(trackerURL + "/api/agent/...")`
4. No more Ed25519 signing in TypeScript — the Go binary handles all P2P auth
5. Add `mesh_peers` tool (new)
6. Update setup/config subcommands

**Key changes:**
- Remove `signRequest()` function (Go handles signing)
- Remove `--tracker` flag
- Add `--port` and `--api-port` flags
- Add child process management (spawn/kill `nocturne-agent`)
- Update `setup` to call `nocturne-agent setup`
- Add `endorse` and `enroll` subcommands

**Step 1: Write integration test**

Test that `nocturne-mesh` can spawn `nocturne-agent` and proxy a `/local/health` call.

**Step 2–5: Implement, test, commit**

```bash
git commit -m "feat(nocturne-mesh): replace HTTPS client with local DHT peer proxy"
```

---

## Phase 8: Cleanup & Migration

### Task 17: Remove Centralized Agent Endpoints

**Files:**
- Modify: `internal/server/server.go` — remove `s.agentRoutes()` call
- Delete: `internal/server/agent.go`
- Delete: `internal/server/agent_test.go`
- Modify: `internal/server/workers.go` — remove agent-specific workers (keep file/link workers)
- Modify: `internal/server/anomaly.go` — remove (moved to `internal/dht/anomaly.go`)
- Delete: `internal/server/anomaly_test.go`

The core Nocturne server retains:
- File upload/download/delete
- Link management
- Recovery
- Public download pages
- Dashboard
- Storage mesh (Phase 5 WebSocket tracker)

**Step 1: Remove agent routes from server.go**

```go
// Remove this line from routes():
// s.agentRoutes()
```

**Step 2: Delete agent.go and agent_test.go**

**Step 3: Update workers.go — remove agent workers**

**Step 4: Run remaining tests to ensure nothing is broken**

Run: `cd /home/mark-ssd/code/ssd.foundation/nocturne && go test ./... -v`
Expected: All non-agent tests PASS. Agent test count drops. Total test count may decrease temporarily.

**Step 5: Commit**

```bash
git commit -m "refactor: remove centralized agent endpoints (replaced by P2P DHT)"
```

---

### Task 18: Update Storage Layer

**Files:**
- Modify: `internal/storage/sqlite.go` — keep agent tables for backward compat but mark deprecated
- Keep: `internal/storage/agent_models.go` — models reused by DHT layer
- Keep: `internal/storage/agent_store.go` — subset reused by DHT local store

The agent models (`KnowledgeEntry`, `ComputeTask`, `Vote`, etc.) are reused as-is by the DHT local store. The SQLite schema stays the same but runs per-node in `~/.nocturne/dht/entries.db` instead of centrally.

**Step 1: Verify agent models are importable from dht package**

Run: `cd /home/mark-ssd/code/ssd.foundation/nocturne && go build ./internal/dht/`
Expected: Compiles cleanly

**Step 2: Run full test suite**

Run: `cd /home/mark-ssd/code/ssd.foundation/nocturne && go test ./... -count=1`
Expected: All PASS

**Step 3: Commit**

```bash
git commit -m "refactor: mark central agent storage as deprecated, models reused by DHT"
```

---

### Task 19: Update README & Documentation

**Files:**
- Modify: `README.md` — update architecture section, add P2P setup instructions
- Modify: `nocturne-mesh/README.md` — update setup flow (no --tracker)

**Step 1: Update README**

Update architecture diagram, setup instructions, and add section on P2P network. Remove references to central server agent API.

**Step 2: Commit**

```bash
git commit -m "docs: update README for P2P agent mesh architecture"
```

---

### Task 20: Integration Test — Full P2P Flow

**Files:**
- Create: `internal/dht/integration_test.go`

End-to-end test with 3 DHT nodes:

1. Start 3 nodes, bootstrap them together
2. Create trust certificates (genesis + endorsements)
3. Publish knowledge entry on node 1
4. Query knowledge from node 3 — verify it's found
5. Submit vote commitments from 2 operators
6. Reveal votes
7. Verify tally updates confidence
8. Publish compute task, claim from different node, submit result
9. Gossip a revocation, verify all nodes reject the revoked operator
10. Verify anomaly detection triggers on burst behavior

**Step 1: Write the integration test**

**Step 2: Run it**

Run: `cd /home/mark-ssd/code/ssd.foundation/nocturne && go test ./internal/dht/ -v -run TestIntegration -timeout 60s`
Expected: All PASS

**Step 3: Commit**

```bash
git commit -m "test: add full P2P integration test covering knowledge, voting, gossip"
```

---

## Execution Order & Dependencies

```
Phase 1 (DHT Core):
  Task 1 (ID/distance) → Task 2 (routing table)

Phase 2 (Transport):
  Task 3 (messages) → Task 4 (WebSocket) → Task 5 (node + RPCs) → Task 6 (store)

Phase 3 (Trust):
  Task 7 (genesis + certs) → Task 8 (revocation)

Phase 4 (Knowledge):
  Task 6 + Task 7 → Task 9 (knowledge DHT) → Task 10 (voting) → Task 11 (compute)

Phase 5 (Gossip):
  Task 5 + Task 8 → Task 12 (gossip) → Task 13 (anomaly)

Phase 6 (Binary):
  Task 9-13 → Task 14 (agent CLI) → Task 15 (setup commands)

Phase 7 (MCP):
  Task 14 → Task 16 (npm update)

Phase 8 (Cleanup):
  Task 16 → Task 17 (remove endpoints) → Task 18 (storage) → Task 19 (docs) → Task 20 (integration)
```

**Parallelizable:** Phase 1-2 and Phase 3 can run in parallel (no dependencies). Tasks 9, 10, 11 are sequential. Tasks 12, 13 can start once Task 5 and Task 8 are done.

---

## Build & Test Commands

```bash
# Run all tests
cd /home/mark-ssd/code/ssd.foundation/nocturne && go test ./... -count=1

# Run DHT tests only
go test ./internal/dht/ -v

# Run agent/trust tests only
go test ./internal/agent/ -v

# Build nocturne-agent binary
go build -o nocturne-agent ./cmd/nocturne-agent/

# Build npm package
cd nocturne-mesh && npm run build

# Run integration tests (longer timeout)
go test ./internal/dht/ -v -run TestIntegration -timeout 120s
```
