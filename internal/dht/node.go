package dht

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// Config holds DHT node configuration.
type Config struct {
	PrivateKey     ed25519.PrivateKey
	PublicKey      ed25519.PublicKey
	K              int      // bucket size (default 20)
	Alpha          int      // concurrency (default 3)
	Port           int      // listen port (0 = random)
	BindAddr       string   // bind address (default "0.0.0.0", use "127.0.0.1" for local-only)
	BootstrapPeers []string // initial peer addresses
	StorePath      string   // SQLite path for local store (empty = :memory:)
}

// Node is a Kademlia DHT peer. It ties together a routing table, transport
// layer, message handling, and local storage to implement the core Kademlia
// RPCs: PING, FIND_NODE, STORE, and FIND_VALUE with iterative lookup.
type Node struct {
	id        NodeID
	config    Config
	table     *RoutingTable
	transport *Transport
	store     *LocalStore

	// Gossip layer (optional, set via SetGossiper).
	gossiper *Gossiper

	// Pending RPC tracking: map message ID -> response channel.
	mu      sync.Mutex
	pending map[string]chan *Message
}

// NewNode creates a new DHT node with the given configuration. If
// Config.StorePath is empty, an in-memory SQLite database is used.
func NewNode(cfg Config) (*Node, error) {
	id := NodeIDFromPublicKey(cfg.PublicKey)
	if cfg.K == 0 {
		cfg.K = 20
	}
	if cfg.Alpha == 0 {
		cfg.Alpha = 3
	}

	storePath := cfg.StorePath
	if storePath == "" {
		storePath = ":memory:"
	}
	store, err := NewLocalStore(storePath)
	if err != nil {
		return nil, fmt.Errorf("init local store: %w", err)
	}

	n := &Node{
		id:        id,
		config:    cfg,
		table:     NewRoutingTable(id, cfg.K),
		transport: NewTransport(id, cfg.PrivateKey),
		store:     store,
		pending:   make(map[string]chan *Message),
	}
	n.transport.OnMessage(n.handleMessage)
	return n, nil
}

// Start listens on the configured port and bootstraps if peers are given.
func (n *Node) Start() error {
	bindAddr := n.config.BindAddr
	if bindAddr == "" {
		bindAddr = "0.0.0.0"
	}
	if err := n.transport.Listen(bindAddr, n.config.Port); err != nil {
		return err
	}
	if len(n.config.BootstrapPeers) > 0 {
		return n.Bootstrap(n.config.BootstrapPeers)
	}
	return nil
}

// ID returns this node's identifier.
func (n *Node) ID() NodeID { return n.id }

// Addr returns the transport's listening address.
func (n *Node) Addr() string { return n.transport.Addr() }

// Table returns the routing table (useful for testing and inspection).
func (n *Node) Table() *RoutingTable { return n.table }

// Gossiper returns the node's gossiper, or nil if none is set.
func (n *Node) Gossiper() *Gossiper { return n.gossiper }

// SetGossiper attaches a gossiper to this node.
func (n *Node) SetGossiper(g *Gossiper) { n.gossiper = g }

// defaultStoreTTL is the time-to-live for entries stored via the STORE RPC.
const defaultStoreTTL = 24 * time.Hour

// Store stores a key-value pair in the DHT. It writes the entry to the local
// store first, then replicates it to the k closest peers found via an
// iterative lookup. Remote stores are best-effort and performed in parallel.
func (n *Node) Store(key NodeID, value []byte) error {
	// Store locally first.
	if err := n.store.Put(key, value, defaultStoreTTL); err != nil {
		return fmt.Errorf("local store: %w", err)
	}

	// Find the k closest peers to the key.
	closest, err := n.FindNode(key)
	if err != nil {
		return nil // local store succeeded; remote replication is best-effort
	}

	// Send STORE RPCs in parallel (best-effort).
	payload, err := json.Marshal(StorePayload{
		Key:   key,
		Value: json.RawMessage(value),
	})
	if err != nil {
		return nil
	}

	var wg sync.WaitGroup
	for _, peer := range closest {
		if peer.ID == n.id {
			continue
		}
		wg.Add(1)
		go func(p PeerInfo) {
			defer wg.Done()
			n.storeRPC(p, payload)
		}(peer)
	}
	wg.Wait()

	return nil
}

// replicateToNetwork replicates a key-value pair to the k closest peers
// without modifying the local store. Used by CAS workflows that have already
// written locally via CompareAndSwap/PutVersioned.
func (n *Node) replicateToNetwork(key NodeID, value []byte) {
	closest, err := n.FindNode(key)
	if err != nil {
		return
	}

	payload, err := json.Marshal(StorePayload{
		Key:   key,
		Value: json.RawMessage(value),
	})
	if err != nil {
		return
	}

	var wg sync.WaitGroup
	for _, peer := range closest {
		if peer.ID == n.id {
			continue
		}
		wg.Add(1)
		go func(p PeerInfo) {
			defer wg.Done()
			n.storeRPC(p, payload)
		}(peer)
	}
	wg.Wait()
}

// StoreLocal stores a value in the local store with versioning and returns
// the new version. Used for initial writes in CAS workflows.
func (n *Node) StoreLocal(key NodeID, value []byte) (uint64, error) {
	return n.store.PutVersioned(key, value, defaultStoreTTL)
}

// FindValueVersioned retrieves a value from the local store with its version.
// Returns (nil, 0, nil) if not found locally.
func (n *Node) FindValueVersioned(key NodeID) ([]byte, uint64, error) {
	value, version, found, err := n.store.GetVersioned(key)
	if err != nil {
		return nil, 0, err
	}
	if !found {
		return nil, 0, nil
	}
	return value, version, nil
}

// CompareAndSwapLocal atomically updates a value in the local store if the
// version matches. Returns the new version or ErrVersionConflict.
func (n *Node) CompareAndSwapLocal(key NodeID, value []byte, expectedVersion uint64) (uint64, error) {
	return n.store.CompareAndSwap(key, value, expectedVersion, defaultStoreTTL)
}

// storeRPC sends a STORE RPC to a specific peer. It connects if needed.
func (n *Node) storeRPC(peer PeerInfo, payload json.RawMessage) error {
	// Ensure we're connected to this peer.
	connected := false
	for _, id := range n.transport.ConnectedPeers() {
		if id == peer.ID {
			connected = true
			break
		}
	}
	if !connected {
		if err := n.transport.Connect(peer.Address, peer.ID); err != nil {
			return fmt.Errorf("connect to %s: %w", peer.Address, err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	msg := &Message{
		Type:    MsgStore,
		ID:      randomMsgID(),
		Payload: payload,
		Sender: SenderInfo{
			NodeID:  n.id,
			Address: n.Addr(),
		},
	}

	_, err := n.sendRPC(peer.ID, msg, 5*time.Second)
	return err
}

// FindValue looks up a value in the DHT by key. It checks the local store
// first, then performs an iterative lookup using FIND_VALUE messages. Each
// peer either returns the value (if it has it) or its closest known peers.
// Returns (nil, nil) if the key is not found anywhere.
func (n *Node) FindValue(key NodeID) ([]byte, error) {
	// Check local store first.
	value, found, err := n.store.Get(key)
	if err != nil {
		return nil, fmt.Errorf("local get: %w", err)
	}
	if found {
		return value, nil
	}

	// Iterative lookup using FIND_VALUE messages.
	shortlist := n.table.ClosestN(key, n.config.K)
	if len(shortlist) == 0 {
		return nil, nil
	}

	queried := make(map[NodeID]bool)
	queried[n.id] = true
	known := make(map[NodeID]PeerInfo)
	for _, p := range shortlist {
		known[p.ID] = p
	}

	for {
		candidates := closestUnqueried(shortlist, key, queried, n.config.Alpha)
		if len(candidates) == 0 {
			break
		}

		type result struct {
			value []byte
			found bool
			peers []PeerInfo
			err   error
		}
		results := make([]result, len(candidates))
		var wg sync.WaitGroup

		for i, candidate := range candidates {
			queried[candidate.ID] = true
			wg.Add(1)
			go func(idx int, peer PeerInfo) {
				defer wg.Done()
				val, fnd, peers, rpcErr := n.findValueRPC(peer, key)
				results[idx] = result{value: val, found: fnd, peers: peers, err: rpcErr}
			}(i, candidate)
		}
		wg.Wait()

		// Check if any peer returned the value.
		for _, r := range results {
			if r.err != nil {
				continue
			}
			if r.found {
				return r.value, nil
			}
			// Merge returned peers into shortlist.
			for _, p := range r.peers {
				if p.ID == n.id {
					continue
				}
				if _, exists := known[p.ID]; !exists {
					known[p.ID] = p
					shortlist = append(shortlist, p)
					n.table.Add(p)
				}
			}
		}
	}

	return nil, nil
}

// findValueRPC sends a FIND_VALUE RPC to a specific peer. It returns either
// the value (if the peer has it) or the peer's closest known peers.
func (n *Node) findValueRPC(peer PeerInfo, key NodeID) ([]byte, bool, []PeerInfo, error) {
	// Ensure we're connected to this peer.
	connected := false
	for _, id := range n.transport.ConnectedPeers() {
		if id == peer.ID {
			connected = true
			break
		}
	}
	if !connected {
		if err := n.transport.Connect(peer.Address, peer.ID); err != nil {
			return nil, false, nil, fmt.Errorf("connect to %s: %w", peer.Address, err)
		}
		time.Sleep(20 * time.Millisecond)
	}

	payload, err := json.Marshal(FindValuePayload{Key: key})
	if err != nil {
		return nil, false, nil, err
	}

	msg := &Message{
		Type:    MsgFindValue,
		ID:      randomMsgID(),
		Payload: payload,
		Sender: SenderInfo{
			NodeID:  n.id,
			Address: n.Addr(),
		},
	}

	resp, err := n.sendRPC(peer.ID, msg, 5*time.Second)
	if err != nil {
		return nil, false, nil, err
	}

	var fvr FindValueResponse
	if err := json.Unmarshal(resp.Payload, &fvr); err != nil {
		return nil, false, nil, fmt.Errorf("unmarshal FindValueResponse: %w", err)
	}

	if fvr.Found {
		return fvr.Value, true, nil, nil
	}
	return nil, false, fvr.Peers, nil
}

// Close shuts down the node, its transport, gossiper, and the local store.
func (n *Node) Close() error {
	if n.gossiper != nil {
		n.gossiper.Close()
	}
	n.transport.Close()
	if n.store != nil {
		return n.store.Close()
	}
	return nil
}

// randomMsgID generates a random 16-byte hex-encoded message ID.
func randomMsgID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// Ping sends a PING to the given address. If the peer responds with PONG,
// it is added to the routing table and its info is returned.
//
// Since we don't know the remote peer's NodeID beforehand, we connect using
// a temporary random NodeID as placeholder, exchange PING/PONG to learn
// the real identity, then re-register the connection under the real NodeID.
func (n *Node) Ping(address string) (*PeerInfo, error) {
	// Generate a temporary placeholder NodeID for the initial connection.
	var tempID NodeID
	rand.Read(tempID[:])

	// Connect to the peer (transport sends a hello PING automatically).
	if err := n.transport.Connect(address, tempID); err != nil {
		return nil, fmt.Errorf("connect to %s: %w", address, err)
	}

	// Build our own PING message with a unique ID for RPC correlation.
	msgID := randomMsgID()
	msg := &Message{
		Type:    MsgPing,
		ID:      msgID,
		Payload: json.RawMessage(`{}`),
		Sender: SenderInfo{
			NodeID:  n.id,
			Address: n.Addr(),
		},
	}

	// Send the PING via sendRPC which waits for a response.
	resp, err := n.sendRPC(tempID, msg, 5*time.Second)
	if err != nil {
		n.transport.Disconnect(tempID)
		return nil, fmt.Errorf("ping %s: %w", address, err)
	}

	// Learn the real peer NodeID from the response.
	realID := resp.Sender.NodeID
	peerAddr := resp.Sender.Address
	if peerAddr == "" {
		peerAddr = address
	}

	// Re-register the connection under the real NodeID.
	n.transport.ReregisterConn(tempID, realID)

	// Add the peer to our routing table.
	peer := PeerInfo{
		ID:         realID,
		Address:    peerAddr,
		OperatorID: resp.Sender.OperatorID,
		LastSeen:   time.Now(),
	}
	n.table.Add(peer)

	return &peer, nil
}

// FindNode performs an iterative Kademlia lookup for the target NodeID.
// Returns the k closest peers found across the network.
func (n *Node) FindNode(target NodeID) ([]PeerInfo, error) {
	// Seed the shortlist from our local routing table.
	shortlist := n.table.ClosestN(target, n.config.K)
	if len(shortlist) == 0 {
		return nil, nil
	}

	// Track which peers we've already queried.
	queried := make(map[NodeID]bool)
	queried[n.id] = true // don't query ourselves

	// Track all known peers by ID (for deduplication).
	known := make(map[NodeID]PeerInfo)
	for _, p := range shortlist {
		known[p.ID] = p
	}

	for {
		// Pick up to Alpha unqueried peers closest to target.
		candidates := closestUnqueried(shortlist, target, queried, n.config.Alpha)
		if len(candidates) == 0 {
			break // no more unqueried peers
		}

		// Query candidates in parallel.
		type result struct {
			peers []PeerInfo
			err   error
		}
		results := make([]result, len(candidates))
		var wg sync.WaitGroup

		for i, candidate := range candidates {
			queried[candidate.ID] = true
			wg.Add(1)
			go func(idx int, peer PeerInfo) {
				defer wg.Done()
				peers, err := n.findNodeRPC(peer, target)
				results[idx] = result{peers: peers, err: err}
			}(i, candidate)
		}
		wg.Wait()

		// Merge results into shortlist.
		for _, r := range results {
			if r.err != nil {
				continue
			}
			for _, p := range r.peers {
				if p.ID == n.id {
					continue // skip ourselves
				}
				if _, exists := known[p.ID]; !exists {
					known[p.ID] = p
					shortlist = append(shortlist, p)
					n.table.Add(p)
				}
			}
		}
	}

	// Return the k closest from our complete shortlist.
	return topK(shortlist, target, n.config.K), nil
}

// findNodeRPC sends a FIND_NODE RPC to a specific peer and returns the peers
// it knows about. It connects to the peer first if not already connected.
func (n *Node) findNodeRPC(peer PeerInfo, target NodeID) ([]PeerInfo, error) {
	// Ensure we're connected to this peer.
	connected := false
	for _, id := range n.transport.ConnectedPeers() {
		if id == peer.ID {
			connected = true
			break
		}
	}
	if !connected {
		if err := n.transport.Connect(peer.Address, peer.ID); err != nil {
			return nil, fmt.Errorf("connect to %s: %w", peer.Address, err)
		}
		// Give the connection a moment to establish.
		time.Sleep(20 * time.Millisecond)
	}

	payload, err := json.Marshal(FindNodePayload{Target: target})
	if err != nil {
		return nil, err
	}

	msg := &Message{
		Type:    MsgFindNode,
		ID:      randomMsgID(),
		Payload: json.RawMessage(payload),
		Sender: SenderInfo{
			NodeID:  n.id,
			Address: n.Addr(),
		},
	}

	resp, err := n.sendRPC(peer.ID, msg, 5*time.Second)
	if err != nil {
		return nil, err
	}

	var fnr FindNodeResponse
	if err := json.Unmarshal(resp.Payload, &fnr); err != nil {
		return nil, fmt.Errorf("unmarshal FindNodeResponse: %w", err)
	}

	return fnr.Peers, nil
}

// Bootstrap connects to the given addresses and performs a self-lookup
// to populate the routing table.
func (n *Node) Bootstrap(addresses []string) error {
	for _, addr := range addresses {
		n.Ping(addr) // best-effort, ignore errors
	}
	// Perform a self-lookup to discover peers close to ourselves.
	n.FindNode(n.id)
	return nil
}

// abs64 returns the absolute value of an int64.
func abs64(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

// maxMessageAge is the maximum allowed age (in seconds) for a message
// timestamp. Messages older than this are rejected as stale.
const maxMessageAge int64 = 300 // 5 minutes

// handleMessage is the callback registered with the transport. It processes
// incoming messages by updating the routing table and handling RPCs.
func (n *Node) handleMessage(msg *Message, from NodeID) {
	// --- Signature and timestamp verification ---

	// 1. Timestamp freshness check: reject messages with missing or stale
	//    timestamps (prevents replay attacks).
	if msg.Timestamp == 0 || abs64(time.Now().Unix()-msg.Timestamp) > maxMessageAge {
		return // missing, stale, or future-dated timestamp
	}

	// 2. Verify sender's public key matches claimed NodeID.
	var senderPubKey ed25519.PublicKey
	if msg.Sender.PublicKey != "" {
		pkBytes, err := hex.DecodeString(msg.Sender.PublicKey)
		if err != nil || len(pkBytes) != ed25519.PublicKeySize {
			return // invalid public key encoding
		}
		senderPubKey = ed25519.PublicKey(pkBytes)

		expectedID := NodeIDFromPublicKey(senderPubKey)
		if expectedID != msg.Sender.NodeID {
			return // NodeID does not match public key
		}
	}

	// 3. Verify message signature if present.
	if msg.Signature != "" {
		if senderPubKey == nil {
			// Has signature but no public key — can't verify, drop.
			return
		}
		if err := msg.Verify(senderPubKey); err != nil {
			return // forged or corrupted signature
		}
	}
	// If no signature and no public key, allow (backwards compat).

	// --- Verification passed — update routing table ---
	n.table.Add(PeerInfo{
		ID:         msg.Sender.NodeID,
		Address:    msg.Sender.Address,
		PublicKey:  senderPubKey,
		OperatorID: msg.Sender.OperatorID,
		LastSeen:   time.Now(),
	})

	switch msg.Type {
	case MsgPing:
		// Respond with PONG.
		n.sendResponse(from, msg.ID, MsgPong, json.RawMessage(`{}`))

	case MsgPong:
		// Deliver to any waiting RPC caller.
		n.deliverResponse(msg)

	case MsgFindNode:
		// Parse the target and return our closest known peers.
		var payload FindNodePayload
		if err := json.Unmarshal(msg.Payload, &payload); err != nil {
			return
		}
		closest := n.table.ClosestN(payload.Target, n.config.K)
		resp, err := json.Marshal(FindNodeResponse{Peers: closest})
		if err != nil {
			return
		}
		n.sendResponse(from, msg.ID, MsgResponse, resp)

	case MsgStore:
		// Store the key-value pair locally.
		var payload StorePayload
		if err := json.Unmarshal(msg.Payload, &payload); err != nil {
			return
		}
		storeErr := n.store.Put(payload.Key, payload.Value, defaultStoreTTL)
		resp, err := json.Marshal(StoreResponse{Stored: storeErr == nil})
		if err != nil {
			return
		}
		n.sendResponse(from, msg.ID, MsgResponse, resp)

	case MsgFindValue:
		// Check local store for the requested key.
		var payload FindValuePayload
		if err := json.Unmarshal(msg.Payload, &payload); err != nil {
			return
		}
		value, found, _ := n.store.Get(payload.Key)
		if found {
			resp, err := json.Marshal(FindValueResponse{
				Found: true,
				Value: json.RawMessage(value),
			})
			if err != nil {
				return
			}
			n.sendResponse(from, msg.ID, MsgResponse, resp)
		} else {
			// Return closest peers instead.
			closest := n.table.ClosestN(payload.Key, n.config.K)
			resp, err := json.Marshal(FindValueResponse{
				Found: false,
				Peers: closest,
			})
			if err != nil {
				return
			}
			n.sendResponse(from, msg.ID, MsgResponse, resp)
		}

	case MsgGossip:
		if n.gossiper != nil {
			n.gossiper.HandleGossipMessage(msg.Payload)
		}

	case MsgResponse:
		// Deliver to any waiting RPC caller.
		n.deliverResponse(msg)
	}
}

// sendResponse sends a reply message to the given peer, reusing the request's
// message ID for correlation.
func (n *Node) sendResponse(target NodeID, replyTo string, msgType string, payload json.RawMessage) {
	msg := &Message{
		Type:    msgType,
		ID:      replyTo,
		Payload: payload,
		Sender: SenderInfo{
			NodeID:  n.id,
			Address: n.Addr(),
		},
	}
	n.transport.Send(target, msg)
}

// sendRPC sends a message and waits for a response with the same message ID.
func (n *Node) sendRPC(target NodeID, msg *Message, timeout time.Duration) (*Message, error) {
	ch := make(chan *Message, 1)
	n.mu.Lock()
	n.pending[msg.ID] = ch
	n.mu.Unlock()

	if err := n.transport.Send(target, msg); err != nil {
		n.mu.Lock()
		delete(n.pending, msg.ID)
		n.mu.Unlock()
		return nil, err
	}

	select {
	case resp := <-ch:
		return resp, nil
	case <-time.After(timeout):
		n.mu.Lock()
		delete(n.pending, msg.ID)
		n.mu.Unlock()
		return nil, fmt.Errorf("RPC timeout")
	}
}

// deliverResponse routes an incoming response message to the waiting RPC
// caller by matching the message ID.
func (n *Node) deliverResponse(msg *Message) {
	n.mu.Lock()
	ch, ok := n.pending[msg.ID]
	if ok {
		delete(n.pending, msg.ID)
	}
	n.mu.Unlock()
	if ok {
		ch <- msg
	}
}

// closestUnqueried returns up to n peers from the shortlist that haven't been
// queried yet, sorted by distance to target.
func closestUnqueried(peers []PeerInfo, target NodeID, queried map[NodeID]bool, n int) []PeerInfo {
	var unqueried []PeerInfo
	for _, p := range peers {
		if !queried[p.ID] {
			unqueried = append(unqueried, p)
		}
	}
	// Sort by distance to target.
	sorted := topK(unqueried, target, n)
	return sorted
}

// closestPeer returns the peer closest to the target from the list.
func closestPeer(peers []PeerInfo, target NodeID) PeerInfo {
	if len(peers) == 0 {
		return PeerInfo{}
	}
	best := peers[0]
	for _, p := range peers[1:] {
		if DistanceLess(target, p.ID, best.ID) {
			best = p
		}
	}
	return best
}

// topK returns the k peers closest to the target, sorted by distance.
func topK(peers []PeerInfo, target NodeID, k int) []PeerInfo {
	if len(peers) == 0 {
		return nil
	}
	// Make a copy to avoid mutating the input.
	sorted := make([]PeerInfo, len(peers))
	copy(sorted, peers)

	// Sort by XOR distance to target.
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if DistanceLess(target, sorted[j].ID, sorted[i].ID) {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	if len(sorted) > k {
		sorted = sorted[:k]
	}
	return sorted
}
