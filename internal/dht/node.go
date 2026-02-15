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
	BootstrapPeers []string // initial peer addresses
}

// Node is a Kademlia DHT peer. It ties together a routing table, transport
// layer, and message handling to implement the core Kademlia RPCs: PING and
// FIND_NODE with iterative lookup.
type Node struct {
	id        NodeID
	config    Config
	table     *RoutingTable
	transport *Transport

	// Pending RPC tracking: map message ID -> response channel.
	mu      sync.Mutex
	pending map[string]chan *Message
}

// NewNode creates a new DHT node with the given configuration.
func NewNode(cfg Config) *Node {
	id := NodeIDFromPublicKey(cfg.PublicKey)
	if cfg.K == 0 {
		cfg.K = 20
	}
	if cfg.Alpha == 0 {
		cfg.Alpha = 3
	}

	n := &Node{
		id:        id,
		config:    cfg,
		table:     NewRoutingTable(id, cfg.K),
		transport: NewTransport(id, cfg.PrivateKey),
		pending:   make(map[string]chan *Message),
	}
	n.transport.OnMessage(n.handleMessage)
	return n
}

// Start listens on the configured port and bootstraps if peers are given.
func (n *Node) Start() error {
	if err := n.transport.Listen(n.config.Port); err != nil {
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

// Close shuts down the node and its transport.
func (n *Node) Close() error {
	n.transport.Close()
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

// handleMessage is the callback registered with the transport. It processes
// incoming messages by updating the routing table and handling RPCs.
func (n *Node) handleMessage(msg *Message, from NodeID) {
	// Update routing table with sender's info on every message.
	n.table.Add(PeerInfo{
		ID:         msg.Sender.NodeID,
		Address:    msg.Sender.Address,
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
