package dht

import (
	"encoding/json"
	"sync"
	"time"
)

// GossipType identifies the kind of gossip message.
type GossipType string

const (
	GossipRevocation    GossipType = "revocation"
	GossipQuarantine    GossipType = "quarantine"
	GossipTrustCert     GossipType = "trust_cert"
	GossipAnomalyReport GossipType = "anomaly_report"
)

// GossipMessage wraps a gossip payload with metadata for deduplication and priority.
type GossipMessage struct {
	GossipID   string          `json:"gossip_id"`
	GossipType GossipType      `json:"gossip_type"`
	Data       json.RawMessage `json:"data"`
	Origin     NodeID          `json:"origin"`   // original sender
	Hops       int             `json:"hops"`     // current hop count
	MaxHops    int             `json:"max_hops"` // max forwarding depth
	Timestamp  int64           `json:"timestamp"`
}

// GossipHandler is called when a gossip message is received.
type GossipHandler func(msg *GossipMessage)

// Gossiper manages gossip message propagation and deduplication. It implements
// eager push gossip for safety-critical messages such as trust certificates,
// revocations, quarantine notices, and anomaly reports.
type Gossiper struct {
	mu       sync.RWMutex
	node     *Node
	seen     map[string]time.Time // gossip_id -> first seen time
	seenTTL  time.Duration
	handlers map[GossipType]GossipHandler
	maxHops  int
}

// NewGossiper creates a gossiper attached to a node.
func NewGossiper(node *Node) *Gossiper {
	return &Gossiper{
		node:     node,
		seen:     make(map[string]time.Time),
		seenTTL:  10 * time.Minute,
		handlers: make(map[GossipType]GossipHandler),
		maxHops:  10,
	}
}

// OnGossip registers a handler for a specific gossip type.
func (g *Gossiper) OnGossip(gtype GossipType, handler GossipHandler) {
	g.mu.Lock()
	g.handlers[gtype] = handler
	g.mu.Unlock()
}

// Broadcast sends a gossip message to all connected peers.
// The message is automatically forwarded by recipients up to maxHops.
func (g *Gossiper) Broadcast(gtype GossipType, data json.RawMessage) error {
	gossipID := randomMsgID()

	gmsg := &GossipMessage{
		GossipID:   gossipID,
		GossipType: gtype,
		Data:       data,
		Origin:     g.node.id,
		Hops:       0,
		MaxHops:    g.maxHops,
		Timestamp:  time.Now().Unix(),
	}

	// Mark as seen so we don't re-process our own messages.
	g.markSeen(gossipID)

	// Send to all connected peers.
	return g.forward(gmsg)
}

// HandleGossipMessage processes an incoming gossip message.
// Called by the node's message handler when a GOSSIP message is received.
func (g *Gossiper) HandleGossipMessage(payload json.RawMessage) {
	var gmsg GossipMessage
	if err := json.Unmarshal(payload, &gmsg); err != nil {
		return
	}

	// Dedup check: drop messages we have already seen.
	if g.hasSeen(gmsg.GossipID) {
		return
	}
	g.markSeen(gmsg.GossipID)

	// Drop messages that have exceeded the hop limit.
	if gmsg.Hops >= gmsg.MaxHops {
		return
	}

	// Call the registered handler for this gossip type.
	g.mu.RLock()
	handler, ok := g.handlers[gmsg.GossipType]
	g.mu.RUnlock()
	if ok {
		handler(&gmsg)
	}

	// Forward to all connected peers, incrementing the hop count.
	gmsg.Hops++
	g.forward(&gmsg)
}

// forward sends a gossip message to all connected peers, skipping the
// original sender to avoid echo loops.
func (g *Gossiper) forward(gmsg *GossipMessage) error {
	data, err := json.Marshal(gmsg)
	if err != nil {
		return err
	}

	peers := g.node.transport.ConnectedPeers()
	for _, peerID := range peers {
		if peerID == gmsg.Origin {
			continue // don't send back to origin
		}
		msg := &Message{
			Type:    MsgGossip,
			ID:      randomMsgID(),
			Payload: json.RawMessage(data),
			Sender: SenderInfo{
				NodeID:  g.node.id,
				Address: g.node.Addr(),
			},
		}
		g.node.transport.Send(peerID, msg)
	}
	return nil
}

func (g *Gossiper) markSeen(id string) {
	g.mu.Lock()
	g.seen[id] = time.Now()
	g.mu.Unlock()
}

func (g *Gossiper) hasSeen(id string) bool {
	g.mu.RLock()
	t, ok := g.seen[id]
	g.mu.RUnlock()
	if !ok {
		return false
	}
	// Check if TTL expired.
	if time.Since(t) > g.seenTTL {
		g.mu.Lock()
		delete(g.seen, id)
		g.mu.Unlock()
		return false
	}
	return true
}

// PruneSeen removes expired entries from the seen set and returns the number
// of entries removed.
func (g *Gossiper) PruneSeen() int {
	g.mu.Lock()
	defer g.mu.Unlock()

	count := 0
	now := time.Now()
	for id, t := range g.seen {
		if now.Sub(t) > g.seenTTL {
			delete(g.seen, id)
			count++
		}
	}
	return count
}
