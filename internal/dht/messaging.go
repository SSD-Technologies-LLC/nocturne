package dht

import (
	"encoding/json"
	"fmt"
	"time"
)

const (
	defaultDirectTTL  = 10 // max relay hops
	maxSeenMessages   = 10000
	seenMessageExpiry = 10 * time.Minute
)

// OnDirectMessage registers a handler for incoming direct messages.
func (n *Node) OnDirectMessage(handler func(from NodeID, content json.RawMessage)) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.msgHandler = handler
}

// SendDirectMessage sends a message to a specific node.
// 3-tier delivery:
//  1. Direct: if recipient is in routing table, send directly
//  2. Relay: find closest peers to recipient, forward through them
//  3. Inbox: store in DHT as fallback
func (n *Node) SendDirectMessage(to NodeID, content json.RawMessage) error {
	nonce := randomMsgID()
	payload := DirectPayload{
		To:      to,
		From:    n.id,
		Content: content,
		TTL:     defaultDirectTTL,
		Nonce:   nonce,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal direct payload: %w", err)
	}

	msg := &Message{
		Type:      MsgDirect,
		ID:        nonce,
		Sender:    SenderInfo{NodeID: n.id, Address: n.Addr()},
		Timestamp: time.Now().Unix(),
		Payload:   payloadBytes,
	}
	msg.Sign(n.config.PrivateKey)

	// Tier 1: Try direct delivery if peer is in our routing table.
	peers := n.table.ClosestN(to, 1)
	if len(peers) > 0 && peers[0].ID == to {
		if err := n.transport.Send(to, msg); err == nil {
			return nil
		}
	}

	// Tier 2: Relay through closest peers to recipient.
	closest := n.table.ClosestN(to, n.config.Alpha)
	for _, peer := range closest {
		if peer.ID == n.id {
			continue
		}
		if err := n.transport.Send(peer.ID, msg); err == nil {
			return nil // successfully relayed to at least one peer
		}
	}

	// Tier 3: Store in DHT inbox as fallback.
	return n.storeInInbox(to, payloadBytes)
}

// handleDirectMessage processes an incoming DIRECT message.
func (n *Node) handleDirectMessage(msg *Message) {
	var payload DirectPayload
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		return
	}

	// Dedup check.
	n.mu.Lock()
	if _, seen := n.seenMessages[payload.Nonce]; seen {
		n.mu.Unlock()
		return
	}
	n.seenMessages[payload.Nonce] = time.Now()
	// Prune old entries if map is too large.
	if len(n.seenMessages) > maxSeenMessages {
		n.pruneSeenMessages()
	}
	n.mu.Unlock()

	// If this message is for us, deliver it.
	if payload.To == n.id {
		n.mu.Lock()
		handler := n.msgHandler
		n.mu.Unlock()
		if handler != nil {
			handler(payload.From, payload.Content)
		}
		// Send ACK back to sender.
		n.sendDirectAck(payload.From, payload.Nonce)
		return
	}

	// Not for us — relay if TTL allows.
	if payload.TTL <= 0 {
		return // expired
	}

	payload.TTL--
	relayPayload, err := json.Marshal(payload)
	if err != nil {
		return
	}

	relayMsg := &Message{
		Type:      MsgDirect,
		ID:        msg.ID,
		Sender:    SenderInfo{NodeID: n.id, Address: n.Addr()},
		Timestamp: time.Now().Unix(),
		Payload:   relayPayload,
	}
	relayMsg.Sign(n.config.PrivateKey)

	// Forward to closest peers to the destination.
	closest := n.table.ClosestN(payload.To, n.config.Alpha)
	for _, peer := range closest {
		if peer.ID == n.id || peer.ID == msg.Sender.NodeID {
			continue
		}
		_ = n.transport.Send(peer.ID, relayMsg)
	}
}

// sendDirectAck sends an acknowledgment back to the message sender.
func (n *Node) sendDirectAck(to NodeID, nonce string) {
	ackPayload := DirectAckPayload{
		Nonce:    nonce,
		Received: true,
	}
	data, err := json.Marshal(ackPayload)
	if err != nil {
		return
	}
	msg := &Message{
		Type:      MsgDirectAck,
		ID:        nonce,
		Sender:    SenderInfo{NodeID: n.id, Address: n.Addr()},
		Timestamp: time.Now().Unix(),
		Payload:   data,
	}
	msg.Sign(n.config.PrivateKey)
	n.transport.Send(to, msg)
}

// storeInInbox stores a message in the DHT inbox for offline delivery.
func (n *Node) storeInInbox(to NodeID, payloadBytes []byte) error {
	inboxKey := PrefixKey("inbox", to.Hex())
	return n.Store(inboxKey, payloadBytes)
}

// CheckInbox retrieves pending messages from the DHT inbox.
func (n *Node) CheckInbox() ([]DirectPayload, error) {
	inboxKey := PrefixKey("inbox", n.id.Hex())
	data, err := n.FindValue(inboxKey)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, nil
	}

	var payload DirectPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, fmt.Errorf("unmarshal inbox message: %w", err)
	}
	return []DirectPayload{payload}, nil
}

// pruneSeenMessages removes expired entries from the seen messages map.
// Must be called with n.mu held.
func (n *Node) pruneSeenMessages() {
	cutoff := time.Now().Add(-seenMessageExpiry)
	for nonce, seen := range n.seenMessages {
		if seen.Before(cutoff) {
			delete(n.seenMessages, nonce)
		}
	}
}
