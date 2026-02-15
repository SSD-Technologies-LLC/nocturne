package dht

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// peerConn wraps a websocket connection with a write mutex. gorilla/websocket
// connections do not support concurrent writers, so every write must be
// serialized per connection.
type peerConn struct {
	conn *websocket.Conn
	wmu  sync.Mutex // guards writes
}

// Transport manages WebSocket connections to DHT peers, providing message
// sending and receiving with automatic Ed25519 signing. Each outbound and
// inbound connection runs a read-loop goroutine that deserializes messages
// and dispatches them to a registered handler.
type Transport struct {
	mu       sync.RWMutex
	self     NodeID
	privKey  ed25519.PrivateKey
	conns    map[NodeID]*peerConn
	handler  func(*Message, NodeID)
	listener net.Listener
	server   *http.Server
}

// upgrader allows any origin (suitable for P2P mesh where there's no browser
// same-origin policy to enforce).
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

// NewTransport creates a new Transport for the given local node.
func NewTransport(self NodeID, privKey ed25519.PrivateKey) *Transport {
	return &Transport{
		self:    self,
		privKey: privKey,
		conns:   make(map[NodeID]*peerConn),
	}
}

// Listen starts a WebSocket server on the given port. Use port 0 to listen on
// a random available port. Incoming connections on /ws are upgraded to
// WebSocket and registered once the remote peer identifies itself.
func (t *Transport) Listen(port int) error {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	t.listener = ln

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", t.handleWS)

	t.server = &http.Server{Handler: mux}
	go t.server.Serve(ln) //nolint:errcheck
	return nil
}

// handleWS upgrades an inbound HTTP connection to WebSocket and starts a read
// loop. The remote peer's NodeID is learned from the first message received.
func (t *Transport) handleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	conn.SetReadLimit(1 << 20) // 1 MB

	// We don't know the remote NodeID yet; it will be set by the first
	// message we read in the read loop.
	pc := &peerConn{conn: conn}
	go t.readLoop(pc, NodeID{}, true)
}

// Connect establishes an outbound WebSocket connection to a remote peer and
// sends an identification message so the remote side can register this
// connection under our NodeID.
func (t *Transport) Connect(address string, peerID NodeID) error {
	url := fmt.Sprintf("ws://%s/ws", address)
	conn, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		return fmt.Errorf("dial %s: %w", address, err)
	}
	conn.SetReadLimit(1 << 20)

	pc := &peerConn{conn: conn}
	t.mu.Lock()
	t.conns[peerID] = pc
	t.mu.Unlock()

	// Send an identification message so the server side can map this
	// connection to our NodeID.
	hello := &Message{
		Type:    MsgPing,
		ID:      "hello",
		Payload: json.RawMessage(`{}`),
	}
	hello.Sender.NodeID = t.self
	hello.Timestamp = time.Now().Unix()
	hello.Sign(t.privKey)

	pc.wmu.Lock()
	writeErr := conn.WriteJSON(hello)
	pc.wmu.Unlock()
	if writeErr != nil {
		conn.Close()
		t.mu.Lock()
		delete(t.conns, peerID)
		t.mu.Unlock()
		return fmt.Errorf("write hello: %w", writeErr)
	}

	go t.readLoop(pc, peerID, false)
	return nil
}

// readLoop reads JSON messages from a WebSocket connection until it errors or
// closes. For inbound connections (inbound == true), the first message
// determines the remote peer's NodeID and registers the connection.
func (t *Transport) readLoop(pc *peerConn, peerID NodeID, inbound bool) {
	identified := !inbound // outbound connections already know the peer ID
	defer func() {
		pc.conn.Close()
		if identified {
			t.mu.Lock()
			// Only remove if the stored conn is the same object (avoids
			// removing a replacement connection).
			if existing, ok := t.conns[peerID]; ok && existing == pc {
				delete(t.conns, peerID)
			}
			t.mu.Unlock()
		}
	}()

	for {
		var msg Message
		if err := pc.conn.ReadJSON(&msg); err != nil {
			return
		}

		// For inbound connections, the first message reveals the peer's identity.
		if !identified {
			peerID = msg.Sender.NodeID
			t.mu.Lock()
			t.conns[peerID] = pc
			t.mu.Unlock()
			identified = true
		}

		t.mu.RLock()
		handler := t.handler
		t.mu.RUnlock()

		if handler != nil {
			handler(&msg, peerID)
		}
	}
}

// Send signs and sends a message to the peer identified by target. The
// message's Sender.NodeID, Timestamp, and Signature fields are set
// automatically. It is safe for concurrent use.
func (t *Transport) Send(target NodeID, msg *Message) error {
	t.mu.RLock()
	pc, ok := t.conns[target]
	t.mu.RUnlock()

	if !ok {
		return fmt.Errorf("not connected to peer %x", target[:4])
	}

	msg.Sender.NodeID = t.self
	msg.Timestamp = time.Now().Unix()
	msg.Sign(t.privKey)

	pc.wmu.Lock()
	err := pc.conn.WriteJSON(msg)
	pc.wmu.Unlock()
	if err != nil {
		return fmt.Errorf("write: %w", err)
	}
	return nil
}

// OnMessage registers a callback that is invoked for every incoming message.
// The callback receives the deserialized message and the sender's NodeID.
func (t *Transport) OnMessage(handler func(*Message, NodeID)) {
	t.mu.Lock()
	t.handler = handler
	t.mu.Unlock()
}

// ReregisterConn changes the NodeID associated with an existing connection.
// This is used during Ping when we initially connect with a temporary placeholder
// NodeID and later learn the real peer ID from the PONG response.
func (t *Transport) ReregisterConn(oldID, newID NodeID) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if pc, ok := t.conns[oldID]; ok {
		delete(t.conns, oldID)
		t.conns[newID] = pc
	}
}

// Disconnect closes the connection to a specific peer and removes it from the
// connection map.
func (t *Transport) Disconnect(id NodeID) {
	t.mu.Lock()
	pc, ok := t.conns[id]
	if ok {
		delete(t.conns, id)
	}
	t.mu.Unlock()

	if ok {
		pc.conn.Close()
	}
}

// ConnectedPeers returns a slice of NodeIDs for all currently connected peers.
func (t *Transport) ConnectedPeers() []NodeID {
	t.mu.RLock()
	defer t.mu.RUnlock()

	peers := make([]NodeID, 0, len(t.conns))
	for id := range t.conns {
		peers = append(peers, id)
	}
	return peers
}

// Close shuts down the listener and closes all peer connections.
func (t *Transport) Close() {
	if t.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		t.server.Shutdown(ctx) //nolint:errcheck
	}

	t.mu.Lock()
	for id, pc := range t.conns {
		pc.conn.Close()
		delete(t.conns, id)
	}
	t.mu.Unlock()
}

// Addr returns the listener's network address (e.g., "127.0.0.1:12345").
// Useful for tests and peer discovery.
func (t *Transport) Addr() string {
	if t.listener == nil {
		return ""
	}
	return t.listener.Addr().String()
}
