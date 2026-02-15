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
