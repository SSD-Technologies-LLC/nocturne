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
