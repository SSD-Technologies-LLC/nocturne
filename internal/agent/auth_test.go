package agent

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strconv"
	"testing"
	"time"
)

func TestSignAndVerifyRequest(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	agentID := AgentIDFromPublicKey(pub)
	body := []byte(`{"domain":"test","content":"hello"}`)

	req, err := http.NewRequest(http.MethodPost, "http://localhost/api/agent/knowledge", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	SignRequest(req, agentID, priv, body)

	// Verify headers are set
	if req.Header.Get("X-Agent-ID") != agentID {
		t.Errorf("X-Agent-ID = %q, want %q", req.Header.Get("X-Agent-ID"), agentID)
	}
	if req.Header.Get("X-Agent-Timestamp") == "" {
		t.Error("X-Agent-Timestamp not set")
	}
	if req.Header.Get("X-Agent-Signature") == "" {
		t.Error("X-Agent-Signature not set")
	}

	// Verification should succeed
	if err := VerifyRequest(req, pub, body); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestVerifyRequestRejectsExpiredTimestamp(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	agentID := AgentIDFromPublicKey(pub)
	body := []byte(`{}`)

	req, err := http.NewRequest(http.MethodGet, "http://localhost/api/agent/channels", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	// Manually set an expired timestamp (10 minutes ago)
	ts := strconv.FormatInt(time.Now().Add(-10*time.Minute).Unix(), 10)
	req.Header.Set("X-Agent-ID", agentID)
	req.Header.Set("X-Agent-Timestamp", ts)

	msg := req.Method + req.URL.Path + ts + string(body)
	sig := ed25519.Sign(priv, []byte(msg))
	req.Header.Set("X-Agent-Signature", hex.EncodeToString(sig))

	err = VerifyRequest(req, pub, body)
	if err == nil {
		t.Fatal("expected error for expired timestamp, got nil")
	}
}

func TestVerifyRequestRejectsBadSignature(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	// Sign with a DIFFERENT key
	_, wrongPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate wrong key: %v", err)
	}

	agentID := AgentIDFromPublicKey(pub)
	body := []byte(`{"data":"test"}`)

	req, err := http.NewRequest(http.MethodPost, "http://localhost/api/agent/knowledge", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}

	SignRequest(req, agentID, wrongPriv, body)

	err = VerifyRequest(req, pub, body)
	if err == nil {
		t.Fatal("expected error for bad signature, got nil")
	}
}

func TestAgentIDFromPublicKey(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	id := AgentIDFromPublicKey(pub)

	if len(id) != 16 {
		t.Errorf("agent ID length = %d, want 16", len(id))
	}

	// Must be valid hex
	if _, err := hex.DecodeString(id); err != nil {
		t.Errorf("agent ID is not valid hex: %v", err)
	}
}
