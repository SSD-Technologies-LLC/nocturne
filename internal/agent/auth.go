// Package agent provides Ed25519 request signing and verification for the
// Nocturne mesh-agent network.
package agent

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"time"
)

// TimestampWindow is the maximum age of a signed request before it is rejected.
const TimestampWindow = 5 * time.Minute

// AgentIDFromPublicKey returns the first 8 bytes of a public key encoded as
// 16-character lowercase hexadecimal. This serves as the agent's short identifier.
func AgentIDFromPublicKey(pub ed25519.PublicKey) string {
	return hex.EncodeToString(pub[:8])
}

// SignRequest adds X-Agent-ID, X-Agent-Timestamp, and X-Agent-Signature headers
// to an outgoing HTTP request. The signature covers:
//
//	method + path + timestamp + body
func SignRequest(req *http.Request, agentID string, privKey ed25519.PrivateKey, body []byte) {
	ts := strconv.FormatInt(time.Now().Unix(), 10)

	req.Header.Set("X-Agent-ID", agentID)
	req.Header.Set("X-Agent-Timestamp", ts)

	msg := req.Method + req.URL.Path + ts + string(body)
	sig := ed25519.Sign(privKey, []byte(msg))
	req.Header.Set("X-Agent-Signature", hex.EncodeToString(sig))
}

// VerifyRequest checks that:
//  1. The timestamp is within TimestampWindow of the current time.
//  2. The Ed25519 signature is valid for the reconstructed message.
//
// Returns a descriptive error on failure.
func VerifyRequest(req *http.Request, pubKey ed25519.PublicKey, body []byte) error {
	tsStr := req.Header.Get("X-Agent-Timestamp")
	sigHex := req.Header.Get("X-Agent-Signature")

	if tsStr == "" {
		return fmt.Errorf("missing X-Agent-Timestamp header")
	}
	if sigHex == "" {
		return fmt.Errorf("missing X-Agent-Signature header")
	}

	ts, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid timestamp: %w", err)
	}

	diff := math.Abs(float64(time.Now().Unix() - ts))
	if diff > TimestampWindow.Seconds() {
		return fmt.Errorf("timestamp expired: %.0fs drift exceeds %v window", diff, TimestampWindow)
	}

	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return fmt.Errorf("invalid signature hex: %w", err)
	}

	msg := req.Method + req.URL.Path + tsStr + string(body)
	if !ed25519.Verify(pubKey, []byte(msg), sig) {
		return fmt.Errorf("ed25519 signature verification failed")
	}

	return nil
}
