package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ssd-technologies/nocturne/internal/agent"
)

// setupAgentTest creates a test server, enrolls an operator and agent, and
// returns the httptest server plus the agent credentials ready for use.
func setupAgentTest(t *testing.T) (ts *httptest.Server, agentPub ed25519.PublicKey, agentPriv ed25519.PrivateKey, agentID string) {
	t.Helper()
	srv := setupTestServer(t) // uses secret "test-secret"
	ts = httptest.NewServer(srv)
	t.Cleanup(ts.Close)

	// --- Generate operator keypair and enroll via admin API ---
	opPub, opPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate operator key: %v", err)
	}

	opBody, _ := json.Marshal(map[string]any{
		"public_key": hex.EncodeToString(opPub),
		"label":      "test-operator",
		"max_agents": 5,
	})
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/admin/operator", bytes.NewReader(opBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Admin-Secret", "test-secret")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("enroll operator: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("enroll operator: status %d, body: %s", resp.StatusCode, b)
	}

	// --- Generate agent keypair ---
	agentPub, agentPriv, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate agent key: %v", err)
	}

	// Operator signs the agent's public key.
	sig := ed25519.Sign(opPriv, agentPub)

	enrollBody, _ := json.Marshal(map[string]string{
		"operator_public_key": hex.EncodeToString(opPub),
		"agent_public_key":    hex.EncodeToString(agentPub),
		"label":               "test-agent",
		"signature":           hex.EncodeToString(sig),
	})
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/api/agent/enroll", bytes.NewReader(enrollBody))
	req.Header.Set("Content-Type", "application/json")

	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("enroll agent: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("enroll agent: status %d, body: %s", resp.StatusCode, b)
	}

	var enrollResult map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&enrollResult); err != nil {
		t.Fatalf("decode enroll result: %v", err)
	}
	agentID = enrollResult["agent_id"]
	return ts, agentPub, agentPriv, agentID
}

// signedRequest creates an HTTP request with Ed25519 auth headers.
func signedRequest(t *testing.T, method, url string, body []byte, agentID string, privKey ed25519.PrivateKey) *http.Request {
	t.Helper()
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	agent.SignRequest(req, agentID, privKey, body)
	return req
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestAdminEnrollOperator(t *testing.T) {
	srv := setupTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	body, _ := json.Marshal(map[string]any{
		"public_key": hex.EncodeToString(pub),
		"label":      "op-1",
		"max_agents": 3,
	})

	// With correct secret -> 201
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/admin/operator", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Admin-Secret", "test-secret")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("status = %d, want 201; body = %s", resp.StatusCode, b)
	}

	var result map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result["id"] == "" {
		t.Error("expected non-empty operator id")
	}
	if result["label"] != "op-1" {
		t.Errorf("label = %q, want %q", result["label"], "op-1")
	}

	// Without secret -> 401
	req2, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/admin/operator", bytes.NewReader(body))
	req2.Header.Set("Content-Type", "application/json")

	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Errorf("no secret: status = %d, want 401", resp2.StatusCode)
	}
}

func TestFullAgentFlow(t *testing.T) {
	ts, _, agentPriv, agentID := setupAgentTest(t)

	// 1. Publish knowledge
	pubBody, _ := json.Marshal(map[string]any{
		"domain":     "testing.integration",
		"content":    "Integration tests validate API correctness",
		"type":       "observation",
		"confidence": 0.9,
	})
	req := signedRequest(t, http.MethodPost, ts.URL+"/api/agent/knowledge", pubBody, agentID, agentPriv)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("publish: status %d, body: %s", resp.StatusCode, b)
	}
	var pubResult map[string]string
	json.NewDecoder(resp.Body).Decode(&pubResult)
	if pubResult["id"] == "" {
		t.Fatal("expected non-empty knowledge id")
	}
	if pubResult["domain"] != "testing.integration" {
		t.Errorf("domain = %q, want %q", pubResult["domain"], "testing.integration")
	}

	// 2. Query knowledge
	req = signedRequest(t, http.MethodGet, ts.URL+"/api/agent/knowledge?domain=testing", nil, agentID, agentPriv)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("query: status %d, body: %s", resp.StatusCode, b)
	}
	var queryResults []map[string]any
	json.NewDecoder(resp.Body).Decode(&queryResults)
	if len(queryResults) == 0 {
		t.Fatal("expected at least one knowledge result")
	}
	if queryResults[0]["_warning"] == nil || queryResults[0]["_warning"] == "" {
		t.Error("expected _warning field in query results")
	}

	// 3. List channels
	req = signedRequest(t, http.MethodGet, ts.URL+"/api/agent/channels", nil, agentID, agentPriv)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("channels: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("channels: status %d, body: %s", resp.StatusCode, b)
	}

	// 4. Get awareness (empty is fine, returns status message)
	req = signedRequest(t, http.MethodGet, ts.URL+"/api/agent/awareness", nil, agentID, agentPriv)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("awareness: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("awareness: status %d, body: %s", resp.StatusCode, b)
	}

	// 5. Submit reflection
	reflectBody, _ := json.Marshal(map[string]string{
		"snapshot": `{"domains":1,"entries":1}`,
	})
	req = signedRequest(t, http.MethodPost, ts.URL+"/api/agent/reflect", reflectBody, agentID, agentPriv)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("reflect: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("reflect: status %d, body: %s", resp.StatusCode, b)
	}

	// 6. Get stats
	req = signedRequest(t, http.MethodGet, ts.URL+"/api/agent/stats", nil, agentID, agentPriv)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("stats: status %d, body: %s", resp.StatusCode, b)
	}
	var stats map[string]any
	json.NewDecoder(resp.Body).Decode(&stats)
	if stats["operators_total"] == nil {
		t.Error("expected operators_total in stats")
	}
}

func TestQuarantinedAgentBlocked(t *testing.T) {
	// Inline setup so we can capture the operator ID for quarantine.
	srv := setupTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	// Enroll operator via admin API.
	opPub, opPriv, _ := ed25519.GenerateKey(rand.Reader)
	opBody, _ := json.Marshal(map[string]any{
		"public_key": hex.EncodeToString(opPub),
		"label":      "quarantine-test-op",
		"max_agents": 5,
	})
	adminReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/admin/operator", bytes.NewReader(opBody))
	adminReq.Header.Set("Content-Type", "application/json")
	adminReq.Header.Set("X-Admin-Secret", "test-secret")
	adminResp, _ := http.DefaultClient.Do(adminReq)
	var opResult map[string]string
	json.NewDecoder(adminResp.Body).Decode(&opResult)
	adminResp.Body.Close()
	operatorID := opResult["id"]

	// Enroll agent under that operator.
	aPub, aPriv, _ := ed25519.GenerateKey(rand.Reader)
	sig := ed25519.Sign(opPriv, aPub)
	enrollBody, _ := json.Marshal(map[string]string{
		"operator_public_key": hex.EncodeToString(opPub),
		"agent_public_key":    hex.EncodeToString(aPub),
		"label":               "quarantine-test-agent",
		"signature":           hex.EncodeToString(sig),
	})
	enrollReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/agent/enroll", bytes.NewReader(enrollBody))
	enrollReq.Header.Set("Content-Type", "application/json")
	enrollResp, _ := http.DefaultClient.Do(enrollReq)
	var enrollResult map[string]string
	json.NewDecoder(enrollResp.Body).Decode(&enrollResult)
	enrollResp.Body.Close()
	aID := enrollResult["agent_id"]

	// Confirm agent works before quarantine.
	req := signedRequest(t, http.MethodGet, ts.URL+"/api/agent/channels", nil, aID, aPriv)
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("pre-quarantine: status %d, want 200", resp.StatusCode)
	}

	// Quarantine the operator.
	qBody, _ := json.Marshal(map[string]bool{"quarantine": true})
	qReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/api/admin/operator/"+operatorID+"/quarantine", bytes.NewReader(qBody))
	qReq.Header.Set("Content-Type", "application/json")
	qReq.Header.Set("X-Admin-Secret", "test-secret")
	qResp, _ := http.DefaultClient.Do(qReq)
	qResp.Body.Close()
	if qResp.StatusCode != http.StatusOK {
		t.Fatalf("quarantine: status %d, want 200", qResp.StatusCode)
	}

	// Agent should now be blocked with 403.
	req = signedRequest(t, http.MethodGet, ts.URL+"/api/agent/channels", nil, aID, aPriv)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post-quarantine: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("post-quarantine: status %d, want 403", resp.StatusCode)
	}
}

// ---------------------------------------------------------------------------
// Security: unauthenticated access tests
// ---------------------------------------------------------------------------

func TestUnauthenticatedAgentRequestsRejected(t *testing.T) {
	srv := setupTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	endpoints := []struct {
		method string
		path   string
	}{
		{"GET", "/api/agent/knowledge"},
		{"POST", "/api/agent/knowledge"},
		{"GET", "/api/agent/compute"},
		{"GET", "/api/agent/awareness"},
		{"GET", "/api/agent/channels"},
		{"GET", "/api/agent/stats"},
		{"POST", "/api/agent/reflect"},
	}

	for _, ep := range endpoints {
		req, _ := http.NewRequest(ep.method, ts.URL+ep.path, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", ep.method, ep.path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s %s: got %d, want 401", ep.method, ep.path, resp.StatusCode)
		}
	}
}

func TestAdminEndpointsRequireSecret(t *testing.T) {
	srv := setupTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	// Try admin endpoint without secret
	body := []byte(`{"public_key":"abc","label":"test","max_agents":5}`)
	req, _ := http.NewRequest("POST", ts.URL+"/api/admin/operator", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("admin without secret: got %d, want 401", resp.StatusCode)
	}

	// Try with wrong secret
	req, _ = http.NewRequest("POST", ts.URL+"/api/admin/operator", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Admin-Secret", "wrong-secret")
	resp, _ = http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("admin wrong secret: got %d, want 401", resp.StatusCode)
	}
}

func TestInvalidSignatureRejected(t *testing.T) {
	srv := setupTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	// Request with headers but invalid signature
	req, _ := http.NewRequest("GET", ts.URL+"/api/agent/channels", nil)
	req.Header.Set("X-Agent-ID", "nonexistent1234")
	req.Header.Set("X-Agent-Timestamp", fmt.Sprintf("%d", time.Now().Unix()))
	req.Header.Set("X-Agent-Signature", "deadbeef")
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("invalid sig: got %d, want 401", resp.StatusCode)
	}
}

func TestRateLimiting(t *testing.T) {
	srv := setupTestServer(t)
	ts := httptest.NewServer(srv)
	defer ts.Close()

	// Hammer an endpoint -- should eventually get 429
	var got429 bool
	for i := 0; i < 200; i++ {
		req, _ := http.NewRequest("GET", ts.URL+"/api/agent/channels", nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			got429 = true
			break
		}
	}
	if !got429 {
		t.Error("expected 429 Too Many Requests after rapid-fire requests")
	}
}
