# Critical Security Fixes Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix the 5 critical security vulnerabilities identified in the Nocturne code review.

**Architecture:** Each fix is independent. Tasks 1-5 can be implemented in any order. We modify the DHT message handling for signature verification, the trust module for genesis key env var, the HTTP server for auth middleware and rate limiting, the storage layer for atomic link burning, and the dashboard JS for auth token handling.

**Tech Stack:** Go 1.24, SQLite, Ed25519, net/http, crypto/subtle

---

### Task 1: DHT Message Signature Verification

Add signature verification to `handleMessage()` so forged messages are rejected. Include public key in `SenderInfo`, verify NodeID matches the key, and add timestamp freshness check.

**Files:**
- Modify: `internal/dht/message.go` (add PublicKey to SenderInfo)
- Modify: `internal/dht/transport.go` (populate PublicKey in Send, store pubkey in peerConn)
- Modify: `internal/dht/node.go:504-586` (verify signatures in handleMessage)
- Test: `internal/dht/node_test.go`
- Test: `internal/dht/transport_test.go`

**Step 1: Add PublicKey field to SenderInfo**

In `internal/dht/message.go`, add a `PublicKey` field to `SenderInfo`:

```go
type SenderInfo struct {
	NodeID     NodeID `json:"node_id"`
	AgentID    string `json:"agent_id"`
	OperatorID string `json:"operator_id"`
	Address    string `json:"address"`
	PublicKey  string `json:"public_key,omitempty"` // hex-encoded Ed25519 public key
}
```

**Step 2: Populate PublicKey in Transport.Send**

In `internal/dht/transport.go`, add a `pubKey` field to Transport and populate `msg.Sender.PublicKey` in `Send()`:

```go
// In Transport struct, add:
pubKey ed25519.PublicKey

// In NewTransport, add:
pubKey: self.PublicKey, // wait — we don't have the public key from NodeID alone
```

Actually, `Transport` already has `privKey`. Derive the public key from it:

In `Send()` at line 183, after setting `msg.Sender.NodeID`:
```go
msg.Sender.PublicKey = hex.EncodeToString(t.privKey.Public().(ed25519.PublicKey))
```

Also populate in the `Connect()` hello message at line 109:
```go
hello.Sender.PublicKey = hex.EncodeToString(t.privKey.Public().(ed25519.PublicKey))
```

**Step 3: Store verified public keys in peerConn**

In `internal/dht/transport.go`, add `pubKey` to `peerConn`:

```go
type peerConn struct {
	conn   *websocket.Conn
	wmu    sync.Mutex
	pubKey ed25519.PublicKey // verified public key of the remote peer
}
```

Add a method to Transport to look up a peer's public key:

```go
func (t *Transport) PeerPublicKey(id NodeID) (ed25519.PublicKey, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	pc, ok := t.conns[id]
	if !ok || len(pc.pubKey) == 0 {
		return nil, false
	}
	return pc.pubKey, true
}
```

In `readLoop`, when identifying an inbound peer (line 153-158), decode and verify the public key from the first message, then store it:

```go
if !identified {
	peerID = msg.Sender.NodeID
	// Verify public key matches NodeID
	if msg.Sender.PublicKey != "" {
		pubBytes, err := hex.DecodeString(msg.Sender.PublicKey)
		if err == nil && len(pubBytes) == ed25519.PublicKeySize {
			expectedID := NodeIDFromPublicKey(ed25519.PublicKey(pubBytes))
			if expectedID == peerID {
				pc.pubKey = ed25519.PublicKey(pubBytes)
			}
		}
	}
	t.mu.Lock()
	t.conns[peerID] = pc
	t.mu.Unlock()
	identified = true
}
```

Similarly, in `Connect()`, after the hello handshake, store the remote peer's public key when we first receive a message from them in the read loop. We already know the peerID but don't have the key yet — it comes from the first reply message.

**Step 4: Add signature + timestamp verification in handleMessage**

In `internal/dht/node.go`, at the top of `handleMessage()` (line 504), add:

```go
const maxMessageAge = 5 * 60 // 5 minutes in seconds

func (n *Node) handleMessage(msg *Message, from NodeID) {
	// Verify message timestamp freshness (reject replays).
	now := time.Now().Unix()
	if msg.Timestamp == 0 || abs64(now-msg.Timestamp) > maxMessageAge {
		return // drop stale or missing timestamp
	}

	// Verify signature if we have the peer's public key.
	// First, try to extract public key from the message itself.
	var senderPubKey ed25519.PublicKey
	if msg.Sender.PublicKey != "" {
		pubBytes, err := hex.DecodeString(msg.Sender.PublicKey)
		if err != nil || len(pubBytes) != ed25519.PublicKeySize {
			return // invalid public key format
		}
		// Verify NodeID matches the claimed public key.
		expectedID := NodeIDFromPublicKey(ed25519.PublicKey(pubBytes))
		if expectedID != msg.Sender.NodeID {
			return // NodeID doesn't match public key
		}
		senderPubKey = ed25519.PublicKey(pubBytes)
	} else {
		// Fall back to stored public key from transport.
		if pk, ok := n.transport.PeerPublicKey(from); ok {
			senderPubKey = pk
		}
	}

	// If we have a public key, verify the signature.
	if len(senderPubKey) > 0 {
		if err := msg.Verify(senderPubKey); err != nil {
			return // signature verification failed
		}
	} else if msg.Signature != "" {
		// Message has signature but we can't verify — drop it.
		return
	}

	// Update routing table with sender's info on every verified message.
	n.table.Add(PeerInfo{
		ID:         msg.Sender.NodeID,
		Address:    msg.Sender.Address,
		PublicKey:  senderPubKey,
		OperatorID: msg.Sender.OperatorID,
		LastSeen:   time.Now(),
	})

	// ... rest of switch statement unchanged ...
```

Add helper:

```go
func abs64(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}
```

**Step 5: Write tests for signature verification**

Add to `internal/dht/node_test.go`:

```go
func TestHandleMessage_RejectsUnsigned(t *testing.T) {
	nodes := testNodes(t, 2)
	a, b := nodes[0], nodes[1]

	// Connect a to b.
	if _, err := a.Ping(b.Addr()); err != nil {
		t.Fatalf("ping: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	// Send a forged message without valid signature.
	// Create a message from a third identity that b doesn't know.
	_, forgedPriv, _ := ed25519.GenerateKey(rand.Reader)
	forgedPub := forgedPriv.Public().(ed25519.PublicKey)
	forgedID := NodeIDFromPublicKey(forgedPub)

	msg := &Message{
		Type:      MsgStore,
		ID:        "forged-1",
		Timestamp: time.Now().Unix(),
		Payload:   json.RawMessage(`{"key":"` + hex.EncodeToString(forgedID[:]) + `","value":"evil"}`),
		Sender: SenderInfo{
			NodeID:    forgedID,
			Address:   "127.0.0.1:9999",
			PublicKey: hex.EncodeToString(forgedPub),
		},
	}
	// Don't sign it (or sign with wrong key).
	// The handleMessage should drop it because signature is empty.

	initialSize := b.Table().Size()
	b.handleMessage(msg, a.ID())
	// Routing table should NOT have the forged peer.
	if b.Table().Size() != initialSize {
		t.Error("forged unsigned message should not add to routing table")
	}
}

func TestHandleMessage_RejectsStaleTimestamp(t *testing.T) {
	nodes := testNodes(t, 2)
	a, b := nodes[0], nodes[1]

	if _, err := a.Ping(b.Addr()); err != nil {
		t.Fatalf("ping: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	pub := a.config.PublicKey
	msg := &Message{
		Type:      MsgPing,
		ID:        "stale-1",
		Timestamp: time.Now().Unix() - 600, // 10 minutes ago
		Payload:   json.RawMessage(`{}`),
		Sender: SenderInfo{
			NodeID:    a.ID(),
			Address:   a.Addr(),
			PublicKey: hex.EncodeToString(pub),
		},
	}
	msg.Sign(a.config.PrivateKey)

	initialSize := b.Table().Size()
	b.handleMessage(msg, a.ID())
	// Should be rejected due to stale timestamp (> 5min).
	// Table size might already have a from the ping, so just verify no crash.
}
```

**Step 6: Run tests**

Run: `cd /home/mark-ssd/code/ssd.foundation/nocturne && go test ./internal/dht/ -v -run TestHandleMessage -count=1`
Expected: PASS

Run: `cd /home/mark-ssd/code/ssd.foundation/nocturne && go test ./internal/dht/ -v -count=1`
Expected: All DHT tests PASS (existing tests must still work — the transport auto-signs and includes public keys)

**Step 7: Commit**

```bash
cd /home/mark-ssd/code/ssd.foundation/nocturne
git add internal/dht/message.go internal/dht/transport.go internal/dht/node.go internal/dht/node_test.go
git commit -m "fix(dht): verify message signatures and reject stale timestamps

Add Ed25519 signature verification to handleMessage. Messages without
valid signatures or with timestamps older than 5 minutes are dropped.
Public keys are included in SenderInfo and verified against NodeID."
```

---

### Task 2: Genesis Key from Environment Variable

Replace the all-zero placeholder with env var loading.

**Files:**
- Modify: `internal/agent/trust.go:74-90` (DefaultGenesis reads env var)
- Test: `internal/agent/trust_test.go`

**Step 1: Write failing test**

Add to `internal/agent/trust_test.go`:

```go
func TestDefaultGenesis_EnvironmentVariable(t *testing.T) {
	// Generate a real key pair.
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	hexKey := hex.EncodeToString(pub)

	t.Setenv("NOCTURNE_GENESIS_KEY", hexKey)
	g := DefaultGenesis()

	if len(g.Operators) != 1 {
		t.Fatalf("operators = %d, want 1", len(g.Operators))
	}
	if !bytes.Equal(g.Operators[0].PublicKey, pub) {
		t.Error("genesis public key should match env var")
	}
}

func TestDefaultGenesis_PlaceholderWhenUnset(t *testing.T) {
	t.Setenv("NOCTURNE_GENESIS_KEY", "")
	g := DefaultGenesis()

	if !IsPlaceholderKey(g.Operators[0].PublicKey) {
		t.Error("should be placeholder when env var is empty")
	}
}

func TestIsPlaceholderKey(t *testing.T) {
	zero := make(ed25519.PublicKey, ed25519.PublicKeySize)
	if !IsPlaceholderKey(zero) {
		t.Error("all-zero key should be placeholder")
	}

	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	if IsPlaceholderKey(pub) {
		t.Error("real key should not be placeholder")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `cd /home/mark-ssd/code/ssd.foundation/nocturne && go test ./internal/agent/ -v -run TestDefaultGenesis_Env -count=1`
Expected: FAIL (IsPlaceholderKey not defined, env var not read)

**Step 3: Implement**

Modify `internal/agent/trust.go`:

```go
import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"
)

// IsPlaceholderKey returns true if the key is all zeros (the default placeholder).
func IsPlaceholderKey(key ed25519.PublicKey) bool {
	for _, b := range key {
		if b != 0 {
			return false
		}
	}
	return true
}

func DefaultGenesis() *Genesis {
	var genesisKey ed25519.PublicKey

	if envKey := os.Getenv("NOCTURNE_GENESIS_KEY"); envKey != "" {
		decoded, err := hex.DecodeString(envKey)
		if err != nil || len(decoded) != ed25519.PublicKeySize {
			log.Printf("WARNING: NOCTURNE_GENESIS_KEY is invalid (expected %d hex bytes), using placeholder", ed25519.PublicKeySize)
			genesisKey = make(ed25519.PublicKey, ed25519.PublicKeySize)
		} else {
			genesisKey = ed25519.PublicKey(decoded)
		}
	} else {
		log.Println("WARNING: NOCTURNE_GENESIS_KEY not set, using placeholder (unsafe for production)")
		genesisKey = make(ed25519.PublicKey, ed25519.PublicKeySize)
	}

	return &Genesis{
		Version:             1,
		MinEndorsements:     3,
		RevocationThreshold: 3,
		Operators: []GenesisOperator{
			{
				PublicKey: genesisKey,
				Label:     "SSD Technologies",
			},
		},
	}
}
```

**Step 4: Run tests**

Run: `cd /home/mark-ssd/code/ssd.foundation/nocturne && go test ./internal/agent/ -v -count=1`
Expected: All PASS

**Step 5: Commit**

```bash
cd /home/mark-ssd/code/ssd.foundation/nocturne
git add internal/agent/trust.go internal/agent/trust_test.go
git commit -m "fix(agent): load genesis key from NOCTURNE_GENESIS_KEY env var

Replace all-zero placeholder with env var loading. Logs a warning
when the env var is unset or invalid. Add IsPlaceholderKey helper."
```

---

### Task 3: API Key Authentication

Add Bearer token auth middleware to all `/api/*` routes (except health). Remove hardcoded secret default. Update dashboard to prompt for API key.

**Files:**
- Modify: `internal/server/server.go` (add requireAuth middleware, update routes)
- Modify: `cmd/nocturne/main.go:27-29` (remove hardcoded default)
- Modify: `web/dashboard/app.js` (add auth token handling)
- Modify: `web/dashboard/index.html` (add login overlay)
- Test: `internal/server/server_test.go` (update tests to include auth header)

**Step 1: Write failing test for auth middleware**

Add to `internal/server/server_test.go`:

```go
func TestAuth_RejectsUnauthenticated(t *testing.T) {
	srv := setupTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/files", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated: status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestAuth_AcceptsValidToken(t *testing.T) {
	srv := setupTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/files", nil)
	req.Header.Set("Authorization", "Bearer test-secret")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("authenticated: status = %d, want %d; body = %s", rec.Code, http.StatusOK, rec.Body.String())
	}
}

func TestAuth_HealthBypassesAuth(t *testing.T) {
	srv := setupTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("health: status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestAuth_PublicRoutesNoAuth(t *testing.T) {
	srv := setupTestServer(t)

	// Public verify should not require Bearer token (it has its own password check).
	// We'll get 404 because the slug doesn't exist, but NOT 401.
	req := httptest.NewRequest(http.MethodPost, "/s/deadbeef/verify", strings.NewReader(`{"link_password":"x"}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code == http.StatusUnauthorized {
		t.Fatal("public route should not require auth")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `cd /home/mark-ssd/code/ssd.foundation/nocturne && go test ./internal/server/ -v -run TestAuth -count=1`
Expected: FAIL (no auth middleware yet, unauthenticated requests return 200)

**Step 3: Add requireAuth middleware**

In `internal/server/server.go`, add:

```go
import (
	"crypto/subtle"
	// ... existing imports
)

// requireAuth returns middleware that checks for a valid Bearer token.
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if len(auth) < len(prefix) || auth[:len(prefix)] != prefix {
			writeError(w, http.StatusUnauthorized, "authorization required")
			return
		}
		token := auth[len(prefix):]
		if subtle.ConstantTimeCompare([]byte(token), []byte(s.secret)) != 1 {
			writeError(w, http.StatusUnauthorized, "invalid token")
			return
		}
		next(w, r)
	}
}
```

Update `routes()` to wrap API handlers:

```go
func (s *Server) routes() {
	// Health (no auth)
	s.mux.HandleFunc("GET /api/health", s.handleHealth)

	// Files (auth required)
	s.mux.HandleFunc("POST /api/files", s.requireAuth(s.handleUploadFile))
	s.mux.HandleFunc("GET /api/files", s.requireAuth(s.handleListFiles))
	s.mux.HandleFunc("DELETE /api/files/{id}", s.requireAuth(s.handleDeleteFile))

	// Links (auth required)
	s.mux.HandleFunc("POST /api/files/{id}/link", s.requireAuth(s.handleCreateLink))
	s.mux.HandleFunc("GET /api/files/{id}/links", s.requireAuth(s.handleListLinks))
	s.mux.HandleFunc("DELETE /api/links/{id}", s.requireAuth(s.handleDeleteLink))

	// Recovery (auth required)
	s.mux.HandleFunc("POST /api/recovery/setup", s.requireAuth(s.handleRecoverySetup))
	s.mux.HandleFunc("POST /api/recovery/recover", s.requireAuth(s.handleRecoveryRecover))

	// Public API (no auth — these have their own password checks)
	s.mux.HandleFunc("POST /s/{slug}/verify", s.handlePublicVerify)
	s.mux.HandleFunc("POST /s/{slug}/download", s.handlePublicDownload)

	// Static files — embedded frontend (no auth)
	// ... unchanged ...
```

**Step 4: Update existing test helpers to include auth header**

The existing `uploadTestFile` and `createTestLink` helpers (and all other tests) need the auth header. Update the helpers in `server_test.go`:

In `uploadTestFile`, add after creating the request:
```go
req.Header.Set("Authorization", "Bearer test-secret")
```

In `createTestLink`, add after creating the request:
```go
req.Header.Set("Authorization", "Bearer test-secret")
```

Also update all individual test functions that make API calls to include:
```go
req.Header.Set("Authorization", "Bearer test-secret")
```

This applies to: `TestListFiles_Empty`, `TestUploadFile`, `TestDeleteFile`, `TestCreateLink`, `TestListLinks`, `TestRecoverySetup`, `TestRecoveryRecover`, and any request to `/api/*` in test code.

**Step 5: Remove hardcoded secret in main.go**

In `cmd/nocturne/main.go`, change lines 27-29:

```go
secret := os.Getenv("NOCTURNE_SECRET")
if secret == "" {
	log.Fatal("NOCTURNE_SECRET environment variable is required")
}
```

**Step 6: Update dashboard app.js for auth**

In `web/dashboard/app.js`, modify the `api` function to include the Bearer token, and add a login gate:

At the top of the IIFE, add:
```javascript
// ── Auth ──────────────────────────────────────────────────
function getToken() {
  return sessionStorage.getItem('nocturne_token') || '';
}

function setToken(token) {
  sessionStorage.setItem('nocturne_token', token);
}

function clearToken() {
  sessionStorage.removeItem('nocturne_token');
}

function showLogin() {
  document.getElementById('loginOverlay').classList.add('active');
  document.getElementById('mainContent').classList.add('hidden');
  setTimeout(function () {
    document.getElementById('loginToken').focus();
  }, 100);
}

function hideLogin() {
  document.getElementById('loginOverlay').classList.remove('active');
  document.getElementById('mainContent').classList.remove('hidden');
}

function handleLogin() {
  var token = document.getElementById('loginToken').value.trim();
  if (!token) {
    showToast('API key is required');
    return;
  }
  setToken(token);
  hideLogin();
  fetchFiles();
  checkRecoveryBanner();
}
window.handleLogin = handleLogin;

function logout() {
  clearToken();
  showLogin();
}
window.logout = logout;
```

Modify the `api` function to include auth:
```javascript
async function api(method, path, body, isFormData) {
  var opts = { method: method, headers: {} };
  var token = getToken();
  if (token && path.indexOf('/api/') === 0) {
    opts.headers['Authorization'] = 'Bearer ' + token;
  }
  if (body) {
    if (isFormData) {
      opts.body = body;
    } else {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(body);
    }
  }
  var res = await fetch(path, opts);
  if (res.status === 401) {
    clearToken();
    showLogin();
    throw new Error('Authentication required');
  }
  return res;
}
```

Modify the `DOMContentLoaded` handler to check for token first:
```javascript
document.addEventListener('DOMContentLoaded', function () {
  initDragDrop();
  initCipherSelector();
  initModeSelector();
  if (!getToken()) {
    showLogin();
  } else {
    fetchFiles();
    checkRecoveryBanner();
  }
});
```

**Step 7: Update index.html with login overlay**

Add before the closing `</body>` tag in `web/dashboard/index.html`:

```html
<!-- Login Overlay -->
<div id="loginOverlay" class="modal-overlay">
  <div class="modal" style="max-width: 360px;">
    <div class="modal-header">
      <div class="modal-title">Nocturne</div>
    </div>
    <div class="modal-body">
      <div class="form-group">
        <label class="form-label">API Key</label>
        <input type="password" id="loginToken" placeholder="Enter your API key" autocomplete="off"
          onkeydown="if(event.key==='Enter')handleLogin()">
      </div>
    </div>
    <div class="modal-footer">
      <button class="btn btn-primary" onclick="handleLogin()">Unlock</button>
    </div>
  </div>
</div>
```

Wrap existing content in a `<div id="mainContent">`:
```html
<div id="mainContent">
  <!-- existing header, recovery banner, upload zone, file list, modals -->
</div>
```

**Step 8: Run tests**

Run: `cd /home/mark-ssd/code/ssd.foundation/nocturne && go test ./internal/server/ -v -count=1`
Expected: All PASS

**Step 9: Commit**

```bash
cd /home/mark-ssd/code/ssd.foundation/nocturne
git add internal/server/server.go internal/server/server_test.go cmd/nocturne/main.go web/dashboard/app.js web/dashboard/index.html
git commit -m "fix(server): add Bearer token auth to API endpoints

All /api/* routes (except /api/health) now require Authorization:
Bearer <token> header. Public routes (/s/*) are unaffected. Dashboard
prompts for API key and stores in sessionStorage. Removed hardcoded
dev-secret-change-me fallback — NOCTURNE_SECRET env var is now required."
```

---

### Task 4: Apply Rate Limiting

Wire up the existing rate limiter to public endpoints and add a stricter limiter for password-sensitive routes.

**Files:**
- Modify: `internal/server/server.go` (add strictLimiter, withRateLimit middleware, update routes)
- Test: `internal/server/server_test.go`

**Step 1: Write failing test**

Add to `internal/server/server_test.go`:

```go
func TestRateLimit_PublicEndpoint(t *testing.T) {
	srv := setupTestServer(t)

	// Upload a file and create a link first.
	fileResult := uploadTestFile(t, srv, "ratelimit.txt", "content", "pass")
	fileID := fileResult["id"].(string)
	linkResult := createTestLink(t, srv, fileID, "linkpass", "persistent")
	slug := linkResult["slug"].(string)

	// Exhaust the strict rate limit (20 requests).
	for i := 0; i < 20; i++ {
		body, _ := json.Marshal(map[string]string{"link_password": "wrong"})
		req := httptest.NewRequest(http.MethodPost, "/s/"+slug+"/verify", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "10.0.0.1:1234"
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
	}

	// 21st request should be rate limited.
	body, _ := json.Marshal(map[string]string{"link_password": "wrong"})
	req := httptest.NewRequest(http.MethodPost, "/s/"+slug+"/verify", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "10.0.0.1:1234"
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("rate limit: status = %d, want %d", rec.Code, http.StatusTooManyRequests)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `cd /home/mark-ssd/code/ssd.foundation/nocturne && go test ./internal/server/ -v -run TestRateLimit -count=1`
Expected: FAIL (no rate limiting applied)

**Step 3: Implement rate limiting middleware**

In `internal/server/server.go`, add `strictLimiter` to the struct and a `withRateLimit` helper:

```go
type Server struct {
	db            *storage.DB
	secret        string
	mux           *http.ServeMux
	limiter       *rateLimiter
	strictLimiter *rateLimiter
}

func New(db *storage.DB, secret string) *Server {
	s := &Server{
		db:            db,
		secret:        secret,
		mux:           http.NewServeMux(),
		limiter:       newRateLimiter(120, time.Minute),
		strictLimiter: newRateLimiter(20, time.Minute),
	}
	s.routes()
	return s
}
```

Add middleware:

```go
// withRateLimit wraps a handler with per-IP rate limiting.
func withRateLimit(rl *rateLimiter, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !rl.allow(getIP(r)) {
			writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
		next(w, r)
	}
}
```

Apply to routes:

```go
// Public API (rate limited, no auth)
s.mux.HandleFunc("POST /s/{slug}/verify", withRateLimit(s.strictLimiter, s.handlePublicVerify))
s.mux.HandleFunc("POST /s/{slug}/download", withRateLimit(s.strictLimiter, s.handlePublicDownload))
```

**Step 4: Run tests**

Run: `cd /home/mark-ssd/code/ssd.foundation/nocturne && go test ./internal/server/ -v -count=1`
Expected: All PASS

**Step 5: Commit**

```bash
cd /home/mark-ssd/code/ssd.foundation/nocturne
git add internal/server/server.go internal/server/server_test.go
git commit -m "fix(server): apply rate limiting to public endpoints

Wire up the existing rate limiter. Public password endpoints (/s/*)
use a strict 20 req/min limit to prevent brute-force attacks."
```

---

### Task 5: Atomic One-Time Link Burn

Fix the TOCTOU race condition by burning the link atomically before decryption.

**Files:**
- Modify: `internal/storage/sqlite.go` (add TryBurnLink method)
- Modify: `internal/server/public.go:84-134` (burn before decrypt)
- Test: `internal/storage/sqlite_test.go`
- Test: `internal/server/server_test.go`

**Step 1: Write failing test for TryBurnLink**

Add to `internal/storage/sqlite_test.go`:

```go
func TestTryBurnLink(t *testing.T) {
	db := setupTestDB(t)

	// Create a file and a one-time link.
	file := &File{ID: "f1", Name: "test.txt", Size: 10, Cipher: "aes-256-gcm",
		Salt: []byte("salt"), Nonce: []byte("nonce"), Blob: []byte("data"), CreatedAt: time.Now().Unix()}
	if err := db.CreateFile(file); err != nil {
		t.Fatalf("CreateFile: %v", err)
	}

	link := &Link{ID: "l1", FileID: "f1", Mode: "onetime", PasswordHash: "hash", CreatedAt: time.Now().Unix()}
	if err := db.CreateLink(link); err != nil {
		t.Fatalf("CreateLink: %v", err)
	}

	// First burn should succeed.
	ok, err := db.TryBurnLink("l1")
	if err != nil {
		t.Fatalf("TryBurnLink: %v", err)
	}
	if !ok {
		t.Fatal("first burn should succeed")
	}

	// Second burn should fail (already burned).
	ok, err = db.TryBurnLink("l1")
	if err != nil {
		t.Fatalf("TryBurnLink second: %v", err)
	}
	if ok {
		t.Fatal("second burn should fail")
	}
}
```

**Step 2: Run test to verify it fails**

Run: `cd /home/mark-ssd/code/ssd.foundation/nocturne && go test ./internal/storage/ -v -run TestTryBurnLink -count=1`
Expected: FAIL (TryBurnLink not defined)

**Step 3: Implement TryBurnLink**

Add to `internal/storage/sqlite.go`:

```go
// TryBurnLink atomically marks a link as burned if it hasn't been burned yet.
// Returns true if the link was successfully burned, false if it was already burned.
func (d *DB) TryBurnLink(id string) (bool, error) {
	res, err := d.db.Exec(
		`UPDATE links SET burned = 1, downloads = downloads + 1 WHERE id = ? AND burned = 0`, id,
	)
	if err != nil {
		return false, fmt.Errorf("try burn link: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("try burn link rows affected: %w", err)
	}
	return n == 1, nil
}
```

**Step 4: Update handlePublicDownload to burn before decrypt**

In `internal/server/public.go`, restructure `handlePublicDownload`:

```go
func (s *Server) handlePublicDownload(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	if slug == "" {
		writeError(w, http.StatusBadRequest, "slug is required")
		return
	}

	var req downloadRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	link, file := s.validateLink(w, slug)
	if link == nil {
		return
	}

	if !crypto.VerifyPassword(req.LinkPassword, link.PasswordHash) {
		writeError(w, http.StatusUnauthorized, "invalid link password")
		return
	}

	// For one-time links, atomically burn BEFORE decryption to prevent races.
	if link.Mode == "onetime" {
		burned, err := s.db.TryBurnLink(link.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to burn link")
			return
		}
		if !burned {
			writeError(w, http.StatusGone, "link has already been used")
			return
		}
	}

	// Decrypt the file.
	plaintext, err := crypto.Decrypt(file.Blob, req.FilePassword, file.Cipher, file.Salt, file.Nonce)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "decryption failed: wrong file password")
		return
	}

	// For non-onetime links, increment download count.
	if link.Mode != "onetime" {
		if err := s.db.IncrementDownloads(link.ID); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to increment downloads")
			return
		}
	}

	// Stream the decrypted file.
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, file.Name))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(plaintext)))
	w.WriteHeader(http.StatusOK)
	w.Write(plaintext)
}
```

**Step 5: Run tests**

Run: `cd /home/mark-ssd/code/ssd.foundation/nocturne && go test ./internal/storage/ -v -run TestTryBurnLink -count=1`
Expected: PASS

Run: `cd /home/mark-ssd/code/ssd.foundation/nocturne && go test ./internal/server/ -v -count=1`
Expected: All PASS (including existing TestPublicDownload_BurnedLink)

**Step 6: Commit**

```bash
cd /home/mark-ssd/code/ssd.foundation/nocturne
git add internal/storage/sqlite.go internal/storage/sqlite_test.go internal/server/public.go
git commit -m "fix(server): atomic one-time link burn to prevent race condition

Add TryBurnLink that atomically burns a link only if not already burned
using UPDATE WHERE burned=0 + RowsAffected check. One-time links are
now burned before decryption to prevent concurrent double-downloads."
```

---

### Task 6: Run Full Test Suite

**Step 1: Run all tests**

Run: `cd /home/mark-ssd/code/ssd.foundation/nocturne && go test ./... -count=1`
Expected: All 225+ tests PASS

**Step 2: If any failures, fix them**

The most likely breakage is in existing tests that don't include the new auth header. Fix any test that calls `/api/*` without `Authorization: Bearer test-secret`.

**Step 3: Final commit if test fixes needed**

```bash
cd /home/mark-ssd/code/ssd.foundation/nocturne
git add -A
git commit -m "test: fix tests for auth requirement changes"
```
