# Code Review Fixes Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Fix all 9 high-confidence bugs identified in the full codebase code review.

**Architecture:** Targeted fixes to 8 source files + their callers/tests. No new packages. Changes are independent except Issue #9 (NewNode signature change) which cascades to callers and tests.

**Tech Stack:** Go 1.24, SQLite (modernc.org/sqlite), gorilla/websocket

---

### Task 1: Fix rate limiter goroutine leak + XFF spoofing (Issues #1, #5)

**Files:**
- Modify: `internal/server/ratelimit.go`
- Modify: `internal/server/server.go` (add `Close()` method, call limiter close)
- Modify: `cmd/nocturne/main.go` (call `srv.Close()` on shutdown)
- Test: `internal/server/server_test.go`

**Step 1: Update `rateLimiter` struct with stop channel and `Close()` method**

In `internal/server/ratelimit.go`:
- Add `done chan struct{}` field to `rateLimiter`
- Replace `time.Sleep` loop with `ticker + select` on `done` channel
- Add `func (rl *rateLimiter) close()` that closes the `done` channel

```go
type rateLimiter struct {
	mu       sync.Mutex
	visitors map[string]*visitor
	rate     int
	window   time.Duration
	done     chan struct{}
}

func newRateLimiter(rate int, window time.Duration) *rateLimiter {
	rl := &rateLimiter{
		visitors: make(map[string]*visitor),
		rate:     rate,
		window:   window,
		done:     make(chan struct{}),
	}
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				rl.cleanup()
			case <-rl.done:
				return
			}
		}
	}()
	return rl
}

func (rl *rateLimiter) close() {
	close(rl.done)
}
```

**Step 2: Fix `getIP` to only trust XFF from trusted proxy**

Replace `getIP` in `internal/server/ratelimit.go`:

```go
func getIP(r *http.Request) string {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	// Only trust X-Forwarded-For when the direct connection is from a
	// trusted reverse proxy (localhost). This prevents attackers from
	// spoofing IPs to bypass rate limiting.
	if host == "127.0.0.1" || host == "::1" {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if idx := strings.Index(xff, ","); idx != -1 {
				return strings.TrimSpace(xff[:idx])
			}
			return strings.TrimSpace(xff)
		}
	}
	return host
}
```

**Step 3: Add `Close()` to Server**

In `internal/server/server.go`, add:

```go
func (s *Server) Close() {
	s.limiter.close()
	s.strictLimiter.close()
}
```

**Step 4: Call `srv.Close()` in main shutdown**

This is combined with Task 3 (graceful shutdown fix).

**Step 5: Run tests**

Run: `cd /home/mark-ssd/code/ssd.foundation/nocturne && go test ./internal/server/ -v -count=1`

**Step 6: Commit**

```
fix(server): add rate limiter cleanup and trusted proxy for XFF
```

---

### Task 2: Fix heartbeat goroutine in nocturne-node (Issue #2)

**Files:**
- Modify: `cmd/nocturne-node/main.go`

**Step 1: Replace `heartbeatDone` self-referencing channel with a shared shutdown channel**

In `cmd/nocturne-node/main.go`, replace lines 267-344 (the heartbeat, stats, and shutdown sections):

- Create a single `shutdownCh := make(chan struct{})` before both goroutines
- Both goroutines select on `<-shutdownCh`
- On SIGTERM, `close(shutdownCh)` signals both goroutines
- Remove `heartbeatDone` and `statsDone` variables

```go
// 10. Shared shutdown channel for goroutines.
shutdownCh := make(chan struct{})

// 11. Start heartbeat loop.
go func() {
    ticker := time.NewTicker(heartbeatInterval)
    defer ticker.Stop()
    for {
        select {
        case <-ticker.C:
            hbPayload, _ := json.Marshal(map[string]string{})
            hbMsg := mesh.WSMessage{
                Type:    "heartbeat",
                Payload: json.RawMessage(hbPayload),
            }
            if err := conn.WriteJSON(hbMsg); err != nil {
                return
            }
        case <-shutdownCh:
            return
        }
    }
}()

// 12. Write stats periodically.
go func() {
    ticker := time.NewTicker(5 * time.Second)
    defer ticker.Stop()
    for {
        select {
        case <-ticker.C:
            // ... same stats writing code ...
        case <-shutdownCh:
            return
        }
    }
}()

// ... signal wait ...

// Cleanup: signal goroutines, then cleanup resources.
close(shutdownCh)
// ... rest of cleanup (disconnect, final stats, listener close, pid remove) ...
```

**Step 2: Run build check**

Run: `cd /home/mark-ssd/code/ssd.foundation/nocturne && go build ./cmd/nocturne-node/`

**Step 3: Commit**

```
fix(node): use shared shutdown channel for heartbeat and stats goroutines
```

---

### Task 3: Fix HTTP server graceful shutdown (Issue #3)

**Files:**
- Modify: `cmd/nocturne/main.go`

**Step 1: Replace `http.ListenAndServe` with `http.Server` + proper shutdown**

```go
func main() {
	// ... existing env/db/secret setup (lines 17-35 unchanged) ...

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv := server.New(db, secret)
	srv.StartWorkers(ctx)

	httpServer := &http.Server{
		Addr:    ":" + port,
		Handler: srv,
	}

	// Graceful shutdown on SIGINT/SIGTERM.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("Shutting down...")
		cancel()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			log.Printf("HTTP shutdown error: %v", err)
		}
	}()

	fmt.Printf("Nocturne running on http://localhost:%s\n", port)
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}

	srv.Close()
}
```

Need to add `"time"` to imports.

**Step 2: Run build check**

Run: `cd /home/mark-ssd/code/ssd.foundation/nocturne && go build ./cmd/nocturne/`

**Step 3: Commit**

```
fix(server): implement graceful HTTP server shutdown on SIGTERM
```

---

### Task 4: Fix Gossiper.seen memory leak (Issue #4)

**Files:**
- Modify: `internal/dht/gossip.go`

**Step 1: Add automatic pruning goroutine with shutdown**

Add `done chan struct{}` field to `Gossiper`. Start a pruning goroutine in `NewGossiper`. Add `Close()` method.

```go
type Gossiper struct {
	mu       sync.RWMutex
	node     *Node
	seen     map[string]time.Time
	seenTTL  time.Duration
	handlers map[GossipType]GossipHandler
	maxHops  int
	done     chan struct{}
}

func NewGossiper(node *Node) *Gossiper {
	g := &Gossiper{
		node:     node,
		seen:     make(map[string]time.Time),
		seenTTL:  10 * time.Minute,
		handlers: make(map[GossipType]GossipHandler),
		maxHops:  10,
		done:     make(chan struct{}),
	}
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				g.PruneSeen()
			case <-g.done:
				return
			}
		}
	}()
	return g
}

func (g *Gossiper) Close() {
	close(g.done)
}
```

**Step 2: Call `g.Close()` from `Node.Close()`**

In `internal/dht/node.go`, update `Close()`:

```go
func (n *Node) Close() error {
	if n.gossiper != nil {
		n.gossiper.Close()
	}
	n.transport.Close()
	if n.store != nil {
		return n.store.Close()
	}
	return nil
}
```

**Step 3: Run tests**

Run: `cd /home/mark-ssd/code/ssd.foundation/nocturne && go test ./internal/dht/ -v -count=1 -run Gossip`

**Step 4: Commit**

```
fix(dht): add automatic gossip seen-map pruning with shutdown
```

---

### Task 5: Fix PutVersioned race condition (Issue #6)

**Files:**
- Modify: `internal/dht/store.go`
- Test: `internal/dht/store_test.go`

**Step 1: Replace non-atomic SELECT+INSERT with atomic UPSERT RETURNING**

```go
func (s *LocalStore) PutVersioned(key NodeID, value []byte, ttl time.Duration) (uint64, error) {
	keyHex := hex.EncodeToString(key[:])
	expiresAt := time.Now().Add(ttl).UnixMilli()
	var newVersion uint64
	err := s.db.QueryRow(
		`INSERT INTO dht_entries (key_hex, value, expires_at, version) VALUES (?, ?, ?, 1)
		 ON CONFLICT(key_hex) DO UPDATE SET value = excluded.value, expires_at = excluded.expires_at, version = dht_entries.version + 1
		 RETURNING version`,
		keyHex, value, expiresAt,
	).Scan(&newVersion)
	return newVersion, err
}
```

**Step 2: Run store tests**

Run: `cd /home/mark-ssd/code/ssd.foundation/nocturne && go test ./internal/dht/ -v -count=1 -run Store`

**Step 3: Commit**

```
fix(dht): make PutVersioned atomic with UPSERT RETURNING
```

---

### Task 6: Fix unbounded io.ReadAll in LocalAPI (Issue #7)

**Files:**
- Modify: `internal/dht/localapi.go`

**Step 1: Add `readBody` helper and apply to all 5 POST endpoints**

Add at top of file:

```go
const maxAPIBodySize = 10 << 20 // 10 MB

func readBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxAPIBodySize+1))
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read body")
		return nil, false
	}
	if len(body) > maxAPIBodySize {
		writeError(w, http.StatusRequestEntityTooLarge, "request body too large")
		return nil, false
	}
	return body, true
}
```

Replace all 5 occurrences of `io.ReadAll(r.Body)` with `readBody(w, r)`:
- `publishKnowledge` (line 113)
- `handleKnowledgeVote` (line 206)
- `handleComputeClaim` (line 322)
- `submitTaskResult` (line 371)
- `storeAwareness` (line 413)

**Step 2: Run tests**

Run: `cd /home/mark-ssd/code/ssd.foundation/nocturne && go test ./internal/dht/ -v -count=1 -run LocalAPI`

**Step 3: Commit**

```
fix(dht): add request body size limit to LocalAPI endpoints
```

---

### Task 7: Fix silent json.Unmarshal in updateTaskIndex (Issue #8)

**Files:**
- Modify: `internal/dht/tasks.go`

**Step 1: Check unmarshal error**

Replace line 236:
```go
// Before:
json.Unmarshal(data, &index)

// After:
if err := json.Unmarshal(data, &index); err != nil {
    return fmt.Errorf("unmarshal task index: %w", err)
}
```

**Step 2: Run tests**

Run: `cd /home/mark-ssd/code/ssd.foundation/nocturne && go test ./internal/dht/ -v -count=1 -run Task`

**Step 3: Commit**

```
fix(dht): check json.Unmarshal error in updateTaskIndex
```

---

### Task 8: Fix NewNode panic → return error (Issue #9)

**Files:**
- Modify: `internal/dht/node.go` (change signature)
- Modify: `internal/dht/node_test.go` (update `testNodes` and `TestNodeBootstrap`)
- Modify: `cmd/nocturne-agent/main.go` (handle error)

**Step 1: Change `NewNode` to return `(*Node, error)`**

In `internal/dht/node.go`:

```go
func NewNode(cfg Config) (*Node, error) {
	id := NodeIDFromPublicKey(cfg.PublicKey)
	if cfg.K == 0 {
		cfg.K = 20
	}
	if cfg.Alpha == 0 {
		cfg.Alpha = 3
	}

	storePath := cfg.StorePath
	if storePath == "" {
		storePath = ":memory:"
	}
	store, err := NewLocalStore(storePath)
	if err != nil {
		return nil, fmt.Errorf("init local store: %w", err)
	}

	n := &Node{
		id:        id,
		config:    cfg,
		table:     NewRoutingTable(id, cfg.K),
		transport: NewTransport(id, cfg.PrivateKey),
		store:     store,
		pending:   make(map[string]chan *Message),
	}
	n.transport.OnMessage(n.handleMessage)
	return n, nil
}
```

**Step 2: Update `testNodes` in `internal/dht/node_test.go`**

```go
node, err := NewNode(cfg)
if err != nil {
    t.Fatalf("create node %d: %v", i, err)
}
```

And in `TestNodeBootstrap`:
```go
b, err := NewNode(cfg)
if err != nil {
    t.Fatalf("create bootstrap node: %v", err)
}
```

**Step 3: Update `cmd/nocturne-agent/main.go`**

```go
node, err := dht.NewNode(cfg)
if err != nil {
    log.Fatalf("Failed to create DHT node: %v", err)
}
```

**Step 4: Run all tests**

Run: `cd /home/mark-ssd/code/ssd.foundation/nocturne && go test ./... -count=1`

**Step 5: Commit**

```
fix(dht): return error from NewNode instead of panicking
```

---

### Task 9: Final verification

**Step 1: Run full test suite**

Run: `cd /home/mark-ssd/code/ssd.foundation/nocturne && go test ./... -count=1 -race`

Expected: All tests pass with no race conditions detected.

**Step 2: Run go vet**

Run: `cd /home/mark-ssd/code/ssd.foundation/nocturne && go vet ./...`

Expected: Clean output.
