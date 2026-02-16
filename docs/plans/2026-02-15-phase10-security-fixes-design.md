# Phase 10: Remaining Security Fixes Design

**Date:** 2026-02-15
**Status:** Approved

## Fix 1: Content-Disposition Header Injection

**Problem:** `internal/server/public.go:137` interpolates `file.Name` directly into a Content-Disposition header without sanitization. A filename containing quotes, newlines, or path traversal sequences (`../../`) can inject HTTP headers or trick browsers into saving files at unexpected paths.

**Design:** Sanitize the filename before use:
1. `filepath.Base()` to strip directory traversal
2. Strip `"`, `\r`, `\n` characters
3. Fallback to `"download"` if the result is empty or `.`

**Files:** `internal/server/public.go`

## Fix 2: Security Headers Middleware

**Problem:** No security headers (X-Frame-Options, X-Content-Type-Options, Content-Security-Policy, Strict-Transport-Security) are set on any response.

**Design:** Override `ServeHTTP()` on Server to inject headers on every response before delegating to the mux. Headers:
- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- `Content-Security-Policy: default-src 'self'`
- `Strict-Transport-Security: max-age=63072000; includeSubDomains`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Permissions-Policy: camera=(), microphone=(), geolocation=()`

**Files:** `internal/server/server.go`

## Fix 3: Transactional File & Operator Deletion

**Problem:** `handleDeleteFile` (files.go:166-182) deletes links in a loop then the file as separate operations. A failure midway leaves orphaned links. `DeleteOperator` (agent_store.go:132-150) has the same pattern with agent_keys.

**Design:**
- Add `DB.BeginTx() (*sql.Tx, error)` helper to expose transactions
- Add `DB.DeleteFileWithLinks(id string) error` that wraps link + file deletion in a single transaction using `DELETE FROM links WHERE file_id = ?` (bulk, not loop) then `DELETE FROM files WHERE id = ?`
- Add `DB.DeleteOperatorCascade(id string) error` that wraps agent_keys + operator deletion in a single transaction
- Update `handleDeleteFile` and delete-operator codepaths to use the transactional methods

**Files:** `internal/storage/sqlite.go`, `internal/storage/agent_store.go`, `internal/server/files.go`

## Fix 4: FK CASCADE in Schema

**Problem:** All foreign key constraints lack `ON DELETE CASCADE`. Deleting a parent row without first deleting children violates FK constraints (or leaves orphans if FKs aren't enforced on a code path).

**Design:** Update the schema definition to add `ON DELETE CASCADE` to all FK constraints:
- `files.recovery_id` → `recovery_keys(id) ON DELETE CASCADE`
- `links.file_id` → `files(id) ON DELETE CASCADE`
- `shards.file_id` → `files(id) ON DELETE CASCADE`
- `shards.node_id` → `nodes(id) ON DELETE CASCADE`
- `agent_keys.operator_id` → `operators(id) ON DELETE CASCADE`
- `knowledge.agent_id` → `agent_keys(id) ON DELETE CASCADE`
- `knowledge.operator_id` → `operators(id) ON DELETE CASCADE`

Since `CREATE TABLE IF NOT EXISTS` won't alter existing tables, add a migration function that detects the old schema (missing CASCADE) and recreates affected tables using SQLite's copy-rename pattern:
1. Create new table with CASCADE
2. Copy data from old table
3. Drop old table
4. Rename new table

**Files:** `internal/storage/sqlite.go`

## Fix 5: DHT Vote/Task Compare-And-Swap

**Problem:** DHT operations `ClaimTask`, `SubmitVoteCommitment`, `SubmitVoteReveal` use fetch→modify→store without concurrency protection. Two concurrent operations can overwrite each other silently.

**Design:** Add optimistic concurrency control to the local DHT store:
1. Add `Version uint64` field to `ComputeTask` and `VoteRecord`
2. Add `StoreWithVersion(key NodeID, data []byte, expectedVersion uint64) (uint64, error)` to Node that checks the stored version before writing. Returns the new version on success, error on version mismatch.
3. Add version tracking to the local store map: `store map[NodeID]versionedEntry` where `versionedEntry{data []byte, version uint64}`
4. Update `ClaimTask`, `SubmitVoteCommitment`, `SubmitVoteReveal`, `SubmitTaskResult`, `TallyVotes` to use versioned reads and compare-and-swap writes with retry loops (max 3 retries)

Cross-node eventual consistency with last-writer-wins remains acceptable for a P2P DHT. This fix prevents local-node races.

**Files:** `internal/dht/node.go`, `internal/dht/tasks.go`, `internal/dht/voting.go`

## Fix 6: Per-Peer Rate Limiting

**Problem:** No per-peer rate limiting on DHT transport WebSocket reads or mesh tracker WebSocket reads. An attacker can flood with messages to cause DoS.

**Design:**
- Add `limiter *rateLimiter` field to `peerConn` struct in `transport.go`, initialized at 100 msg/min
- Check `pc.limiter.allow()` in `readLoop` before dispatching; silently drop excess messages and log a warning
- Reuse the existing `rateLimiter` type from `internal/server/ratelimit.go` by extracting it to a shared `internal/ratelimit` package (or duplicate a minimal version in `internal/dht/`)
- Add per-connection rate limiting in `mesh/ws.go` HandleWebSocket: create a limiter per connection (60 msg/min), check before processing each message
- Limit gossip forwarding in `gossip.go` `forward()` to 3 randomly selected peers instead of all connected peers (reduces amplification factor)

**Files:** `internal/dht/transport.go`, `internal/dht/gossip.go`, `internal/mesh/ws.go`, new `internal/ratelimit/ratelimit.go`

## Scoped Out

- **Routing table pollution (Eclipse attack):** Already mitigated by Ed25519 signature verification (Phase 9) and standard Kademlia bucket eviction preferring long-lived peers. Full IP-diversity checks are deferred.
- **CSRF protection:** Not applicable. Auth uses Bearer tokens via sessionStorage, not cookies. Cross-origin JavaScript cannot access another origin's sessionStorage.
