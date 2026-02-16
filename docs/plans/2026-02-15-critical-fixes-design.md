# Nocturne Critical Security Fixes Design

**Date:** 2026-02-15
**Status:** Approved

## Fix 1: DHT Message Signature Verification

**Problem:** `handleMessage()` in `internal/dht/node.go` processes all incoming messages without calling `Message.Verify()`. Any attacker can forge messages from any NodeID, inject fake peers, store malicious data, and forge votes.

**Design:** Add signature verification at the top of `handleMessage()`. Add a `PublicKey` field to `SenderInfo` so peers include their Ed25519 public key in messages. On receipt, verify the signature against the included public key, and confirm that `NodeIDFromPublicKey(pubKey) == msg.Sender.NodeID` (the NodeID must match the key). Store verified public keys in `PeerInfo` for subsequent lookups. Add 5-minute timestamp window to reject replays.

**Changes:**
- Add `PublicKey string` (hex-encoded) to `SenderInfo`
- Add `PublicKey ed25519.PublicKey` to `PeerInfo`
- Populate `SenderInfo.PublicKey` in `Transport.Send()` from the transport's public key
- In `handleMessage`: verify signature, verify NodeID matches public key, check timestamp freshness, drop invalid messages
- In routing table `Add`: store public key from verified messages

## Fix 2: Genesis Key from Environment Variable

**Problem:** `DefaultGenesis()` creates an all-zero Ed25519 public key placeholder with no actual build-time replacement mechanism.

**Design:** `DefaultGenesis()` reads `NOCTURNE_GENESIS_KEY` env var (hex-encoded 32-byte Ed25519 public key). If unset, keeps the placeholder but logs a warning. Add `IsPlaceholder()` helper.

**Changes:**
- Modify `DefaultGenesis()` to read and decode `NOCTURNE_GENESIS_KEY` env var
- Add `IsPlaceholder(key ed25519.PublicKey) bool` helper
- Log warning when placeholder is used

## Fix 3: API Key Authentication via Bearer Token

**Problem:** All file/link/recovery endpoints are completely unauthenticated. The `secret` field exists but is never used.

**Design:** Add `requireAuth` middleware checking `Authorization: Bearer <token>` against `s.secret` using constant-time comparison. Apply to all `/api/*` routes except `/api/health`. Remove hardcoded `"dev-secret-change-me"` fallback — fail at startup if `NOCTURNE_SECRET` is unset. Update dashboard `app.js` with a login gate that prompts for API key and stores it in `sessionStorage`.

**Changes:**
- Add `requireAuth(next http.HandlerFunc) http.HandlerFunc` middleware
- Wrap all `/api/*` handlers (except health) in `routes()`
- Remove hardcoded default in `cmd/nocturne/main.go`
- Update `web/dashboard/app.js` with login/auth token handling

## Fix 4: Apply Rate Limiting

**Problem:** Rate limiter is implemented and initialized but `.allow()` is never called on any endpoint.

**Design:** Add `withRateLimit(limiter *rateLimiter, next http.HandlerFunc) http.HandlerFunc` middleware. Create a second stricter rate limiter (20 req/min) for password-sensitive public endpoints. Apply general limiter (120/min) to API endpoints, strict limiter to `/s/{slug}/verify` and `/s/{slug}/download`.

**Changes:**
- Add `withRateLimit` middleware function
- Add `strictLimiter` field to Server struct (20 req/min)
- Apply limiters in `routes()`

## Fix 5: Atomic One-Time Link Burn

**Problem:** TOCTOU race in `handlePublicDownload` — validate then burn as separate operations. Two concurrent requests can both download a one-time link.

**Design:** Burn-first approach using atomic SQL: `UPDATE links SET burned = 1, downloads = downloads + 1 WHERE id = ? AND burned = 0` checking `RowsAffected() == 1`. For one-time links, burn before decryption. If 0 rows affected, return 410 Gone.

**Changes:**
- Add `TryBurnLink(id string) (bool, error)` to storage layer
- Restructure `handlePublicDownload` to burn before decrypt for one-time links
