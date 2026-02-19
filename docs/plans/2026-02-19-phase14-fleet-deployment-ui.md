# Phase 14: Railway Fleet Deployment & UI Polish

**Date:** 2026-02-19
**Status:** Approved
**Scope:** Redeploy Railway fleet with Phase 13 P2P code, enable DHT bootstrapping between nodes, add essential P2P UI indicators

## Context

Phase 13 added P2P distributed storage (4+2 erasure coding), agent-to-agent messaging, client-side encryption, and background shard repair. The code is tested (278 tests) but the Railway fleet still runs pre-Phase 13 code. Nodes are independent instances — not connected via DHT.

## Architecture Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Node mode | Server + embedded DHT | Single process per container, simplest architecture |
| Inter-node transport | Railway private network (UDP) | `*.railway.internal` hostnames, free, low-latency, supports UDP |
| DHT bootstrap | Environment variable list | `NOCTURNE_DHT_BOOTSTRAP=host1:port,host2:port,...` per service |
| Node identity | Persistent Ed25519 keypair | Stored at `$NOCTURNE_DATA_DIR/dht.key`, stable across restarts |
| UI scope | Essential indicators | Storage toggle, P2P/Local badges, header network status dot |

## Changes

### 1. Persistent DHT Keypair

**File:** `cmd/nocturne/main.go`

Currently generates a fresh Ed25519 keypair on every start (lines 50-51). Change to:
- On first start: generate keypair, write to `$NOCTURNE_DATA_DIR/dht.key`
- On subsequent starts: load existing keypair from disk
- Node keeps same DHT identity across restarts/redeploys

### 2. DHT Bootstrap on Server Startup

**File:** `cmd/nocturne/main.go`

After `dhtNode.Start()`, parse `NOCTURNE_DHT_BOOTSTRAP` env var and call `dhtNode.Bootstrap(peers)`. Format: comma-separated `host:port` pairs.

### 3. Dockerfile

Add `EXPOSE 4001/udp` for DHT transport.

### 4. API: Storage Mode in File List

**File:** `internal/server/files.go`

`GET /api/files` response adds `storage_mode` field per file:
- `"local"` if blob is non-empty
- `"p2p"` if blob is empty (shards in DHT)

### 5. API: DHT Status in Health Check

**File:** `internal/server/server.go`

`GET /api/health` response adds:
```json
{
  "dht_enabled": true,
  "dht_peers": 3
}
```

### 6. Dashboard: Storage Mode Toggle

**Files:** `web/dashboard/index.html`, `web/dashboard/app.js`

Upload form gets a Local/P2P toggle (next to cipher selector). Visible only when server reports `dht_enabled: true` via health endpoint. P2P selected by default when available. Controls whether `storage_mode: 'p2p'` or `storage_mode: 'local'` is sent.

### 7. Dashboard: Storage Badges

**Files:** `web/dashboard/app.js`, `web/dashboard/styles.css`

Each file card shows a "LOCAL" (green) or "P2P" (purple) badge next to the cipher badge.

### 8. Dashboard: Network Status Indicator

**Files:** `web/dashboard/index.html`, `web/dashboard/app.js`, `web/dashboard/styles.css`

Small indicator in header: green dot + "N peers" when DHT active, grey dot + "local" when DHT disabled.

### 9. Railway Environment Variables

Set per service via Railway dashboard or CLI:
- `NOCTURNE_DHT_ENABLED=true`
- `NOCTURNE_DHT_PORT=4001`
- `NOCTURNE_DHT_BOOTSTRAP=<other 3 nodes' .railway.internal:4001 addresses>`

### 10. Testing & Verification

- Unit tests: keypair persistence, bootstrap config parsing
- Fleet verification: hit each node's `/api/health` to confirm DHT enabled + peers connected
- Smoke test: upload file via dashboard in P2P mode, confirm badge, verify download
