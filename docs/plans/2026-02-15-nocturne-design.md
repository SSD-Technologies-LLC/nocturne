# Nocturne — Encrypted File Storage Design

## Overview

Nocturne is a minimalist encrypted file storage solution with a locally accessible dashboard and remote server deployment. All files are encrypted server-side. Shareable links allow password-protected downloads. Password recovery via hex recovery key or 6-word mnemonic.

Open-source project from SSD Technologies.

## Architecture

**Single Go binary** serving API, dashboard, and public download pages. HTML/JS/CSS embedded via `go:embed`. SQLite for storage (encrypted blobs stored inline). Self-hosting: download binary, run it.

```
nocturne/
├── cmd/
│   ├── nocturne/main.go        # Server binary
│   └── nocturne-node/main.go   # Node binary (mesh network)
├── internal/
│   ├── server/          # HTTP server, routes, middleware
│   ├── crypto/          # AES-256-GCM, Noctis-256, KDF, recovery
│   ├── storage/         # SQLite operations, models
│   ├── link/            # Link generation, mode logic
│   └── mesh/            # Distributed network (tracker + node logic)
├── web/
│   ├── dashboard/       # Main dashboard (HTML/JS/CSS)
│   └── public/          # Public download page
├── Dockerfile
└── railway.json
```

## Encryption

### Default: AES-256-GCM
- Password → Argon2id (time=3, memory=64MB, threads=4) → 256-bit key
- Random 12-byte nonce per file
- Authenticated encryption

### Optional: Noctis-256 (Novel, Experimental)
- **Block size:** 256 bits (32 bytes)
- **Key schedule:** 512-bit key expanded through Feistel-like network with non-linear S-box substitution + bit rotation → 20 round keys
- **Round function (20 rounds):**
  1. Substitution: Key-dependent 8-bit S-box (deterministic shuffle of 256 byte values)
  2. Permutation: Bit-level permutation across 256-bit block (extended MixColumns)
  3. Diffusion: XOR with round key + left-rotate by round-dependent offset
  4. Non-linearity: Modular addition of block halves (128-bit add-with-carry)
- **Mode:** CTR for parallelizable streaming + HMAC-SHA3-256 for authentication
- **Nonce:** 192 bits (24 bytes)
- Explicitly marked as **experimental/unaudited** in UI and README

### Recovery System
- 256-bit master entropy generated on first setup
- **Primary:** 64-character hex key (maximum entropy)
- **Secondary:** 6-word mnemonic (convenience)
- Master entropy encrypts a key escrow blob → can reconstruct file decryption key from password salt
- Recovery flow: hex key/mnemonic → decrypt escrow → derive new password → re-encrypt file keys

## Data Model

```sql
CREATE TABLE files (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    size        INTEGER NOT NULL,
    mime_type   TEXT,
    cipher      TEXT NOT NULL,       -- 'aes-256-gcm' or 'noctis-256'
    salt        BLOB NOT NULL,
    nonce       BLOB NOT NULL,
    blob        BLOB NOT NULL,
    recovery_id TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    FOREIGN KEY (recovery_id) REFERENCES recovery_keys(id)
);

CREATE TABLE recovery_keys (
    id          TEXT PRIMARY KEY,
    hex_key     TEXT NOT NULL,
    mnemonic    TEXT,
    escrow_blob BLOB NOT NULL,
    created_at  INTEGER NOT NULL
);

CREATE TABLE links (
    id          TEXT PRIMARY KEY,    -- 8-char slug
    file_id     TEXT NOT NULL,
    mode        TEXT NOT NULL,       -- 'persistent', 'timed', 'onetime'
    password_hash BLOB NOT NULL,
    expires_at  INTEGER,
    burned      INTEGER DEFAULT 0,
    downloads   INTEGER DEFAULT 0,
    created_at  INTEGER NOT NULL,
    FOREIGN KEY (file_id) REFERENCES files(id)
);
```

## API Routes

```
Dashboard:
  GET  /                          → Dashboard
  GET  /api/files                 → List files
  POST /api/files                 → Upload + encrypt
  DELETE /api/files/:id           → Delete file
  POST /api/files/:id/link        → Create link
  GET  /api/files/:id/links       → List links
  DELETE /api/links/:id           → Revoke link
  POST /api/recovery/setup        → Generate recovery keys
  POST /api/recovery/recover      → Recover via key/mnemonic

Public:
  GET  /s/:slug                   → Download page
  POST /s/:slug/verify            → Verify password
  POST /s/:slug/download          → Decrypt + stream file
```

## Link Modes

| Mode | Behavior |
|------|----------|
| Persistent | Password-protected, never expires |
| Timed | Password-protected, expires after set duration (1h/24h/7d) |
| One-time | Password-protected, burns after single download |

## UI Design

- **Theme:** Premium dark — black (#0A0A0A), red (#DC2626), white (#FFFFFF)
- **Dashboard:** File cards with cipher badges, drag-and-drop upload with red glow, modal for link creation
- **Public page:** Centered password prompt on pure black, "NOCTURNE" branding, mode indicator
- **Typography:** System font stack, monospace for keys

## Deployment

- Single Dockerfile (multi-stage: Go compile → minimal image)
- Railway with persistent volume for SQLite
- Env vars: `PORT`, `NOCTURNE_SECRET`, `NOCTURNE_DATA_DIR`
- Self-hosting: `./nocturne` → localhost:8080

## Testing

- Go `testing` + `httptest` for API
- Table-driven crypto tests with known vectors
- Integration: upload → link → download → verify
- Noctis-256 reference test vectors

## Distributed Network (Nocturne Mesh)

Users can turn any machine into a storage node in a shared encrypted network. Nodes store encrypted shards of other users' files — they cannot read them. Only the file owner (seed + password) can reassemble and decrypt.

### How It Works

1. **Shard creation:** When uploading to the mesh, the file is encrypted, then split into N shards using erasure coding (Reed-Solomon). Any K-of-N shards can reconstruct the file. Shards are distributed across available nodes.

2. **Node script:** A single cross-platform Go binary (`nocturne-node`). Run it to join, run it again to leave. Stores shards in a local `~/.nocturne/shards/` directory. Communicates with the tracker (Nocturne server on Railway) via WebSocket.

3. **Tracker:** The Nocturne server maintains a registry of active nodes and a shard map (which node holds which shard IDs). No file content or keys pass through the tracker — only metadata routing.

4. **Retrieval:** Owner requests file → tracker returns shard locations → client fetches K shards from nodes → reassembles → decrypts with password.

5. **Redundancy:** If a node goes offline, the tracker detects it and re-distributes its shards to remaining nodes (when enough nodes are online to supply the missing shards).

### Node Script Behavior

```
nocturne-node connect    # Join the network, start storing/serving shards
nocturne-node disconnect # Leave the network gracefully
nocturne-node status     # Show node stats (shards stored, space used, uptime)
```

- Cross-platform: Linux (any distro), Windows, macOS
- Zero config: connects to public tracker automatically
- Storage limit configurable: `nocturne-node connect --max-storage 10GB`
- Runs as a background process (daemonizes on connect, stops on disconnect)

### Data Model Additions

```sql
-- Tracker: registered nodes
CREATE TABLE nodes (
    id          TEXT PRIMARY KEY,     -- Node UUID
    public_key  BLOB NOT NULL,       -- Ed25519 public key for node auth
    address     TEXT NOT NULL,        -- IP:port or domain
    max_storage INTEGER NOT NULL,     -- Max bytes willing to store
    used_storage INTEGER DEFAULT 0,
    last_seen   INTEGER NOT NULL,     -- Unix timestamp
    online      INTEGER DEFAULT 1
);

-- Tracker: shard → node mapping
CREATE TABLE shards (
    id          TEXT PRIMARY KEY,     -- Shard UUID
    file_id     TEXT NOT NULL,        -- Owner's file ID
    shard_index INTEGER NOT NULL,     -- Position in erasure coding sequence
    node_id     TEXT NOT NULL,        -- Which node holds this shard
    size        INTEGER NOT NULL,
    checksum    TEXT NOT NULL,        -- SHA-256 of shard data
    FOREIGN KEY (file_id) REFERENCES files(id),
    FOREIGN KEY (node_id) REFERENCES nodes(id)
);
```

### API Routes (Tracker)

```
Node communication:
  WS   /ws/node                    → Node WebSocket (heartbeat, shard ops)
  POST /api/mesh/upload             → Upload file to mesh (shard + distribute)
  POST /api/mesh/download           → Request file from mesh (reassemble)
  GET  /api/mesh/status             → Network stats (nodes online, total storage)
```

### Security

- Nodes only store encrypted shards — opaque blobs with no metadata
- Shard-to-file mapping only exists on the tracker
- Node-to-tracker auth via Ed25519 keypair (generated on first connect)
- Shard transfers between nodes use TLS
- Even if tracker is compromised, files remain encrypted — attacker would need the password AND enough shards

## Excluded (v1)

- No user accounts (single-user dashboard)
- No file versioning
- No client-side encryption for dashboard mode (server does crypto)
- No rate limiting
