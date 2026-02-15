# Nocturne — Encrypted File Storage Design

## Overview

Nocturne is a minimalist encrypted file storage solution with a locally accessible dashboard and remote server deployment. All files are encrypted server-side. Shareable links allow password-protected downloads. Password recovery via hex recovery key or 6-word mnemonic.

Open-source project from SSD Technologies.

## Architecture

**Single Go binary** serving API, dashboard, and public download pages. HTML/JS/CSS embedded via `go:embed`. SQLite for storage (encrypted blobs stored inline). Self-hosting: download binary, run it.

```
nocturne/
├── cmd/vault/main.go
├── internal/
│   ├── server/          # HTTP server, routes, middleware
│   ├── crypto/          # AES-256-GCM, Noctis-256, KDF, recovery
│   ├── storage/         # SQLite operations, models
│   └── link/            # Link generation, mode logic
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

## Excluded (v1)

- No user accounts (single-user)
- No file versioning
- No multi-server sync
- No client-side encryption
- No rate limiting
