# Nocturne

Encrypted file storage with a novel cipher. Upload files, share them with a link, recover your password with a seed phrase. Everything encrypted.

**From [SSD Technologies](https://ssd.foundation)**

## What it does

- Upload files through a dark, minimal dashboard
- Every file is encrypted (AES-256-GCM or the experimental Noctis-256 cipher)
- Create password-protected download links (persistent, time-limited, or one-time)
- Recover your password using a hex recovery key
- Join the mesh network and share storage with others

## Quick start

```bash
# Download and run
./nocturne

# Open http://localhost:8080
```

Or with Docker:

```bash
docker run -p 8080:8080 -v nocturne-data:/app/data ghcr.io/ssd-technologies/nocturne
```

## Mesh network

Turn your machine into a storage node. You store encrypted fragments of other users' files — you can't read them. Only the owner can reassemble and decrypt.

```bash
# Join the network
nocturne-node connect --max-storage 10GB

# Check your node
nocturne-node status

# Leave the network
nocturne-node disconnect
```

Files are split using erasure coding — even if some nodes go offline, your files survive.

## How encryption works

1. You set a password when uploading
2. Password → Argon2id → encryption key
3. File encrypted with AES-256-GCM (default) or Noctis-256 (experimental)
4. A hex recovery key lets you recover your password if you forget it

**Noctis-256** is an experimental cipher built for this project. It uses a 256-bit block size, 20-round Feistel network with key-dependent S-boxes, CTR mode, and HMAC-SHA3-256 authentication. It is **not audited** — use AES for anything important.

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `8080` | Server port |
| `NOCTURNE_DATA_DIR` | `data` | Where the database lives |
| `NOCTURNE_SECRET` | — | Server secret (set in production) |
| `NOCTURNE_TRACKER` | — | Mesh tracker URL (for nodes) |

## License

MIT
