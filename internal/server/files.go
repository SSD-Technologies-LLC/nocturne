package server

import (
	crand "crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/ssd-technologies/nocturne/internal/crypto"
	"github.com/ssd-technologies/nocturne/internal/dht"
	"github.com/ssd-technologies/nocturne/internal/storage"
)

const maxUploadSize = 100 << 20 // 100 MB

// handleUploadFile handles POST /api/files — upload and encrypt a file.
// Supports two modes:
//   - Server-side encryption: client sends plaintext + password, server encrypts.
//   - Pre-encrypted (P2P): client encrypts in-browser, sends ciphertext + salt + nonce.
func (s *Server) handleUploadFile(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(maxUploadSize); err != nil {
		writeError(w, http.StatusBadRequest, "failed to parse multipart form")
		return
	}

	preEncrypted := r.FormValue("pre_encrypted") == "true"

	if preEncrypted {
		s.handlePreEncryptedUpload(w, r)
		return
	}
	s.handleServerEncryptedUpload(w, r)
}

// handleServerEncryptedUpload is the original upload path: server-side encryption.
func (s *Server) handleServerEncryptedUpload(w http.ResponseWriter, r *http.Request) {
	password := r.FormValue("password")
	if password == "" {
		writeError(w, http.StatusBadRequest, "password is required")
		return
	}

	cipherName := r.FormValue("cipher")
	if cipherName == "" {
		cipherName = crypto.CipherAES
	}
	if cipherName != crypto.CipherAES && cipherName != crypto.CipherNoctis {
		writeError(w, http.StatusBadRequest, "unsupported cipher")
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "file is required")
		return
	}
	defer file.Close()

	plaintext, err := io.ReadAll(file)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read file")
		return
	}

	// Encrypt
	ciphertext, salt, nonce, err := crypto.Encrypt(plaintext, password, cipherName)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "encryption failed")
		return
	}

	// Ensure a recovery key exists
	recoveryID, err := s.ensureRecoveryKey(password, salt)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to setup recovery")
		return
	}

	f := &storage.File{
		ID:         uuid.New().String(),
		Name:       header.Filename,
		Size:       int64(len(plaintext)),
		MimeType:   header.Header.Get("Content-Type"),
		Cipher:     cipherName,
		Salt:       salt,
		Nonce:      nonce,
		Blob:       ciphertext,
		RecoveryID: recoveryID,
		CreatedAt:  time.Now().Unix(),
	}

	// P2P distributed storage path: erasure-code and distribute via DHT.
	storageMode := r.FormValue("storage_mode")
	if storageMode == "p2p" && s.dhtNode != nil {
		manifest, err := s.dhtNode.DistributeFile(dht.DistributeFileParams{
			FileID:       f.ID,
			FileName:     f.Name,
			FileSize:     int64(len(ciphertext)),
			Cipher:       f.Cipher,
			Salt:         f.Salt,
			Nonce:        f.Nonce,
			Ciphertext:   ciphertext,
			DataShards:   4,
			ParityShards: 2,
			OperatorID:   "server",
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, "P2P distribution failed")
			return
		}

		// Store metadata only (empty blob) in SQLite.
		f.Blob = []byte{}

		if err := s.db.CreateFile(f); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to store file")
			return
		}

		writeJSON(w, http.StatusCreated, map[string]any{
			"id":           f.ID,
			"name":         f.Name,
			"size":         f.Size,
			"mime_type":    f.MimeType,
			"cipher":       f.Cipher,
			"recovery_id":  f.RecoveryID,
			"created_at":   f.CreatedAt,
			"storage_mode": "p2p",
			"shards":       manifest.TotalShards(),
		})
		return
	}

	if err := s.db.CreateFile(f); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to store file")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"id":          f.ID,
		"name":        f.Name,
		"size":        f.Size,
		"mime_type":   f.MimeType,
		"cipher":      f.Cipher,
		"recovery_id": f.RecoveryID,
		"created_at":  f.CreatedAt,
	})
}

// handlePreEncryptedUpload handles uploads where the browser already encrypted
// the file client-side (P2P mode with argon2-browser + Web Crypto AES-256-GCM).
// The server receives ciphertext, salt, and nonce — it does NOT re-encrypt.
func (s *Server) handlePreEncryptedUpload(w http.ResponseWriter, r *http.Request) {
	// Decode salt and nonce from base64 form fields.
	saltB64 := r.FormValue("salt")
	nonceB64 := r.FormValue("nonce")
	if saltB64 == "" || nonceB64 == "" {
		writeError(w, http.StatusBadRequest, "salt and nonce are required for pre-encrypted uploads")
		return
	}

	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid salt encoding")
		return
	}
	nonce, err := base64.StdEncoding.DecodeString(nonceB64)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid nonce encoding")
		return
	}

	cipherName := r.FormValue("cipher")
	if cipherName == "" {
		cipherName = crypto.CipherAES
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "file is required")
		return
	}
	defer file.Close()

	ciphertext, err := io.ReadAll(file)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to read file")
		return
	}

	// Parse original plaintext size if provided; otherwise use ciphertext len.
	originalSize := int64(len(ciphertext))
	if sizeStr := r.FormValue("original_size"); sizeStr != "" {
		if parsed, err := strconv.ParseInt(sizeStr, 10, 64); err == nil {
			originalSize = parsed
		}
	}

	// Ensure a recovery key exists. Without the user's password we cannot create
	// an escrow, but we can reference an existing recovery key.
	recoveryID, err := s.ensureRecoveryKeyWithSalt()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to setup recovery")
		return
	}

	f := &storage.File{
		ID:         uuid.New().String(),
		Name:       header.Filename,
		Size:       originalSize,
		MimeType:   header.Header.Get("Content-Type"),
		Cipher:     cipherName,
		Salt:       salt,
		Nonce:      nonce,
		Blob:       ciphertext,
		RecoveryID: recoveryID,
		CreatedAt:  time.Now().Unix(),
	}

	// P2P distribution via DHT when available.
	if s.dhtNode != nil {
		manifest, err := s.dhtNode.DistributeFile(dht.DistributeFileParams{
			FileID:       f.ID,
			FileName:     f.Name,
			FileSize:     int64(len(ciphertext)),
			Cipher:       f.Cipher,
			Salt:         f.Salt,
			Nonce:        f.Nonce,
			Ciphertext:   ciphertext,
			DataShards:   4,
			ParityShards: 2,
			OperatorID:   "server",
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, "P2P distribution failed")
			return
		}

		// Store metadata only (empty blob) in SQLite.
		f.Blob = []byte{}

		if err := s.db.CreateFile(f); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to store file")
			return
		}

		writeJSON(w, http.StatusCreated, map[string]any{
			"id":           f.ID,
			"name":         f.Name,
			"size":         f.Size,
			"mime_type":    f.MimeType,
			"cipher":       f.Cipher,
			"recovery_id":  f.RecoveryID,
			"created_at":   f.CreatedAt,
			"storage_mode": "p2p",
			"shards":       manifest.TotalShards(),
		})
		return
	}

	// No DHT node — store pre-encrypted blob locally in SQLite.
	if err := s.db.CreateFile(f); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to store file")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"id":           f.ID,
		"name":         f.Name,
		"size":         f.Size,
		"mime_type":    f.MimeType,
		"cipher":       f.Cipher,
		"recovery_id":  f.RecoveryID,
		"created_at":   f.CreatedAt,
		"storage_mode": "pre_encrypted",
	})
}

// ensureRecoveryKeyWithSalt returns the first existing recovery key ID, or empty string
// if none exist. Pre-encrypted uploads don't have the user's password on the server,
// so we cannot create an escrow — but we can reference an existing recovery key.
func (s *Server) ensureRecoveryKeyWithSalt() (string, error) {
	keys, err := s.db.ListRecoveryKeys()
	if err != nil {
		return "", err
	}
	if len(keys) > 0 {
		return keys[0].ID, nil
	}
	// No recovery key and no password to create one — return empty.
	return "", nil
}

// ensureRecoveryKey checks for existing recovery keys and creates one if none exist.
func (s *Server) ensureRecoveryKey(password string, salt []byte) (string, error) {
	keys, err := s.db.ListRecoveryKeys()
	if err != nil {
		return "", err
	}
	if len(keys) > 0 {
		return keys[0].ID, nil
	}

	hexKey, mnemonic, err := crypto.GenerateRecoveryKey()
	if err != nil {
		return "", err
	}

	escrowBlob, err := crypto.CreateEscrow(hexKey, password, salt)
	if err != nil {
		return "", err
	}

	rk := &storage.RecoveryKey{
		ID:         uuid.New().String(),
		HexKey:     hexKey,
		Mnemonic:   mnemonic,
		EscrowBlob: escrowBlob,
		CreatedAt:  time.Now().Unix(),
	}
	if err := s.db.CreateRecoveryKey(rk); err != nil {
		return "", err
	}
	return rk.ID, nil
}

// handleListFiles handles GET /api/files — list all files.
func (s *Server) handleListFiles(w http.ResponseWriter, r *http.Request) {
	files, err := s.db.ListFiles()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list files")
		return
	}

	// Return empty array instead of null
	if files == nil {
		files = []storage.File{}
	}

	// Build response without sensitive fields
	result := make([]map[string]any, len(files))
	for i, f := range files {
		result[i] = map[string]any{
			"id":          f.ID,
			"name":        f.Name,
			"size":        f.Size,
			"mime_type":   f.MimeType,
			"cipher":      f.Cipher,
			"recovery_id": f.RecoveryID,
			"created_at":  f.CreatedAt,
		}
	}

	writeJSON(w, http.StatusOK, result)
}

// handleDeleteFile handles DELETE /api/files/{id} — delete a file.
func (s *Server) handleDeleteFile(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "file id is required")
		return
	}

	// Clean up DHT shards if this was a P2P-stored file.
	if s.dhtNode != nil {
		s.dhtNode.DeleteDistributedFile(id, "server")
	}

	if err := s.db.DeleteFileWithLinks(id); err != nil {
		writeError(w, http.StatusNotFound, "file not found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// generateSlug creates a random 8-character hex slug for link URLs.
func generateSlug() string {
	b := make([]byte, 4)
	if _, err := crand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}
