package server

import (
	crand "crypto/rand"
	"encoding/hex"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/ssd-technologies/nocturne/internal/crypto"
	"github.com/ssd-technologies/nocturne/internal/dht"
	"github.com/ssd-technologies/nocturne/internal/storage"
)

const maxUploadSize = 100 << 20 // 100 MB

// handleUploadFile handles POST /api/files — upload and encrypt a file.
func (s *Server) handleUploadFile(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(maxUploadSize); err != nil {
		writeError(w, http.StatusBadRequest, "failed to parse multipart form")
		return
	}

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
			FileSize:     f.Size,
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
		// The blob column has a NOT NULL constraint, so we use an empty slice.
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
