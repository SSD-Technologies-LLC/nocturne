package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/ssd-technologies/nocturne/internal/crypto"
	"github.com/ssd-technologies/nocturne/internal/storage"
)

// sanitizeFilename strips directory traversal, quotes, and CR/LF from a filename
// to prevent Content-Disposition header injection attacks.
func sanitizeFilename(name string) string {
	// Normalize backslash separators (Windows-style paths) before calling filepath.Base.
	name = strings.ReplaceAll(name, `\`, "/")
	name = filepath.Base(name)
	name = strings.NewReplacer(`"`, "", "\r", "", "\n", "").Replace(name)
	if name == "" || name == "." || name == ".." {
		return "download"
	}
	return name
}

// verifyRequest is the JSON body for verifying a link password.
type verifyRequest struct {
	LinkPassword string `json:"link_password"`
}

// downloadRequest is the JSON body for downloading a file via a link.
type downloadRequest struct {
	LinkPassword string `json:"link_password"`
	FilePassword string `json:"file_password"`
}

// validateLink checks that a link exists, is not burned, and is not expired.
// Returns the link and file if valid, or writes an error and returns nil.
func (s *Server) validateLink(w http.ResponseWriter, slug string) (*storage.Link, *storage.File) {
	link, err := s.db.GetLink(slug)
	if err != nil {
		writeError(w, http.StatusNotFound, "link not found")
		return nil, nil
	}

	if link.Burned {
		writeError(w, http.StatusGone, "link has been used")
		return nil, nil
	}

	if link.ExpiresAt != nil && *link.ExpiresAt < time.Now().Unix() {
		writeError(w, http.StatusGone, "link has expired")
		return nil, nil
	}

	file, err := s.db.GetFile(link.FileID)
	if err != nil {
		writeError(w, http.StatusNotFound, "file not found")
		return nil, nil
	}

	return link, file
}

// handlePublicVerify handles POST /s/{slug}/verify — verify link password and return file metadata.
func (s *Server) handlePublicVerify(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	if slug == "" {
		writeError(w, http.StatusBadRequest, "slug is required")
		return
	}

	var req verifyRequest
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

	resp := map[string]any{
		"name":   file.Name,
		"size":   file.Size,
		"cipher": file.Cipher,
	}

	// Signal P2P mode so the frontend knows to decrypt client-side.
	if len(file.Blob) == 0 {
		resp["storage_mode"] = "p2p"
	}

	writeJSON(w, http.StatusOK, resp)
}

// handlePublicDownload handles POST /s/{slug}/download — decrypt and stream file download.
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

	// Determine ciphertext source: P2P (empty blob + DHT) or local SQLite blob.
	var ciphertext []byte
	isP2P := len(file.Blob) == 0
	if isP2P && s.dhtNode != nil {
		reconstructed, err := s.dhtNode.ReconstructFile(file.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to reconstruct file from network")
			return
		}
		ciphertext = reconstructed
	} else if isP2P {
		// Empty blob but no DHT — pre-encrypted file stored locally.
		writeError(w, http.StatusInternalServerError, "P2P file but no DHT node available")
		return
	} else {
		ciphertext = file.Blob
	}

	// For non-onetime links, increment download count.
	if link.Mode != "onetime" {
		if err := s.db.IncrementDownloads(link.ID); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to increment downloads")
			return
		}
	}

	// P2P mode: return ciphertext + params as JSON for client-side decryption.
	// The browser will use argon2-browser + Web Crypto to decrypt locally.
	if isP2P {
		writeJSON(w, http.StatusOK, map[string]any{
			"storage_mode": "p2p",
			"ciphertext":   base64.StdEncoding.EncodeToString(ciphertext),
			"salt":         base64.StdEncoding.EncodeToString(file.Salt),
			"nonce":        base64.StdEncoding.EncodeToString(file.Nonce),
			"file_name":    file.Name,
		})
		return
	}

	// Non-P2P: decrypt server-side and stream plaintext.
	plaintext, err := crypto.Decrypt(ciphertext, req.FilePassword, file.Cipher, file.Salt, file.Nonce)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "decryption failed: wrong file password")
		return
	}

	// Stream the decrypted file.
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, sanitizeFilename(file.Name)))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(plaintext)))
	w.WriteHeader(http.StatusOK)
	w.Write(plaintext)
}
