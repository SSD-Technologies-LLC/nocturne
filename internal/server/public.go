package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/ssd-technologies/nocturne/internal/crypto"
	"github.com/ssd-technologies/nocturne/internal/storage"
)

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

	writeJSON(w, http.StatusOK, map[string]any{
		"name":   file.Name,
		"size":   file.Size,
		"cipher": file.Cipher,
	})
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

	// Decrypt the file.
	plaintext, err := crypto.Decrypt(file.Blob, req.FilePassword, file.Cipher, file.Salt, file.Nonce)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "decryption failed: wrong file password")
		return
	}

	// For non-onetime links, increment download count.
	if link.Mode != "onetime" {
		if err := s.db.IncrementDownloads(link.ID); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to increment downloads")
			return
		}
	}

	// Stream the decrypted file.
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, file.Name))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(plaintext)))
	w.WriteHeader(http.StatusOK)
	w.Write(plaintext)
}
