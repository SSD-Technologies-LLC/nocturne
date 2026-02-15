package server

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/ssd-technologies/nocturne/internal/crypto"
	"github.com/ssd-technologies/nocturne/internal/storage"
)

// linkRequest is the JSON body for creating a shareable link.
type linkRequest struct {
	Password  string `json:"password"`
	Mode      string `json:"mode"`
	ExpiresIn int64  `json:"expires_in"`
}

// handleCreateLink handles POST /api/files/{id}/link — create a shareable link.
func (s *Server) handleCreateLink(w http.ResponseWriter, r *http.Request) {
	fileID := r.PathValue("id")
	if fileID == "" {
		writeError(w, http.StatusBadRequest, "file id is required")
		return
	}

	// Verify file exists
	if _, err := s.db.GetFile(fileID); err != nil {
		writeError(w, http.StatusNotFound, "file not found")
		return
	}

	var req linkRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Password == "" {
		writeError(w, http.StatusBadRequest, "password is required")
		return
	}

	if req.Mode == "" {
		req.Mode = "persistent"
	}
	if req.Mode != "persistent" && req.Mode != "timed" && req.Mode != "onetime" {
		writeError(w, http.StatusBadRequest, "invalid mode: must be persistent, timed, or onetime")
		return
	}

	slug := generateSlug()
	passwordHash := crypto.HashPassword(req.Password)

	link := &storage.Link{
		ID:           slug,
		FileID:       fileID,
		Mode:         req.Mode,
		PasswordHash: passwordHash,
		CreatedAt:    time.Now().Unix(),
	}

	// For timed mode, calculate expiration
	if req.Mode == "timed" && req.ExpiresIn > 0 {
		expiresAt := time.Now().Unix() + req.ExpiresIn
		link.ExpiresAt = &expiresAt
	}

	if err := s.db.CreateLink(link); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to create link")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{
		"slug": slug,
		"url":  "/s/" + slug,
	})
}

// handleListLinks handles GET /api/files/{id}/links — list links for a file.
func (s *Server) handleListLinks(w http.ResponseWriter, r *http.Request) {
	fileID := r.PathValue("id")
	if fileID == "" {
		writeError(w, http.StatusBadRequest, "file id is required")
		return
	}

	links, err := s.db.ListLinksForFile(fileID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list links")
		return
	}

	// Return empty array instead of null
	if links == nil {
		links = []storage.Link{}
	}

	// Build response without sensitive fields
	result := make([]map[string]any, len(links))
	for i, l := range links {
		entry := map[string]any{
			"id":         l.ID,
			"file_id":    l.FileID,
			"mode":       l.Mode,
			"burned":     l.Burned,
			"downloads":  l.Downloads,
			"created_at": l.CreatedAt,
			"url":        "/s/" + l.ID,
		}
		if l.ExpiresAt != nil {
			entry["expires_at"] = *l.ExpiresAt
		}
		result[i] = entry
	}

	writeJSON(w, http.StatusOK, result)
}

// handleDeleteLink handles DELETE /api/links/{id} — revoke a link.
func (s *Server) handleDeleteLink(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "link id is required")
		return
	}

	if err := s.db.DeleteLink(id); err != nil {
		writeError(w, http.StatusNotFound, "link not found")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
