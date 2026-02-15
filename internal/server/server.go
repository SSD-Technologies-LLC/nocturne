package server

import (
	"encoding/json"
	"net/http"

	"github.com/ssd-technologies/nocturne/internal/storage"
)

// Server is the main HTTP server for the Nocturne API.
type Server struct {
	db     *storage.DB
	secret string
	mux    *http.ServeMux
}

// New creates a new Server with all routes registered.
func New(db *storage.DB, secret string) *Server {
	s := &Server{
		db:     db,
		secret: secret,
		mux:    http.NewServeMux(),
	}
	s.routes()
	return s
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

// routes registers all HTTP routes on the server mux.
func (s *Server) routes() {
	// Health
	s.mux.HandleFunc("GET /api/health", s.handleHealth)

	// Files
	s.mux.HandleFunc("POST /api/files", s.handleUploadFile)
	s.mux.HandleFunc("GET /api/files", s.handleListFiles)
	s.mux.HandleFunc("DELETE /api/files/{id}", s.handleDeleteFile)

	// Links
	s.mux.HandleFunc("POST /api/files/{id}/link", s.handleCreateLink)
	s.mux.HandleFunc("GET /api/files/{id}/links", s.handleListLinks)
	s.mux.HandleFunc("DELETE /api/links/{id}", s.handleDeleteLink)

	// Recovery
	s.mux.HandleFunc("POST /api/recovery/setup", s.handleRecoverySetup)
	s.mux.HandleFunc("POST /api/recovery/recover", s.handleRecoveryRecover)

	// Public
	s.mux.HandleFunc("POST /s/{slug}/verify", s.handlePublicVerify)
	s.mux.HandleFunc("POST /s/{slug}/download", s.handlePublicDownload)
}

// handleHealth returns a simple health check response.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"service": "nocturne",
	})
}

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// writeError writes a JSON error response with the given status code and message.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
