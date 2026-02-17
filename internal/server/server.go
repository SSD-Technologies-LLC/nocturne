package server

import (
	"crypto/subtle"
	"encoding/json"
	"io/fs"
	"net/http"
	"time"

	"github.com/ssd-technologies/nocturne/internal/dht"
	"github.com/ssd-technologies/nocturne/internal/storage"
	"github.com/ssd-technologies/nocturne/web"
)

// Server is the main HTTP server for the Nocturne API.
type Server struct {
	db            *storage.DB
	secret        string
	mux           *http.ServeMux
	limiter       *rateLimiter
	strictLimiter *rateLimiter
	dhtNode       *dht.Node
}

// New creates a new Server with all routes registered.
func New(db *storage.DB, secret string) *Server {
	s := &Server{
		db:            db,
		secret:        secret,
		mux:           http.NewServeMux(),
		limiter:       newRateLimiter(120, time.Minute),
		strictLimiter: newRateLimiter(20, time.Minute),
	}
	s.routes()
	return s
}

// Close stops background goroutines owned by the server.
func (s *Server) Close() {
	s.limiter.close()
	s.strictLimiter.close()
}

// SetDHTNode attaches an optional DHT node to the server for P2P storage.
// If nil, the server falls back to its existing SQLite blob storage.
func (s *Server) SetDHTNode(node *dht.Node) {
	s.dhtNode = node
}

// DHTNode returns the server's DHT node, or nil if not configured.
func (s *Server) DHTNode() *dht.Node {
	return s.dhtNode
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'; connect-src 'self'")
	w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	s.mux.ServeHTTP(w, r)
}

// requireAuth returns middleware that checks for a valid Bearer token.
func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if len(auth) < len(prefix) || auth[:len(prefix)] != prefix {
			writeError(w, http.StatusUnauthorized, "authorization required")
			return
		}
		token := auth[len(prefix):]
		if subtle.ConstantTimeCompare([]byte(token), []byte(s.secret)) != 1 {
			writeError(w, http.StatusUnauthorized, "invalid token")
			return
		}
		next(w, r)
	}
}

// withRateLimit wraps a handler with per-IP rate limiting.
func withRateLimit(rl *rateLimiter, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !rl.allow(getIP(r)) {
			writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
			return
		}
		next(w, r)
	}
}

// routes registers all HTTP routes on the server mux.
func (s *Server) routes() {
	// Health (no auth)
	s.mux.HandleFunc("GET /api/health", s.handleHealth)

	// Files (auth required)
	s.mux.HandleFunc("POST /api/files", s.requireAuth(s.handleUploadFile))
	s.mux.HandleFunc("GET /api/files", s.requireAuth(s.handleListFiles))
	s.mux.HandleFunc("DELETE /api/files/{id}", s.requireAuth(s.handleDeleteFile))

	// Links (auth required)
	s.mux.HandleFunc("POST /api/files/{id}/link", s.requireAuth(s.handleCreateLink))
	s.mux.HandleFunc("GET /api/files/{id}/links", s.requireAuth(s.handleListLinks))
	s.mux.HandleFunc("DELETE /api/links/{id}", s.requireAuth(s.handleDeleteLink))

	// Recovery (auth required)
	s.mux.HandleFunc("POST /api/recovery/setup", s.requireAuth(s.handleRecoverySetup))
	s.mux.HandleFunc("POST /api/recovery/recover", s.requireAuth(s.handleRecoveryRecover))

	// Public API (rate limited, no auth — these have their own password checks)
	s.mux.HandleFunc("POST /s/{slug}/verify", withRateLimit(s.strictLimiter, s.handlePublicVerify))
	s.mux.HandleFunc("POST /s/{slug}/download", withRateLimit(s.strictLimiter, s.handlePublicDownload))

	// Static files — embedded frontend
	dashboardFS, _ := fs.Sub(web.FS, "dashboard")
	publicFS, _ := fs.Sub(web.FS, "public")

	// Dashboard: serve index.html at root, plus its assets
	s.mux.Handle("GET /styles.css", http.FileServerFS(dashboardFS))
	s.mux.Handle("GET /app.js", http.FileServerFS(dashboardFS))
	s.mux.Handle("GET /crypto.js", http.FileServerFS(dashboardFS))
	s.mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFileFS(w, r, dashboardFS, "index.html")
	})

	// Public download page: serve download.html for GET /s/{slug}
	s.mux.Handle("GET /download.js", http.FileServerFS(publicFS))
	s.mux.HandleFunc("GET /s/{slug}", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFileFS(w, r, publicFS, "download.html")
	})
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
