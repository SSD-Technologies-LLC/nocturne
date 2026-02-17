package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ssd-technologies/nocturne/internal/dht"
	"github.com/ssd-technologies/nocturne/internal/storage"
)

// setupTestDB creates a temporary SQLite database for testing.
func setupTestDB(t *testing.T) *storage.DB {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	db, err := storage.NewDB(dbPath)
	if err != nil {
		t.Fatalf("NewDB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// setupTestServer creates a test server with a fresh database.
func setupTestServer(t *testing.T) *Server {
	t.Helper()
	db := setupTestDB(t)
	return New(db, "test-secret")
}

// uploadTestFile is a helper that uploads a file and returns the response body as a map.
func uploadTestFile(t *testing.T, srv *Server, filename, content, password string) map[string]any {
	t.Helper()

	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	// Add password field
	if err := writer.WriteField("password", password); err != nil {
		t.Fatalf("write password field: %v", err)
	}

	// Add file
	part, err := writer.CreateFormFile("file", filename)
	if err != nil {
		t.Fatalf("create form file: %v", err)
	}
	if _, err := part.Write([]byte(content)); err != nil {
		t.Fatalf("write file content: %v", err)
	}

	if err := writer.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/files", &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer test-secret")
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("upload file: status = %d, want %d; body = %s", rec.Code, http.StatusCreated, rec.Body.String())
	}

	var result map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decode upload response: %v", err)
	}
	return result
}

// createTestLink is a helper that creates a link for a file.
func createTestLink(t *testing.T, srv *Server, fileID, password, mode string) map[string]any {
	t.Helper()

	body := map[string]any{
		"password": password,
		"mode":     mode,
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/api/files/"+fileID+"/link", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-secret")
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("create link: status = %d, want %d; body = %s", rec.Code, http.StatusCreated, rec.Body.String())
	}

	var result map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decode link response: %v", err)
	}
	return result
}

// TestServer_HealthEndpoint tests GET /api/health returns 200.
func TestServer_HealthEndpoint(t *testing.T) {
	srv := setupTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var body map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("status = %q, want %q", body["status"], "ok")
	}
	if body["service"] != "nocturne" {
		t.Errorf("service = %q, want %q", body["service"], "nocturne")
	}
}

// TestListFiles_Empty tests GET /api/files returns empty array.
func TestListFiles_Empty(t *testing.T) {
	srv := setupTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/files", nil)
	req.Header.Set("Authorization", "Bearer test-secret")
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var body []any
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body) != 0 {
		t.Errorf("len = %d, want 0", len(body))
	}
}

// TestUploadFile tests the full upload flow.
func TestUploadFile(t *testing.T) {
	srv := setupTestServer(t)

	result := uploadTestFile(t, srv, "hello.txt", "Hello, World!", "testpassword123")

	if result["id"] == nil || result["id"] == "" {
		t.Error("expected non-empty id")
	}
	if result["name"] != "hello.txt" {
		t.Errorf("name = %q, want %q", result["name"], "hello.txt")
	}
	// Size should be the original plaintext size
	if size, ok := result["size"].(float64); !ok || size != 13 {
		t.Errorf("size = %v, want 13", result["size"])
	}
	if result["cipher"] != "aes-256-gcm" {
		t.Errorf("cipher = %q, want %q", result["cipher"], "aes-256-gcm")
	}
	if result["recovery_id"] == nil || result["recovery_id"] == "" {
		t.Error("expected non-empty recovery_id")
	}

	// Verify the file shows up in the list
	req := httptest.NewRequest(http.MethodGet, "/api/files", nil)
	req.Header.Set("Authorization", "Bearer test-secret")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	var files []map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&files); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("len = %d, want 1", len(files))
	}
}

// TestDeleteFile tests upload then delete.
func TestDeleteFile(t *testing.T) {
	srv := setupTestServer(t)

	result := uploadTestFile(t, srv, "delete-me.txt", "content", "password")
	fileID := result["id"].(string)

	req := httptest.NewRequest(http.MethodDelete, "/api/files/"+fileID, nil)
	req.Header.Set("Authorization", "Bearer test-secret")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("delete: status = %d, want %d; body = %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	// Verify file is gone
	req = httptest.NewRequest(http.MethodGet, "/api/files", nil)
	req.Header.Set("Authorization", "Bearer test-secret")
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	var files []any
	if err := json.NewDecoder(rec.Body).Decode(&files); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(files) != 0 {
		t.Errorf("expected 0 files after delete, got %d", len(files))
	}
}

// TestCreateLink tests creating a link for an existing file.
func TestCreateLink(t *testing.T) {
	srv := setupTestServer(t)

	fileResult := uploadTestFile(t, srv, "linked.txt", "content", "password")
	fileID := fileResult["id"].(string)

	linkResult := createTestLink(t, srv, fileID, "linkpass", "persistent")

	slug, ok := linkResult["slug"].(string)
	if !ok || len(slug) != 8 {
		t.Errorf("slug = %q, want 8-char hex string", slug)
	}
	url, ok := linkResult["url"].(string)
	if !ok || !strings.HasPrefix(url, "/s/") {
		t.Errorf("url = %q, want prefix /s/", url)
	}
}

// TestListLinks tests listing links for a file.
func TestListLinks(t *testing.T) {
	srv := setupTestServer(t)

	fileResult := uploadTestFile(t, srv, "linked.txt", "content", "password")
	fileID := fileResult["id"].(string)

	// Create two links
	createTestLink(t, srv, fileID, "linkpass1", "persistent")
	createTestLink(t, srv, fileID, "linkpass2", "onetime")

	req := httptest.NewRequest(http.MethodGet, "/api/files/"+fileID+"/links", nil)
	req.Header.Set("Authorization", "Bearer test-secret")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	var links []map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&links); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(links) != 2 {
		t.Fatalf("len = %d, want 2", len(links))
	}
}

// TestPublicVerify tests verifying a link password.
func TestPublicVerify(t *testing.T) {
	srv := setupTestServer(t)

	fileResult := uploadTestFile(t, srv, "verify.txt", "secret content", "filepass")
	fileID := fileResult["id"].(string)

	linkResult := createTestLink(t, srv, fileID, "linkpass", "persistent")
	slug := linkResult["slug"].(string)

	// Verify with correct password
	body, _ := json.Marshal(map[string]string{"link_password": "linkpass"})
	req := httptest.NewRequest(http.MethodPost, "/s/"+slug+"/verify", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("verify: status = %d, want %d; body = %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var result map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result["name"] != "verify.txt" {
		t.Errorf("name = %q, want %q", result["name"], "verify.txt")
	}
	if result["cipher"] != "aes-256-gcm" {
		t.Errorf("cipher = %q, want %q", result["cipher"], "aes-256-gcm")
	}

	// Verify with wrong password
	body, _ = json.Marshal(map[string]string{"link_password": "wrongpass"})
	req = httptest.NewRequest(http.MethodPost, "/s/"+slug+"/verify", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("wrong password: status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

// TestPublicDownload tests the full download flow.
func TestPublicDownload(t *testing.T) {
	srv := setupTestServer(t)

	originalContent := "This is the secret file content for download test."
	fileResult := uploadTestFile(t, srv, "download.txt", originalContent, "filepass")
	fileID := fileResult["id"].(string)

	linkResult := createTestLink(t, srv, fileID, "linkpass", "persistent")
	slug := linkResult["slug"].(string)

	body, _ := json.Marshal(map[string]string{
		"link_password": "linkpass",
		"file_password": "filepass",
	})
	req := httptest.NewRequest(http.MethodPost, "/s/"+slug+"/download", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("download: status = %d, want %d; body = %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	downloaded, err := io.ReadAll(rec.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	if string(downloaded) != originalContent {
		t.Errorf("content = %q, want %q", string(downloaded), originalContent)
	}

	// Check Content-Disposition header
	cd := rec.Header().Get("Content-Disposition")
	if !strings.Contains(cd, "download.txt") {
		t.Errorf("Content-Disposition = %q, want to contain %q", cd, "download.txt")
	}
}

// TestPublicDownload_WrongPassword tests that wrong file password returns an error.
func TestPublicDownload_WrongPassword(t *testing.T) {
	srv := setupTestServer(t)

	fileResult := uploadTestFile(t, srv, "secret.txt", "secret", "correctpass")
	fileID := fileResult["id"].(string)

	linkResult := createTestLink(t, srv, fileID, "linkpass", "persistent")
	slug := linkResult["slug"].(string)

	body, _ := json.Marshal(map[string]string{
		"link_password": "linkpass",
		"file_password": "wrongpass",
	})
	req := httptest.NewRequest(http.MethodPost, "/s/"+slug+"/download", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password: status = %d, want %d; body = %s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
}

// TestPublicDownload_BurnedLink tests that a one-time link cannot be reused.
func TestPublicDownload_BurnedLink(t *testing.T) {
	srv := setupTestServer(t)

	fileResult := uploadTestFile(t, srv, "onetime.txt", "one-time content", "filepass")
	fileID := fileResult["id"].(string)

	linkResult := createTestLink(t, srv, fileID, "linkpass", "onetime")
	slug := linkResult["slug"].(string)

	body, _ := json.Marshal(map[string]string{
		"link_password": "linkpass",
		"file_password": "filepass",
	})

	// First download should succeed
	req := httptest.NewRequest(http.MethodPost, "/s/"+slug+"/download", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("first download: status = %d, want %d; body = %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	// Second download should fail (link is burned)
	body, _ = json.Marshal(map[string]string{
		"link_password": "linkpass",
		"file_password": "filepass",
	})
	req = httptest.NewRequest(http.MethodPost, "/s/"+slug+"/download", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusGone {
		t.Fatalf("burned link: status = %d, want %d; body = %s", rec.Code, http.StatusGone, rec.Body.String())
	}
}

// TestRecoverySetup tests POST /api/recovery/setup returns hex key and mnemonic.
func TestRecoverySetup(t *testing.T) {
	srv := setupTestServer(t)

	body, _ := json.Marshal(map[string]string{"password": "mypassword"})
	req := httptest.NewRequest(http.MethodPost, "/api/recovery/setup", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-secret")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusCreated, rec.Body.String())
	}

	var result map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}

	hexKey := result["hex_key"]
	if len(hexKey) != 64 {
		t.Errorf("hex_key length = %d, want 64", len(hexKey))
	}

	mnemonic := result["mnemonic"]
	words := strings.Fields(mnemonic)
	if len(words) != 6 {
		t.Errorf("mnemonic words = %d, want 6", len(words))
	}
}

// TestRecoveryRecover tests recovering a password via hex key.
func TestRecoveryRecover(t *testing.T) {
	srv := setupTestServer(t)

	password := "my-secret-password"

	// Setup recovery
	setupBody, _ := json.Marshal(map[string]string{"password": password})
	req := httptest.NewRequest(http.MethodPost, "/api/recovery/setup", bytes.NewReader(setupBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-secret")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("setup: status = %d, want %d; body = %s", rec.Code, http.StatusCreated, rec.Body.String())
	}

	var setupResult map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&setupResult); err != nil {
		t.Fatalf("decode setup: %v", err)
	}

	hexKey := setupResult["hex_key"]

	// Recover password
	recoverBody, _ := json.Marshal(map[string]string{"hex_key": hexKey})
	req = httptest.NewRequest(http.MethodPost, "/api/recovery/recover", bytes.NewReader(recoverBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-secret")
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("recover: status = %d, want %d; body = %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var recoverResult map[string]string
	if err := json.NewDecoder(rec.Body).Decode(&recoverResult); err != nil {
		t.Fatalf("decode recover: %v", err)
	}

	if recoverResult["password"] != password {
		t.Errorf("recovered password = %q, want %q", recoverResult["password"], password)
	}
}

func TestAuth_RejectsUnauthenticated(t *testing.T) {
	srv := setupTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/files", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated: status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestAuth_AcceptsValidToken(t *testing.T) {
	srv := setupTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/files", nil)
	req.Header.Set("Authorization", "Bearer test-secret")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("authenticated: status = %d, want %d; body = %s", rec.Code, http.StatusOK, rec.Body.String())
	}
}

func TestAuth_RejectsWrongToken(t *testing.T) {
	srv := setupTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/files", nil)
	req.Header.Set("Authorization", "Bearer wrong-secret")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token: status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
}

func TestAuth_HealthBypassesAuth(t *testing.T) {
	srv := setupTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("health: status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestRateLimit_PublicEndpoint(t *testing.T) {
	srv := setupTestServer(t)

	// Upload a file and create a link first (these need auth).
	fileResult := uploadTestFile(t, srv, "ratelimit.txt", "content", "pass")
	fileID := fileResult["id"].(string)
	linkResult := createTestLink(t, srv, fileID, "linkpass", "persistent")
	slug := linkResult["slug"].(string)

	// Exhaust the strict rate limit (20 requests).
	for i := 0; i < 20; i++ {
		body, _ := json.Marshal(map[string]string{"link_password": "wrong"})
		req := httptest.NewRequest(http.MethodPost, "/s/"+slug+"/verify", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "10.0.0.1:1234"
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
	}

	// 21st request should be rate limited.
	body, _ := json.Marshal(map[string]string{"link_password": "wrong"})
	req := httptest.NewRequest(http.MethodPost, "/s/"+slug+"/verify", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "10.0.0.1:1234"
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("rate limit: status = %d, want %d", rec.Code, http.StatusTooManyRequests)
	}
}

func TestAuth_PublicRoutesNoAuth(t *testing.T) {
	srv := setupTestServer(t)
	body, _ := json.Marshal(map[string]string{"link_password": "x"})
	req := httptest.NewRequest(http.MethodPost, "/s/deadbeef/verify", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code == http.StatusUnauthorized {
		t.Fatal("public route should not require auth")
	}
}

// TestSanitizeFilename tests the sanitizeFilename function against various attack vectors.
func TestSanitizeFilename(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"normal", "hello.txt", "hello.txt"},
		{"directory traversal", "../../etc/passwd", "passwd"},
		{"quotes and CRLF injection", "file\"\r\nX-Injected: true", "fileX-Injected: true"},
		{"only dots", "..", "download"},
		{"empty after strip", "", "download"},
		{"single dot", ".", "download"},
		{"nested traversal", "../../../secret.txt", "secret.txt"},
		{"backslash path", `..\..\secret.txt`, "secret.txt"},
		{"quotes only", `"`, "download"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeFilename(tt.input)
			if got != tt.want {
				t.Errorf("sanitizeFilename(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// TestPublicDownload_SanitizesFilename tests that malicious filenames are sanitized
// in the Content-Disposition header to prevent header injection and directory traversal.
func TestPublicDownload_SanitizesFilename(t *testing.T) {
	srv := setupTestServer(t)

	// Upload a file with a filename containing directory traversal characters.
	// Note: \r\n cannot be tested via multipart upload since the encoder rejects them,
	// but sanitizeFilename is tested separately for those in TestSanitizeFilename.
	maliciousName := `../../etc/passwd"`
	fileResult := uploadTestFile(t, srv, maliciousName, "malicious content", "filepass")
	fileID := fileResult["id"].(string)

	linkResult := createTestLink(t, srv, fileID, "linkpass", "persistent")
	slug := linkResult["slug"].(string)

	body, _ := json.Marshal(map[string]string{
		"link_password": "linkpass",
		"file_password": "filepass",
	})
	req := httptest.NewRequest(http.MethodPost, "/s/"+slug+"/download", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("download: status = %d, want %d; body = %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	cd := rec.Header().Get("Content-Disposition")

	// The sanitized header must not contain directory traversal or injection chars.
	if strings.Contains(cd, "..") {
		t.Errorf("Content-Disposition contains '..': %q", cd)
	}
	if strings.Contains(cd, "\r") {
		t.Errorf("Content-Disposition contains '\\r': %q", cd)
	}
	if strings.Contains(cd, "\n") {
		t.Errorf("Content-Disposition contains '\\n': %q", cd)
	}
	if strings.Contains(cd, "etc/passwd") {
		t.Errorf("Content-Disposition contains 'etc/passwd': %q", cd)
	}
	if strings.Contains(cd, "X-Injected") {
		t.Errorf("Content-Disposition contains injected header: %q", cd)
	}
}

// TestSecurityHeaders verifies that all security headers are set on every response.
func TestSecurityHeaders(t *testing.T) {
	srv := setupTestServer(t)

	req := httptest.NewRequest(http.MethodGet, "/api/health", nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}

	expected := map[string]string{
		"X-Frame-Options":           "DENY",
		"X-Content-Type-Options":    "nosniff",
		"Content-Security-Policy":   "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
		"Strict-Transport-Security": "max-age=63072000; includeSubDomains",
		"Referrer-Policy":           "strict-origin-when-cross-origin",
		"Permissions-Policy":        "camera=(), microphone=(), geolocation=()",
	}

	for header, want := range expected {
		got := rec.Header().Get(header)
		if got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
}

// createTestDHTCluster creates a minimal 3-node DHT cluster for testing,
// connects them, and returns the nodes. All nodes are cleaned up at test end.
func createTestDHTCluster(t *testing.T) []*dht.Node {
	t.Helper()
	nodes := make([]*dht.Node, 3)
	for i := range nodes {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("generate key %d: %v", i, err)
		}
		node, err := dht.NewNode(dht.Config{
			PrivateKey: priv,
			PublicKey:  pub,
			K:          20,
			Alpha:      3,
			Port:       0,
			BindAddr:   "127.0.0.1",
		})
		if err != nil {
			t.Fatalf("create DHT node %d: %v", i, err)
		}
		if err := node.Start(); err != nil {
			t.Fatalf("start DHT node %d: %v", i, err)
		}
		nodes[i] = node
		t.Cleanup(func() { node.Close() })
	}
	// Connect nodes in a chain: 0->1, 1->2.
	for i := 1; i < len(nodes); i++ {
		if _, err := nodes[i-1].Ping(nodes[i].Addr()); err != nil {
			t.Fatalf("ping %d->%d: %v", i-1, i, err)
		}
	}
	time.Sleep(500 * time.Millisecond)
	return nodes
}

// TestUploadFile_P2P tests the P2P upload path that distributes via DHT.
func TestUploadFile_P2P(t *testing.T) {
	srv := setupTestServer(t)
	defer srv.Close()

	// Create and attach a DHT cluster.
	nodes := createTestDHTCluster(t)
	srv.SetDHTNode(nodes[0])

	// Build multipart form with storage_mode=p2p.
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	if err := writer.WriteField("password", "testpassword123"); err != nil {
		t.Fatalf("write password: %v", err)
	}
	if err := writer.WriteField("storage_mode", "p2p"); err != nil {
		t.Fatalf("write storage_mode: %v", err)
	}
	part, err := writer.CreateFormFile("file", "p2p-test.txt")
	if err != nil {
		t.Fatalf("create form file: %v", err)
	}
	content := bytes.Repeat([]byte("P2P-TEST-DATA-"), 100) // 1400 bytes
	if _, err := part.Write(content); err != nil {
		t.Fatalf("write file content: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/files", &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer test-secret")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("upload P2P: status = %d, want %d; body = %s", rec.Code, http.StatusCreated, rec.Body.String())
	}

	var result map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&result); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	// Verify response includes P2P fields.
	if result["storage_mode"] != "p2p" {
		t.Errorf("storage_mode = %v, want %q", result["storage_mode"], "p2p")
	}
	shards, ok := result["shards"].(float64)
	if !ok || shards != 6 {
		t.Errorf("shards = %v, want 6", result["shards"])
	}
	if result["id"] == nil || result["id"] == "" {
		t.Error("expected non-empty id")
	}
	if result["name"] != "p2p-test.txt" {
		t.Errorf("name = %v, want %q", result["name"], "p2p-test.txt")
	}

	fileID := result["id"].(string)

	// Verify file metadata appears in the list.
	req = httptest.NewRequest(http.MethodGet, "/api/files", nil)
	req.Header.Set("Authorization", "Bearer test-secret")
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	var files []map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&files); err != nil {
		t.Fatalf("decode file list: %v", err)
	}
	if len(files) != 1 {
		t.Fatalf("file count = %d, want 1", len(files))
	}
	if files[0]["id"] != fileID {
		t.Errorf("listed file id = %v, want %q", files[0]["id"], fileID)
	}

	// Verify blob is empty in SQLite (metadata only, no ciphertext stored).
	storedFile, err := srv.db.GetFile(fileID)
	if err != nil {
		t.Fatalf("GetFile: %v", err)
	}
	if len(storedFile.Blob) > 0 {
		t.Errorf("blob length = %d, want 0 (P2P file should have empty blob)", len(storedFile.Blob))
	}
	if storedFile.Name != "p2p-test.txt" {
		t.Errorf("stored name = %q, want %q", storedFile.Name, "p2p-test.txt")
	}
}

// TestPublicDownload_P2P tests the full P2P download flow: upload via P2P,
// create a link, then download and verify content matches original plaintext.
func TestPublicDownload_P2P(t *testing.T) {
	srv := setupTestServer(t)
	defer srv.Close()

	// Create and attach a DHT cluster.
	nodes := createTestDHTCluster(t)
	srv.SetDHTNode(nodes[0])

	originalContent := "This is secret P2P content for download test."
	filePassword := "p2p-file-pass"
	linkPassword := "p2p-link-pass"

	// Upload a file with storage_mode=p2p.
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	if err := writer.WriteField("password", filePassword); err != nil {
		t.Fatalf("write password: %v", err)
	}
	if err := writer.WriteField("storage_mode", "p2p"); err != nil {
		t.Fatalf("write storage_mode: %v", err)
	}
	part, err := writer.CreateFormFile("file", "p2p-download.txt")
	if err != nil {
		t.Fatalf("create form file: %v", err)
	}
	if _, err := part.Write([]byte(originalContent)); err != nil {
		t.Fatalf("write file content: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/files", &buf)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("Authorization", "Bearer test-secret")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("upload P2P: status = %d, want %d; body = %s", rec.Code, http.StatusCreated, rec.Body.String())
	}

	var uploadResult map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&uploadResult); err != nil {
		t.Fatalf("decode upload response: %v", err)
	}
	fileID := uploadResult["id"].(string)
	if uploadResult["storage_mode"] != "p2p" {
		t.Fatalf("storage_mode = %v, want %q", uploadResult["storage_mode"], "p2p")
	}

	// Verify blob is empty in SQLite.
	storedFile, err := srv.db.GetFile(fileID)
	if err != nil {
		t.Fatalf("GetFile: %v", err)
	}
	if len(storedFile.Blob) > 0 {
		t.Fatalf("blob should be empty for P2P file, got %d bytes", len(storedFile.Blob))
	}

	// Create a link for the file.
	linkResult := createTestLink(t, srv, fileID, linkPassword, "persistent")
	slug := linkResult["slug"].(string)

	// Download via the public endpoint with both link and file passwords.
	body, _ := json.Marshal(map[string]string{
		"link_password": linkPassword,
		"file_password": filePassword,
	})
	req = httptest.NewRequest(http.MethodPost, "/s/"+slug+"/download", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("P2P download: status = %d, want %d; body = %s", rec.Code, http.StatusOK, rec.Body.String())
	}

	downloaded, err := io.ReadAll(rec.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	if string(downloaded) != originalContent {
		t.Errorf("content = %q, want %q", string(downloaded), originalContent)
	}

	// Check Content-Disposition header.
	cd := rec.Header().Get("Content-Disposition")
	if !strings.Contains(cd, "p2p-download.txt") {
		t.Errorf("Content-Disposition = %q, want to contain %q", cd, "p2p-download.txt")
	}
}
