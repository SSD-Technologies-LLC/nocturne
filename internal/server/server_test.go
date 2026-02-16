package server

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

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
