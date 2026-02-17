package dht

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestLocalAPIHealth(t *testing.T) {
	nodes := testNodes(t, 1)
	api := NewLocalAPI(nodes[0])
	srv := httptest.NewServer(api.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/local/health")
	if err != nil {
		t.Fatalf("GET /local/health: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var body map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if body["status"] != "ok" {
		t.Fatalf("expected status=ok, got %v", body["status"])
	}
	if body["node_id"] == nil || body["node_id"] == "" {
		t.Fatal("expected non-empty node_id")
	}
	// peers should be a number (0 for a lone node)
	if _, ok := body["peers"]; !ok {
		t.Fatal("expected peers field in health response")
	}
}

func TestLocalAPIKnowledgeCRUD(t *testing.T) {
	nodes := testNodes(t, 1)
	node := nodes[0]
	api := NewLocalAPI(node)
	srv := httptest.NewServer(api.Handler())
	defer srv.Close()

	// 1. Publish knowledge via POST /local/knowledge
	entry := KnowledgeEntry{
		ID:         "test-entry-1",
		AgentID:    "agent-1",
		OperatorID: "op-1",
		Type:       "fact",
		Domain:     "testing",
		Content:    "Unit tests are important",
		Confidence: 0.95,
		CreatedAt:  time.Now().Unix(),
		Signature:  "test-sig",
	}
	body, _ := json.Marshal(entry)
	resp, err := http.Post(srv.URL+"/local/knowledge", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /local/knowledge: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST knowledge: expected 200, got %d", resp.StatusCode)
	}

	// Allow time for local storage.
	time.Sleep(100 * time.Millisecond)

	// 2. Query knowledge via GET /local/knowledge?domain=testing
	resp, err = http.Get(srv.URL + "/local/knowledge?domain=testing")
	if err != nil {
		t.Fatalf("GET /local/knowledge: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET knowledge: expected 200, got %d", resp.StatusCode)
	}

	var results []KnowledgeEntry
	if err := json.NewDecoder(resp.Body).Decode(&results); err != nil {
		t.Fatalf("decode knowledge results: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].ID != "test-entry-1" {
		t.Fatalf("expected entry ID test-entry-1, got %s", results[0].ID)
	}
	if results[0].Content != "Unit tests are important" {
		t.Fatalf("unexpected content: %s", results[0].Content)
	}

	// 3. Delete knowledge via DELETE /local/knowledge/test-entry-1?domain=testing
	req, _ := http.NewRequest(http.MethodDelete, srv.URL+"/local/knowledge/test-entry-1?domain=testing", nil)
	dresp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("DELETE /local/knowledge: %v", err)
	}
	dresp.Body.Close()
	if dresp.StatusCode != http.StatusOK {
		t.Fatalf("DELETE knowledge: expected 200, got %d", dresp.StatusCode)
	}

	time.Sleep(100 * time.Millisecond)

	// 4. Query again — should be empty.
	resp2, err := http.Get(srv.URL + "/local/knowledge?domain=testing")
	if err != nil {
		t.Fatalf("GET /local/knowledge after delete: %v", err)
	}
	defer resp2.Body.Close()

	var results2 []KnowledgeEntry
	json.NewDecoder(resp2.Body).Decode(&results2)
	if len(results2) != 0 {
		t.Fatalf("expected 0 results after delete, got %d", len(results2))
	}
}

func TestLocalAPIPeers(t *testing.T) {
	nodes := testNodes(t, 2)
	a, b := nodes[0], nodes[1]

	// Connect A to B.
	if _, err := a.Ping(b.Addr()); err != nil {
		t.Fatalf("ping: %v", err)
	}
	waitForTableSize(t, a, 1, 2*time.Second)

	api := NewLocalAPI(a)
	srv := httptest.NewServer(api.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/local/peers")
	if err != nil {
		t.Fatalf("GET /local/peers: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var body struct {
		Peers []struct {
			ID      string `json:"id"`
			Address string `json:"address"`
		} `json:"peers"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode peers: %v", err)
	}

	if len(body.Peers) < 1 {
		t.Fatalf("expected at least 1 peer, got %d", len(body.Peers))
	}

	// Verify that B is in the peer list.
	bID := b.ID()
	bIDHex := hex.EncodeToString(bID[:])
	found := false
	for _, p := range body.Peers {
		if p.ID == bIDHex {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected peer B (%s) in peer list, got %v", bIDHex, body.Peers)
	}
}

func TestLocalAPIComputeTask(t *testing.T) {
	nodes := testNodes(t, 1)
	node := nodes[0]
	api := NewLocalAPI(node)
	srv := httptest.NewServer(api.Handler())
	defer srv.Close()

	// 1. Publish a task directly on the node.
	task := &ComputeTask{
		ID:          "task-api-001",
		Type:        "verify",
		Domain:      "security",
		Description: "Verify file integrity",
		Priority:    7,
	}
	if err := node.PublishTask(task); err != nil {
		t.Fatalf("PublishTask: %v", err)
	}

	time.Sleep(100 * time.Millisecond)

	// 2. GET /local/compute — list tasks.
	resp, err := http.Get(srv.URL + "/local/compute")
	if err != nil {
		t.Fatalf("GET /local/compute: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list tasks: expected 200, got %d", resp.StatusCode)
	}

	var tasks []ComputeTask
	if err := json.NewDecoder(resp.Body).Decode(&tasks); err != nil {
		t.Fatalf("decode tasks: %v", err)
	}
	if len(tasks) != 1 {
		t.Fatalf("expected 1 task, got %d", len(tasks))
	}
	if tasks[0].ID != "task-api-001" {
		t.Fatalf("expected task ID task-api-001, got %s", tasks[0].ID)
	}

	// 3. POST /local/compute/claim — claim the task.
	claimBody, _ := json.Marshal(map[string]string{
		"task_id":  "task-api-001",
		"agent_id": "agent-tester",
	})
	claimResp, err := http.Post(srv.URL+"/local/compute/claim", "application/json", bytes.NewReader(claimBody))
	if err != nil {
		t.Fatalf("POST /local/compute/claim: %v", err)
	}
	defer claimResp.Body.Close()

	if claimResp.StatusCode != http.StatusOK {
		t.Fatalf("claim task: expected 200, got %d", claimResp.StatusCode)
	}

	var claimed ComputeTask
	if err := json.NewDecoder(claimResp.Body).Decode(&claimed); err != nil {
		t.Fatalf("decode claimed task: %v", err)
	}
	if claimed.ClaimedBy != "agent-tester" {
		t.Fatalf("expected claimed_by=agent-tester, got %s", claimed.ClaimedBy)
	}

	time.Sleep(100 * time.Millisecond)

	// 4. POST /local/compute/task-api-001/result — submit result.
	resultBody, _ := json.Marshal(map[string]string{
		"result_id": "result-xyz",
	})
	resultResp, err := http.Post(
		srv.URL+"/local/compute/task-api-001/result",
		"application/json",
		bytes.NewReader(resultBody),
	)
	if err != nil {
		t.Fatalf("POST /local/compute/{id}/result: %v", err)
	}
	defer resultResp.Body.Close()

	if resultResp.StatusCode != http.StatusOK {
		t.Fatalf("submit result: expected 200, got %d", resultResp.StatusCode)
	}

	time.Sleep(100 * time.Millisecond)

	// 5. Verify task is completed via list.
	resp2, err := http.Get(srv.URL + "/local/compute")
	if err != nil {
		t.Fatalf("GET /local/compute after result: %v", err)
	}
	defer resp2.Body.Close()

	var tasks2 []ComputeTask
	json.NewDecoder(resp2.Body).Decode(&tasks2)
	if len(tasks2) != 1 {
		t.Fatalf("expected 1 task, got %d", len(tasks2))
	}
	if !tasks2[0].Completed {
		t.Fatal("expected task to be completed")
	}
	if tasks2[0].ResultID != "result-xyz" {
		t.Fatalf("expected result_id=result-xyz, got %s", tasks2[0].ResultID)
	}
}

func TestLocalAPIAwareness(t *testing.T) {
	nodes := testNodes(t, 1)
	node := nodes[0]
	api := NewLocalAPI(node)
	srv := httptest.NewServer(api.Handler())
	defer srv.Close()

	// 1. POST /local/awareness — store a snapshot.
	snapshot := map[string]interface{}{
		"id":             "agent-abc",
		"status":         "active",
		"capabilities":   []string{"verify", "summarize"},
		"load":           0.42,
		"last_heartbeat": time.Now().Unix(),
	}
	body, _ := json.Marshal(snapshot)
	resp, err := http.Post(srv.URL+"/local/awareness", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /local/awareness: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST awareness: expected 200, got %d", resp.StatusCode)
	}

	time.Sleep(100 * time.Millisecond)

	// 2. GET /local/awareness?id=agent-abc — retrieve the snapshot.
	resp2, err := http.Get(srv.URL + "/local/awareness?id=agent-abc")
	if err != nil {
		t.Fatalf("GET /local/awareness: %v", err)
	}
	defer resp2.Body.Close()

	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("GET awareness: expected 200, got %d", resp2.StatusCode)
	}

	var retrieved map[string]interface{}
	if err := json.NewDecoder(resp2.Body).Decode(&retrieved); err != nil {
		t.Fatalf("decode awareness: %v", err)
	}
	if retrieved["id"] != "agent-abc" {
		t.Fatalf("expected id=agent-abc, got %v", retrieved["id"])
	}
	if retrieved["status"] != "active" {
		t.Fatalf("expected status=active, got %v", retrieved["status"])
	}
	if fmt.Sprintf("%v", retrieved["load"]) != "0.42" {
		t.Fatalf("expected load=0.42, got %v", retrieved["load"])
	}
}

func TestLocalAPIFileUpload(t *testing.T) {
	nodes := testNodes(t, 3)
	for i := 1; i < len(nodes); i++ {
		nodes[i-1].Ping(nodes[i].Addr())
	}
	time.Sleep(300 * time.Millisecond)

	api := NewLocalAPI(nodes[0])
	srv := httptest.NewServer(api.Handler())
	defer srv.Close()

	body := map[string]interface{}{
		"file_id":       "api-file-001",
		"file_name":     "test.txt",
		"file_size":     1000,
		"cipher":        "aes-256-gcm",
		"salt":          base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")),
		"nonce":         base64.StdEncoding.EncodeToString([]byte("0123456789ab")),
		"ciphertext":    base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("X"), 1000)),
		"data_shards":   4,
		"parity_shards": 2,
		"operator_id":   "op-1",
	}
	data, _ := json.Marshal(body)
	resp, err := http.Post(srv.URL+"/local/files", "application/json", bytes.NewReader(data))
	if err != nil {
		t.Fatalf("POST /local/files: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, respBody)
	}
}

func TestLocalAPIFileList(t *testing.T) {
	nodes := testNodes(t, 3)
	for i := 1; i < len(nodes); i++ {
		nodes[i-1].Ping(nodes[i].Addr())
	}
	time.Sleep(300 * time.Millisecond)

	api := NewLocalAPI(nodes[0])
	srv := httptest.NewServer(api.Handler())
	defer srv.Close()

	ciphertext := bytes.Repeat([]byte("Y"), 500)
	nodes[0].DistributeFile(DistributeFileParams{
		FileID: "list-file-001", FileName: "list.txt", FileSize: 500,
		Cipher: "aes-256-gcm", Salt: make([]byte, 32), Nonce: make([]byte, 12),
		Ciphertext: ciphertext, DataShards: 4, ParityShards: 2, OperatorID: "op-1",
	})
	time.Sleep(300 * time.Millisecond)

	resp, err := http.Get(srv.URL + "/local/files?operator_id=op-1")
	if err != nil {
		t.Fatalf("GET /local/files: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var result FileIndex
	json.NewDecoder(resp.Body).Decode(&result)
	if len(result.FileIDs) < 1 {
		t.Fatal("expected at least 1 file in index")
	}
}

func TestLocalAPIFileManifest(t *testing.T) {
	nodes := testNodes(t, 3)
	for i := 1; i < len(nodes); i++ {
		nodes[i-1].Ping(nodes[i].Addr())
	}
	time.Sleep(300 * time.Millisecond)

	ciphertext := bytes.Repeat([]byte("Z"), 800)
	nodes[0].DistributeFile(DistributeFileParams{
		FileID: "dl-file-001", FileName: "download.bin", FileSize: int64(len(ciphertext)),
		Cipher: "aes-256-gcm", Salt: make([]byte, 32), Nonce: make([]byte, 12),
		Ciphertext: ciphertext, DataShards: 4, ParityShards: 2, OperatorID: "op-1",
	})
	time.Sleep(500 * time.Millisecond)

	api := NewLocalAPI(nodes[1])
	srv := httptest.NewServer(api.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/local/files/dl-file-001")
	if err != nil {
		t.Fatalf("GET /local/files/dl-file-001: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
}

func TestLocalAPIFileDownload(t *testing.T) {
	nodes := testNodes(t, 3)
	for i := 1; i < len(nodes); i++ {
		nodes[i-1].Ping(nodes[i].Addr())
	}
	time.Sleep(300 * time.Millisecond)

	ciphertext := bytes.Repeat([]byte("Z"), 800)
	nodes[0].DistributeFile(DistributeFileParams{
		FileID: "dl-file-002", FileName: "download.bin", FileSize: int64(len(ciphertext)),
		Cipher: "aes-256-gcm", Salt: make([]byte, 32), Nonce: make([]byte, 12),
		Ciphertext: ciphertext, DataShards: 4, ParityShards: 2, OperatorID: "op-1",
	})
	time.Sleep(500 * time.Millisecond)

	api := NewLocalAPI(nodes[1])
	srv := httptest.NewServer(api.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/local/files/dl-file-002/data")
	if err != nil {
		t.Fatalf("GET /local/files/dl-file-002/data: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, body)
	}

	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	if !bytes.Equal(got, ciphertext) {
		t.Fatalf("response body mismatch: got %d bytes, want %d bytes", len(got), len(ciphertext))
	}
}
