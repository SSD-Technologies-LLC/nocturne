package mesh

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestTracker_RegisterAndOnline(t *testing.T) {
	tracker := NewTracker()

	node := &NodeInfo{
		ID:         "node-1",
		Address:    "127.0.0.1:8080",
		MaxStorage: 1024 * 1024,
	}
	tracker.Register(node)

	online := tracker.OnlineNodes()
	if len(online) != 1 {
		t.Fatalf("expected 1 online node, got %d", len(online))
	}
	if online[0].ID != "node-1" {
		t.Fatalf("expected node ID node-1, got %s", online[0].ID)
	}
	if !online[0].Online {
		t.Fatal("expected node to be online")
	}
}

func TestTracker_Heartbeat(t *testing.T) {
	tracker := NewTracker()

	node := &NodeInfo{
		ID:         "node-1",
		Address:    "127.0.0.1:8080",
		MaxStorage: 1024 * 1024,
	}
	tracker.Register(node)

	before := node.LastSeen
	time.Sleep(10 * time.Millisecond)
	tracker.Heartbeat("node-1")

	tracker.mu.RLock()
	after := tracker.nodes["node-1"].LastSeen
	tracker.mu.RUnlock()

	if !after.After(before) {
		t.Fatal("expected LastSeen to be updated after heartbeat")
	}
}

func TestTracker_Unregister(t *testing.T) {
	tracker := NewTracker()

	node := &NodeInfo{
		ID:         "node-1",
		Address:    "127.0.0.1:8080",
		MaxStorage: 1024 * 1024,
	}
	tracker.Register(node)
	tracker.Unregister("node-1")

	online := tracker.OnlineNodes()
	if len(online) != 0 {
		t.Fatalf("expected 0 online nodes after unregister, got %d", len(online))
	}
}

func TestTracker_PruneOffline(t *testing.T) {
	tracker := NewTracker()

	node := &NodeInfo{
		ID:         "node-1",
		Address:    "127.0.0.1:8080",
		MaxStorage: 1024 * 1024,
	}
	tracker.Register(node)

	// Set LastSeen to the past.
	tracker.mu.Lock()
	tracker.nodes["node-1"].LastSeen = time.Now().Add(-2 * time.Minute)
	tracker.mu.Unlock()

	tracker.PruneOffline(60 * time.Second)

	online := tracker.OnlineNodes()
	if len(online) != 0 {
		t.Fatalf("expected 0 online nodes after prune, got %d", len(online))
	}

	// Verify node still exists but is offline.
	tracker.mu.RLock()
	n, ok := tracker.nodes["node-1"]
	tracker.mu.RUnlock()
	if !ok {
		t.Fatal("expected node to still exist in tracker")
	}
	if n.Online {
		t.Fatal("expected node to be offline after prune")
	}
}

func TestTracker_AssignShard(t *testing.T) {
	tracker := NewTracker()

	// Register two nodes with different storage usage.
	tracker.Register(&NodeInfo{
		ID:          "node-1",
		Address:     "127.0.0.1:8080",
		MaxStorage:  1024 * 1024,
		UsedStorage: 500 * 1024, // more loaded
	})
	tracker.Register(&NodeInfo{
		ID:          "node-2",
		Address:     "127.0.0.1:8081",
		MaxStorage:  1024 * 1024,
		UsedStorage: 100 * 1024, // less loaded
	})

	shard := &ShardInfo{
		ID:         "shard-1",
		FileID:     "file-1",
		ShardIndex: 0,
		Size:       1024,
		Checksum:   "abc123",
	}

	if err := tracker.AssignShard(shard); err != nil {
		t.Fatalf("unexpected error assigning shard: %v", err)
	}

	if shard.NodeID != "node-2" {
		t.Fatalf("expected shard assigned to least-loaded node-2, got %s", shard.NodeID)
	}
}

func TestTracker_AssignShard_NoNode(t *testing.T) {
	tracker := NewTracker()

	shard := &ShardInfo{
		ID:         "shard-1",
		FileID:     "file-1",
		ShardIndex: 0,
		Size:       1024,
	}

	err := tracker.AssignShard(shard)
	if err == nil {
		t.Fatal("expected error when no nodes available")
	}
}

func TestTracker_GetShardsForFile(t *testing.T) {
	tracker := NewTracker()

	tracker.Register(&NodeInfo{
		ID:         "node-1",
		Address:    "127.0.0.1:8080",
		MaxStorage: 1024 * 1024,
	})

	shards := []*ShardInfo{
		{ID: "s1", FileID: "file-1", ShardIndex: 0, Size: 100, Checksum: "a"},
		{ID: "s2", FileID: "file-1", ShardIndex: 1, Size: 100, Checksum: "b"},
		{ID: "s3", FileID: "file-2", ShardIndex: 0, Size: 100, Checksum: "c"},
	}
	for _, s := range shards {
		if err := tracker.AssignShard(s); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}

	file1Shards := tracker.GetShardsForFile("file-1")
	if len(file1Shards) != 2 {
		t.Fatalf("expected 2 shards for file-1, got %d", len(file1Shards))
	}

	file2Shards := tracker.GetShardsForFile("file-2")
	if len(file2Shards) != 1 {
		t.Fatalf("expected 1 shard for file-2, got %d", len(file2Shards))
	}
}

func TestTracker_RemoveShards(t *testing.T) {
	tracker := NewTracker()

	tracker.Register(&NodeInfo{
		ID:         "node-1",
		Address:    "127.0.0.1:8080",
		MaxStorage: 1024 * 1024,
	})

	s := &ShardInfo{ID: "s1", FileID: "file-1", ShardIndex: 0, Size: 100, Checksum: "a"}
	if err := tracker.AssignShard(s); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tracker.RemoveShards("file-1")

	shards := tracker.GetShardsForFile("file-1")
	if len(shards) != 0 {
		t.Fatalf("expected 0 shards after removal, got %d", len(shards))
	}

	// Verify storage reclaimed.
	tracker.mu.RLock()
	used := tracker.nodes["node-1"].UsedStorage
	tracker.mu.RUnlock()
	if used != 0 {
		t.Fatalf("expected 0 used storage after shard removal, got %d", used)
	}
}

func TestTracker_Stats(t *testing.T) {
	tracker := NewTracker()

	tracker.Register(&NodeInfo{
		ID:          "node-1",
		Address:     "127.0.0.1:8080",
		MaxStorage:  1024 * 1024,
		UsedStorage: 100,
	})
	tracker.Register(&NodeInfo{
		ID:          "node-2",
		Address:     "127.0.0.1:8081",
		MaxStorage:  2048 * 1024,
		UsedStorage: 200,
	})

	// Mark node-2 as offline.
	tracker.mu.Lock()
	tracker.nodes["node-2"].Online = false
	tracker.mu.Unlock()

	stats := tracker.Stats()

	if stats.NodesTotal != 2 {
		t.Fatalf("expected 2 total nodes, got %d", stats.NodesTotal)
	}
	if stats.NodesOnline != 1 {
		t.Fatalf("expected 1 online node, got %d", stats.NodesOnline)
	}
	if stats.TotalStorage != 1024*1024+2048*1024 {
		t.Fatalf("unexpected total storage: %d", stats.TotalStorage)
	}
	if stats.UsedStorage != 300 {
		t.Fatalf("expected 300 used storage, got %d", stats.UsedStorage)
	}
}

// WebSocket tests

func setupWSTest(t *testing.T) (*Tracker, *websocket.Conn, *httptest.Server) {
	t.Helper()
	tracker := NewTracker()
	server := httptest.NewServer(HandleWebSocket(tracker))
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
	conn, resp, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("failed to connect websocket: %v", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("expected status 101, got %d", resp.StatusCode)
	}
	return tracker, conn, server
}

func sendWSMessage(t *testing.T, conn *websocket.Conn, msgType string, payload interface{}) {
	t.Helper()
	p, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("failed to marshal payload: %v", err)
	}
	msg := WSMessage{
		Type:    msgType,
		Payload: json.RawMessage(p),
	}
	if err := conn.WriteJSON(msg); err != nil {
		t.Fatalf("failed to write message: %v", err)
	}
}

func readWSResponse(t *testing.T, conn *websocket.Conn) WSResponse {
	t.Helper()
	var resp WSResponse
	if err := conn.ReadJSON(&resp); err != nil {
		t.Fatalf("failed to read response: %v", err)
	}
	return resp
}

func TestWS_Register(t *testing.T) {
	tracker, conn, server := setupWSTest(t)
	defer server.Close()
	defer conn.Close()

	sendWSMessage(t, conn, "register", RegisterPayload{
		ID:         "ws-node-1",
		Address:    "127.0.0.1:9090",
		MaxStorage: 1024 * 1024,
	})

	resp := readWSResponse(t, conn)
	if resp.Type != "registered" {
		t.Fatalf("expected registered response, got %s", resp.Type)
	}

	online := tracker.OnlineNodes()
	if len(online) != 1 {
		t.Fatalf("expected 1 online node, got %d", len(online))
	}
	if online[0].ID != "ws-node-1" {
		t.Fatalf("expected node ID ws-node-1, got %s", online[0].ID)
	}
}

func TestWS_Heartbeat(t *testing.T) {
	tracker, conn, server := setupWSTest(t)
	defer server.Close()
	defer conn.Close()

	sendWSMessage(t, conn, "register", RegisterPayload{
		ID:         "ws-node-1",
		Address:    "127.0.0.1:9090",
		MaxStorage: 1024 * 1024,
	})
	_ = readWSResponse(t, conn) // consume registered response

	time.Sleep(10 * time.Millisecond)

	tracker.mu.RLock()
	before := tracker.nodes["ws-node-1"].LastSeen
	tracker.mu.RUnlock()

	time.Sleep(10 * time.Millisecond)
	sendWSMessage(t, conn, "heartbeat", map[string]string{})
	resp := readWSResponse(t, conn)

	if resp.Type != "heartbeat_ack" {
		t.Fatalf("expected heartbeat_ack, got %s", resp.Type)
	}

	tracker.mu.RLock()
	after := tracker.nodes["ws-node-1"].LastSeen
	tracker.mu.RUnlock()

	if !after.After(before) {
		t.Fatal("expected LastSeen updated after heartbeat")
	}
}

func TestWS_Disconnect(t *testing.T) {
	tracker, conn, server := setupWSTest(t)
	defer server.Close()
	defer conn.Close()

	sendWSMessage(t, conn, "register", RegisterPayload{
		ID:         "ws-node-1",
		Address:    "127.0.0.1:9090",
		MaxStorage: 1024 * 1024,
	})
	_ = readWSResponse(t, conn) // consume registered response

	sendWSMessage(t, conn, "disconnect", map[string]string{})
	resp := readWSResponse(t, conn)
	if resp.Type != "disconnected" {
		t.Fatalf("expected disconnected, got %s", resp.Type)
	}

	online := tracker.OnlineNodes()
	if len(online) != 0 {
		t.Fatalf("expected 0 online nodes after disconnect, got %d", len(online))
	}
}

func TestWS_ConnectionClose(t *testing.T) {
	tracker, conn, server := setupWSTest(t)
	defer server.Close()

	sendWSMessage(t, conn, "register", RegisterPayload{
		ID:         "ws-node-1",
		Address:    "127.0.0.1:9090",
		MaxStorage: 1024 * 1024,
	})
	_ = readWSResponse(t, conn)

	// Close the connection abruptly.
	conn.Close()

	// Give the server time to process the close.
	time.Sleep(100 * time.Millisecond)

	online := tracker.OnlineNodes()
	if len(online) != 0 {
		t.Fatalf("expected 0 online nodes after connection close, got %d", len(online))
	}
}
