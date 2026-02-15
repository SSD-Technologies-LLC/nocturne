// cmd/nocturne-node/main.go
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"github.com/ssd-technologies/nocturne/internal/mesh"
)

const (
	defaultMaxStorage = 10 * 1024 * 1024 * 1024 // 10GB
	heartbeatInterval = 30 * time.Second
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: nocturne-node <connect|disconnect|status>")
		os.Exit(1)
	}

	switch os.Args[1] {
	case "connect":
		cmdConnect()
	case "disconnect":
		cmdDisconnect()
	case "status":
		cmdStatus()
	default:
		fmt.Printf("Unknown command: %s\n", os.Args[1])
		fmt.Println("Usage: nocturne-node <connect|disconnect|status>")
		os.Exit(1)
	}
}

func nocturneDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: cannot determine home directory: %v\n", err)
		os.Exit(1)
	}
	return filepath.Join(home, ".nocturne")
}

func parseMaxStorage(args []string) int64 {
	for i, arg := range args {
		if arg == "--max-storage" && i+1 < len(args) {
			return parseStorageSize(args[i+1])
		}
		if strings.HasPrefix(arg, "--max-storage=") {
			return parseStorageSize(strings.TrimPrefix(arg, "--max-storage="))
		}
	}
	return defaultMaxStorage
}

func parseStorageSize(s string) int64 {
	s = strings.TrimSpace(s)
	s = strings.ToUpper(s)

	multiplier := int64(1)
	if strings.HasSuffix(s, "GB") {
		multiplier = 1024 * 1024 * 1024
		s = strings.TrimSuffix(s, "GB")
	} else if strings.HasSuffix(s, "MB") {
		multiplier = 1024 * 1024
		s = strings.TrimSuffix(s, "MB")
	} else if strings.HasSuffix(s, "KB") {
		multiplier = 1024
		s = strings.TrimSuffix(s, "KB")
	}

	n, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid storage size: %s\n", s)
		os.Exit(1)
	}
	return n * multiplier
}

func parseTrackerURL(args []string) string {
	for i, arg := range args {
		if arg == "--tracker" && i+1 < len(args) {
			return args[i+1]
		}
		if strings.HasPrefix(arg, "--tracker=") {
			return strings.TrimPrefix(arg, "--tracker=")
		}
	}
	url := os.Getenv("NOCTURNE_TRACKER")
	if url == "" {
		fmt.Fprintln(os.Stderr, "Error: set NOCTURNE_TRACKER environment variable")
		os.Exit(1)
	}
	return url
}

func loadOrGenerateKeypair(keyPath string) (ed25519.PublicKey, ed25519.PrivateKey) {
	data, err := os.ReadFile(keyPath)
	if err == nil && len(data) == ed25519.SeedSize {
		priv := ed25519.NewKeyFromSeed(data)
		pub := priv.Public().(ed25519.PublicKey)
		return pub, priv
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: generating keypair: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(keyPath, priv.Seed(), 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Error: writing keypair: %v\n", err)
		os.Exit(1)
	}
	return pub, priv
}

func nodeIDFromPublicKey(pub ed25519.PublicKey) string {
	// Use first 8 bytes of public key as hex node ID.
	return fmt.Sprintf("%x", pub[:8])
}

type nodeStats struct {
	NodeID        string `json:"node_id"`
	UptimeSeconds int64  `json:"uptime_seconds"`
	ShardsStored  int    `json:"shards_stored"`
	StorageUsed   int64  `json:"storage_used"`
	MaxStorage    int64  `json:"max_storage"`
}

func cmdConnect() {
	dir := nocturneDir()
	pidFile := filepath.Join(dir, "node.pid")
	keyFile := filepath.Join(dir, "node.key")
	shardsDir := filepath.Join(dir, "shards")
	statsFile := filepath.Join(dir, "stats.json")

	// 1. Check if already running.
	if pidData, err := os.ReadFile(pidFile); err == nil {
		pid, err := strconv.Atoi(strings.TrimSpace(string(pidData)))
		if err == nil {
			if process, err := os.FindProcess(pid); err == nil {
				// On Unix, FindProcess always succeeds. Check if process is alive.
				if err := process.Signal(syscall.Signal(0)); err == nil {
					fmt.Fprintf(os.Stderr, "Error: node already running (PID %d)\n", pid)
					os.Exit(1)
				}
			}
		}
	}

	// 2. Create directories.
	if err := os.MkdirAll(shardsDir, 0700); err != nil {
		fmt.Fprintf(os.Stderr, "Error: creating directories: %v\n", err)
		os.Exit(1)
	}

	// 3. Load or generate keypair.
	pub, _ := loadOrGenerateKeypair(keyFile)
	nodeID := nodeIDFromPublicKey(pub)

	// 4. Parse arguments.
	maxStorage := parseMaxStorage(os.Args[2:])
	trackerURL := parseTrackerURL(os.Args[2:])

	// 5. Start shard HTTP server on random port.
	shardHandler := http.NewServeMux()
	shardHandler.HandleFunc("/shard/", func(w http.ResponseWriter, r *http.Request) {
		shardID := strings.TrimPrefix(r.URL.Path, "/shard/")
		if shardID == "" {
			http.Error(w, "shard ID required", http.StatusBadRequest)
			return
		}
		shardPath := filepath.Join(shardsDir, shardID)
		data, err := os.ReadFile(shardPath)
		if err != nil {
			http.Error(w, "shard not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(data)
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: starting shard server: %v\n", err)
		os.Exit(1)
	}
	shardAddr := listener.Addr().String()

	go http.Serve(listener, shardHandler)

	// 6. Connect to tracker via WebSocket.
	conn, _, err := websocket.DefaultDialer.Dial(trackerURL, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: connecting to tracker: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	// 7. Send register message.
	regPayload, _ := json.Marshal(mesh.RegisterPayload{
		ID:         nodeID,
		Address:    shardAddr,
		PublicKey:  pub,
		MaxStorage: maxStorage,
	})
	regMsg := mesh.WSMessage{
		Type:    "register",
		Payload: json.RawMessage(regPayload),
	}
	if err := conn.WriteJSON(regMsg); err != nil {
		fmt.Fprintf(os.Stderr, "Error: sending register message: %v\n", err)
		os.Exit(1)
	}

	// Read register response.
	var resp mesh.WSResponse
	if err := conn.ReadJSON(&resp); err != nil {
		fmt.Fprintf(os.Stderr, "Error: reading register response: %v\n", err)
		os.Exit(1)
	}
	if resp.Type != "registered" {
		fmt.Fprintf(os.Stderr, "Error: unexpected response: %s\n", resp.Type)
		os.Exit(1)
	}

	// 8. Write PID file.
	if err := os.WriteFile(pidFile, []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
		fmt.Fprintf(os.Stderr, "Error: writing PID file: %v\n", err)
		os.Exit(1)
	}

	startTime := time.Now()

	fmt.Printf("Connected to Nocturne mesh. Node ID: %s\n", nodeID)
	fmt.Printf("Shard server listening on %s\n", shardAddr)

	// 9. Start heartbeat loop.
	heartbeatDone := make(chan struct{})
	go func() {
		defer close(heartbeatDone)
		ticker := time.NewTicker(heartbeatInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				hbPayload, _ := json.Marshal(map[string]string{})
				hbMsg := mesh.WSMessage{
					Type:    "heartbeat",
					Payload: json.RawMessage(hbPayload),
				}
				if err := conn.WriteJSON(hbMsg); err != nil {
					return
				}
			case <-heartbeatDone:
				return
			}
		}
	}()

	// 10. Write stats periodically.
	statsDone := make(chan struct{})
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				shardsStored := countShards(shardsDir)
				storageUsed := dirSize(shardsDir)
				stats := nodeStats{
					NodeID:        nodeID,
					UptimeSeconds: int64(time.Since(startTime).Seconds()),
					ShardsStored:  shardsStored,
					StorageUsed:   storageUsed,
					MaxStorage:    maxStorage,
				}
				data, _ := json.Marshal(stats)
				_ = os.WriteFile(statsFile, data, 0600)
			case <-statsDone:
				return
			}
		}
	}()

	// 11. Block until signal.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	fmt.Println("\nShutting down...")

	// Send disconnect.
	discPayload, _ := json.Marshal(map[string]string{})
	discMsg := mesh.WSMessage{
		Type:    "disconnect",
		Payload: json.RawMessage(discPayload),
	}
	_ = conn.WriteJSON(discMsg)

	// Write final stats.
	shardsStored := countShards(shardsDir)
	storageUsed := dirSize(shardsDir)
	stats := nodeStats{
		NodeID:        nodeID,
		UptimeSeconds: int64(time.Since(startTime).Seconds()),
		ShardsStored:  shardsStored,
		StorageUsed:   storageUsed,
		MaxStorage:    maxStorage,
	}
	data, _ := json.Marshal(stats)
	_ = os.WriteFile(statsFile, data, 0600)

	// Cleanup.
	close(statsDone)
	listener.Close()
	os.Remove(pidFile)

	fmt.Println("Disconnected from Nocturne mesh.")
}

func cmdDisconnect() {
	dir := nocturneDir()
	pidFile := filepath.Join(dir, "node.pid")

	pidData, err := os.ReadFile(pidFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error: no running node found (missing PID file)")
		os.Exit(1)
	}

	pid, err := strconv.Atoi(strings.TrimSpace(string(pidData)))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: invalid PID file: %v\n", err)
		os.Exit(1)
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: finding process %d: %v\n", pid, err)
		os.Exit(1)
	}

	if err := process.Signal(syscall.SIGTERM); err != nil {
		fmt.Fprintf(os.Stderr, "Error: sending signal to process %d: %v\n", pid, err)
		os.Exit(1)
	}

	fmt.Println("Disconnected from Nocturne mesh.")
}

func cmdStatus() {
	dir := nocturneDir()
	statsFile := filepath.Join(dir, "stats.json")

	data, err := os.ReadFile(statsFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error: no stats available (node may not be running)")
		os.Exit(1)
	}

	var stats nodeStats
	if err := json.Unmarshal(data, &stats); err != nil {
		fmt.Fprintf(os.Stderr, "Error: reading stats: %v\n", err)
		os.Exit(1)
	}

	// Check if node is still running.
	pidFile := filepath.Join(dir, "node.pid")
	online := false
	if pidData, err := os.ReadFile(pidFile); err == nil {
		pid, err := strconv.Atoi(strings.TrimSpace(string(pidData)))
		if err == nil {
			if process, err := os.FindProcess(pid); err == nil {
				if err := process.Signal(syscall.Signal(0)); err == nil {
					online = true
				}
			}
		}
	}

	statusStr := "offline"
	if online {
		statusStr = "online"
	}

	fmt.Printf("Node ID:       %s\n", stats.NodeID)
	fmt.Printf("Status:        %s\n", statusStr)
	fmt.Printf("Uptime:        %s\n", formatDuration(time.Duration(stats.UptimeSeconds)*time.Second))
	fmt.Printf("Shards stored: %d\n", stats.ShardsStored)
	fmt.Printf("Storage:       %s / %s\n", formatBytes(stats.StorageUsed), formatBytes(stats.MaxStorage))
}

func countShards(dir string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	count := 0
	for _, e := range entries {
		if !e.IsDir() {
			count++
		}
	}
	return count
}

func dirSize(dir string) int64 {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	var total int64
	for _, e := range entries {
		if !e.IsDir() {
			info, err := e.Info()
			if err == nil {
				total += info.Size()
			}
		}
	}
	return total
}

func formatDuration(d time.Duration) string {
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh %dm %ds", h, m, s)
	}
	if m > 0 {
		return fmt.Sprintf("%dm %ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}

func formatBytes(b int64) string {
	const (
		kb = 1024
		mb = 1024 * kb
		gb = 1024 * mb
	)
	switch {
	case b >= gb:
		return fmt.Sprintf("%.1f GB", float64(b)/float64(gb))
	case b >= mb:
		return fmt.Sprintf("%.1f MB", float64(b)/float64(mb))
	case b >= kb:
		return fmt.Sprintf("%.1f KB", float64(b)/float64(kb))
	default:
		return fmt.Sprintf("%d B", b)
	}
}
