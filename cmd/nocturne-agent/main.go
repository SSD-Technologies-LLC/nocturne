// cmd/nocturne-agent/main.go
//
// nocturne-agent is a full DHT peer for the Nocturne P2P agent mesh network.
// It starts a Kademlia DHT node with gossip support and exposes a localhost
// REST API for knowledge, voting, compute tasks, and awareness operations.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/ssd-technologies/nocturne/internal/dht"
)

func main() {
	port := flag.Int("port", 9090, "P2P listen port")
	apiPort := flag.Int("api-port", 9091, "localhost API port")
	bootstrap := flag.String("bootstrap", "", "comma-separated bootstrap peer addresses")
	dataDir := flag.String("data-dir", "", "data directory (default ~/.nocturne/agent)")
	flag.Parse()

	// Setup data directory.
	dir := *dataDir
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			log.Fatalf("Cannot determine home directory: %v", err)
		}
		dir = filepath.Join(home, ".nocturne", "agent")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		log.Fatalf("Create data directory: %v", err)
	}

	// Load or generate Ed25519 keypair.
	keyPath := filepath.Join(dir, "agent.key")
	pub, priv := loadOrGenerateKeypair(keyPath)

	// Create and start DHT node.
	cfg := dht.Config{
		PrivateKey: priv,
		PublicKey:  pub,
		K:          20,
		Alpha:      3,
		Port:       *port,
		StorePath:  filepath.Join(dir, "dht.db"),
	}
	if *bootstrap != "" {
		cfg.BootstrapPeers = strings.Split(*bootstrap, ",")
	}

	node := dht.NewNode(cfg)

	// Set up gossiper.
	gossiper := dht.NewGossiper(node)
	node.SetGossiper(gossiper)

	if err := node.Start(); err != nil {
		log.Fatalf("Failed to start DHT node: %v", err)
	}
	defer node.Close()

	// Start local API server (localhost only).
	api := dht.NewLocalAPI(node)
	apiAddr := fmt.Sprintf("127.0.0.1:%d", *apiPort)
	apiServer := &http.Server{Addr: apiAddr, Handler: api.Handler()}
	go func() {
		if err := apiServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("API server error: %v", err)
		}
	}()

	nodeID := node.ID()
	fmt.Printf("nocturne-agent started\n")
	fmt.Printf("  Node ID: %x\n", nodeID[:8])
	fmt.Printf("  P2P:     %s\n", node.Addr())
	fmt.Printf("  API:     http://%s\n", apiAddr)

	// Wait for shutdown signal.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	fmt.Println("\nShutting down...")
	apiServer.Shutdown(context.Background())
}

// loadOrGenerateKeypair loads an Ed25519 keypair from disk, or generates a new
// one if the file does not exist. The seed (32 bytes) is stored at keyPath.
func loadOrGenerateKeypair(keyPath string) (ed25519.PublicKey, ed25519.PrivateKey) {
	data, err := os.ReadFile(keyPath)
	if err == nil && len(data) == ed25519.SeedSize {
		priv := ed25519.NewKeyFromSeed(data)
		pub := priv.Public().(ed25519.PublicKey)
		return pub, priv
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("Generate keypair: %v", err)
	}
	if err := os.WriteFile(keyPath, priv.Seed(), 0600); err != nil {
		log.Fatalf("Write keypair: %v", err)
	}
	return pub, priv
}
