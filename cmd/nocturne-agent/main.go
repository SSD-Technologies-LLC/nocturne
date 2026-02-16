// cmd/nocturne-agent/main.go
//
// nocturne-agent is a full DHT peer for the Nocturne P2P agent mesh network.
// It starts a Kademlia DHT node with gossip support and exposes a localhost
// REST API for knowledge, voting, compute tasks, and awareness operations.
//
// Usage:
//
//	nocturne-agent start [--port 9090] [--api-port 9091] [--bootstrap addr1,addr2]
//	nocturne-agent setup --label "my-org"
//	nocturne-agent endorse --operator <pubkey-hex> --key <path-to-private-key>
//	nocturne-agent enroll --endorsements e1.json,e2.json,e3.json
//	nocturne-agent status
//	nocturne-agent stop
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ssd-technologies/nocturne/internal/agent"
	"github.com/ssd-technologies/nocturne/internal/dht"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "start":
		cmdStart(os.Args[2:])
	case "setup":
		cmdSetup(os.Args[2:])
	case "endorse":
		cmdEndorse(os.Args[2:])
	case "enroll":
		cmdEnroll(os.Args[2:])
	case "status":
		cmdStatus(os.Args[2:])
	case "stop":
		cmdStop(os.Args[2:])
	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `Usage: nocturne-agent <command> [flags]

Commands:
  start     Start the DHT node and API server
  setup     Generate operator identity
  endorse   Create an endorsement for another operator
  enroll    Create a trust certificate from endorsements
  status    Check if the agent is running
  stop      Stop the running agent

Run 'nocturne-agent <command> --help' for details on each command.
`)
}

// resolveDataDir returns the data directory, using the explicit path if
// provided, otherwise defaulting to ~/.nocturne/agent.
func resolveDataDir(explicit string) string {
	if explicit != "" {
		return explicit
	}
	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("Cannot determine home directory: %v", err)
	}
	return filepath.Join(home, ".nocturne", "agent")
}

// ensureDataDir creates the data directory if it does not exist and returns the path.
func ensureDataDir(explicit string) string {
	dir := resolveDataDir(explicit)
	if err := os.MkdirAll(dir, 0700); err != nil {
		log.Fatalf("Create data directory: %v", err)
	}
	return dir
}

// operatorInfo is the JSON structure stored in operator.json.
type operatorInfo struct {
	Label      string `json:"label"`
	PublicKey  string `json:"public_key"`
	OperatorID string `json:"operator_id"`
}

// cmdStart starts the DHT node and API server. It writes a PID file and an API
// port file so that other subcommands can locate the running agent.
func cmdStart(args []string) {
	fs := flag.NewFlagSet("start", flag.ExitOnError)
	port := fs.Int("port", 9090, "P2P listen port")
	apiPort := fs.Int("api-port", 9091, "localhost API port")
	bootstrap := fs.String("bootstrap", "", "comma-separated bootstrap peer addresses")
	dataDir := fs.String("data-dir", "", "data directory (default ~/.nocturne/agent)")
	fs.Parse(args)

	dir := ensureDataDir(*dataDir)

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

	node, err := dht.NewNode(cfg)
	if err != nil {
		log.Fatalf("Failed to create DHT node: %v", err)
	}

	// Set up gossiper.
	gossiper := dht.NewGossiper(node)
	node.SetGossiper(gossiper)

	if err := node.Start(); err != nil {
		log.Fatalf("Failed to start DHT node: %v", err)
	}
	defer node.Close()

	// Write PID file.
	pidPath := filepath.Join(dir, "agent.pid")
	if err := os.WriteFile(pidPath, []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
		log.Fatalf("Write PID file: %v", err)
	}
	defer os.Remove(pidPath)

	// Write API port file.
	apiFile := filepath.Join(dir, "agent.api")
	if err := os.WriteFile(apiFile, []byte(strconv.Itoa(*apiPort)), 0600); err != nil {
		log.Fatalf("Write API port file: %v", err)
	}
	defer os.Remove(apiFile)

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

// cmdSetup generates (or loads) an operator identity and saves it to operator.json.
func cmdSetup(args []string) {
	fs := flag.NewFlagSet("setup", flag.ExitOnError)
	label := fs.String("label", "", "operator label (required)")
	dataDir := fs.String("data-dir", "", "data directory (default ~/.nocturne/agent)")
	fs.Parse(args)

	if *label == "" {
		fmt.Fprintf(os.Stderr, "Error: --label is required\n")
		fs.Usage()
		os.Exit(1)
	}

	dir := ensureDataDir(*dataDir)

	// Load or generate keypair.
	keyPath := filepath.Join(dir, "agent.key")
	pub, _ := loadOrGenerateKeypair(keyPath)

	pubHex := hex.EncodeToString(pub)
	opID := agent.AgentIDFromPublicKey(pub)

	info := operatorInfo{
		Label:      *label,
		PublicKey:  pubHex,
		OperatorID: opID,
	}

	data, err := json.MarshalIndent(info, "", "  ")
	if err != nil {
		log.Fatalf("Marshal operator info: %v", err)
	}

	opPath := filepath.Join(dir, "operator.json")
	if err := os.WriteFile(opPath, data, 0600); err != nil {
		log.Fatalf("Write operator.json: %v", err)
	}

	fmt.Printf("Operator identity created\n")
	fmt.Printf("  Label:       %s\n", info.Label)
	fmt.Printf("  Operator ID: %s\n", info.OperatorID)
	fmt.Printf("  Public Key:  %s\n", info.PublicKey)
	fmt.Printf("  Saved to:    %s\n", opPath)
}

// cmdEndorse creates an endorsement for a target operator and writes it to stdout as JSON.
func cmdEndorse(args []string) {
	fs := flag.NewFlagSet("endorse", flag.ExitOnError)
	operatorPub := fs.String("operator", "", "target operator public key (hex)")
	keyPath := fs.String("key", "", "path to endorser's private key seed file")
	fs.Parse(args)

	if *operatorPub == "" || *keyPath == "" {
		fmt.Fprintf(os.Stderr, "Error: --operator and --key are required\n")
		fs.Usage()
		os.Exit(1)
	}

	// Load endorser private key.
	seed, err := os.ReadFile(*keyPath)
	if err != nil {
		log.Fatalf("Read endorser key: %v", err)
	}
	if len(seed) != ed25519.SeedSize {
		log.Fatalf("Invalid key file: expected %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	endorserPriv := ed25519.NewKeyFromSeed(seed)

	// Decode target operator public key.
	targetPubBytes, err := hex.DecodeString(*operatorPub)
	if err != nil {
		log.Fatalf("Decode operator public key: %v", err)
	}
	if len(targetPubBytes) != ed25519.PublicKeySize {
		log.Fatalf("Invalid public key length: expected %d bytes, got %d", ed25519.PublicKeySize, len(targetPubBytes))
	}
	targetPub := ed25519.PublicKey(targetPubBytes)

	endorsement, err := agent.CreateEndorsement(endorserPriv, targetPub, time.Now().Unix())
	if err != nil {
		log.Fatalf("Create endorsement: %v", err)
	}

	data, err := json.MarshalIndent(endorsement, "", "  ")
	if err != nil {
		log.Fatalf("Marshal endorsement: %v", err)
	}

	fmt.Println(string(data))
}

// cmdEnroll reads endorsement files, creates a trust certificate, and saves it.
func cmdEnroll(args []string) {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	endorsementFiles := fs.String("endorsements", "", "comma-separated endorsement JSON file paths")
	dataDir := fs.String("data-dir", "", "data directory (default ~/.nocturne/agent)")
	fs.Parse(args)

	if *endorsementFiles == "" {
		fmt.Fprintf(os.Stderr, "Error: --endorsements is required\n")
		fs.Usage()
		os.Exit(1)
	}

	dir := resolveDataDir(*dataDir)

	// Load operator identity.
	opPath := filepath.Join(dir, "operator.json")
	opData, err := os.ReadFile(opPath)
	if err != nil {
		log.Fatalf("Read operator.json: %v\nRun 'nocturne-agent setup' first.", err)
	}
	var info operatorInfo
	if err := json.Unmarshal(opData, &info); err != nil {
		log.Fatalf("Parse operator.json: %v", err)
	}

	// Load keypair.
	keyPath := filepath.Join(dir, "agent.key")
	pub, _ := loadOrGenerateKeypair(keyPath)

	// Read and parse endorsement files.
	files := strings.Split(*endorsementFiles, ",")
	var endorsements []agent.Endorsement
	for _, f := range files {
		f = strings.TrimSpace(f)
		data, err := os.ReadFile(f)
		if err != nil {
			log.Fatalf("Read endorsement file %s: %v", f, err)
		}
		var e agent.Endorsement
		if err := json.Unmarshal(data, &e); err != nil {
			log.Fatalf("Parse endorsement file %s: %v", f, err)
		}
		endorsements = append(endorsements, e)
	}

	// Create trust certificate.
	cert := agent.NewTrustCertificate(pub, info.Label, 10, endorsements)

	certData, err := json.MarshalIndent(cert, "", "  ")
	if err != nil {
		log.Fatalf("Marshal trust certificate: %v", err)
	}

	// Save certificate.
	certPath := filepath.Join(dir, "trust_cert.json")
	if err := os.WriteFile(certPath, certData, 0600); err != nil {
		log.Fatalf("Write trust_cert.json: %v", err)
	}

	fmt.Println(string(certData))
	fmt.Fprintf(os.Stderr, "\nTrust certificate saved to %s\n", certPath)
}

// cmdStatus checks whether the agent is running by reading the API port file
// and hitting the health endpoint.
func cmdStatus(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	dataDir := fs.String("data-dir", "", "data directory (default ~/.nocturne/agent)")
	fs.Parse(args)

	dir := resolveDataDir(*dataDir)

	// Check PID file.
	pidPath := filepath.Join(dir, "agent.pid")
	pidData, err := os.ReadFile(pidPath)
	if err != nil {
		fmt.Println("agent not running")
		return
	}

	pid, err := strconv.Atoi(strings.TrimSpace(string(pidData)))
	if err != nil {
		fmt.Println("agent not running")
		return
	}

	// Check if process exists.
	process, err := os.FindProcess(pid)
	if err != nil {
		fmt.Println("agent not running")
		return
	}
	// On Unix, FindProcess always succeeds. Send signal 0 to check.
	if err := process.Signal(syscall.Signal(0)); err != nil {
		fmt.Println("agent not running")
		return
	}

	// Read API port file.
	apiPath := filepath.Join(dir, "agent.api")
	apiData, err := os.ReadFile(apiPath)
	if err != nil {
		fmt.Printf("agent running (PID %d) but API port unknown\n", pid)
		return
	}
	apiPort := strings.TrimSpace(string(apiData))

	// Hit health endpoint.
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%s/local/health", apiPort))
	if err != nil {
		fmt.Printf("agent running (PID %d) but API unreachable: %v\n", pid, err)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Printf("agent running (PID %d)\n", pid)
	fmt.Printf("  API: http://127.0.0.1:%s\n", apiPort)
	fmt.Printf("  Health: %s\n", strings.TrimSpace(string(body)))
}

// cmdStop sends SIGTERM to the running agent process.
func cmdStop(args []string) {
	fs := flag.NewFlagSet("stop", flag.ExitOnError)
	dataDir := fs.String("data-dir", "", "data directory (default ~/.nocturne/agent)")
	fs.Parse(args)

	dir := resolveDataDir(*dataDir)

	pidPath := filepath.Join(dir, "agent.pid")
	pidData, err := os.ReadFile(pidPath)
	if err != nil {
		fmt.Println("agent not running")
		return
	}

	pid, err := strconv.Atoi(strings.TrimSpace(string(pidData)))
	if err != nil {
		fmt.Println("agent not running (invalid PID file)")
		return
	}

	process, err := os.FindProcess(pid)
	if err != nil {
		fmt.Println("agent not running")
		os.Remove(pidPath)
		return
	}

	if err := process.Signal(syscall.SIGTERM); err != nil {
		fmt.Printf("failed to stop agent (PID %d): %v\n", pid, err)
		os.Remove(pidPath)
		return
	}

	os.Remove(pidPath)
	fmt.Printf("agent stopped (PID %d)\n", pid)
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
