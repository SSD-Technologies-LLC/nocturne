package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/ssd-technologies/nocturne/internal/dht"
	"github.com/ssd-technologies/nocturne/internal/server"
	"github.com/ssd-technologies/nocturne/internal/storage"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	dataDir := os.Getenv("NOCTURNE_DATA_DIR")
	if dataDir == "" {
		dataDir = "data"
	}

	secret := os.Getenv("NOCTURNE_SECRET")
	if secret == "" {
		log.Fatal("NOCTURNE_SECRET environment variable is required")
	}

	db, err := storage.NewDB(dataDir + "/nocturne.db")
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	srv := server.New(db, secret)
	srv.StartWorkers(ctx)

	// Optionally start a DHT node for P2P distributed storage.
	if os.Getenv("NOCTURNE_DHT_ENABLED") == "true" {
		pub, priv, err := dht.LoadOrGenerateKeypair(dataDir + "/dht.key")
		if err != nil {
			log.Fatalf("Failed to load DHT keypair: %v", err)
		}

		dhtPort := 0
		if p := os.Getenv("NOCTURNE_DHT_PORT"); p != "" {
			dhtPort, _ = strconv.Atoi(p)
		}

		cfg := dht.Config{
			PrivateKey: priv,
			PublicKey:  pub,
			K:          20,
			Alpha:      3,
			Port:       dhtPort,
			BindAddr:   "0.0.0.0",
		}

		dhtNode, err := dht.NewNode(cfg)
		if err != nil {
			log.Fatalf("Failed to create DHT node: %v", err)
		}
		if err := dhtNode.Start(); err != nil {
			log.Fatalf("Failed to start DHT node: %v", err)
		}
		defer dhtNode.Close()

		srv.SetDHTNode(dhtNode)
		log.Printf("DHT node started on %s", dhtNode.Addr())
	}

	httpServer := &http.Server{
		Addr:    ":" + port,
		Handler: srv,
	}

	// Graceful shutdown on SIGINT/SIGTERM.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("Shutting down...")
		cancel()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		if err := httpServer.Shutdown(shutdownCtx); err != nil {
			log.Printf("HTTP shutdown error: %v", err)
		}
	}()

	fmt.Printf("Nocturne running on http://localhost:%s\n", port)
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}

	srv.Close()
}
