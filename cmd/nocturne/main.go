package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

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

	// Graceful shutdown on SIGINT/SIGTERM.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("Shutting down...")
		cancel()
	}()

	fmt.Printf("Nocturne running on http://localhost:%s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, srv))
}
