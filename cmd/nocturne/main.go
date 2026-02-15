package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

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
		secret = "dev-secret-change-me"
	}

	db, err := storage.NewDB(dataDir + "/nocturne.db")
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	srv := server.New(db, secret)

	fmt.Printf("Nocturne running on http://localhost:%s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, srv))
}
