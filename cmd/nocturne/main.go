// cmd/nocturne/main.go
package main

import (
	"fmt"
	"os"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	fmt.Printf("Nocturne starting on :%s\n", port)
}
