// cmd/nocturne-node/main.go
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: nocturne-node <connect|disconnect|status>")
		os.Exit(1)
	}
	fmt.Printf("nocturne-node: %s\n", os.Args[1])
}
