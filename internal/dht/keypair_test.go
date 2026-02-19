package dht

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrGenerateKeypair_GeneratesNew(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dht.key")

	pub, priv, err := LoadOrGenerateKeypair(path)
	if err != nil {
		t.Fatalf("LoadOrGenerateKeypair: %v", err)
	}
	if len(pub) != 32 {
		t.Fatalf("public key length = %d, want 32", len(pub))
	}
	if len(priv) != 64 {
		t.Fatalf("private key length = %d, want 64", len(priv))
	}

	// File should exist now.
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("key file not created: %v", err)
	}
}

func TestLoadOrGenerateKeypair_LoadsExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "dht.key")

	pub1, priv1, err := LoadOrGenerateKeypair(path)
	if err != nil {
		t.Fatalf("first call: %v", err)
	}

	pub2, priv2, err := LoadOrGenerateKeypair(path)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}

	if string(pub1) != string(pub2) {
		t.Error("public keys differ across calls")
	}
	if string(priv1) != string(priv2) {
		t.Error("private keys differ across calls")
	}
}
