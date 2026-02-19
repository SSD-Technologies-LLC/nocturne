package dht

import (
	"crypto/ed25519"
	"fmt"
	"os"
)

// LoadOrGenerateKeypair loads an Ed25519 keypair from path, or generates a new
// one and saves it if the file doesn't exist. The file format is the 64-byte
// Ed25519 private key (which contains the public key in its last 32 bytes).
func LoadOrGenerateKeypair(path string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		if len(data) != ed25519.PrivateKeySize {
			return nil, nil, fmt.Errorf("invalid key file: expected %d bytes, got %d", ed25519.PrivateKeySize, len(data))
		}
		priv := ed25519.PrivateKey(data)
		pub := priv.Public().(ed25519.PublicKey)
		return pub, priv, nil
	}

	if !os.IsNotExist(err) {
		return nil, nil, fmt.Errorf("read key file: %w", err)
	}

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, nil, fmt.Errorf("generate keypair: %w", err)
	}

	if err := os.WriteFile(path, []byte(priv), 0600); err != nil {
		return nil, nil, fmt.Errorf("write key file: %w", err)
	}

	return pub, priv, nil
}
