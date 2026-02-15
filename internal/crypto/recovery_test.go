package crypto

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

func TestGenerateRecoveryKey_Format(t *testing.T) {
	hexKey, mnemonic, err := GenerateRecoveryKey()
	if err != nil {
		t.Fatalf("GenerateRecoveryKey failed: %v", err)
	}

	// hex key must be 64 characters (32 bytes = 256 bits)
	if len(hexKey) != 64 {
		t.Fatalf("hex key length: got %d, want 64", len(hexKey))
	}

	// hex key must be valid hex
	if _, err := hex.DecodeString(hexKey); err != nil {
		t.Fatalf("hex key is not valid hex: %v", err)
	}

	// mnemonic must be exactly 6 words
	words := strings.Fields(mnemonic)
	if len(words) != 6 {
		t.Fatalf("mnemonic word count: got %d, want 6", len(words))
	}

	// each word must exist in the wordlist
	wordSet := make(map[string]bool)
	for _, w := range wordlist {
		wordSet[w] = true
	}
	for _, w := range words {
		if !wordSet[w] {
			t.Fatalf("mnemonic word %q not in wordlist", w)
		}
	}
}

func TestGenerateRecoveryKey_Unique(t *testing.T) {
	key1, _, err := GenerateRecoveryKey()
	if err != nil {
		t.Fatalf("GenerateRecoveryKey (1) failed: %v", err)
	}

	key2, _, err := GenerateRecoveryKey()
	if err != nil {
		t.Fatalf("GenerateRecoveryKey (2) failed: %v", err)
	}

	if key1 == key2 {
		t.Fatal("two generated recovery keys should not be identical")
	}
}

func TestWordlistLength(t *testing.T) {
	if len(wordlist) != 256 {
		t.Fatalf("wordlist length: got %d, want 256", len(wordlist))
	}
}

func TestCreateEscrow_RecoverPassword(t *testing.T) {
	hexKey, _, err := GenerateRecoveryKey()
	if err != nil {
		t.Fatalf("GenerateRecoveryKey failed: %v", err)
	}

	password := "my-secret-vault-password"
	salt := GenerateSalt()

	escrow, err := CreateEscrow(hexKey, password, salt)
	if err != nil {
		t.Fatalf("CreateEscrow failed: %v", err)
	}

	recoveredPassword, recoveredSalt, err := RecoverFromEscrow(hexKey, escrow)
	if err != nil {
		t.Fatalf("RecoverFromEscrow failed: %v", err)
	}

	if recoveredPassword != password {
		t.Fatalf("recovered password: got %q, want %q", recoveredPassword, password)
	}

	if !bytes.Equal(recoveredSalt, salt) {
		t.Fatalf("recovered salt does not match original")
	}
}

func TestRecoverFromEscrow_WrongKey_Fails(t *testing.T) {
	hexKey, _, err := GenerateRecoveryKey()
	if err != nil {
		t.Fatalf("GenerateRecoveryKey failed: %v", err)
	}

	password := "some-password"
	salt := GenerateSalt()

	escrow, err := CreateEscrow(hexKey, password, salt)
	if err != nil {
		t.Fatalf("CreateEscrow failed: %v", err)
	}

	// Generate a different key
	wrongKey, _, err := GenerateRecoveryKey()
	if err != nil {
		t.Fatalf("GenerateRecoveryKey (wrong) failed: %v", err)
	}

	_, _, err = RecoverFromEscrow(wrongKey, escrow)
	if err == nil {
		t.Fatal("RecoverFromEscrow should fail with wrong key")
	}
}

func TestRecoverFromEscrow_TruncatedBlob_Fails(t *testing.T) {
	hexKey, _, err := GenerateRecoveryKey()
	if err != nil {
		t.Fatalf("GenerateRecoveryKey failed: %v", err)
	}

	// Blob too short to contain even a nonce
	_, _, err = RecoverFromEscrow(hexKey, []byte{0x01, 0x02})
	if err == nil {
		t.Fatal("RecoverFromEscrow should fail with truncated blob")
	}
}

func TestEncryptDecrypt_Interface_AES(t *testing.T) {
	plaintext := []byte("testing the unified cipher interface with AES")
	password := "aes-interface-password"

	ciphertext, salt, nonce, err := Encrypt(plaintext, password, CipherAES)
	if err != nil {
		t.Fatalf("Encrypt (AES) failed: %v", err)
	}

	decrypted, err := Decrypt(ciphertext, password, CipherAES, salt, nonce)
	if err != nil {
		t.Fatalf("Decrypt (AES) failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatalf("AES interface roundtrip failed: got %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptDecrypt_Interface_Noctis(t *testing.T) {
	plaintext := []byte("testing the unified cipher interface with Noctis")
	password := "noctis-interface-password"

	ciphertext, salt, nonce, err := Encrypt(plaintext, password, CipherNoctis)
	if err != nil {
		t.Fatalf("Encrypt (Noctis) failed: %v", err)
	}

	decrypted, err := Decrypt(ciphertext, password, CipherNoctis, salt, nonce)
	if err != nil {
		t.Fatalf("Decrypt (Noctis) failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatalf("Noctis interface roundtrip failed: got %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptDecrypt_UnknownCipher(t *testing.T) {
	plaintext := []byte("test data")
	password := "test-password"

	_, _, _, err := Encrypt(plaintext, password, "unknown-cipher")
	if err == nil {
		t.Fatal("Encrypt should fail with unknown cipher")
	}

	_, err = Decrypt(plaintext, password, "unknown-cipher", nil, nil)
	if err == nil {
		t.Fatal("Decrypt should fail with unknown cipher")
	}
}
