package crypto

import (
	"bytes"
	"testing"
)

func TestNoctis_EncryptDecrypt_Roundtrip(t *testing.T) {
	plaintext := []byte("hello, nocturne noctis-256 encryption!")
	password := "strong-noctis-password-42"

	ciphertext, salt, nonce, err := NoctisEncrypt(plaintext, password)
	if err != nil {
		t.Fatalf("NoctisEncrypt failed: %v", err)
	}

	decrypted, err := NoctisDecrypt(ciphertext, password, salt, nonce)
	if err != nil {
		t.Fatalf("NoctisDecrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatalf("decrypted text does not match original: got %q, want %q", decrypted, plaintext)
	}
}

func TestNoctis_WrongPassword_Fails(t *testing.T) {
	plaintext := []byte("secret data for noctis")
	password := "correct-password"

	ciphertext, salt, nonce, err := NoctisEncrypt(plaintext, password)
	if err != nil {
		t.Fatalf("NoctisEncrypt failed: %v", err)
	}

	_, err = NoctisDecrypt(ciphertext, "wrong-password", salt, nonce)
	if err == nil {
		t.Fatal("NoctisDecrypt should fail with wrong password")
	}
}

func TestNoctis_Deterministic_SameKeyNonce(t *testing.T) {
	plaintext := []byte("deterministic test payload")
	key := make([]byte, noctisKeySize)
	for i := range key {
		key[i] = byte(i * 3)
	}
	nonce := make([]byte, noctisNonceLen)
	for i := range nonce {
		nonce[i] = byte(i * 7)
	}

	ct1 := noctisEncryptRaw(plaintext, key, nonce)
	ct2 := noctisEncryptRaw(plaintext, key, nonce)

	if !bytes.Equal(ct1, ct2) {
		t.Fatal("same key and nonce should produce identical ciphertext")
	}
}

func TestNoctis_DifferentBlocks_Differ(t *testing.T) {
	password := "differ-test-password"

	pt1 := []byte("plaintext block one")
	pt2 := []byte("plaintext block two")

	ct1, _, _, err := NoctisEncrypt(pt1, password)
	if err != nil {
		t.Fatalf("NoctisEncrypt failed for pt1: %v", err)
	}

	ct2, _, _, err := NoctisEncrypt(pt2, password)
	if err != nil {
		t.Fatalf("NoctisEncrypt failed for pt2: %v", err)
	}

	if bytes.Equal(ct1, ct2) {
		t.Fatal("different plaintexts should produce different ciphertexts")
	}
}

func TestNoctis_LargeFile(t *testing.T) {
	// 1 MB of data
	plaintext := make([]byte, 1<<20)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}
	password := "large-file-noctis-password"

	ciphertext, salt, nonce, err := NoctisEncrypt(plaintext, password)
	if err != nil {
		t.Fatalf("NoctisEncrypt failed for 1MB: %v", err)
	}

	decrypted, err := NoctisDecrypt(ciphertext, password, salt, nonce)
	if err != nil {
		t.Fatalf("NoctisDecrypt failed for 1MB: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatal("1MB roundtrip failed: decrypted data does not match original")
	}
}

func TestNoctis_BlockEncryptDecrypt_Roundtrip(t *testing.T) {
	// Test raw block encrypt/decrypt without CTR mode
	key := make([]byte, noctisKeySize)
	for i := range key {
		key[i] = byte(i + 42)
	}
	state := newNoctisState(key)

	original := make([]byte, noctisBlockSize)
	for i := range original {
		original[i] = byte(i * 11)
	}

	block := make([]byte, noctisBlockSize)
	copy(block, original)

	// Encrypt then decrypt
	state.encryptBlock(block)

	// Encrypted block should differ from original
	if bytes.Equal(block, original) {
		t.Fatal("encrypted block should differ from original")
	}

	state.decryptBlock(block)

	if !bytes.Equal(block, original) {
		t.Fatalf("block roundtrip failed: got %x, want %x", block, original)
	}
}
