package crypto

import (
	"bytes"
	"testing"
)

func TestAES_EncryptDecrypt_Roundtrip(t *testing.T) {
	plaintext := []byte("hello, nocturne encryption!")
	password := "strong-password-42"

	ciphertext, salt, nonce, err := AESEncrypt(plaintext, password)
	if err != nil {
		t.Fatalf("AESEncrypt failed: %v", err)
	}

	decrypted, err := AESDecrypt(ciphertext, password, salt, nonce)
	if err != nil {
		t.Fatalf("AESDecrypt failed: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatalf("decrypted text does not match original: got %q, want %q", decrypted, plaintext)
	}
}

func TestAES_WrongPassword_Fails(t *testing.T) {
	plaintext := []byte("secret data")
	password := "correct-password"

	ciphertext, salt, nonce, err := AESEncrypt(plaintext, password)
	if err != nil {
		t.Fatalf("AESEncrypt failed: %v", err)
	}

	_, err = AESDecrypt(ciphertext, "wrong-password", salt, nonce)
	if err == nil {
		t.Fatal("AESDecrypt should fail with wrong password")
	}
}

func TestAES_LargeFile(t *testing.T) {
	// 1 MB of data
	plaintext := make([]byte, 1<<20)
	for i := range plaintext {
		plaintext[i] = byte(i % 256)
	}
	password := "large-file-password"

	ciphertext, salt, nonce, err := AESEncrypt(plaintext, password)
	if err != nil {
		t.Fatalf("AESEncrypt failed for 1MB: %v", err)
	}

	decrypted, err := AESDecrypt(ciphertext, password, salt, nonce)
	if err != nil {
		t.Fatalf("AESDecrypt failed for 1MB: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatal("1MB roundtrip failed: decrypted data does not match original")
	}
}

func TestAES_EncryptedDiffersFromPlaintext(t *testing.T) {
	plaintext := []byte("this should be encrypted, not stored in plain")
	password := "encryption-password"

	ciphertext, _, _, err := AESEncrypt(plaintext, password)
	if err != nil {
		t.Fatalf("AESEncrypt failed: %v", err)
	}

	if bytes.Equal(plaintext, ciphertext) {
		t.Fatal("ciphertext should differ from plaintext")
	}
}
