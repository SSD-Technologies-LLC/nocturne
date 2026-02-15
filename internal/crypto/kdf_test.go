package crypto

import (
	"bytes"
	"testing"
)

func TestDeriveKey_ProducesDeterministicOutput(t *testing.T) {
	password := "test-password-123"
	salt := []byte("0123456789abcdef0123456789abcdef") // 32 bytes

	key1 := DeriveKey(password, salt)
	key2 := DeriveKey(password, salt)

	if len(key1) != 32 {
		t.Fatalf("expected key length 32, got %d", len(key1))
	}

	if !bytes.Equal(key1, key2) {
		t.Fatal("same password and salt should produce the same key")
	}
}

func TestDeriveKey_DifferentPasswordsDifferentKeys(t *testing.T) {
	salt := []byte("0123456789abcdef0123456789abcdef") // 32 bytes

	key1 := DeriveKey("password-one", salt)
	key2 := DeriveKey("password-two", salt)

	if bytes.Equal(key1, key2) {
		t.Fatal("different passwords should produce different keys")
	}
}

func TestGenerateSalt(t *testing.T) {
	salt1 := GenerateSalt()
	salt2 := GenerateSalt()

	if len(salt1) != 32 {
		t.Fatalf("expected salt length 32, got %d", len(salt1))
	}

	if len(salt2) != 32 {
		t.Fatalf("expected salt length 32, got %d", len(salt2))
	}

	if bytes.Equal(salt1, salt2) {
		t.Fatal("two generated salts should not be equal")
	}
}

func TestHashPassword_AndVerify(t *testing.T) {
	password := "my-secure-password"

	hash := HashPassword(password)

	if !VerifyPassword(password, hash) {
		t.Fatal("VerifyPassword should return true for the correct password")
	}
}

func TestVerifyPassword_WrongPassword(t *testing.T) {
	password := "correct-password"
	wrong := "wrong-password"

	hash := HashPassword(password)

	if VerifyPassword(wrong, hash) {
		t.Fatal("VerifyPassword should return false for a wrong password")
	}
}
