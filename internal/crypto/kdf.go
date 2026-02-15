package crypto

import (
	"crypto/hmac"
	"crypto/rand"

	"golang.org/x/crypto/argon2"
)

const (
	argonTime    = 3
	argonMemory  = 64 * 1024 // 64 MB
	argonThreads = 4
	keyLen       = 32 // 256 bits
	saltLen      = 32
)

func DeriveKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, keyLen)
}

func DeriveKeyWithLen(password string, salt []byte, length uint32) []byte {
	return argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, length)
}

func GenerateSalt() []byte {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return salt
}

func HashPassword(password string) []byte {
	salt := GenerateSalt()
	hash := DeriveKey(password, salt)
	result := make([]byte, saltLen+keyLen)
	copy(result[:saltLen], salt)
	copy(result[saltLen:], hash)
	return result
}

func VerifyPassword(password string, storedHash []byte) bool {
	if len(storedHash) < saltLen+keyLen {
		return false
	}
	salt := storedHash[:saltLen]
	hash := storedHash[saltLen:]
	computed := DeriveKey(password, salt)
	return hmac.Equal(hash, computed)
}
