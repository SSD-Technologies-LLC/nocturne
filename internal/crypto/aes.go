package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
)

const aesNonceLen = 12

func AESEncrypt(plaintext []byte, password string) (ciphertext, salt, nonce []byte, err error) {
	salt = GenerateSalt()
	key := DeriveKey(password, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("new cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("new gcm: %w", err)
	}

	nonce = make([]byte, aesNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, nil, fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext = gcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, salt, nonce, nil
}

func AESDecrypt(ciphertext []byte, password string, salt, nonce []byte) ([]byte, error) {
	key := DeriveKey(password, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("new cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("new gcm: %w", err)
	}

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}

	return plaintext, nil
}
