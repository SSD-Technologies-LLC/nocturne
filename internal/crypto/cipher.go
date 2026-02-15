package crypto

import "fmt"

const (
	CipherAES    = "aes-256-gcm"
	CipherNoctis = "noctis-256"
)

func Encrypt(plaintext []byte, password, cipher string) (ciphertext, salt, nonce []byte, err error) {
	switch cipher {
	case CipherAES:
		return AESEncrypt(plaintext, password)
	case CipherNoctis:
		return NoctisEncrypt(plaintext, password)
	default:
		return nil, nil, nil, fmt.Errorf("unknown cipher: %s", cipher)
	}
}

func Decrypt(ciphertext []byte, password, cipherName string, salt, nonce []byte) ([]byte, error) {
	switch cipherName {
	case CipherAES:
		return AESDecrypt(ciphertext, password, salt, nonce)
	case CipherNoctis:
		return NoctisDecrypt(ciphertext, password, salt, nonce)
	default:
		return nil, fmt.Errorf("unknown cipher: %s", cipherName)
	}
}
