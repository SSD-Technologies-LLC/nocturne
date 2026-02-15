package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/sha3"
)

const (
	noctisBlockSize = 32 // 256 bits
	noctisKeySize   = 64 // 512 bits
	noctisNonceLen  = 24 // 192 bits
	noctisRounds    = 20
	noctisMACSize   = 32 // HMAC-SHA3-256 output
)

// noctisState holds precomputed cipher state for a given key.
type noctisState struct {
	roundKeys [noctisRounds][noctisBlockSize]byte
	sbox      [256]byte
	sboxInv   [256]byte
}

// ---- Key Schedule ----

// noctisKeySchedule expands a 64-byte master key into 20 round keys
// using a Feistel-like network with SHA3-256.
func noctisKeySchedule(key []byte) [noctisRounds][noctisBlockSize]byte {
	var roundKeys [noctisRounds][noctisBlockSize]byte

	left := make([]byte, 32)
	right := make([]byte, 32)
	copy(left, key[:32])
	copy(right, key[32:64])

	for r := 0; r < noctisRounds; r++ {
		// Hash right half with SHA3-256, including round byte
		h := sha3.New256()
		h.Write(right)
		h.Write([]byte{byte(r)})
		digest := h.Sum(nil)

		// XOR digest into left
		for i := 0; i < 32; i++ {
			left[i] ^= digest[i]
		}

		// Bit-rotate left by (r*7 + 3) % 256 positions
		rotAmount := (r*7 + 3) % 256
		left = rotateBytes(left, rotAmount)

		// Store left as round key r
		copy(roundKeys[r][:], left)

		// Swap left and right
		left, right = right, left
	}

	return roundKeys
}

// rotateBytes performs a bit-level left rotation on a byte slice by n positions.
func rotateBytes(data []byte, n int) []byte {
	totalBits := len(data) * 8
	n = n % totalBits
	if n == 0 {
		return append([]byte(nil), data...)
	}

	result := make([]byte, len(data))
	byteShift := n / 8
	bitShift := uint(n % 8)

	for i := 0; i < len(data); i++ {
		srcIdx := (i + byteShift) % len(data)
		nextIdx := (srcIdx + 1) % len(data)
		if bitShift == 0 {
			result[i] = data[srcIdx]
		} else {
			result[i] = (data[srcIdx] << bitShift) | (data[nextIdx] >> (8 - bitShift))
		}
	}

	return result
}

// ---- Key-Dependent S-Box ----

// noctisGenerateSBox creates a key-dependent substitution box using
// Fisher-Yates shuffle seeded by SHA3-256(key || "sbox").
func noctisGenerateSBox(key []byte) (sbox [256]byte, sboxInv [256]byte) {
	// Start with identity permutation
	for i := 0; i < 256; i++ {
		sbox[i] = byte(i)
	}

	// Initial seed
	h := sha3.New256()
	h.Write(key)
	h.Write([]byte("sbox"))
	seed := h.Sum(nil)
	seedIdx := 0

	// Fisher-Yates shuffle
	for i := 255; i > 0; i-- {
		// Re-hash seed every 32 iterations for more entropy
		if seedIdx >= 32 {
			h.Reset()
			h.Write(seed)
			seed = h.Sum(nil)
			seedIdx = 0
		}

		// Use seed byte to generate swap index
		j := int(seed[seedIdx]) % (i + 1)
		seedIdx++

		sbox[i], sbox[j] = sbox[j], sbox[i]
	}

	// Compute inverse S-box
	for i := 0; i < 256; i++ {
		sboxInv[sbox[i]] = byte(i)
	}

	return sbox, sboxInv
}

// ---- Cipher State ----

func newNoctisState(key []byte) *noctisState {
	s := &noctisState{}
	s.roundKeys = noctisKeySchedule(key)
	s.sbox, s.sboxInv = noctisGenerateSBox(key)
	return s
}

// ---- Round Function (Encryption) ----

// encryptBlock encrypts a single 32-byte block in place.
func (s *noctisState) encryptBlock(block []byte) {
	for r := 0; r < noctisRounds; r++ {
		// 1. Substitution: apply S-box
		for i := 0; i < noctisBlockSize; i++ {
			block[i] = s.sbox[block[i]]
		}

		// 2. Permutation: byte-level rotation
		var tmp [noctisBlockSize]byte
		for i := 0; i < noctisBlockSize; i++ {
			newPos := (i + r*5 + 1) % noctisBlockSize
			tmp[newPos] = block[i]
		}
		copy(block, tmp[:])

		// 3. Diffusion: XOR each byte with round key
		for i := 0; i < noctisBlockSize; i++ {
			block[i] ^= s.roundKeys[r][i]
		}

		// 4. Non-linearity: modular addition of block halves
		// for i=15..0: block[i] = (block[i] + block[i+16] + carry) & 0xFF
		carry := 0
		for i := 15; i >= 0; i-- {
			sum := int(block[i]) + int(block[i+16]) + carry
			block[i] = byte(sum & 0xFF)
			carry = sum >> 8
		}
	}
}

// ---- Round Function (Decryption) ----

// decryptBlock decrypts a single 32-byte block in place.
func (s *noctisState) decryptBlock(block []byte) {
	for r := noctisRounds - 1; r >= 0; r-- {
		// 1. Reverse non-linearity: modular subtraction with borrow
		// Encryption processed i=15..0 with carry propagating downward.
		// To reverse, process i=15..0 and reconstruct the carry chain.
		carry := 0
		for i := 15; i >= 0; i-- {
			// block[i] = (original[i] + block[i+16] + carry_in) & 0xFF during encryption
			// We need to recover original[i] and the carry that was produced.
			diff := int(block[i]) - int(block[i+16]) - carry
			if diff < 0 {
				diff += 256
				carry = 1
			} else {
				carry = 0
			}
			block[i] = byte(diff)
		}

		// 2. Reverse diffusion: XOR with round key
		for i := 0; i < noctisBlockSize; i++ {
			block[i] ^= s.roundKeys[r][i]
		}

		// 3. Reverse permutation: inverse byte rotation
		var tmp [noctisBlockSize]byte
		for i := 0; i < noctisBlockSize; i++ {
			newPos := (i + r*5 + 1) % noctisBlockSize
			tmp[i] = block[newPos]
		}
		copy(block, tmp[:])

		// 4. Reverse substitution: apply inverse S-box
		for i := 0; i < noctisBlockSize; i++ {
			block[i] = s.sboxInv[block[i]]
		}
	}
}

// ---- CTR Mode ----

// noctisCTR applies CTR mode encryption/decryption.
// Counter block = nonce (24 bytes) || counter (8 bytes, big-endian)
func (s *noctisState) noctisCTR(data, nonce []byte) []byte {
	result := make([]byte, len(data))
	counterBlock := make([]byte, noctisBlockSize)
	copy(counterBlock[:noctisNonceLen], nonce)

	numBlocks := (len(data) + noctisBlockSize - 1) / noctisBlockSize

	for ctr := uint64(0); ctr < uint64(numBlocks); ctr++ {
		// Set counter (big-endian) in last 8 bytes
		binary.BigEndian.PutUint64(counterBlock[noctisNonceLen:], ctr)

		// Encrypt counter block to produce keystream
		keystream := make([]byte, noctisBlockSize)
		copy(keystream, counterBlock)
		s.encryptBlock(keystream)

		// XOR keystream with data
		offset := int(ctr) * noctisBlockSize
		remaining := len(data) - offset
		if remaining > noctisBlockSize {
			remaining = noctisBlockSize
		}
		for i := 0; i < remaining; i++ {
			result[offset+i] = data[offset+i] ^ keystream[i]
		}
	}

	return result
}

// ---- HMAC-SHA3-256 ----

// noctisMAC computes HMAC-SHA3-256(key, nonce || ciphertext).
func noctisMAC(key, nonce, ciphertext []byte) []byte {
	mac := hmac.New(sha3.New256, key)
	mac.Write(nonce)
	mac.Write(ciphertext)
	return mac.Sum(nil)
}

// ---- Public API ----

// noctisEncryptRaw encrypts plaintext with the given key and nonce using
// Noctis-256 in CTR mode (no HMAC). For internal use and testing determinism.
func noctisEncryptRaw(plaintext, key, nonce []byte) []byte {
	state := newNoctisState(key)
	return state.noctisCTR(plaintext, nonce)
}

// NoctisEncrypt encrypts plaintext with password using Noctis-256 + HMAC-SHA3-256.
// Returns ciphertext (with appended 32-byte MAC), salt, and nonce.
func NoctisEncrypt(plaintext []byte, password string) (ciphertext, salt, nonce []byte, err error) {
	salt = GenerateSalt()
	key := DeriveKeyWithLen(password, salt, noctisKeySize)

	nonce = make([]byte, noctisNonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, nil, fmt.Errorf("generate nonce: %w", err)
	}

	// Encrypt with CTR mode
	ct := noctisEncryptRaw(plaintext, key, nonce)

	// Compute HMAC-SHA3-256(key[:32], nonce || ciphertext)
	mac := noctisMAC(key[:32], nonce, ct)

	// Append MAC to ciphertext
	ciphertext = make([]byte, len(ct)+noctisMACSize)
	copy(ciphertext, ct)
	copy(ciphertext[len(ct):], mac)

	return ciphertext, salt, nonce, nil
}

// NoctisDecrypt decrypts ciphertext with password using Noctis-256 + HMAC-SHA3-256.
// The ciphertext must include the appended 32-byte MAC.
func NoctisDecrypt(ciphertext []byte, password string, salt, nonce []byte) ([]byte, error) {
	if len(ciphertext) < noctisMACSize {
		return nil, errors.New("noctis: ciphertext too short")
	}

	key := DeriveKeyWithLen(password, salt, noctisKeySize)

	// Split ciphertext and MAC
	ct := ciphertext[:len(ciphertext)-noctisMACSize]
	providedMAC := ciphertext[len(ciphertext)-noctisMACSize:]

	// Verify MAC first
	expectedMAC := noctisMAC(key[:32], nonce, ct)
	if !hmac.Equal(providedMAC, expectedMAC) {
		return nil, errors.New("noctis: HMAC verification failed")
	}

	// Decrypt with CTR mode
	plaintext := noctisEncryptRaw(ct, key, nonce)

	return plaintext, nil
}
