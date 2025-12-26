package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

// AEAD errors
var (
	ErrAEADAuthFailed     = errors.New("AEAD authentication failed")
	ErrCiphertextTooShort = errors.New("ciphertext too short")
)

// AEADEncryptor provides XChaCha20-Poly1305 authenticated encryption.
//
// SECURITY: This is the core encryption primitive for shard indistinguishability.
// - Authentication prevents false positives in trial decryption
// - Wrong key = authentication failure (not garbage output)
// - All tampering is detected via Poly1305 MAC
type AEADEncryptor struct {
	aead cipher.AEAD
	key  []byte
}

// NewAEADEncryptor creates a new AEAD encryptor with XChaCha20-Poly1305.
//
// Parameters:
//   - key: 32-byte encryption key
//
// Returns error if key size is invalid.
func NewAEADEncryptor(key []byte) (*AEADEncryptor, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("%w: expected 32 bytes, got %d", ErrInvalidKeySize, len(key))
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create XChaCha20-Poly1305: %w", err)
	}

	// Copy key for internal use
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)

	return &AEADEncryptor{
		aead: aead,
		key:  keyCopy,
	}, nil
}

// Encrypt encrypts plaintext using XChaCha20-Poly1305.
//
// Output format: [24-byte nonce][ciphertext][16-byte auth tag]
//
// A random nonce is generated for each encryption, ensuring unique
// ciphertexts even for identical plaintexts.
func (e *AEADEncryptor) Encrypt(plaintext []byte) ([]byte, error) {
	// Generate random nonce (24 bytes for XChaCha20)
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt with AEAD (includes authentication tag)
	ciphertext := e.aead.Seal(nil, nonce, plaintext, nil)

	// Prepend nonce to ciphertext
	result := make([]byte, len(nonce)+len(ciphertext))
	copy(result[:len(nonce)], nonce)
	copy(result[len(nonce):], ciphertext)

	return result, nil
}

// Decrypt decrypts ciphertext using XChaCha20-Poly1305.
//
// Expected format: [24-byte nonce][ciphertext][16-byte auth tag]
//
// Returns ErrAEADAuthFailed if:
// - Ciphertext was tampered with
// - Wrong key was used
// - Nonce was modified
func (e *AEADEncryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	nonceSize := chacha20poly1305.NonceSizeX
	minSize := nonceSize + e.aead.Overhead()

	if len(ciphertext) < minSize {
		return nil, fmt.Errorf("%w: got %d bytes, need at least %d",
			ErrCiphertextTooShort, len(ciphertext), minSize)
	}

	// Extract nonce and actual ciphertext
	nonce := ciphertext[:nonceSize]
	actualCiphertext := ciphertext[nonceSize:]

	// Decrypt and authenticate
	plaintext, err := e.aead.Open(nil, nonce, actualCiphertext, nil)
	if err != nil {
		return nil, ErrAEADAuthFailed
	}

	return plaintext, nil
}

// EncryptWithAAD encrypts plaintext with additional authenticated data.
//
// AAD is authenticated but not encrypted - useful for binding ciphertext
// to a context (like bundle ID or position).
func (e *AEADEncryptor) EncryptWithAAD(plaintext, aad []byte) ([]byte, error) {
	// Generate random nonce
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt with AAD
	ciphertext := e.aead.Seal(nil, nonce, plaintext, aad)

	// Prepend nonce
	result := make([]byte, len(nonce)+len(ciphertext))
	copy(result[:len(nonce)], nonce)
	copy(result[len(nonce):], ciphertext)

	return result, nil
}

// DecryptWithAAD decrypts ciphertext with additional authenticated data.
//
// The same AAD must be provided as was used during encryption.
// Returns ErrAEADAuthFailed if AAD doesn't match.
func (e *AEADEncryptor) DecryptWithAAD(ciphertext, aad []byte) ([]byte, error) {
	nonceSize := chacha20poly1305.NonceSizeX
	minSize := nonceSize + e.aead.Overhead()

	if len(ciphertext) < minSize {
		return nil, fmt.Errorf("%w: got %d bytes, need at least %d",
			ErrCiphertextTooShort, len(ciphertext), minSize)
	}

	nonce := ciphertext[:nonceSize]
	actualCiphertext := ciphertext[nonceSize:]

	plaintext, err := e.aead.Open(nil, nonce, actualCiphertext, aad)
	if err != nil {
		return nil, ErrAEADAuthFailed
	}

	return plaintext, nil
}

// EncryptWithNonce encrypts using a provided nonce (for deterministic testing only).
//
// WARNING: Using the same nonce twice with the same key completely breaks security.
// This method is only for testing reproducibility.
func (e *AEADEncryptor) EncryptWithNonce(plaintext, nonce []byte) ([]byte, error) {
	if len(nonce) != chacha20poly1305.NonceSizeX {
		return nil, fmt.Errorf("%w: expected %d bytes, got %d",
			ErrInvalidNonceSize, chacha20poly1305.NonceSizeX, len(nonce))
	}

	ciphertext := e.aead.Seal(nil, nonce, plaintext, nil)

	result := make([]byte, len(nonce)+len(ciphertext))
	copy(result[:len(nonce)], nonce)
	copy(result[len(nonce):], ciphertext)

	return result, nil
}

// NonceSize returns the nonce size for XChaCha20-Poly1305 (24 bytes).
func (e *AEADEncryptor) NonceSize() int {
	return chacha20poly1305.NonceSizeX
}

// Overhead returns the authentication tag size (16 bytes).
func (e *AEADEncryptor) Overhead() int {
	return e.aead.Overhead()
}

// Clear securely clears the encryption key from memory.
func (e *AEADEncryptor) Clear() {
	clearBytes(e.key)
}
