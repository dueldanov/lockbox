package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/chacha20poly1305"
)

var (
	ErrInvalidKeySize       = errors.New("invalid key size")
	ErrInvalidSaltSize      = errors.New("invalid salt size")
	ErrInvalidNonceSize     = errors.New("invalid nonce size")
	ErrDecryptionFailed     = errors.New("decryption failed")
	ErrKeyDerivationFailed  = errors.New("key derivation failed")
)

const (
	// HKDF parameters
	HKDFSaltSize   = 32
	HKDFKeySize    = 32
	HKDFInfoString = "lockbox-hkdf-v1"
	
	// Encryption parameters
	NonceSize      = 24
	TagSize        = 16
)

// HKDFManager manages HKDF key derivation and encryption operations
type HKDFManager struct {
	mu              sync.RWMutex
	masterKey       []byte
	salt            []byte
	derivedKeysPool sync.Pool
}

// NewHKDFManager creates a new HKDF manager with the given master key
func NewHKDFManager(masterKey []byte) (*HKDFManager, error) {
	if len(masterKey) != HKDFKeySize {
		return nil, fmt.Errorf("%w: expected %d, got %d", ErrInvalidKeySize, HKDFKeySize, len(masterKey))
	}

	// Generate random salt
	salt := make([]byte, HKDFSaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	// Create manager with properly allocated key
	manager := &HKDFManager{
		masterKey: make([]byte, len(masterKey)),
		salt:      salt,
		derivedKeysPool: sync.Pool{
			New: func() interface{} {
				return make([]byte, HKDFKeySize)
			},
		},
	}

	// FIX: Actually copy the master key into the allocated slice
	copy(manager.masterKey, masterKey)

	return manager, nil
}

// DeriveKey derives a new key from the master key using HKDF
func (h *HKDFManager) DeriveKey(context []byte) ([]byte, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	// Get a buffer from the pool
	derivedKey := h.derivedKeysPool.Get().([]byte)
	defer h.derivedKeysPool.Put(derivedKey)

	// Create HKDF reader
	hkdfReader := hkdf.New(sha256.New, h.masterKey, h.salt, append([]byte(HKDFInfoString), context...))
	
	// Derive key
	if _, err := io.ReadFull(hkdfReader, derivedKey); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeyDerivationFailed, err)
	}

	// Return a copy of the derived key
	result := make([]byte, len(derivedKey))
	copy(result, derivedKey)
	
	return result, nil
}

// DeriveKeyForShard derives a key specifically for a shard
func (h *HKDFManager) DeriveKeyForShard(shardID uint32) ([]byte, error) {
	context := make([]byte, 4)
	binary.BigEndian.PutUint32(context, shardID)
	return h.DeriveKey(context)
}

// RotateSalt generates a new salt for key derivation
func (h *HKDFManager) RotateSalt() error {
	h.mu.Lock()
	defer h.mu.Unlock()

	newSalt := make([]byte, HKDFSaltSize)
	if _, err := io.ReadFull(rand.Reader, newSalt); err != nil {
		return fmt.Errorf("failed to generate new salt: %w", err)
	}

	h.salt = newSalt
	return nil
}

// GetSalt returns a copy of the current salt
func (h *HKDFManager) GetSalt() []byte {
	h.mu.RLock()
	defer h.mu.RUnlock()

	salt := make([]byte, len(h.salt))
	copy(salt, h.salt)
	return salt
}

// UpdateMasterKey updates the master key (use with caution)
func (h *HKDFManager) UpdateMasterKey(newKey []byte) error {
	if len(newKey) != HKDFKeySize {
		return fmt.Errorf("%w: expected %d, got %d", ErrInvalidKeySize, HKDFKeySize, len(newKey))
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	// Securely clear old key
	clearBytes(h.masterKey)
	
	// Set new key
	h.masterKey = make([]byte, len(newKey))
	copy(h.masterKey, newKey)
	
	return nil
}

// Clear securely clears the manager's keys
func (h *HKDFManager) Clear() {
	h.mu.Lock()
	defer h.mu.Unlock()

	clearBytes(h.masterKey)
	clearBytes(h.salt)
}

// HKDFEncryptor provides encryption using HKDF-derived keys
type HKDFEncryptor struct {
	hkdfManager *HKDFManager
	aead        cipher.AEAD
}

// NewHKDFEncryptor creates a new encryptor with HKDF key derivation
func NewHKDFEncryptor(masterKey []byte) (*HKDFEncryptor, error) {
	manager, err := NewHKDFManager(masterKey)
	if err != nil {
		return nil, err
	}

	// Create AEAD cipher
	aead, err := chacha20poly1305.NewX(masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create AEAD: %w", err)
	}

	return &HKDFEncryptor{
		hkdfManager: manager,
		aead:        aead,
	}, nil
}

// EncryptWithContext encrypts data with a derived key based on context
func (e *HKDFEncryptor) EncryptWithContext(plaintext, context []byte) ([]byte, error) {
	// Derive key for this context
	derivedKey, err := e.hkdfManager.DeriveKey(context)
	if err != nil {
		return nil, err
	}
	defer clearBytes(derivedKey)

	// Create cipher with derived key
	aead, err := chacha20poly1305.NewX(derivedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Generate nonce
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt
	ciphertext := aead.Seal(nil, nonce, plaintext, context)
	
	// Prepend nonce to ciphertext
	result := make([]byte, len(nonce)+len(ciphertext))
	copy(result[:len(nonce)], nonce)
	copy(result[len(nonce):], ciphertext)
	
	return result, nil
}

// DecryptWithContext decrypts data with a derived key based on context
func (e *HKDFEncryptor) DecryptWithContext(ciphertext, context []byte) ([]byte, error) {
	if len(ciphertext) < NonceSize {
		return nil, ErrDecryptionFailed
	}

	// Extract nonce
	nonce := ciphertext[:NonceSize]
	actualCiphertext := ciphertext[NonceSize:]

	// Derive key for this context
	derivedKey, err := e.hkdfManager.DeriveKey(context)
	if err != nil {
		return nil, err
	}
	defer clearBytes(derivedKey)

	// Create cipher with derived key
	aead, err := chacha20poly1305.NewX(derivedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Decrypt
	plaintext, err := aead.Open(nil, nonce, actualCiphertext, context)
	if err != nil {
		return nil, ErrDecryptionFailed
	}

	return plaintext, nil
}

// Clear clears the encryptor's keys
func (e *HKDFEncryptor) Clear() {
	e.hkdfManager.Clear()
}