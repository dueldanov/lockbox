package crypto

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/dueldanov/lockbox/v2/internal/logging"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
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

// NewHKDFManagerWithSalt creates a new HKDF manager with a provided salt
// Use this to restore a manager with a previously saved salt
func NewHKDFManagerWithSalt(masterKey []byte, salt []byte) (*HKDFManager, error) {
	if len(masterKey) != HKDFKeySize {
		return nil, fmt.Errorf("%w: expected %d, got %d", ErrInvalidKeySize, HKDFKeySize, len(masterKey))
	}

	if len(salt) != HKDFSaltSize {
		return nil, fmt.Errorf("%w: expected %d, got %d", ErrInvalidSaltSize, HKDFSaltSize, len(salt))
	}

	// Create manager with properly allocated key and salt
	manager := &HKDFManager{
		masterKey: make([]byte, len(masterKey)),
		salt:      make([]byte, len(salt)),
		derivedKeysPool: sync.Pool{
			New: func() interface{} {
				return make([]byte, HKDFKeySize)
			},
		},
	}

	copy(manager.masterKey, masterKey)
	copy(manager.salt, salt)

	return manager, nil
}

// DeriveKey derives a new key from the master key using HKDF
func (h *HKDFManager) DeriveKey(hkdfContext []byte) ([]byte, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	// Get a buffer from the pool
	derivedKey := h.derivedKeysPool.Get().([]byte)
	defer h.derivedKeysPool.Put(derivedKey)

	// Create HKDF reader
	hkdfReader := hkdf.New(sha256.New, h.masterKey, h.salt, append([]byte(HKDFInfoString), hkdfContext...))

	// Derive key
	if _, err := io.ReadFull(hkdfReader, derivedKey); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeyDerivationFailed, err)
	}

	// Return a copy of the derived key
	result := make([]byte, len(derivedKey))
	copy(result, derivedKey)

	return result, nil
}

// DeriveKeyWithContext derives a key with logging support
func (h *HKDFManager) DeriveKeyWithContext(ctx context.Context, hkdfContext []byte) ([]byte, error) {
	start := time.Now()
	key, err := h.DeriveKey(hkdfContext)
	logging.LogFromContextWithDuration(ctx, logging.PhaseKeyDerivation, "DeriveHKDFKey",
		fmt.Sprintf("contextLen=%d", len(hkdfContext)), time.Since(start), err)
	return key, err
}

// DeriveKeyForShard derives a key specifically for a shard
func (h *HKDFManager) DeriveKeyForShard(shardID uint32) ([]byte, error) {
	context := make([]byte, 4)
	binary.BigEndian.PutUint32(context, shardID)
	return h.DeriveKey(context)
}

// Purpose-specific HKDF key derivation according to LockBox requirements
// These methods generate unique keys for each character/metadata fragment

// DeriveKeyForRealChar derives a key for a real character at the given index.
// Uses info string format: "LockBox:real-char:{index}"
func (h *HKDFManager) DeriveKeyForRealChar(index uint32) ([]byte, error) {
	context := []byte(fmt.Sprintf("LockBox:real-char:%d", index))
	return h.DeriveKey(context)
}

// DeriveKeyForDecoyChar derives a key for a decoy character at the given index.
// Uses info string format: "LockBox:decoy-char:{index}"
// Note: Uses numeric index (not alphabetic) to support >26 decoys
func (h *HKDFManager) DeriveKeyForDecoyChar(index uint32) ([]byte, error) {
	context := []byte(fmt.Sprintf("LockBox:decoy-char:%d", index))
	return h.DeriveKey(context)
}

// DeriveKeyForPosition derives a key for a shard at the given position.
// This is the UNIFIED key derivation method for shard indistinguishability.
//
// SECURITY: This context does NOT contain "real" or "decoy" - all shards use
// the same derivation format. Real shards use position=originalIndex,
// decoy shards use position=randomHighIndex.
//
// Uses info string format: "LockBox:shard:{bundleID}:{position}"
func (h *HKDFManager) DeriveKeyForPosition(bundleID string, position uint32) ([]byte, error) {
	context := h.GetContextForPosition(bundleID, position)
	return h.DeriveKey(context)
}

// GetContextForPosition returns the HKDF context bytes for a position.
// Used for testing to verify no type markers are present.
func (h *HKDFManager) GetContextForPosition(bundleID string, position uint32) []byte {
	return []byte(fmt.Sprintf("LockBox:shard:%s:%d", bundleID, position))
}

// DeriveKeyForRealMeta derives a key for a real metadata fragment at the given index.
// Uses info string format: "LockBoxMeta:real-meta:{index}"
func (h *HKDFManager) DeriveKeyForRealMeta(index uint32) ([]byte, error) {
	context := []byte(fmt.Sprintf("LockBoxMeta:real-meta:%d", index))
	return h.DeriveKey(context)
}

// DeriveKeyForDecoyMeta derives a key for a decoy metadata fragment at the given index.
// Uses info string format: "LockBoxMeta:decoy-meta:{index}"
func (h *HKDFManager) DeriveKeyForDecoyMeta(index uint32) ([]byte, error) {
	context := []byte(fmt.Sprintf("LockBoxMeta:decoy-meta:%d", index))
	return h.DeriveKey(context)
}

// CharacterKeyType represents the type of character for key derivation
type CharacterKeyType int

const (
	KeyTypeRealChar CharacterKeyType = iota
	KeyTypeDecoyChar
	KeyTypeRealMeta
	KeyTypeDecoyMeta
)

// DeriveKeyByType derives a key based on type and index.
// This is a convenience method that dispatches to the appropriate method.
func (h *HKDFManager) DeriveKeyByType(keyType CharacterKeyType, index uint32) ([]byte, error) {
	switch keyType {
	case KeyTypeRealChar:
		return h.DeriveKeyForRealChar(index)
	case KeyTypeDecoyChar:
		return h.DeriveKeyForDecoyChar(index)
	case KeyTypeRealMeta:
		return h.DeriveKeyForRealMeta(index)
	case KeyTypeDecoyMeta:
		return h.DeriveKeyForDecoyMeta(index)
	default:
		return nil, fmt.Errorf("unknown key type: %d", keyType)
	}
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

// CloneWithSalt creates a new HKDFManager with the same master key but different salt.
// Use this to restore key derivation for a bundle with its persisted salt.
// The caller is responsible for calling Clear() on the returned manager.
func (h *HKDFManager) CloneWithSalt(salt []byte) (*HKDFManager, error) {
	h.mu.RLock()
	masterKeyCopy := make([]byte, len(h.masterKey))
	copy(masterKeyCopy, h.masterKey)
	h.mu.RUnlock()

	// Create new manager with copied master key and provided salt
	return NewHKDFManagerWithSalt(masterKeyCopy, salt)
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

// NewHKDFEncryptorWithSalt creates a new encryptor with a provided salt
// Use this to restore an encryptor with a previously saved salt
func NewHKDFEncryptorWithSalt(masterKey []byte, salt []byte) (*HKDFEncryptor, error) {
	manager, err := NewHKDFManagerWithSalt(masterKey, salt)
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

// GetSalt returns a copy of the current salt
func (e *HKDFEncryptor) GetSalt() []byte {
	return e.hkdfManager.GetSalt()
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