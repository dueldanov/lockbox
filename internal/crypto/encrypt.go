package crypto

import (
	"context"
	"crypto/hmac"
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
)

var (
	ErrInvalidShardSize     = errors.New("invalid shard size")
	ErrInvalidShardCount    = errors.New("invalid shard count")
	ErrShardDecryptionFailed = errors.New("shard decryption failed")
	ErrInsufficientShards   = errors.New("insufficient shards for reconstruction")
)

const (
	// Shard parameters
	MinShardSize = 32
	MaxShardSize = 1024 * 1024 // 1MB
	
	// Argon2 parameters for key derivation
	Argon2Time    = 1
	Argon2Memory  = 64 * 1024
	Argon2Threads = 4
	Argon2KeyLen  = 32
)

// CharacterShard represents an encrypted shard of data
type CharacterShard struct {
	ID        uint32
	Index     uint32
	Total     uint32
	Data      []byte
	Nonce     []byte
	Timestamp int64
	Checksum  []byte
}

// ShardEncryptor handles character shard encryption and decryption
type ShardEncryptor struct {
	mu           sync.RWMutex
	hkdfManager  *HKDFManager
	shardSize    int
	secureMemory *SecureMemoryPool
}

// NewShardEncryptor creates a new shard encryptor
func NewShardEncryptor(masterKey []byte, shardSize int) (*ShardEncryptor, error) {
	if shardSize < MinShardSize || shardSize > MaxShardSize {
		return nil, fmt.Errorf("%w: size must be between %d and %d", ErrInvalidShardSize, MinShardSize, MaxShardSize)
	}

	hkdfManager, err := NewHKDFManager(masterKey)
	if err != nil {
		return nil, err
	}

	return &ShardEncryptor{
		hkdfManager:  hkdfManager,
		shardSize:    shardSize,
		secureMemory: NewSecureMemoryPool(10), // Pool of 10 secure buffers
	}, nil
}

// EncryptData encrypts data and splits it into character shards
func (e *ShardEncryptor) EncryptData(data []byte) ([]*CharacterShard, error) {
	e.mu.RLock()
	shardSize := e.shardSize
	e.mu.RUnlock()

	// Calculate number of shards needed
	dataLen := len(data)
	numShards := (dataLen + shardSize - 1) / shardSize
	
	if numShards == 0 {
		return nil, ErrInvalidShardCount
	}

	shards := make([]*CharacterShard, numShards)
	shardID := generateShardID()

	// Process each shard
	for i := 0; i < numShards; i++ {
		start := i * shardSize
		end := start + shardSize
		if end > dataLen {
			end = dataLen
		}

		// Get shard data
		shardData := data[start:end]

		// Encrypt shard
		encryptedShard, err := e.encryptShard(shardData, shardID, uint32(i), uint32(numShards))
		if err != nil {
			// Clean up already created shards
			for j := 0; j < i; j++ {
				clearBytes(shards[j].Data)
			}
			return nil, fmt.Errorf("failed to encrypt shard %d: %w", i, err)
		}

		shards[i] = encryptedShard
	}

	return shards, nil
}

// EncryptDataWithContext encrypts data with logging support
func (e *ShardEncryptor) EncryptDataWithContext(ctx context.Context, data []byte) ([]*CharacterShard, error) {
	start := time.Now()
	shards, err := e.EncryptData(data)
	logging.LogFromContextWithDuration(ctx, logging.PhaseEncryption, "EncryptData",
		fmt.Sprintf("dataLen=%d, shardCount=%d", len(data), len(shards)), time.Since(start), err)
	return shards, err
}

// encryptShard encrypts a single shard
func (e *ShardEncryptor) encryptShard(data []byte, shardID uint32, index uint32, total uint32) (*CharacterShard, error) {
	// Derive key for this shard
	shardKey, err := e.hkdfManager.DeriveKeyForShard(shardID + index)
	if err != nil {
		return nil, err
	}
	defer clearBytes(shardKey)

	// Create cipher
	aead, err := chacha20poly1305.NewX(shardKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Generate nonce
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Additional data for AEAD
	additionalData := make([]byte, 12)
	binary.BigEndian.PutUint32(additionalData[0:4], shardID)
	binary.BigEndian.PutUint32(additionalData[4:8], index)
	binary.BigEndian.PutUint32(additionalData[8:12], total)

	// Get secure buffer for encryption
	secureBuffer := e.secureMemory.Get()
	defer e.secureMemory.Put(secureBuffer)

	// Encrypt data
	ciphertext := aead.Seal(nil, nonce, data, additionalData)

	// Calculate checksum
	checksum := calculateChecksum(ciphertext)

	return &CharacterShard{
		ID:        shardID,
		Index:     index,
		Total:     total,
		Data:      ciphertext,
		Nonce:     nonce,
		Timestamp: time.Now().Unix(),
		Checksum:  checksum,
	}, nil
}

// DecryptShards decrypts and reconstructs data from character shards
func (e *ShardEncryptor) DecryptShards(shards []*CharacterShard) ([]byte, error) {
	if len(shards) == 0 {
		return nil, ErrInsufficientShards
	}

	// Verify all shards belong to same set
	shardID := shards[0].ID
	totalShards := shards[0].Total

	// Create map for ordering shards
	shardMap := make(map[uint32]*CharacterShard)
	
	for _, shard := range shards {
		if shard.ID != shardID || shard.Total != totalShards {
			return nil, errors.New("mismatched shard set")
		}
		
		// Verify checksum
		if !verifyChecksum(shard.Data, shard.Checksum) {
			return nil, fmt.Errorf("shard %d checksum verification failed", shard.Index)
		}
		
		shardMap[shard.Index] = shard
	}

	// Check if we have all shards
	if len(shardMap) != int(totalShards) {
		return nil, fmt.Errorf("%w: have %d, need %d", ErrInsufficientShards, len(shardMap), totalShards)
	}

	// Decrypt shards in order
	decryptedData := make([]byte, 0)
	
	for i := uint32(0); i < totalShards; i++ {
		shard, exists := shardMap[i]
		if !exists {
			return nil, fmt.Errorf("missing shard %d", i)
		}

		decrypted, err := e.decryptShard(shard)
		if err != nil {
			clearBytes(decryptedData)
			return nil, fmt.Errorf("failed to decrypt shard %d: %w", i, err)
		}

		decryptedData = append(decryptedData, decrypted...)
		clearBytes(decrypted)
	}

	return decryptedData, nil
}

// DecryptShardsWithContext decrypts shards with logging support
func (e *ShardEncryptor) DecryptShardsWithContext(ctx context.Context, shards []*CharacterShard) ([]byte, error) {
	start := time.Now()
	data, err := e.DecryptShards(shards)
	logging.LogFromContextWithDuration(ctx, logging.PhaseShardDecryption, "DecryptShards",
		fmt.Sprintf("shardCount=%d, dataLen=%d", len(shards), len(data)), time.Since(start), err)
	return data, err
}

// decryptShard decrypts a single shard
func (e *ShardEncryptor) decryptShard(shard *CharacterShard) ([]byte, error) {
	// Derive key for this shard
	shardKey, err := e.hkdfManager.DeriveKeyForShard(shard.ID + shard.Index)
	if err != nil {
		return nil, err
	}
	defer clearBytes(shardKey)

	// Create cipher
	aead, err := chacha20poly1305.NewX(shardKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Additional data for AEAD
	additionalData := make([]byte, 12)
	binary.BigEndian.PutUint32(additionalData[0:4], shard.ID)
	binary.BigEndian.PutUint32(additionalData[4:8], shard.Index)
	binary.BigEndian.PutUint32(additionalData[8:12], shard.Total)

	// Get secure buffer for decryption
	secureBuffer := e.secureMemory.Get()
	defer e.secureMemory.Put(secureBuffer)

	// Decrypt data
	plaintext, err := aead.Open(nil, shard.Nonce, shard.Data, additionalData)
	if err != nil {
		return nil, ErrShardDecryptionFailed
	}

	return plaintext, nil
}

// ReencryptShards re-encrypts shards with a new key
func (e *ShardEncryptor) ReencryptShards(shards []*CharacterShard, newMasterKey []byte) ([]*CharacterShard, error) {
	// Decrypt with current key
	data, err := e.DecryptShards(shards)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt shards: %w", err)
	}
	defer clearBytes(data)

	// Update master key
	if err := e.hkdfManager.UpdateMasterKey(newMasterKey); err != nil {
		return nil, fmt.Errorf("failed to update master key: %w", err)
	}

	// Re-encrypt with new key
	return e.EncryptData(data)
}

// Clear clears the encryptor's keys and secure memory
func (e *ShardEncryptor) Clear() {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.hkdfManager.Clear()
	e.secureMemory.Clear()
}

// Helper functions

func generateShardID() uint32 {
	var id uint32
	binary.Read(rand.Reader, binary.BigEndian, &id)
	return id
}

// calculateChecksum computes a SHA-256 based checksum for data integrity.
// Returns first 16 bytes of SHA-256 hash for compact storage while maintaining
// collision resistance (128 bits is sufficient for integrity checks).
func calculateChecksum(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:16] // 128 bits is sufficient for integrity
}

// verifyChecksum validates data integrity using constant-time comparison.
// Uses hmac.Equal to prevent timing attacks.
func verifyChecksum(data, checksum []byte) bool {
	calculated := calculateChecksum(data)
	// Use constant-time comparison to prevent timing attacks
	return hmac.Equal(calculated, checksum)
}

// ShardStorage interface for storing encrypted shards
type ShardStorage interface {
	Store(shard *CharacterShard) error
	Retrieve(shardID uint32, index uint32) (*CharacterShard, error)
	RetrieveAll(shardID uint32) ([]*CharacterShard, error)
	Delete(shardID uint32) error
}

// === V2 Methods for Shard Indistinguishability ===
// These methods use DeriveKeyForPosition(bundleID, position) instead of
// DeriveKeyForShard(shardID + index) for uniform key derivation that
// doesn't leak shard type information.

// EncryptDataV2 encrypts data using V2 key derivation (DeriveKeyForPosition).
// This method is used for Shard Indistinguishability where all shards
// (real and decoy) must use the same key derivation pattern.
//
// SECURITY: Real shards use position = originalIndex (0, 1, 2...)
// Decoy shards should use position = high random values to avoid collisions.
func (e *ShardEncryptor) EncryptDataV2(data []byte, bundleID string) ([]*CharacterShard, error) {
	e.mu.RLock()
	shardSize := e.shardSize
	e.mu.RUnlock()

	// Calculate number of shards needed
	dataLen := len(data)
	numShards := (dataLen + shardSize - 1) / shardSize

	if numShards == 0 {
		return nil, ErrInvalidShardCount
	}

	shards := make([]*CharacterShard, numShards)

	// Process each shard
	for i := 0; i < numShards; i++ {
		start := i * shardSize
		end := start + shardSize
		if end > dataLen {
			end = dataLen
		}

		// Get shard data
		shardData := data[start:end]

		// Encrypt shard using V2 key derivation
		encryptedShard, err := e.encryptShardV2(shardData, bundleID, uint32(i), uint32(numShards))
		if err != nil {
			// Clean up already created shards
			for j := 0; j < i; j++ {
				clearBytes(shards[j].Data)
			}
			return nil, fmt.Errorf("failed to encrypt shard %d: %w", i, err)
		}

		shards[i] = encryptedShard
	}

	return shards, nil
}

// EncryptSingleShardV2 encrypts a single piece of data with a specific position.
// This is used when creating shards individually (e.g., real shards with position 0,1,2
// and decoy shards with high random positions).
//
// SECURITY: The position determines the key derivation. Real shards use sequential
// positions (0, 1, 2...), decoys use random high positions to avoid collision.
func (e *ShardEncryptor) EncryptSingleShardV2(data []byte, bundleID string, position uint32) (*CharacterShard, error) {
	return e.encryptShardV2(data, bundleID, position, 1)
}

// encryptShardV2 encrypts a single shard using V2 key derivation.
// Uses DeriveKeyForPosition(bundleID, position) for uniform key derivation.
func (e *ShardEncryptor) encryptShardV2(data []byte, bundleID string, position uint32, total uint32) (*CharacterShard, error) {
	// V2: Derive key using bundleID and position (no type info!)
	shardKey, err := e.hkdfManager.DeriveKeyForPosition(bundleID, position)
	if err != nil {
		return nil, err
	}
	defer clearBytes(shardKey)

	// Create cipher
	aead, err := chacha20poly1305.NewX(shardKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Generate nonce
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// V2.1: AAD = SHA256(bundleID)[0:32] || realIndexBE32[0:4]
	// Full 32-byte hash prevents collision attacks on truncated hashes
	bundleHash := sha256.Sum256([]byte(bundleID))
	additionalData := make([]byte, 36)
	copy(additionalData[0:32], bundleHash[:])
	binary.BigEndian.PutUint32(additionalData[32:36], position)

	// Encrypt data
	ciphertext := aead.Seal(nil, nonce, data, additionalData)

	return &CharacterShard{
		ID:        0, // V2 doesn't use random ID (bundleID serves this purpose)
		Index:     position,
		Total:     total,
		Data:      ciphertext,
		Nonce:     nonce,
		Timestamp: time.Now().Unix(),
		Checksum:  calculateChecksum(ciphertext),
	}, nil
}

// DecryptShardV2 decrypts a single shard using V2 key derivation.
// Used for trial decryption where we try keys for positions 0..realCount-1.
//
// Parameters:
//   - shard: The encrypted shard to decrypt
//   - bundleID: The bundle identifier
//   - keyPosition: The position to derive the key from (NOT the shard's storage position)
//
// SECURITY: During trial decryption, keyPosition iterates 0..realCount-1
// and we try each key against all stored shards until AEAD auth succeeds.
func (e *ShardEncryptor) DecryptShardV2(shard *CharacterShard, bundleID string, keyPosition uint32) ([]byte, error) {
	// V2: Derive key using bundleID and keyPosition
	shardKey, err := e.hkdfManager.DeriveKeyForPosition(bundleID, keyPosition)
	if err != nil {
		return nil, err
	}
	defer clearBytes(shardKey)

	// Create cipher
	aead, err := chacha20poly1305.NewX(shardKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// V2.1: AAD = SHA256(bundleID)[0:32] || realIndexBE32[0:4]
	// Must match encryption exactly
	bundleHash := sha256.Sum256([]byte(bundleID))
	additionalData := make([]byte, 36)
	copy(additionalData[0:32], bundleHash[:])
	binary.BigEndian.PutUint32(additionalData[32:36], keyPosition)

	// Decrypt data - AEAD will fail if wrong key (trial decryption relies on this)
	plaintext, err := aead.Open(nil, shard.Nonce, shard.Data, additionalData)
	if err != nil {
		return nil, ErrShardDecryptionFailed
	}

	return plaintext, nil
}

// DecryptShardV2WithHKDF decrypts a shard using a custom HKDF manager.
// Used when the bundle's salt differs from the session salt.
func (e *ShardEncryptor) DecryptShardV2WithHKDF(shard *CharacterShard, bundleID string, keyPosition uint32, hkdf *HKDFManager) ([]byte, error) {
	// Derive key using the provided HKDF manager
	shardKey, err := hkdf.DeriveKeyForPosition(bundleID, keyPosition)
	if err != nil {
		return nil, err
	}
	defer clearBytes(shardKey)

	// Create cipher
	aead, err := chacha20poly1305.NewX(shardKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// V2.1: AAD = SHA256(bundleID)[0:32] || realIndexBE32[0:4]
	bundleHash := sha256.Sum256([]byte(bundleID))
	additionalData := make([]byte, 36)
	copy(additionalData[0:32], bundleHash[:])
	binary.BigEndian.PutUint32(additionalData[32:36], keyPosition)

	// Decrypt data
	plaintext, err := aead.Open(nil, shard.Nonce, shard.Data, additionalData)
	if err != nil {
		return nil, ErrShardDecryptionFailed
	}

	return plaintext, nil
}

// GetSalt returns a copy of the HKDF salt for persistence.
// Must be saved with the bundle to enable future decryption.
func (e *ShardEncryptor) GetSalt() []byte {
	return e.hkdfManager.GetSalt()
}

// GetHKDFManager returns the internal HKDF manager.
// Used for trial decryption recovery where direct access to key derivation is needed.
func (e *ShardEncryptor) GetHKDFManager() *HKDFManager {
	return e.hkdfManager
}

// CloneWithSalt creates a new ShardEncryptor with the same master key but different salt.
// Used to restore encryption for a bundle with its persisted salt.
func (e *ShardEncryptor) CloneWithSalt(salt []byte) (*ShardEncryptor, error) {
	hkdfClone, err := e.hkdfManager.CloneWithSalt(salt)
	if err != nil {
		return nil, err
	}

	return &ShardEncryptor{
		hkdfManager:  hkdfClone,
		shardSize:    e.shardSize,
		secureMemory: NewSecureMemoryPool(10),
	}, nil
}