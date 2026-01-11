package crypto

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// DecoyType indicates whether a shard contains real or decoy data
type DecoyType int

const (
	ShardTypeReal DecoyType = iota
	ShardTypeDecoy
)

// DecoyConfig holds configuration for decoy generation per tier
type DecoyConfig struct {
	// DecoyRatio is the ratio of decoy chars to real chars
	// Basic=0.5, Standard=1.0, Premium=1.5, Elite=2.0
	DecoyRatio float64

	// MetadataDecoyRatio is the ratio of decoy metadata
	// Basic=0, Standard=0, Premium=1.0, Elite=2.0
	MetadataDecoyRatio float64
}

// MixedShard represents either a real or decoy shard
// Storage nodes cannot distinguish between the two
type MixedShard struct {
	CharacterShard
	// ShardType is ONLY known to the client, never sent to storage
	ShardType DecoyType
	// OriginalIndex is the index in the original data (real) or decoy set
	OriginalIndex uint32
}

// DecoyGenerator generates decoy data that is indistinguishable from real data
type DecoyGenerator struct {
	mu          sync.RWMutex
	hkdfManager *HKDFManager
	config      DecoyConfig
}

// NewDecoyGenerator creates a new decoy generator with the given configuration
func NewDecoyGenerator(hkdfManager *HKDFManager, config DecoyConfig) *DecoyGenerator {
	return &DecoyGenerator{
		hkdfManager: hkdfManager,
		config:      config,
	}
}

// GenerateDecoyShards generates decoy shards for a given number of real shards
// Returns shards that are cryptographically indistinguishable from real data
func (g *DecoyGenerator) GenerateDecoyShards(realShardCount int, shardSize int) ([]*MixedShard, error) {
	g.mu.RLock()
	decoyRatio := g.config.DecoyRatio
	g.mu.RUnlock()

	// Calculate number of decoys based on ratio
	decoyCount := int(float64(realShardCount) * decoyRatio)
	if decoyCount == 0 && decoyRatio > 0 {
		decoyCount = 1 // At least one decoy if ratio > 0
	}

	decoys := make([]*MixedShard, decoyCount)
	shardID := generateShardID()

	for i := 0; i < decoyCount; i++ {
		// Generate random decoy data of same size as real shards
		decoyData := make([]byte, shardSize)
		if _, err := io.ReadFull(rand.Reader, decoyData); err != nil {
			return nil, fmt.Errorf("failed to generate decoy data: %w", err)
		}

		// Encrypt using decoy-specific HKDF key
		encryptedShard, err := g.encryptDecoyCharShard(decoyData, shardID, uint32(i), uint32(decoyCount))
		if err != nil {
			// Clean up already created decoys
			for j := 0; j < i; j++ {
				clearBytes(decoys[j].Data)
			}
			return nil, fmt.Errorf("failed to encrypt decoy %d: %w", i, err)
		}

		decoys[i] = &MixedShard{
			CharacterShard: *encryptedShard,
			ShardType:      ShardTypeDecoy,
			OriginalIndex:  uint32(i),
		}

		clearBytes(decoyData)
	}

	return decoys, nil
}

// encryptDecoyCharShard encrypts a decoy character shard with a random key.
//
// SECURITY: Uses completely random key (NOT derived from master key).
// This ensures that even with master key access, an attacker cannot
// distinguish decoy from real shards by trying different KDF contexts.
// The decoy key is generated fresh and discarded - we never need to
// decrypt decoys, only real shards.
func (g *DecoyGenerator) encryptDecoyCharShard(data []byte, shardID uint32, index uint32, total uint32) (*CharacterShard, error) {
	// SECURITY FIX: Generate completely random key for decoy encryption.
	// NOT derived from master key - prevents KDF context leak attack.
	// Since decoys are never decrypted, the key is ephemeral and discarded.
	decoyKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, decoyKey); err != nil {
		return nil, fmt.Errorf("failed to generate random decoy key: %w", err)
	}
	defer clearBytes(decoyKey)

	// Create cipher
	aead, err := chacha20poly1305.NewX(decoyKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Generate nonce
	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Additional data for AEAD (same format as real shards)
	additionalData := make([]byte, 12)
	binary.BigEndian.PutUint32(additionalData[0:4], shardID)
	binary.BigEndian.PutUint32(additionalData[4:8], index)
	binary.BigEndian.PutUint32(additionalData[8:12], total)

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

// GenerateDecoyMetadata generates decoy metadata shards
func (g *DecoyGenerator) GenerateDecoyMetadata(realMetaCount int, metaSize int) ([]*MixedShard, error) {
	g.mu.RLock()
	metaRatio := g.config.MetadataDecoyRatio
	g.mu.RUnlock()

	// No metadata decoys for Basic/Standard tiers
	if metaRatio == 0 {
		return nil, nil
	}

	// Calculate number of decoy metadata fragments
	decoyCount := int(float64(realMetaCount) * metaRatio)
	if decoyCount == 0 && metaRatio > 0 {
		decoyCount = 1
	}

	decoys := make([]*MixedShard, decoyCount)
	shardID := generateShardID()

	for i := 0; i < decoyCount; i++ {
		// Generate random decoy metadata
		decoyMeta := make([]byte, metaSize)
		if _, err := io.ReadFull(rand.Reader, decoyMeta); err != nil {
			return nil, fmt.Errorf("failed to generate decoy metadata: %w", err)
		}

		// Encrypt using decoy-meta-specific HKDF key
		encryptedShard, err := g.encryptDecoyMetaShard(decoyMeta, shardID, uint32(i), uint32(decoyCount))
		if err != nil {
			for j := 0; j < i; j++ {
				clearBytes(decoys[j].Data)
			}
			return nil, fmt.Errorf("failed to encrypt decoy metadata %d: %w", i, err)
		}

		decoys[i] = &MixedShard{
			CharacterShard: *encryptedShard,
			ShardType:      ShardTypeDecoy,
			OriginalIndex:  uint32(i),
		}

		clearBytes(decoyMeta)
	}

	return decoys, nil
}

// encryptDecoyMetaShard encrypts a decoy metadata shard with a random key.
//
// SECURITY: Uses completely random key (NOT derived from master key).
// Same security rationale as encryptDecoyCharShard - prevents KDF context leak.
func (g *DecoyGenerator) encryptDecoyMetaShard(data []byte, shardID uint32, index uint32, total uint32) (*CharacterShard, error) {
	// SECURITY FIX: Generate completely random key for decoy metadata encryption.
	// NOT derived from master key - prevents KDF context leak attack.
	decoyKey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, decoyKey); err != nil {
		return nil, fmt.Errorf("failed to generate random decoy meta key: %w", err)
	}
	defer clearBytes(decoyKey)

	// Create cipher
	aead, err := chacha20poly1305.NewX(decoyKey)
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

// ShardMixer handles mixing real and decoy shards for storage
type ShardMixer struct {
	mu sync.RWMutex
	// realIndexMap maps mixed index to original real shard index
	// This is kept only on the client side, never shared with storage
	realIndexMap map[uint32]uint32
}

// NewShardMixer creates a new shard mixer
func NewShardMixer() *ShardMixer {
	return &ShardMixer{
		realIndexMap: make(map[uint32]uint32),
	}
}

// MixShards combines real and decoy shards into a randomly ordered set
// Returns the mixed shards and a mapping to recover original order
// The mapping should be stored securely by the client, never shared with storage nodes
func (m *ShardMixer) MixShards(realShards []*CharacterShard, decoyShards []*MixedShard) ([]*MixedShard, map[uint32]uint32, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	totalCount := len(realShards) + len(decoyShards)
	mixed := make([]*MixedShard, totalCount)
	realIndexMap := make(map[uint32]uint32)

	// Generate random permutation
	permutation := make([]int, totalCount)
	for i := range permutation {
		permutation[i] = i
	}
	shuffleInPlace(permutation)

	// Place real shards at random positions
	for i, shard := range realShards {
		pos := permutation[i]
		mixed[pos] = &MixedShard{
			CharacterShard: *shard,
			ShardType:      ShardTypeReal,
			OriginalIndex:  uint32(i),
		}
		realIndexMap[uint32(pos)] = uint32(i)
	}

	// Place decoy shards at remaining positions
	for i, shard := range decoyShards {
		pos := permutation[len(realShards)+i]
		mixed[pos] = shard
	}

	return mixed, realIndexMap, nil
}

// ExtractRealShards extracts and reorders real shards from a mixed set
// Uses the mapping created during MixShards
func (m *ShardMixer) ExtractRealShards(mixed []*MixedShard, realIndexMap map[uint32]uint32) ([]*CharacterShard, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	realCount := len(realIndexMap)
	realShards := make([]*CharacterShard, realCount)

	for mixedIdx, originalIdx := range realIndexMap {
		if int(mixedIdx) >= len(mixed) {
			return nil, fmt.Errorf("invalid mixed index: %d", mixedIdx)
		}
		if int(originalIdx) >= realCount {
			return nil, fmt.Errorf("invalid original index: %d", originalIdx)
		}
		realShards[originalIdx] = &mixed[mixedIdx].CharacterShard
	}

	// Verify all real shards were found
	for i, shard := range realShards {
		if shard == nil {
			return nil, fmt.Errorf("missing real shard at index %d", i)
		}
	}

	return realShards, nil
}

// shuffleInPlace performs Fisher-Yates shuffle on a slice
func shuffleInPlace(slice []int) {
	for i := len(slice) - 1; i > 0; i-- {
		var j int32
		binary.Read(rand.Reader, binary.BigEndian, &j)
		jPos := int(j) % (i + 1)
		if jPos < 0 {
			jPos = -jPos
		}
		slice[i], slice[jPos] = slice[jPos], slice[i]
	}
}

// TierDecoyConfig returns the DecoyConfig for a given tier
func TierDecoyConfig(shardCopies int, decoyRatio, metadataDecoyRatio float64) DecoyConfig {
	return DecoyConfig{
		DecoyRatio:         decoyRatio,
		MetadataDecoyRatio: metadataDecoyRatio,
	}
}

// DecoyStats holds statistics about decoy generation
type DecoyStats struct {
	RealShardCount     int
	DecoyShardCount    int
	RealMetaCount      int
	DecoyMetaCount     int
	TotalShards        int
	DecoyRatio         float64
	MetadataDecoyRatio float64
}

// GetDecoyStats returns statistics about a mixed shard set
func GetDecoyStats(mixed []*MixedShard, config DecoyConfig) DecoyStats {
	var realCount, decoyCount int
	for _, shard := range mixed {
		if shard.ShardType == ShardTypeReal {
			realCount++
		} else {
			decoyCount++
		}
	}

	return DecoyStats{
		RealShardCount:     realCount,
		DecoyShardCount:    decoyCount,
		TotalShards:        len(mixed),
		DecoyRatio:         config.DecoyRatio,
		MetadataDecoyRatio: config.MetadataDecoyRatio,
	}
}
