package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
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
		// P1-02: Generate DETERMINISTIC decoy data via HKDF (not random)
		// This ensures reproducibility and consistent timing with real shards
		decoyData, err := g.generateDeterministicDecoyData(shardID, uint32(i), shardSize)
		if err != nil {
			return nil, fmt.Errorf("failed to generate decoy data: %w", err)
		}

		// Encrypt using decoy-specific HKDF key
		encryptedShard, err := g.encryptDecoyCharShard(decoyData, shardID, uint32(i), uint32(decoyCount))
		if err != nil {
			// Clean up already created decoys
			for j := 0; j < i; j++ {
				clearBytes(decoys[j].Data)
			}
			clearBytes(decoyData)
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

// generateDeterministicDecoyData generates deterministic pseudorandom data via HKDF.
//
// P1-02: This replaces crypto/rand.Reader to ensure:
//   - Deterministic generation (same inputs = same output)
//   - Uniform timing with real shard generation
//   - Indistinguishability from real encrypted data
//
// Uses HKDF context: "LockBox:decoy-data:{shardID}:{index}"
func (g *DecoyGenerator) generateDeterministicDecoyData(shardID uint32, index uint32, size int) ([]byte, error) {
	if g.hkdfManager == nil {
		return nil, fmt.Errorf("HKDF manager not available for deterministic decoy generation")
	}

	// Derive a seed key for this specific decoy
	context := []byte(fmt.Sprintf("LockBox:decoy-data:%d:%d", shardID, index))
	seedKey, err := g.hkdfManager.DeriveKey(context)
	if err != nil {
		return nil, fmt.Errorf("failed to derive decoy data seed: %w", err)
	}
	defer clearBytes(seedKey)

	// Use the seed key with HKDF to generate pseudorandom data
	// HKDF has a limit of ~8KB (255 * hash_len), so for larger sizes we use multiple rounds
	data := make([]byte, size)

	// Generate data in chunks to avoid HKDF entropy limit
	const maxChunkSize = 8000 // Conservative limit (below 255*32=8160)
	offset := 0

	for offset < size {
		chunkSize := size - offset
		if chunkSize > maxChunkSize {
			chunkSize = maxChunkSize
		}

		// Create HKDF reader for this chunk (include chunk index in context for uniqueness)
		chunkContext := fmt.Sprintf("decoy-data-expansion-chunk-%d", offset/maxChunkSize)
		hkdfReader := hkdf.New(sha256.New, seedKey, nil, []byte(chunkContext))

		if _, err := io.ReadFull(hkdfReader, data[offset:offset+chunkSize]); err != nil {
			return nil, fmt.Errorf("failed to expand decoy data chunk %d: %w", offset/maxChunkSize, err)
		}

		offset += chunkSize
	}

	return data, nil
}

// generateDeterministicNonce generates a deterministic nonce via HKDF.
//
// P1-02: Replaces crypto/rand.Reader for nonce generation.
//
// Parameters:
//   - shardID: unique shard identifier
//   - index: shard index (ensures uniqueness)
//
// Returns:
//   - 24-byte nonce (XChaCha20-Poly1305 nonce size)
//
// Uses HKDF context: "LockBox:decoy-nonce:{shardID}:{index}"
func (g *DecoyGenerator) generateDeterministicNonce(shardID uint32, index uint32) ([]byte, error) {
	if g.hkdfManager == nil {
		return nil, fmt.Errorf("HKDF manager not available for nonce generation")
	}

	// Derive nonce seed for this specific decoy
	context := []byte(fmt.Sprintf("LockBox:decoy-nonce:%d:%d", shardID, index))
	nonceSeed, err := g.hkdfManager.DeriveKey(context)
	if err != nil {
		return nil, fmt.Errorf("failed to derive nonce seed: %w", err)
	}
	defer clearBytes(nonceSeed)

	// Extract 24 bytes for XChaCha20-Poly1305 nonce from the 32-byte seed
	nonce := make([]byte, NonceSize)
	copy(nonce, nonceSeed[:NonceSize])

	return nonce, nil
}

// encryptDecoyCharShard encrypts a decoy character shard with HKDF-derived key.
//
// P1-02: Now uses HKDF key derivation (deterministic) instead of random.
//
// SECURITY: Uses HKDF-derived key from master key via DeriveKeyForDecoyChar().
// This ensures deterministic, reproducible encryption while maintaining
// indistinguishability from real shards. The decoy key is derived consistently
// from the master key + salt, allowing recreation if needed (though decoys
// are never decrypted in normal operation).
func (g *DecoyGenerator) encryptDecoyCharShard(data []byte, shardID uint32, index uint32, total uint32) (*CharacterShard, error) {
	if g.hkdfManager == nil {
		return nil, fmt.Errorf("HKDF manager not available for decoy encryption")
	}

	// P1-02: Derive decoy encryption key via HKDF (deterministic)
	// Uses context "LockBox:decoy-char:{index}"
	decoyKey, err := g.hkdfManager.DeriveKeyForDecoyChar(index)
	if err != nil {
		return nil, fmt.Errorf("failed to derive decoy encryption key: %w", err)
	}
	defer clearBytes(decoyKey)

	// Create cipher
	aead, err := chacha20poly1305.NewX(decoyKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// P1-02: Generate DETERMINISTIC nonce via HKDF
	// Uses context "LockBox:decoy-nonce:{shardID}:{index}"
	nonce, err := g.generateDeterministicNonce(shardID, index)
	if err != nil {
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
		// P1-02: Generate DETERMINISTIC decoy metadata via HKDF (not random)
		decoyMeta, err := g.generateDeterministicDecoyMetadata(shardID, uint32(i), metaSize)
		if err != nil {
			return nil, fmt.Errorf("failed to generate decoy metadata: %w", err)
		}

		// Encrypt using decoy-meta-specific HKDF key
		encryptedShard, err := g.encryptDecoyMetaShard(decoyMeta, shardID, uint32(i), uint32(decoyCount))
		if err != nil {
			for j := 0; j < i; j++ {
				clearBytes(decoys[j].Data)
			}
			clearBytes(decoyMeta)
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

// generateDeterministicDecoyMetadata generates deterministic pseudorandom metadata via HKDF.
//
// P1-02: Similar to generateDeterministicDecoyData but for metadata.
//
// Uses HKDF context: "LockBox:decoy-metadata:{shardID}:{index}"
func (g *DecoyGenerator) generateDeterministicDecoyMetadata(shardID uint32, index uint32, size int) ([]byte, error) {
	if g.hkdfManager == nil {
		return nil, fmt.Errorf("HKDF manager not available for deterministic decoy metadata generation")
	}

	// Derive a seed key for this specific decoy metadata
	context := []byte(fmt.Sprintf("LockBox:decoy-metadata:%d:%d", shardID, index))
	seedKey, err := g.hkdfManager.DeriveKey(context)
	if err != nil {
		return nil, fmt.Errorf("failed to derive decoy metadata seed: %w", err)
	}
	defer clearBytes(seedKey)

	// Use the seed key with HKDF to generate pseudorandom metadata
	// Similar chunking strategy as generateDeterministicDecoyData to avoid entropy limit
	data := make([]byte, size)

	const maxChunkSize = 8000 // Conservative limit to avoid HKDF entropy exhaustion
	offset := 0

	for offset < size {
		chunkSize := size - offset
		if chunkSize > maxChunkSize {
			chunkSize = maxChunkSize
		}

		chunkContext := fmt.Sprintf("decoy-metadata-expansion-chunk-%d", offset/maxChunkSize)
		hkdfReader := hkdf.New(sha256.New, seedKey, nil, []byte(chunkContext))

		if _, err := io.ReadFull(hkdfReader, data[offset:offset+chunkSize]); err != nil {
			return nil, fmt.Errorf("failed to expand decoy metadata chunk %d: %w", offset/maxChunkSize, err)
		}

		offset += chunkSize
	}

	return data, nil
}

// generateDeterministicMetaNonce generates a deterministic nonce for metadata via HKDF.
//
// P1-02: Similar to generateDeterministicNonce but for metadata.
//
// Uses HKDF context: "LockBox:decoy-meta-nonce:{shardID}:{index}"
func (g *DecoyGenerator) generateDeterministicMetaNonce(shardID uint32, index uint32) ([]byte, error) {
	if g.hkdfManager == nil {
		return nil, fmt.Errorf("HKDF manager not available for meta nonce generation")
	}

	// Derive nonce seed for this specific decoy metadata
	context := []byte(fmt.Sprintf("LockBox:decoy-meta-nonce:%d:%d", shardID, index))
	nonceSeed, err := g.hkdfManager.DeriveKey(context)
	if err != nil {
		return nil, fmt.Errorf("failed to derive meta nonce seed: %w", err)
	}
	defer clearBytes(nonceSeed)

	// Extract 24 bytes for XChaCha20-Poly1305 nonce
	nonce := make([]byte, NonceSize)
	copy(nonce, nonceSeed[:NonceSize])

	return nonce, nil
}

// encryptDecoyMetaShard encrypts a decoy metadata shard with HKDF-derived key.
//
// P1-02: Now uses HKDF key derivation (deterministic) instead of random.
// Same approach as encryptDecoyCharShard but for metadata.
func (g *DecoyGenerator) encryptDecoyMetaShard(data []byte, shardID uint32, index uint32, total uint32) (*CharacterShard, error) {
	if g.hkdfManager == nil {
		return nil, fmt.Errorf("HKDF manager not available for decoy metadata encryption")
	}

	// P1-02: Derive decoy metadata encryption key via HKDF (deterministic)
	// Uses context "LockBoxMeta:decoy-meta:{index}"
	decoyKey, err := g.hkdfManager.DeriveKeyForDecoyMeta(index)
	if err != nil {
		return nil, fmt.Errorf("failed to derive decoy meta encryption key: %w", err)
	}
	defer clearBytes(decoyKey)

	// Create cipher
	aead, err := chacha20poly1305.NewX(decoyKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// P1-02: Generate DETERMINISTIC nonce for metadata via HKDF
	// Uses context "LockBox:decoy-meta-nonce:{shardID}:{index}"
	nonce, err := g.generateDeterministicMetaNonce(shardID, index)
	if err != nil {
		return nil, fmt.Errorf("failed to generate meta nonce: %w", err)
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
