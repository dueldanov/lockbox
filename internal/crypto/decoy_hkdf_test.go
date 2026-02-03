package crypto

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestDecoyGeneration_Deterministic verifies that decoy generation is deterministic with same HKDF.
//
// P1-02: This ensures decoys are reproducible (not random).
func TestDecoyGeneration_Deterministic(t *testing.T) {
	// Create master key
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}

	// Create two HKDF managers with SAME master key and salt
	hkdf1, err := NewHKDFManager(masterKey)
	require.NoError(t, err)
	defer hkdf1.Clear()

	salt := hkdf1.GetSalt()

	hkdf2, err := NewHKDFManagerWithSalt(masterKey, salt)
	require.NoError(t, err)
	defer hkdf2.Clear()

	// Create generators
	config := DecoyConfig{DecoyRatio: 1.0}
	gen1 := NewDecoyGenerator(hkdf1, config)
	gen2 := NewDecoyGenerator(hkdf2, config)

	// Test deterministic helper functions directly (bypassing random shardID)
	fixedShardID := uint32(12345)

	// Generate deterministic decoy data
	data1, err := gen1.generateDeterministicDecoyData(fixedShardID, 0, 1024)
	require.NoError(t, err)

	data2, err := gen2.generateDeterministicDecoyData(fixedShardID, 0, 1024)
	require.NoError(t, err)

	// CRITICAL: Data should be IDENTICAL (deterministic)
	require.Equal(t, data1, data2, "Decoy data should be deterministic with same HKDF")

	// Generate deterministic nonce
	nonce1, err := gen1.generateDeterministicNonce(fixedShardID, 0)
	require.NoError(t, err)

	nonce2, err := gen2.generateDeterministicNonce(fixedShardID, 0)
	require.NoError(t, err)

	// CRITICAL: Nonce should be IDENTICAL
	require.Equal(t, nonce1, nonce2, "Nonce should be deterministic")

	// Encrypt with deterministic key
	encrypted1, err := gen1.encryptDecoyCharShard(data1, fixedShardID, 0, 1)
	require.NoError(t, err)

	encrypted2, err := gen2.encryptDecoyCharShard(data2, fixedShardID, 0, 1)
	require.NoError(t, err)

	// CRITICAL: Encrypted shards should be IDENTICAL
	require.Equal(t, encrypted1.Data, encrypted2.Data, "Encrypted decoy should be deterministic")
	require.Equal(t, encrypted1.Nonce, encrypted2.Nonce, "Nonce should be deterministic")
	require.Equal(t, encrypted1.Checksum, encrypted2.Checksum, "Checksum should be deterministic")
}

// TestDecoyGeneration_DifferentSalts verifies that decoys differ with different salts.
//
// P1-02: Ensures salt provides randomness across different sessions.
func TestDecoyGeneration_DifferentSalts(t *testing.T) {
	// Create master key
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}

	// Create two HKDF managers with DIFFERENT salts
	hkdf1, err := NewHKDFManager(masterKey)
	require.NoError(t, err)
	defer hkdf1.Clear()

	hkdf2, err := NewHKDFManager(masterKey)
	require.NoError(t, err)
	defer hkdf2.Clear()

	// Verify salts are different
	salt1 := hkdf1.GetSalt()
	salt2 := hkdf2.GetSalt()
	require.NotEqual(t, salt1, salt2, "Salts should be different")

	// Create generators
	config := DecoyConfig{DecoyRatio: 1.0}
	gen1 := NewDecoyGenerator(hkdf1, config)
	gen2 := NewDecoyGenerator(hkdf2, config)

	// Generate decoys
	decoys1, err := gen1.GenerateDecoyShards(3, 1024)
	require.NoError(t, err)

	decoys2, err := gen2.GenerateDecoyShards(3, 1024)
	require.NoError(t, err)

	// CRITICAL: Decoys should be DIFFERENT (different salts)
	for i := 0; i < 3; i++ {
		require.NotEqual(t, decoys1[i].Data, decoys2[i].Data,
			"Decoy %d data should differ with different salts", i)
		require.NotEqual(t, decoys1[i].Nonce, decoys2[i].Nonce,
			"Decoy %d nonce should differ with different salts", i)
	}
}

// TestDecoyMetadata_Deterministic verifies metadata decoy determinism.
//
// P1-02: Same as TestDecoyGeneration_Deterministic but for metadata.
func TestDecoyMetadata_Deterministic(t *testing.T) {
	// Create master key
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}

	// Create two HKDF managers with SAME master key and salt
	hkdf1, err := NewHKDFManager(masterKey)
	require.NoError(t, err)
	defer hkdf1.Clear()

	salt := hkdf1.GetSalt()

	hkdf2, err := NewHKDFManagerWithSalt(masterKey, salt)
	require.NoError(t, err)
	defer hkdf2.Clear()

	// Create generators
	config := DecoyConfig{MetadataDecoyRatio: 1.0}
	gen1 := NewDecoyGenerator(hkdf1, config)
	gen2 := NewDecoyGenerator(hkdf2, config)

	// Test deterministic metadata helper functions directly
	fixedShardID := uint32(67890)

	// Generate deterministic metadata
	meta1, err := gen1.generateDeterministicDecoyMetadata(fixedShardID, 0, 512)
	require.NoError(t, err)

	meta2, err := gen2.generateDeterministicDecoyMetadata(fixedShardID, 0, 512)
	require.NoError(t, err)

	// CRITICAL: Metadata should be IDENTICAL
	require.Equal(t, meta1, meta2, "Decoy metadata should be deterministic")

	// Generate deterministic meta nonce
	metaNonce1, err := gen1.generateDeterministicMetaNonce(fixedShardID, 0)
	require.NoError(t, err)

	metaNonce2, err := gen2.generateDeterministicMetaNonce(fixedShardID, 0)
	require.NoError(t, err)

	// CRITICAL: Meta nonce should be IDENTICAL
	require.Equal(t, metaNonce1, metaNonce2, "Meta nonce should be deterministic")

	// Encrypt metadata with deterministic key
	encryptedMeta1, err := gen1.encryptDecoyMetaShard(meta1, fixedShardID, 0, 1)
	require.NoError(t, err)

	encryptedMeta2, err := gen2.encryptDecoyMetaShard(meta2, fixedShardID, 0, 1)
	require.NoError(t, err)

	// CRITICAL: Encrypted metadata should be IDENTICAL
	require.Equal(t, encryptedMeta1.Data, encryptedMeta2.Data, "Encrypted metadata should be deterministic")
	require.Equal(t, encryptedMeta1.Nonce, encryptedMeta2.Nonce, "Meta nonce should be deterministic")
}

// TestDecoyHKDFContexts verifies correct HKDF contexts are used.
//
// P1-02: Ensures decoy keys are derived with proper contexts.
func TestDecoyHKDFContexts(t *testing.T) {
	// Create HKDF manager
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}

	hkdf, err := NewHKDFManager(masterKey)
	require.NoError(t, err)
	defer hkdf.Clear()

	// Test that DeriveKeyForDecoyChar works
	key1, err := hkdf.DeriveKeyForDecoyChar(0)
	require.NoError(t, err)
	require.Len(t, key1, 32)

	key2, err := hkdf.DeriveKeyForDecoyChar(1)
	require.NoError(t, err)
	require.Len(t, key2, 32)

	// Different indices should produce different keys
	require.NotEqual(t, key1, key2, "Different decoy indices should produce different keys")

	// Same index should produce same key (deterministic)
	key1Again, err := hkdf.DeriveKeyForDecoyChar(0)
	require.NoError(t, err)
	require.Equal(t, key1, key1Again, "Same index should produce same key")

	// Test metadata key derivation
	metaKey1, err := hkdf.DeriveKeyForDecoyMeta(0)
	require.NoError(t, err)
	require.Len(t, metaKey1, 32)

	// Decoy char key and decoy meta key should be different (different contexts)
	require.NotEqual(t, key1, metaKey1, "Decoy char and decoy meta should use different contexts")
}

// TestDecoyWithoutHKDF_Fails verifies that decoy generation fails without HKDF manager.
//
// P1-02: Ensures HKDF is mandatory (not optional).
func TestDecoyWithoutHKDF_Fails(t *testing.T) {
	// Create generator WITHOUT HKDF manager (nil)
	config := DecoyConfig{DecoyRatio: 1.0}
	gen := NewDecoyGenerator(nil, config)

	// Should FAIL with descriptive error
	decoys, err := gen.GenerateDecoyShards(3, 1024)
	require.Error(t, err, "Should fail without HKDF manager")
	require.Nil(t, decoys)
	require.Contains(t, err.Error(), "HKDF", "Error should mention HKDF")
}

// TestDecoyDataSize_Matches verifies decoy data size matches requested size.
//
// P1-02: Ensures generateDeterministicDecoyData generates correct size.
func TestDecoyDataSize_Matches(t *testing.T) {
	masterKey := make([]byte, 32)
	hkdf, err := NewHKDFManager(masterKey)
	require.NoError(t, err)
	defer hkdf.Clear()

	config := DecoyConfig{DecoyRatio: 1.0}
	gen := NewDecoyGenerator(hkdf, config)

	// Test various sizes
	sizes := []int{512, 1024, 4096, 8192}

	for _, size := range sizes {
		decoys, err := gen.GenerateDecoyShards(1, size)
		require.NoError(t, err)
		require.Len(t, decoys, 1)

		// Decoy data should match requested size (before encryption)
		// After encryption, ciphertext = plaintext + auth tag (16 bytes)
		expectedCiphertextSize := size + 16
		require.Equal(t, expectedCiphertextSize, len(decoys[0].Data),
			"Decoy ciphertext size should be %d+16=%d bytes", size, expectedCiphertextSize)
	}
}
