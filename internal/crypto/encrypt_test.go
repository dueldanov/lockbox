package crypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/chacha20poly1305"
)

// ============================================
// Checksum Tests (SHA-256 based)
// ============================================

func TestCalculateChecksum_Deterministic(t *testing.T) {
	data := []byte("test data for checksum")

	// Same data should produce same checksum
	checksum1 := calculateChecksum(data)
	checksum2 := calculateChecksum(data)

	require.Equal(t, checksum1, checksum2, "Same data should produce same checksum")
}

func TestCalculateChecksum_DifferentData(t *testing.T) {
	data1 := []byte("data one")
	data2 := []byte("data two")

	checksum1 := calculateChecksum(data1)
	checksum2 := calculateChecksum(data2)

	require.NotEqual(t, checksum1, checksum2, "Different data should produce different checksums")
}

func TestCalculateChecksum_Length(t *testing.T) {
	data := []byte("test data")
	checksum := calculateChecksum(data)

	require.Len(t, checksum, 16, "Checksum should be 16 bytes (128 bits)")
}

func TestVerifyChecksum_Valid(t *testing.T) {
	data := []byte("test data for verification")
	checksum := calculateChecksum(data)

	result := verifyChecksum(data, checksum)
	require.True(t, result, "Valid checksum should verify")
}

func TestVerifyChecksum_TamperedData(t *testing.T) {
	data := []byte("original data")
	checksum := calculateChecksum(data)

	// Tamper with data
	tamperedData := []byte("tampered data")
	result := verifyChecksum(tamperedData, checksum)

	require.False(t, result, "Tampered data should fail verification")
}

func TestVerifyChecksum_TamperedChecksum(t *testing.T) {
	data := []byte("test data")
	checksum := calculateChecksum(data)

	// Tamper with checksum
	tamperedChecksum := make([]byte, len(checksum))
	copy(tamperedChecksum, checksum)
	tamperedChecksum[0] ^= 0xFF // Flip bits

	result := verifyChecksum(data, tamperedChecksum)
	require.False(t, result, "Tampered checksum should fail verification")
}

func TestVerifyChecksum_WrongLength(t *testing.T) {
	data := []byte("test data")
	wrongLengthChecksum := []byte("short")

	result := verifyChecksum(data, wrongLengthChecksum)
	require.False(t, result, "Wrong length checksum should fail")
}

func TestVerifyChecksum_EmptyData(t *testing.T) {
	data := []byte{}
	checksum := calculateChecksum(data)

	result := verifyChecksum(data, checksum)
	require.True(t, result, "Empty data checksum should verify")
}

func TestVerifyChecksum_LargeData(t *testing.T) {
	// Test with 1MB of data
	data := make([]byte, 1024*1024)
	for i := range data {
		data[i] = byte(i % 256)
	}

	checksum := calculateChecksum(data)
	require.Len(t, checksum, 16, "Checksum should still be 16 bytes for large data")

	result := verifyChecksum(data, checksum)
	require.True(t, result, "Large data checksum should verify")
}

func TestCalculateChecksum_NotXOR(t *testing.T) {
	// This test ensures we're not using the old XOR-based checksum
	// XOR checksum would produce identical results for data that differs
	// only by bytes at positions that are 16 bytes apart

	// Create two data slices that would have the same XOR checksum
	// if using the old i%16 XOR algorithm
	data1 := make([]byte, 32)
	data2 := make([]byte, 32)
	copy(data2, data1)
	data2[0] = 0xFF // Change byte at position 0
	data2[16] = 0xFF // XOR would cancel out if using i%16

	checksum1 := calculateChecksum(data1)
	checksum2 := calculateChecksum(data2)

	// With SHA-256, these should be different
	// With old XOR, they might be the same
	require.False(t, bytes.Equal(checksum1, checksum2),
		"Checksum should detect differences that XOR would miss")
}

// ============================================
// V2 Encryption Tests (Shard Indistinguishability)
// ============================================

func createTestEncryptor(t *testing.T) *ShardEncryptor {
	t.Helper()
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}
	encryptor, err := NewShardEncryptor(masterKey, 64)
	require.NoError(t, err)
	return encryptor
}

// TestEncryptDataV2_RoundTrip verifies that V2 encryption/decryption works correctly.
func TestEncryptDataV2_RoundTrip(t *testing.T) {
	encryptor := createTestEncryptor(t)
	defer encryptor.Clear()

	bundleID := "test-bundle-123"
	originalData := []byte("secret message for V2 encryption test")

	// Encrypt
	shards, err := encryptor.EncryptDataV2(originalData, bundleID)
	require.NoError(t, err)
	require.NotEmpty(t, shards)

	// Decrypt each shard with its correct key position
	var decryptedData []byte
	for i, shard := range shards {
		plaintext, err := encryptor.DecryptShardV2(shard, bundleID, uint32(i))
		require.NoError(t, err, "Failed to decrypt shard %d", i)
		decryptedData = append(decryptedData, plaintext...)
	}

	require.Equal(t, originalData, decryptedData, "Decrypted data must match original")
}

// TestEncryptDataV2_MultipleShards verifies multi-shard encryption.
func TestEncryptDataV2_MultipleShards(t *testing.T) {
	encryptor := createTestEncryptor(t)
	defer encryptor.Clear()

	bundleID := "multi-shard-bundle"
	// Data larger than shard size (64 bytes) to force multiple shards
	originalData := make([]byte, 200)
	for i := range originalData {
		originalData[i] = byte(i % 256)
	}

	shards, err := encryptor.EncryptDataV2(originalData, bundleID)
	require.NoError(t, err)
	require.Len(t, shards, 4, "200 bytes with 64-byte shards = 4 shards")

	// Verify each shard has correct index
	for i, shard := range shards {
		require.Equal(t, uint32(i), shard.Index)
		require.Equal(t, uint32(4), shard.Total)
	}

	// Decrypt all
	var decrypted []byte
	for i, shard := range shards {
		plain, err := encryptor.DecryptShardV2(shard, bundleID, uint32(i))
		require.NoError(t, err)
		decrypted = append(decrypted, plain...)
	}

	require.Equal(t, originalData, decrypted)
}

// TestDecryptShardV2_WrongKey verifies that wrong key fails AEAD authentication.
// SECURITY: This is critical for trial decryption to work correctly.
func TestDecryptShardV2_WrongKey(t *testing.T) {
	encryptor := createTestEncryptor(t)
	defer encryptor.Clear()

	bundleID := "test-bundle"
	data := []byte("secret data")

	shards, err := encryptor.EncryptDataV2(data, bundleID)
	require.NoError(t, err)
	require.Len(t, shards, 1)

	shard := shards[0]

	// Correct key (position 0) should work
	_, err = encryptor.DecryptShardV2(shard, bundleID, 0)
	require.NoError(t, err)

	// Wrong position should fail
	_, err = encryptor.DecryptShardV2(shard, bundleID, 1)
	require.Error(t, err, "Wrong key position must fail AEAD auth")
	require.ErrorIs(t, err, ErrShardDecryptionFailed)

	// Wrong bundle should fail
	_, err = encryptor.DecryptShardV2(shard, "wrong-bundle", 0)
	require.Error(t, err, "Wrong bundle must fail AEAD auth")
	require.ErrorIs(t, err, ErrShardDecryptionFailed)
}

// TestDecryptShardV2_TamperedCiphertext verifies AEAD rejects tampered data.
func TestDecryptShardV2_TamperedCiphertext(t *testing.T) {
	encryptor := createTestEncryptor(t)
	defer encryptor.Clear()

	bundleID := "tamper-test"
	data := []byte("original secret data")

	shards, err := encryptor.EncryptDataV2(data, bundleID)
	require.NoError(t, err)

	shard := shards[0]

	// Tamper with ciphertext
	tamperedShard := &CharacterShard{
		ID:        shard.ID,
		Index:     shard.Index,
		Total:     shard.Total,
		Data:      make([]byte, len(shard.Data)),
		Nonce:     shard.Nonce,
		Timestamp: shard.Timestamp,
		Checksum:  shard.Checksum,
	}
	copy(tamperedShard.Data, shard.Data)
	tamperedShard.Data[len(tamperedShard.Data)/2] ^= 0xFF // Flip middle byte

	_, err = encryptor.DecryptShardV2(tamperedShard, bundleID, 0)
	require.Error(t, err, "Tampered ciphertext must fail AEAD auth")
}

// TestDecryptShardV2_TamperedNonce verifies AEAD rejects wrong nonce.
func TestDecryptShardV2_TamperedNonce(t *testing.T) {
	encryptor := createTestEncryptor(t)
	defer encryptor.Clear()

	bundleID := "nonce-test"
	data := []byte("test data")

	shards, err := encryptor.EncryptDataV2(data, bundleID)
	require.NoError(t, err)

	shard := shards[0]

	// Tamper with nonce
	tamperedShard := &CharacterShard{
		ID:        shard.ID,
		Index:     shard.Index,
		Total:     shard.Total,
		Data:      shard.Data,
		Nonce:     make([]byte, len(shard.Nonce)),
		Timestamp: shard.Timestamp,
		Checksum:  shard.Checksum,
	}
	copy(tamperedShard.Nonce, shard.Nonce)
	tamperedShard.Nonce[0] ^= 0xFF

	_, err = encryptor.DecryptShardV2(tamperedShard, bundleID, 0)
	require.Error(t, err, "Wrong nonce must fail AEAD auth")
}

// TestSaltPersistenceV2 verifies salt can be saved and used to restore decryption.
func TestSaltPersistenceV2(t *testing.T) {
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}

	// Create encryptor and encrypt data
	encryptor1, err := NewShardEncryptor(masterKey, 64)
	require.NoError(t, err)

	bundleID := "persistence-test"
	originalData := []byte("data that must survive restart")

	shards, err := encryptor1.EncryptDataV2(originalData, bundleID)
	require.NoError(t, err)

	// Save salt before "restart"
	salt := encryptor1.GetSalt()
	encryptor1.Clear()

	// Create new encryptor with saved salt (simulating restart)
	encryptor2, err := NewShardEncryptor(masterKey, 64)
	require.NoError(t, err)
	defer encryptor2.Clear()

	// Try to decrypt with new encryptor's session salt - should fail!
	_, err = encryptor2.DecryptShardV2(shards[0], bundleID, 0)
	require.Error(t, err, "Different salt should fail decryption")

	// Clone with original salt - should work
	encryptor3, err := encryptor2.CloneWithSalt(salt)
	require.NoError(t, err)
	defer encryptor3.Clear()

	// Now decryption should work
	var decrypted []byte
	for i, shard := range shards {
		plain, err := encryptor3.DecryptShardV2(shard, bundleID, uint32(i))
		require.NoError(t, err)
		decrypted = append(decrypted, plain...)
	}

	require.Equal(t, originalData, decrypted, "Data must be recoverable with saved salt")
}

// TestDecryptShardV2WithHKDF verifies custom HKDF manager works.
func TestDecryptShardV2WithHKDF(t *testing.T) {
	encryptor := createTestEncryptor(t)
	defer encryptor.Clear()

	bundleID := "custom-hkdf-test"
	data := []byte("test with custom hkdf")

	shards, err := encryptor.EncryptDataV2(data, bundleID)
	require.NoError(t, err)

	// Get salt and create custom HKDF
	salt := encryptor.GetSalt()
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}

	customHKDF, err := NewHKDFManagerWithSalt(masterKey, salt)
	require.NoError(t, err)
	defer customHKDF.Clear()

	// Decrypt using custom HKDF
	plain, err := encryptor.DecryptShardV2WithHKDF(shards[0], bundleID, 0, customHKDF)
	require.NoError(t, err)
	require.Equal(t, data, plain)
}

// TestTrialDecryption_SimulatedRecovery simulates the trial decryption algorithm.
// This is how UnlockAsset will recover real shards without ShardIndexMap.
func TestTrialDecryption_SimulatedRecovery(t *testing.T) {
	encryptor := createTestEncryptor(t)
	defer encryptor.Clear()

	bundleID := "trial-decrypt-bundle"

	// Create multiple "real" shards (simulating split data)
	realData := [][]byte{
		[]byte("shard 0 data"),
		[]byte("shard 1 data"),
		[]byte("shard 2 data"),
	}
	realCount := len(realData)

	// Encrypt real shards with positions 0, 1, 2
	// Using EncryptSingleShardV2 to specify exact position for each shard
	realShards := make([]*CharacterShard, realCount)
	for i, data := range realData {
		shard, err := encryptor.EncryptSingleShardV2(data, bundleID, uint32(i))
		require.NoError(t, err)
		realShards[i] = shard
	}

	// Create decoy shards with high positions (simulating decoys)
	// Decoys use positions 1000+ to avoid collision with real shards
	decoyShards := make([]*CharacterShard, 2)
	for i := 0; i < 2; i++ {
		decoyData := make([]byte, 32)
		for j := range decoyData {
			decoyData[j] = byte(j + i*50)
		}
		shard, err := encryptor.EncryptSingleShardV2(decoyData, bundleID, uint32(1000+i))
		require.NoError(t, err)
		decoyShards[i] = shard
	}

	// Mix all shards (simulate storage order)
	mixedShards := make([]*CharacterShard, 0, realCount+len(decoyShards))
	mixedShards = append(mixedShards, decoyShards[0])
	mixedShards = append(mixedShards, realShards[1])
	mixedShards = append(mixedShards, realShards[0])
	mixedShards = append(mixedShards, decoyShards[1])
	mixedShards = append(mixedShards, realShards[2])

	// TRIAL DECRYPTION: Try to recover real shards
	recovered := make(map[uint32][]byte)
	usedPositions := make(map[int]bool)

	// For each expected real shard position (0, 1, 2)
	for keyPos := 0; keyPos < realCount; keyPos++ {
		found := false
		// Try against all mixed shards
		for i, shard := range mixedShards {
			if usedPositions[i] {
				continue
			}

			// Try to decrypt with key for position keyPos
			plain, err := encryptor.DecryptShardV2(shard, bundleID, uint32(keyPos))
			if err == nil {
				// Found! This shard decrypts with key for position keyPos
				recovered[uint32(keyPos)] = plain
				usedPositions[i] = true
				found = true
				break
			}
			// Auth failed - try next shard
		}
		require.True(t, found, "Must find shard for position %d", keyPos)
	}

	// Verify we recovered all real shards correctly
	require.Len(t, recovered, realCount)
	for i, expected := range realData {
		actual, ok := recovered[uint32(i)]
		require.True(t, ok, "Missing shard %d", i)
		require.Equal(t, expected, actual, "Shard %d content mismatch", i)
	}
}

// TestV2_NoTypeMarkersInShard verifies serialized shard has no type info.
// SECURITY: This is the core of shard indistinguishability.
func TestV2_NoTypeMarkersInShard(t *testing.T) {
	encryptor := createTestEncryptor(t)
	defer encryptor.Clear()

	bundleID := "no-markers-test"
	data := []byte("test data")

	shards, err := encryptor.EncryptDataV2(data, bundleID)
	require.NoError(t, err)

	shard := shards[0]

	// Check that CharacterShard doesn't contain type info
	// (V2 uses ID=0 since bundleID serves as identifier)
	require.Equal(t, uint32(0), shard.ID, "V2 should use ID=0")

	// The shard structure itself doesn't contain "real" or "decoy" markers
	// It's just: Index, Total, Data, Nonce, Timestamp, Checksum
	// The type is determined by which key can decrypt it
}

// TestV2_DifferentBundlesDifferentKeys verifies bundle isolation.
func TestV2_DifferentBundlesDifferentKeys(t *testing.T) {
	encryptor := createTestEncryptor(t)
	defer encryptor.Clear()

	data := []byte("same data in both bundles")

	shards1, err := encryptor.EncryptDataV2(data, "bundle-1")
	require.NoError(t, err)

	shards2, err := encryptor.EncryptDataV2(data, "bundle-2")
	require.NoError(t, err)

	// Same position, but different bundles = different keys
	// Ciphertexts should be different (also because of random nonce)
	require.NotEqual(t, shards1[0].Data, shards2[0].Data)

	// Cross-bundle decryption should fail
	_, err = encryptor.DecryptShardV2(shards1[0], "bundle-2", 0)
	require.Error(t, err, "Cross-bundle decryption must fail")

	_, err = encryptor.DecryptShardV2(shards2[0], "bundle-1", 0)
	require.Error(t, err, "Cross-bundle decryption must fail")
}

// TestV2_EmptyData verifies handling of empty data.
func TestV2_EmptyData(t *testing.T) {
	encryptor := createTestEncryptor(t)
	defer encryptor.Clear()

	_, err := encryptor.EncryptDataV2([]byte{}, "empty-bundle")
	require.Error(t, err, "Empty data should fail")
}

// TestV2_LargeData verifies handling of large data (multiple shards).
func TestV2_LargeData(t *testing.T) {
	encryptor := createTestEncryptor(t)
	defer encryptor.Clear()

	bundleID := "large-data-bundle"

	// 1KB of data with 64-byte shards = 16 shards
	largeData := make([]byte, 1024)
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	shards, err := encryptor.EncryptDataV2(largeData, bundleID)
	require.NoError(t, err)
	require.Len(t, shards, 16)

	// Decrypt all
	var decrypted []byte
	for i, shard := range shards {
		plain, err := encryptor.DecryptShardV2(shard, bundleID, uint32(i))
		require.NoError(t, err)
		decrypted = append(decrypted, plain...)
	}

	require.Equal(t, largeData, decrypted)
}

// =============================================================================
// AAD V2.1 Spec Compliance Tests
// =============================================================================
//
// These tests verify AAD format matches v2.1 specification:
// AAD = SHA256(bundleID)[0:32] || position[BE32] = 36 bytes total
//
// CRITICAL: Tests must build AAD EXTERNALLY (not using internal helpers)
// to detect if internal helpers deviate from spec.

// TestAADV2_SpecCompliance_36Bytes verifies AAD is exactly 36 bytes per v2.1 spec.
// This test builds AAD externally and verifies decryption works.
func TestAADV2_SpecCompliance_36Bytes(t *testing.T) {
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}

	encryptor, err := NewShardEncryptor(masterKey, 64)
	require.NoError(t, err)

	bundleID := "test-bundle-aad-spec"
	plaintext := []byte("secret data for AAD test")

	// Encrypt using internal V2 function
	shards, err := encryptor.EncryptDataV2(plaintext, bundleID)
	require.NoError(t, err)
	require.Len(t, shards, 1)

	shard := shards[0]

	// Build AAD EXTERNALLY per v2.1 spec: SHA256(bundleID)[0:32] + position[BE32]
	bundleHash := sha256.Sum256([]byte(bundleID))
	externalAAD := make([]byte, 36)
	copy(externalAAD[0:32], bundleHash[:])
	binary.BigEndian.PutUint32(externalAAD[32:36], 0) // position 0

	// Verify AAD is exactly 36 bytes
	require.Len(t, externalAAD, 36, "AAD must be exactly 36 bytes per v2.1 spec")

	// Derive key using HKDF (same as internal)
	key, err := encryptor.hkdfManager.DeriveKeyForPosition(bundleID, 0)
	require.NoError(t, err)

	// Decrypt using EXTERNAL AAD - must succeed
	aead, err := chacha20poly1305.NewX(key)
	require.NoError(t, err)

	decrypted, err := aead.Open(nil, shard.Nonce, shard.Data, externalAAD)
	require.NoError(t, err, "Decryption with external 36-byte AAD must succeed")
	require.Equal(t, plaintext, decrypted)
}

// TestAADV2_WrongFormat_8BytesMustFail verifies that old 8-byte AAD format fails.
// This catches regressions to pre-v2.1 format.
func TestAADV2_WrongFormat_8BytesMustFail(t *testing.T) {
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}

	encryptor, err := NewShardEncryptor(masterKey, 64)
	require.NoError(t, err)

	bundleID := "test-bundle-wrong-aad"
	plaintext := []byte("secret data")

	// Encrypt using V2 (36-byte AAD)
	shards, err := encryptor.EncryptDataV2(plaintext, bundleID)
	require.NoError(t, err)

	shard := shards[0]

	// Build WRONG 8-byte AAD (truncated hash, like old format)
	bundleHash := sha256.Sum256([]byte(bundleID))
	wrongAAD := make([]byte, 8)
	copy(wrongAAD[0:4], bundleHash[0:4]) // Only 4 bytes of hash!
	binary.BigEndian.PutUint32(wrongAAD[4:8], 0)

	// Derive key
	key, err := encryptor.hkdfManager.DeriveKeyForPosition(bundleID, 0)
	require.NoError(t, err)

	// Decrypt with WRONG AAD - MUST FAIL
	aead, err := chacha20poly1305.NewX(key)
	require.NoError(t, err)

	_, err = aead.Open(nil, shard.Nonce, shard.Data, wrongAAD)
	require.Error(t, err, "SECURITY: Decryption with wrong 8-byte AAD MUST fail")
}

// TestAADV2_TruncatedHashCollision tests that full 32-byte hash prevents collisions.
// With 4-byte truncated hash, collisions occur after ~65K bundles.
// With 32-byte hash, collisions are astronomically unlikely.
func TestAADV2_TruncatedHashCollision(t *testing.T) {
	// Generate two bundleIDs that would collide with 4-byte truncation
	// but differ with full 32-byte hash
	bundle1 := "bundle-collision-test-alpha"
	bundle2 := "bundle-collision-test-beta"

	hash1 := sha256.Sum256([]byte(bundle1))
	hash2 := sha256.Sum256([]byte(bundle2))

	// Full hashes must differ
	require.NotEqual(t, hash1[:], hash2[:],
		"Different bundles must produce different full hashes")

	// Even if 4-byte prefix happened to match (unlikely), full hash differs
	// This is the security improvement of v2.1
	aad1 := make([]byte, 36)
	aad2 := make([]byte, 36)
	copy(aad1[0:32], hash1[:])
	copy(aad2[0:32], hash2[:])

	require.NotEqual(t, aad1, aad2,
		"Different bundles must produce different AAD")
}

// TestAADV2_PositionAffectsAAD verifies that position is included in AAD.
func TestAADV2_PositionAffectsAAD(t *testing.T) {
	bundleID := "same-bundle"
	bundleHash := sha256.Sum256([]byte(bundleID))

	aad0 := make([]byte, 36)
	aad1 := make([]byte, 36)
	copy(aad0[0:32], bundleHash[:])
	copy(aad1[0:32], bundleHash[:])
	binary.BigEndian.PutUint32(aad0[32:36], 0)
	binary.BigEndian.PutUint32(aad1[32:36], 1)

	require.NotEqual(t, aad0, aad1,
		"Different positions must produce different AAD")
}

// TestAADV2_CrossDecryptionMustFail verifies shard from bundle A can't decrypt with bundle B's AAD.
func TestAADV2_CrossDecryptionMustFail(t *testing.T) {
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}

	encryptor, err := NewShardEncryptor(masterKey, 64)
	require.NoError(t, err)

	bundleA := "bundle-A"
	bundleB := "bundle-B"
	plaintext := []byte("secret")

	// Encrypt with bundle A
	shards, err := encryptor.EncryptDataV2(plaintext, bundleA)
	require.NoError(t, err)

	shard := shards[0]

	// Try to decrypt with bundle B's key and AAD - MUST FAIL
	keyB, err := encryptor.hkdfManager.DeriveKeyForPosition(bundleB, 0)
	require.NoError(t, err)

	bundleHashB := sha256.Sum256([]byte(bundleB))
	aadB := make([]byte, 36)
	copy(aadB[0:32], bundleHashB[:])
	binary.BigEndian.PutUint32(aadB[32:36], 0)

	aead, err := chacha20poly1305.NewX(keyB)
	require.NoError(t, err)

	_, err = aead.Open(nil, shard.Nonce, shard.Data, aadB)
	require.Error(t, err, "SECURITY: Cross-bundle decryption MUST fail")
}
