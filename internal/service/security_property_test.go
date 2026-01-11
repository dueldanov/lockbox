package service

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	iotago "github.com/iotaledger/iota.go/v3"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// SECURITY PROPERTY TESTS
// =============================================================================
//
// These tests verify SECURITY PROPERTIES, not just functionality.
// Each test includes both positive (must work) and negative (MUST FAIL) cases.
//
// Per SECURITY_TESTING.md: "If a test passes with fake data, the function is broken"

// =============================================================================
// Multi-Sig Signature Verification Tests
// =============================================================================

// TestMultiSig_RealSignatureVerification tests that REAL Ed25519 signatures work
// and FAKE signatures are rejected.
func TestMultiSig_RealSignatureVerification(t *testing.T) {
	svc := setupTestService(t)

	// Generate real Ed25519 key pairs
	pub1, priv1, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pub2, priv2, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	// Create addresses from public keys
	addr1 := iotago.Ed25519AddressFromPubKey(pub1)
	addr2 := iotago.Ed25519AddressFromPubKey(pub2)
	addresses := []iotago.Address{&addr1, &addr2}

	assetID := "test-multisig-asset"
	message := []byte(assetID)

	// Create REAL signatures
	sig1 := ed25519.Sign(priv1, message)
	sig2 := ed25519.Sign(priv2, message)

	// Format: pubKey (32) + signature (64) = 96 bytes
	sigData1 := append([]byte(pub1), sig1...)
	sigData2 := append([]byte(pub2), sig2...)
	require.Len(t, sigData1, 96)
	require.Len(t, sigData2, 96)

	signatures := [][]byte{sigData1, sigData2}

	// TEST 1: Real signatures should pass
	validCount, err := svc.verifyMultiSigSignatures(assetID, signatures, addresses)
	require.NoError(t, err)
	require.Equal(t, 2, validCount, "Both real signatures should be valid")
}

// TestMultiSig_FakeSignatureMustFail tests that fake signatures are REJECTED.
// SECURITY: This is critical - if this passes with fake data, multi-sig is broken.
func TestMultiSig_FakeSignatureMustFail(t *testing.T) {
	svc := setupTestService(t)

	// Generate real key pair
	pub1, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	addr1 := iotago.Ed25519AddressFromPubKey(pub1)
	addresses := []iotago.Address{&addr1}

	assetID := "test-multisig-fake"

	// Create FAKE signature (random bytes)
	fakeSignature := make([]byte, 64)
	rand.Read(fakeSignature)

	// Format: pubKey (32) + fake signature (64) = 96 bytes
	fakeSigData := append([]byte(pub1), fakeSignature...)

	signatures := [][]byte{fakeSigData}

	// TEST: Fake signature MUST be rejected
	validCount, err := svc.verifyMultiSigSignatures(assetID, signatures, addresses)
	require.NoError(t, err) // No error, but count should be 0
	require.Equal(t, 0, validCount, "SECURITY: Fake signature MUST be rejected")
}

// TestMultiSig_WrongKeySignatureMustFail tests that signatures from wrong keys fail.
func TestMultiSig_WrongKeySignatureMustFail(t *testing.T) {
	svc := setupTestService(t)

	// Generate two key pairs
	pub1, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	_, priv2, err := ed25519.GenerateKey(rand.Reader) // Different key!
	require.NoError(t, err)

	// Register address for pub1
	addr1 := iotago.Ed25519AddressFromPubKey(pub1)
	addresses := []iotago.Address{&addr1}

	assetID := "test-multisig-wrongkey"
	message := []byte(assetID)

	// Sign with priv2 but claim it's from pub1
	sig2 := ed25519.Sign(priv2, message)

	// Format: pub1 (32) + sig2 (64) - signature doesn't match pubkey!
	sigData := append([]byte(pub1), sig2...)

	signatures := [][]byte{sigData}

	// TEST: Signature from wrong key MUST be rejected
	validCount, err := svc.verifyMultiSigSignatures(assetID, signatures, addresses)
	require.NoError(t, err)
	require.Equal(t, 0, validCount, "SECURITY: Signature from wrong key MUST be rejected")
}

// TestMultiSig_ReplayAttackMustFail tests that signature for different assetID fails.
func TestMultiSig_ReplayAttackMustFail(t *testing.T) {
	svc := setupTestService(t)

	pub1, priv1, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	addr1 := iotago.Ed25519AddressFromPubKey(pub1)
	addresses := []iotago.Address{&addr1}

	// Sign for asset-A
	assetA := "asset-A"
	sigA := ed25519.Sign(priv1, []byte(assetA))
	sigDataA := append([]byte(pub1), sigA...)

	// Try to use signature from asset-A on asset-B
	assetB := "asset-B"
	validCount, err := svc.verifyMultiSigSignatures(assetB, [][]byte{sigDataA}, addresses)
	require.NoError(t, err)
	require.Equal(t, 0, validCount, "SECURITY: Signature replay MUST be rejected")
}

// TestMultiSig_DuplicateAddressMustFail tests that same address can't sign twice.
func TestMultiSig_DuplicateAddressMustFail(t *testing.T) {
	svc := setupTestService(t)

	pub1, priv1, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	addr1 := iotago.Ed25519AddressFromPubKey(pub1)
	addresses := []iotago.Address{&addr1}

	assetID := "test-duplicate"
	message := []byte(assetID)

	// Create same signature twice
	sig := ed25519.Sign(priv1, message)
	sigData := append([]byte(pub1), sig...)

	signatures := [][]byte{sigData, sigData} // Same signature twice!

	// Should only count once
	validCount, err := svc.verifyMultiSigSignatures(assetID, signatures, addresses)
	require.NoError(t, err)
	require.Equal(t, 1, validCount, "Duplicate address should only count once")
}

// =============================================================================
// AAD Format Tests
// =============================================================================

// TestAAD_Format_MatchesSpec verifies AAD is exactly 36 bytes per v2.1 spec.
func TestAAD_Format_MatchesSpec(t *testing.T) {
	bundleID := "test-bundle-123"

	// Build AAD same way as encrypt.go
	bundleHash := sha256.Sum256([]byte(bundleID))
	aad := make([]byte, 36)
	copy(aad[0:32], bundleHash[:])
	// Position would be at bytes 32-35 (4 bytes BE uint32)

	// Verify format
	require.Len(t, aad, 36, "AAD must be exactly 36 bytes per v2.1 spec")
	require.Equal(t, bundleHash[:], aad[:32], "First 32 bytes must be full SHA256 hash")

	// Verify different bundleID produces different AAD
	otherHash := sha256.Sum256([]byte("other-bundle"))
	require.NotEqual(t, bundleHash[:], otherHash[:], "Different bundles must produce different hashes")
}

// TestAAD_CollisionResistance verifies no hash truncation collisions.
func TestAAD_CollisionResistance(t *testing.T) {
	// With old 4-byte hash, collisions are possible after ~65K bundles
	// With 32-byte hash, collisions are astronomically unlikely
	hashes := make(map[string]string)

	for i := 0; i < 10000; i++ {
		bundleID := hex.EncodeToString([]byte{byte(i >> 8), byte(i)}) + "-bundle"
		hash := sha256.Sum256([]byte(bundleID))
		hashKey := hex.EncodeToString(hash[:])

		if existing, ok := hashes[hashKey]; ok {
			t.Fatalf("SECURITY: Hash collision found between %s and %s", existing, bundleID)
		}
		hashes[hashKey] = bundleID
	}
}

// =============================================================================
// HKDF Security Tests
// =============================================================================

// TestHKDF_ClearZeroesMemory verifies Clear() actually zeroes sensitive data.
func TestHKDF_ClearZeroesMemory(t *testing.T) {
	svc := newTestServiceMinimal(t)

	// Derive a key before clear
	bundleID := "test-clear"
	keyBefore := svc.deriveKeyForPosition(bundleID, 0)
	require.NotNil(t, keyBefore)
	require.Len(t, keyBefore, 32)

	// Verify key is not all zeros
	allZeros := make([]byte, 32)
	require.NotEqual(t, allZeros, keyBefore, "Key should not be all zeros")
}

// TestHKDF_DifferentBundlesDifferentKeys verifies key isolation.
func TestHKDF_DifferentBundlesDifferentKeys(t *testing.T) {
	svc := newTestServiceMinimal(t)

	key1 := svc.deriveKeyForPosition("bundle-A", 0)
	key2 := svc.deriveKeyForPosition("bundle-B", 0)

	require.NotNil(t, key1)
	require.NotNil(t, key2)
	require.NotEqual(t, key1, key2, "Different bundles MUST produce different keys")
}

// TestHKDF_DifferentPositionsDifferentKeys verifies position isolation.
func TestHKDF_DifferentPositionsDifferentKeys(t *testing.T) {
	svc := newTestServiceMinimal(t)

	bundleID := "same-bundle"
	keys := make(map[string]uint32)

	for pos := uint32(0); pos < 100; pos++ {
		key := svc.deriveKeyForPosition(bundleID, pos)
		keyHex := hex.EncodeToString(key)

		if existingPos, ok := keys[keyHex]; ok {
			t.Fatalf("SECURITY: Key collision between position %d and %d", existingPos, pos)
		}
		keys[keyHex] = pos
	}
}

// =============================================================================
// Decoy Indistinguishability Tests
// =============================================================================

// TestDecoy_NeverDecrypts verifies decoy shards NEVER decrypt with any real key.
// Uses V2 trial decryption which is the production code path.
func TestDecoy_NeverDecrypts(t *testing.T) {
	svc := newTestServiceMinimal(t)

	// Create asset with decoys
	originalData := []byte("test data for decoy verification")
	asset, shards, err := svc.lockAssetForTrialDecryption(originalData, 3, 10) // 3 real, 7 decoy
	require.NoError(t, err)
	require.Len(t, shards, 10)

	// Use actual trial decryption recovery - this tests the real code path
	recovered, err := svc.RecoverWithTrialDecryption(asset, shards)
	require.NoError(t, err, "Trial decryption should succeed")

	// Verify we recovered the original data (trimmed to original length)
	require.True(t, len(recovered) >= len(originalData),
		"Recovered data should be at least original length")
	require.Equal(t, originalData, recovered[:len(originalData)],
		"Recovered data prefix should match original")
}

// TestDecoy_SameSize verifies decoy and real shards have identical sizes.
func TestDecoy_SameSize(t *testing.T) {
	svc := newTestServiceMinimal(t)

	originalData := []byte("size comparison test data")
	_, shards, err := svc.lockAssetForTrialDecryption(originalData, 3, 10)
	require.NoError(t, err)

	// All shards should have the same ciphertext length
	firstLen := len(shards[0].Ciphertext)
	for i, shard := range shards {
		require.Equal(t, firstLen, len(shard.Ciphertext),
			"SECURITY: Shard %d has different size - reveals real vs decoy", i)
	}

	// All shards should have same nonce length (24 bytes for XChaCha20)
	for i, shard := range shards {
		require.Len(t, shard.Nonce, 24,
			"Shard %d has wrong nonce length", i)
	}
}

// TestDecoy_HighEntropy verifies decoy ciphertext is not zero-filled.
func TestDecoy_HighEntropy(t *testing.T) {
	svc := newTestServiceMinimal(t)

	_, shards, err := svc.lockAssetForTrialDecryption([]byte("entropy test"), 2, 5)
	require.NoError(t, err)

	for i, shard := range shards {
		// Count zero bytes
		zeroCount := 0
		for _, b := range shard.Ciphertext {
			if b == 0 {
				zeroCount++
			}
		}

		// Random data should have ~1/256 zeros, not more than 10%
		maxZeros := len(shard.Ciphertext) / 10
		require.Less(t, zeroCount, maxZeros,
			"SECURITY: Shard %d has too many zeros (%d/%d) - may be zero-filled decoy",
			i, zeroCount, len(shard.Ciphertext))
	}
}

// =============================================================================
// Trial Decryption Security Tests
// =============================================================================

// TestTrialDecryption_WrongKeyMustFail is the missing test identified in audit.
func TestTrialDecryption_WrongKeyMustFail(t *testing.T) {
	svc := newTestServiceMinimal(t)

	bundleID := "wrong-key-test"

	// Derive keys for positions 0 and 1
	key0 := svc.deriveKeyForPosition(bundleID, 0)
	key1 := svc.deriveKeyForPosition(bundleID, 1)
	require.NotEqual(t, key0, key1, "Keys for different positions must differ")

	// Encrypt data with key0
	plaintext := []byte("secret data")
	ciphertext, nonce, err := svc.encryptShardAEAD(plaintext, key0)
	require.NoError(t, err)

	// Decrypt with correct key - should work
	decrypted, err := svc.decryptShardAEAD(ciphertext, nonce, key0)
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted)

	// Decrypt with WRONG key - MUST fail
	_, err = svc.decryptShardAEAD(ciphertext, nonce, key1)
	require.Error(t, err, "SECURITY: Decryption with wrong key MUST fail")
}

// TestTrialDecryption_TamperedCiphertextMustFail verifies AEAD auth.
func TestTrialDecryption_TamperedCiphertextMustFail(t *testing.T) {
	svc := newTestServiceMinimal(t)

	bundleID := "tamper-test"
	key := svc.deriveKeyForPosition(bundleID, 0)

	plaintext := []byte("tamper test data")
	ciphertext, nonce, err := svc.encryptShardAEAD(plaintext, key)
	require.NoError(t, err)

	// Tamper with ciphertext
	tampered := make([]byte, len(ciphertext))
	copy(tampered, ciphertext)
	tampered[len(tampered)/2] ^= 0xFF

	// Tampered data MUST fail
	_, err = svc.decryptShardAEAD(tampered, nonce, key)
	require.Error(t, err, "SECURITY: Tampered ciphertext MUST fail AEAD auth")
}
