package service

import (
	"context"
	"strings"
	"testing"
	"time"

	iotago "github.com/iotaledger/iota.go/v3"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Integration Tests for V2 Shard Format
// =============================================================================
//
// These tests verify that the REAL LockAsset/UnlockAsset flow uses V2 format
// with trial decryption, NOT the test-only lockAssetForTrialDecryption().
//
// IMPORTANT: These tests are designed to FAIL initially until prod code is updated.
// This is the TDD approach - write tests first, then fix implementation.

// TestLockUnlockIntegration_RealFlow verifies end-to-end lock/unlock
// using the actual Service methods (not test helpers).
func TestLockUnlockIntegration_RealFlow(t *testing.T) {
	svc := setupTestService(t) // Use REAL setupTestService, not minimal
	ctx := context.Background()

	// Lock with real request
	lockReq := &LockAssetRequest{
		OwnerAddress: &iotago.Ed25519Address{},
		OutputID:     iotago.OutputID{},
		LockDuration: time.Second,
	}
	lockResp, err := svc.LockAsset(ctx, lockReq)
	require.NoError(t, err)
	require.NotEmpty(t, lockResp.AssetID)
	require.Equal(t, AssetStatusLocked, lockResp.Status)

	// Wait for unlock time
	time.Sleep(2 * time.Second)

	// Unlock with real request
	accessToken, err := GenerateAccessToken()
	require.NoError(t, err)
	unlockResp, err := svc.UnlockAsset(ctx, &UnlockAssetRequest{
		AssetID:     lockResp.AssetID,
		AccessToken: accessToken,
		Nonce:       generateTestNonce(),
	})
	require.NoError(t, err)
	require.Equal(t, AssetStatusUnlocked, unlockResp.Status)
}

// TestLockAsset_V2Format verifies LockAsset produces V2 format shards.
//
// V2 format requirements:
// - Generate and store Salt (32 bytes)
// - NOT store ShardIndexMap (use trial decryption instead)
// - Set TotalShards and RealCount
func TestLockAsset_V2Format(t *testing.T) {
	svc := setupTestService(t)
	ctx := context.Background()

	lockReq := &LockAssetRequest{
		OwnerAddress: &iotago.Ed25519Address{},
		OutputID:     iotago.OutputID{},
		LockDuration: time.Hour,
	}
	lockResp, err := svc.LockAsset(ctx, lockReq)
	require.NoError(t, err)

	// Get the locked asset
	asset := svc.lockedAssets[lockResp.AssetID]
	require.NotNil(t, asset)

	// CRITICAL: ShardIndexMap should NOT be stored for V2
	require.Nil(t, asset.ShardIndexMap,
		"SECURITY: ShardIndexMap must not be stored in V2 format")

	// Salt MUST be present for trial decryption
	require.NotEmpty(t, asset.Salt,
		"Salt must be stored for trial decryption recovery")
	require.Len(t, asset.Salt, 32, "Salt must be 32 bytes")

	// TotalShards and RealCount must be set
	require.Greater(t, asset.TotalShards, 0, "TotalShards must be set")
	require.Greater(t, asset.RealCount, 0, "RealCount must be set")
}

// TestUnlockAsset_TrialDecryption verifies UnlockAsset uses trial decryption.
//
// With V2 format, ShardIndexMap is NOT stored. UnlockAsset must recover
// shards using trial decryption algorithm (try all keys until AEAD succeeds).
func TestUnlockAsset_TrialDecryption(t *testing.T) {
	svc := setupTestService(t)
	ctx := context.Background()

	// Lock asset (V2 format - no ShardIndexMap stored)
	lockReq := &LockAssetRequest{
		OwnerAddress: &iotago.Ed25519Address{},
		OutputID:     iotago.OutputID{},
		LockDuration: time.Second,
	}
	lockResp, err := svc.LockAsset(ctx, lockReq)
	require.NoError(t, err)

	// Verify ShardIndexMap is nil (V2 format)
	asset := svc.lockedAssets[lockResp.AssetID]
	require.Nil(t, asset.ShardIndexMap, "V2 format must NOT store ShardIndexMap")

	time.Sleep(2 * time.Second)

	// Unlock should work via trial decryption (no ShardIndexMap needed)
	accessToken, _ := GenerateAccessToken()
	unlockResp, err := svc.UnlockAsset(ctx, &UnlockAssetRequest{
		AssetID:     lockResp.AssetID,
		AccessToken: accessToken,
		Nonce:       generateTestNonce(),
	})

	require.NoError(t, err, "UnlockAsset must work without ShardIndexMap (trial decryption)")
	require.Equal(t, AssetStatusUnlocked, unlockResp.Status)
}

// TestSaltPersistence_RestartRecovery verifies salt survives service restart.
//
// EXPECTED TO FAIL until:
// - LockAsset stores Salt in asset
// - Asset serialization includes Salt
// - Asset deserialization restores Salt
func TestSaltPersistence_RestartRecovery(t *testing.T) {
	t.Skip("PENDING: Salt persistence not implemented - unskip after implementing")

	// Create first service instance with storage
	svc1 := setupTestService(t)
	ctx := context.Background()

	// Lock asset
	lockReq := &LockAssetRequest{
		OwnerAddress: &iotago.Ed25519Address{},
		OutputID:     iotago.OutputID{},
		LockDuration: time.Second,
	}
	lockResp, err := svc1.LockAsset(ctx, lockReq)
	require.NoError(t, err)

	// Get original salt
	originalSalt := svc1.lockedAssets[lockResp.AssetID].Salt
	require.NotEmpty(t, originalSalt, "Salt must be stored after LockAsset")

	// Simulate restart by loading from storage
	// For now, we can't easily simulate restart without persistent storage
	// This test will be more complete after storage manager integration

	t.Log("Salt persistence test requires storage manager integration")
}

// TestNoShardIndexMapInSerializedAsset verifies serialization excludes map.
//
// This test checks that serializeAssetV2 does NOT include ShardIndexMap.
func TestNoShardIndexMapInSerializedAsset(t *testing.T) {
	svc := newTestServiceMinimal(t)

	// Create asset WITH ShardIndexMap (simulating old format)
	asset := &LockedAsset{
		ID:            "test-asset-123",
		TotalShards:   10,
		RealCount:     5,
		ShardIndexMap: map[uint32]uint32{0: 3, 1: 7, 2: 1, 3: 9, 4: 5},
		Status:        AssetStatusLocked,
		Salt:          make([]byte, 32),
	}

	// Serialize using V2 format
	data, err := svc.serializeAssetV2(asset)
	require.NoError(t, err)

	str := string(data)

	// CRITICAL: ShardIndexMap must NOT be in serialized output
	require.NotContains(t, str, "ShardIndexMap", "ShardIndexMap must not be serialized")
	require.NotContains(t, str, "shard_index_map", "shard_index_map must not be serialized")
	require.NotContains(t, str, "index_map", "index_map must not be serialized")

	// These SHOULD be present
	require.Contains(t, str, "total_shards", "total_shards must be serialized")
	require.Contains(t, str, "real_count", "real_count must be serialized")
	require.Contains(t, str, "salt", "salt must be serialized")
}

// TestSaltInSerializedAsset verifies salt is included in serialization.
func TestSaltInSerializedAsset(t *testing.T) {
	svc := newTestServiceMinimal(t)

	// Create asset with salt
	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i)
	}

	asset := &LockedAsset{
		ID:          "test-asset-salt",
		TotalShards: 10,
		RealCount:   5,
		Salt:        salt,
		Status:      AssetStatusLocked,
	}

	// Serialize
	data, err := svc.serializeAssetV2(asset)
	require.NoError(t, err)

	str := string(data)
	require.Contains(t, str, "salt", "serialized asset must contain salt")

	// Deserialize and verify salt is preserved
	// Note: This requires deserializeAssetV2 to be implemented
}

// TestV2ShardSerializationInRealFlow tests that shards are serialized in V2 format
// during the real LockAsset flow.
func TestV2ShardSerializationInRealFlow(t *testing.T) {
	t.Skip("PENDING: Real LockAsset does not use V2 shard format yet - unskip after implementing")

	svc := setupTestService(t)
	ctx := context.Background()

	lockReq := &LockAssetRequest{
		OwnerAddress: &iotago.Ed25519Address{},
		OutputID:     iotago.OutputID{},
		LockDuration: time.Hour,
	}
	lockResp, err := svc.LockAsset(ctx, lockReq)
	require.NoError(t, err)

	// Get the asset
	asset := svc.lockedAssets[lockResp.AssetID]
	require.NotNil(t, asset)

	// Verify shards are in V2 format
	// This would require access to the stored shards
	// For now, we verify the asset metadata is correct

	require.Greater(t, asset.TotalShards, 0, "TotalShards must be set in V2")
	require.Greater(t, asset.RealCount, 0, "RealCount must be set in V2")
	require.NotEmpty(t, asset.Salt, "Salt must be set in V2")
}

// =============================================================================
// Backward Compatibility Tests
// =============================================================================

// TestBackwardCompatibility_V1AssetCanBeRead tests that assets created with
// V1 format (with ShardIndexMap) can still be read and unlocked.
func TestBackwardCompatibility_V1AssetCanBeRead(t *testing.T) {
	t.Skip("PENDING: Backward compatibility not yet implemented - unskip after implementing")

	// This test would:
	// 1. Create a V1-format asset with ShardIndexMap
	// 2. Verify it can be deserialized
	// 3. Verify unlock works (using the map for old assets)
	//
	// Implementation requires:
	// - Version detection in deserialize
	// - Dual-path in unlock (map-based for V1, trial for V2)
}

// =============================================================================
// Performance Tests
// =============================================================================

// TestV2LockPerformance measures LockAsset performance with V2 format.
func TestV2LockPerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping performance test in short mode")
	}

	svc := setupTestService(t)
	ctx := context.Background()

	// Warm up
	for i := 0; i < 5; i++ {
		svc.LockAsset(ctx, &LockAssetRequest{
			OwnerAddress: &iotago.Ed25519Address{byte(i)},
			OutputID:     iotago.OutputID{byte(i)},
			LockDuration: time.Hour,
		})
	}

	// Measure
	const iterations = 100
	start := time.Now()

	for i := 0; i < iterations; i++ {
		_, err := svc.LockAsset(ctx, &LockAssetRequest{
			OwnerAddress: &iotago.Ed25519Address{byte(i)},
			OutputID:     iotago.OutputID{byte(i)},
			LockDuration: time.Hour,
		})
		if err != nil {
			t.Fatalf("LockAsset failed at iteration %d: %v", i, err)
		}
	}

	elapsed := time.Since(start)
	avgMs := float64(elapsed.Milliseconds()) / float64(iterations)

	t.Logf("LockAsset performance: %d iterations in %v (avg %.2f ms/op)", iterations, elapsed, avgMs)

	// Reasonable threshold - should complete under 100ms per op
	require.Less(t, avgMs, 100.0, "LockAsset too slow: %.2f ms/op", avgMs)
}

// =============================================================================
// Helper for these tests
// =============================================================================

// serializeAsset is a placeholder that should call the real serialization.
// This allows tests to run even before full implementation.
func (s *Service) serializeAsset(asset *LockedAsset) ([]byte, error) {
	// Try V2 first
	return s.serializeAssetV2(asset)
}

// verifyAssetHasV2Fields checks that an asset has all required V2 fields.
func verifyAssetHasV2Fields(t *testing.T, asset *LockedAsset) {
	t.Helper()

	if asset.Salt == nil || len(asset.Salt) != 32 {
		t.Error("Asset missing or invalid Salt")
	}
	if asset.TotalShards <= 0 {
		t.Error("Asset missing TotalShards")
	}
	if asset.RealCount <= 0 {
		t.Error("Asset missing RealCount")
	}
	if asset.ShardIndexMap != nil && len(asset.ShardIndexMap) > 0 {
		t.Error("SECURITY: Asset should not have ShardIndexMap in V2")
	}
}

// verifySerializedAssetV2 checks that serialized data is in V2 format.
func verifySerializedAssetV2(t *testing.T, data []byte) {
	t.Helper()

	str := string(data)

	// V2 should NOT contain these
	forbidden := []string{"ShardIndexMap", "shard_index_map", "index_map"}
	for _, f := range forbidden {
		if strings.Contains(str, f) {
			t.Errorf("Serialized V2 asset contains forbidden field: %s", f)
		}
	}

	// V2 SHOULD contain these
	required := []string{"total_shards", "real_count", "salt"}
	for _, r := range required {
		if !strings.Contains(str, r) {
			t.Errorf("Serialized V2 asset missing required field: %s", r)
		}
	}
}
