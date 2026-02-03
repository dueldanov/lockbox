package service

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/dueldanov/lockbox/v2/internal/interfaces"
	iotago "github.com/iotaledger/iota.go/v3"
	"github.com/stretchr/testify/require"
)

// TestLockAsset_MetadataDecoys_PremiumTier verifies Premium tier generates metadata decoys
func TestLockAsset_MetadataDecoys_PremiumTier(t *testing.T) {
	svc := createTestService(t)
	svc.config.Tier = interfaces.TierPremium

	// Generate test address
	addr, err := generateTestEd25519Address()
	require.NoError(t, err)

	// Create lock request
	req := &LockAssetRequest{
		OwnerAddress:        addr,
		OutputID:            generateTestOutputID(),
		LockDuration: 1 * time.Hour,
	}

	// Lock asset
	resp, err := svc.LockAsset(context.Background(), req)
	require.NoError(t, err)
	require.NotEmpty(t, resp.AssetID)

	// Verify metadata shards were created
	asset, err := svc.storageManager.GetLockedAsset(resp.AssetID)
	require.NoError(t, err)

	// Premium tier: ratio 1.0 → 2 total metadata shards (1 real + 1 decoy)
	require.Equal(t, 2, asset.MetadataShardCount,
		"Premium tier should have 2 metadata shards (1 real + 1 decoy)")

	// Verify index map
	require.NotNil(t, asset.MetadataIndexMap)
	require.Len(t, asset.MetadataIndexMap, 2,
		"MetadataIndexMap should have 2 entries")

	// Count real vs decoy
	realCount := 0
	decoyCount := 0
	for _, isReal := range asset.MetadataIndexMap {
		if isReal {
			realCount++
		} else {
			decoyCount++
		}
	}

	require.Equal(t, 1, realCount, "Should have exactly 1 real metadata shard")
	require.Equal(t, 1, decoyCount, "Should have exactly 1 decoy metadata shard")

	// Verify metadata shards can be retrieved
	for i := 0; i < asset.MetadataShardCount; i++ {
		shardID := fmt.Sprintf("%s-meta-%d", resp.AssetID, i)
		shard, err := svc.storageManager.GetShard(shardID)
		require.NoError(t, err, "Failed to retrieve metadata shard %d", i)
		require.NotEmpty(t, shard, "Metadata shard %d should not be empty", i)
	}
}

// TestLockAsset_MetadataDecoys_EliteTier verifies Elite tier generates more metadata decoys
func TestLockAsset_MetadataDecoys_EliteTier(t *testing.T) {
	svc := createTestService(t)
	svc.config.Tier = interfaces.TierElite

	addr, err := generateTestEd25519Address()
	require.NoError(t, err)

	req := &LockAssetRequest{
		OwnerAddress:        addr,
		OutputID:            generateTestOutputID(),
		LockDuration: 1 * time.Hour,
	}

	resp, err := svc.LockAsset(context.Background(), req)
	require.NoError(t, err)

	asset, err := svc.storageManager.GetLockedAsset(resp.AssetID)
	require.NoError(t, err)

	// Elite tier: ratio 2.0 → 3 total metadata shards (1 real + 2 decoys)
	require.Equal(t, 3, asset.MetadataShardCount,
		"Elite tier should have 3 metadata shards (1 real + 2 decoys)")

	require.NotNil(t, asset.MetadataIndexMap)
	require.Len(t, asset.MetadataIndexMap, 3)

	realCount := 0
	for _, isReal := range asset.MetadataIndexMap {
		if isReal {
			realCount++
		}
	}

	require.Equal(t, 1, realCount, "Should have exactly 1 real metadata shard")
}

// TestLockAsset_MetadataDecoys_BasicTier verifies Basic tier does NOT generate metadata decoys
func TestLockAsset_MetadataDecoys_BasicTier(t *testing.T) {
	svc := createTestService(t)
	svc.config.Tier = interfaces.TierBasic

	addr, err := generateTestEd25519Address()
	require.NoError(t, err)

	req := &LockAssetRequest{
		OwnerAddress:        addr,
		OutputID:            generateTestOutputID(),
		LockDuration: 1 * time.Hour,
	}

	resp, err := svc.LockAsset(context.Background(), req)
	require.NoError(t, err)

	asset, err := svc.storageManager.GetLockedAsset(resp.AssetID)
	require.NoError(t, err)

	// Basic tier: no metadata decoys
	require.Equal(t, 0, asset.MetadataShardCount,
		"Basic tier should NOT have metadata shards")
	require.Nil(t, asset.MetadataIndexMap,
		"Basic tier should NOT have MetadataIndexMap")
}

// TestLockAsset_MetadataDecoys_StandardTier verifies Standard tier does NOT generate metadata decoys
func TestLockAsset_MetadataDecoys_StandardTier(t *testing.T) {
	svc := createTestService(t)
	svc.config.Tier = interfaces.TierStandard

	addr, err := generateTestEd25519Address()
	require.NoError(t, err)

	req := &LockAssetRequest{
		OwnerAddress:        addr,
		OutputID:            generateTestOutputID(),
		LockDuration: 1 * time.Hour,
	}

	resp, err := svc.LockAsset(context.Background(), req)
	require.NoError(t, err)

	asset, err := svc.storageManager.GetLockedAsset(resp.AssetID)
	require.NoError(t, err)

	// Standard tier: no metadata decoys
	require.Equal(t, 0, asset.MetadataShardCount,
		"Standard tier should NOT have metadata shards")
	require.Nil(t, asset.MetadataIndexMap)
}

// TestLockAsset_MetadataDecoys_Indistinguishability verifies real and decoy metadata shards are same size
func TestLockAsset_MetadataDecoys_Indistinguishability(t *testing.T) {
	svc := createTestService(t)
	svc.config.Tier = interfaces.TierPremium

	addr, err := generateTestEd25519Address()
	require.NoError(t, err)

	req := &LockAssetRequest{
		OwnerAddress:        addr,
		OutputID:            generateTestOutputID(),
		LockDuration: 1 * time.Hour,
	}

	resp, err := svc.LockAsset(context.Background(), req)
	require.NoError(t, err)

	asset, err := svc.storageManager.GetLockedAsset(resp.AssetID)
	require.NoError(t, err)

	// Retrieve all metadata shards
	shardSizes := make(map[int]int)
	for i := 0; i < asset.MetadataShardCount; i++ {
		shardID := fmt.Sprintf("%s-meta-%d", resp.AssetID, i)
		shard, err := svc.storageManager.GetShard(shardID)
		require.NoError(t, err)
		shardSizes[i] = len(shard)
	}

	// All metadata shards must be the same size (indistinguishable)
	require.Len(t, shardSizes, asset.MetadataShardCount)

	var expectedSize int
	for i, size := range shardSizes {
		if i == 0 {
			expectedSize = size
		}
		require.Equal(t, expectedSize, size,
			"All metadata shards must be the same size (real and decoys indistinguishable)")
	}

	// Size should be non-zero
	require.Greater(t, expectedSize, 0, "Metadata shards should not be empty")
}

// TestLockAsset_MetadataDecoys_RandomPositions verifies real metadata is placed randomly
func TestLockAsset_MetadataDecoys_RandomPositions(t *testing.T) {
	svc := createTestService(t)
	svc.config.Tier = interfaces.TierPremium

	// Lock multiple assets and track where real metadata appears
	realPositions := make(map[int]int)
	numAssets := 20

	for i := 0; i < numAssets; i++ {
		addr, err := generateTestEd25519Address()
		require.NoError(t, err)

		req := &LockAssetRequest{
			OwnerAddress:        addr,
			OutputID:            generateTestOutputID(),
			LockDuration: 1 * time.Hour,
		}

		resp, err := svc.LockAsset(context.Background(), req)
		require.NoError(t, err)

		asset, err := svc.storageManager.GetLockedAsset(resp.AssetID)
		require.NoError(t, err)

		// Find which position has the real metadata
		for pos, isReal := range asset.MetadataIndexMap {
			if isReal {
				realPositions[pos]++
				break
			}
		}
	}

	// For Premium tier (2 total shards), real metadata can be at position 0 or 1
	// With truly random placement, both positions should appear
	require.NotEmpty(t, realPositions, "Should have tracked real metadata positions")

	// At least one position should have appeared (sanity check)
	totalCount := 0
	for _, count := range realPositions {
		totalCount += count
	}
	require.Equal(t, numAssets, totalCount, "Should have tracked all assets")

	// With 20 assets and 2 positions, expect both positions to appear at least once
	// (probability of all 20 in same position is 2^-20 ≈ 0.000095%, essentially impossible)
	require.GreaterOrEqual(t, len(realPositions), 2,
		"Real metadata should appear at different positions (not always same position)")
}

// Helper: Generate test Ed25519 address
func generateTestEd25519Address() (iotago.Address, error) {
	// Use a fixed seed for deterministic testing
	var pubKeyArray [32]byte
	for i := range pubKeyArray {
		pubKeyArray[i] = byte(i)
	}
	addr := &iotago.Ed25519Address{}
	copy(addr[:], pubKeyArray[:])
	return addr, nil
}

// Helper: Generate test OutputID
func generateTestOutputID() iotago.OutputID {
	var outputID iotago.OutputID
	for i := range outputID {
		outputID[i] = byte(i)
	}
	return outputID
}
