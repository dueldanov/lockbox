package service

import (
	"strings"
	"testing"

	"github.com/dueldanov/lockbox/v2/internal/crypto"
)

// Serialized shards must not leak type markers and should be fixed-size.
func TestSerializeMixedShardV2_NoTypeMarkersAndFixedLength(t *testing.T) {
	svc := newTestServiceMinimal(t)

	shards := []*crypto.MixedShard{
		createTestRealShard(t, 0),
		createTestDecoyShard(t, 1),
		createTestRealShard(t, 2),
	}

	var expectedLen int
	for i, shard := range shards {
		out, err := svc.serializeMixedShardV2(shard, uint32(i))
		if err != nil {
			t.Fatalf("serialize shard %d: %v", i, err)
		}
		if out[0] != ShardFormatV2 {
			t.Fatalf("shard %d version = 0x%02x, want 0x%02x", i, out[0], ShardFormatV2)
		}
		if expectedLen == 0 {
			expectedLen = len(out)
			if expectedLen != V2TotalSize {
				t.Fatalf("shard length = %d, want %d", expectedLen, V2TotalSize)
			}
		} else if len(out) != expectedLen {
			t.Fatalf("shard %d length mismatch: got %d want %d", i, len(out), expectedLen)
		}

		s := string(out)
		for _, forbidden := range []string{"ShardType", "OriginalIndex", "real", "decoy"} {
			if strings.Contains(s, forbidden) {
				t.Fatalf("serialized shard %d leaks marker %q", i, forbidden)
			}
		}
	}
}

// V2 shards should deserialize back to StoredShard without type info.
func TestSerializeDeserializeV2RoundTrip(t *testing.T) {
	svc := newTestServiceMinimal(t)

	shard := createTestRealShard(t, 42)
	out, err := svc.serializeMixedShardV2(shard, 123)
	if err != nil {
		t.Fatalf("serialize: %v", err)
	}

	stored, err := svc.deserializeMixedShardV2(out)
	if err != nil {
		t.Fatalf("deserialize: %v", err)
	}

	if stored.Position != 123 {
		t.Fatalf("position = %d, want 123", stored.Position)
	}
	if len(stored.Nonce) != V2NonceSize {
		t.Fatalf("nonce length = %d, want %d", len(stored.Nonce), V2NonceSize)
	}
	if len(stored.Ciphertext) != V2TotalSize-V2HeaderSize {
		t.Fatalf("ciphertext length = %d, want %d", len(stored.Ciphertext), V2TotalSize-V2HeaderSize)
	}
}

// Asset serialization must not persist ShardIndexMap.
func TestSerializeAssetV2_NoShardIndexMap(t *testing.T) {
	svc := newTestServiceMinimal(t)

	asset := &LockedAsset{
		ID:            "asset-123",
		TotalShards:   10,
		RealCount:     5,
		ShardIndexMap: map[uint32]uint32{0: 3, 1: 7},
		Status:        AssetStatusLocked,
	}

	data, err := svc.serializeAssetV2(asset)
	if err != nil {
		t.Fatalf("serialize asset: %v", err)
	}

	str := string(data)
	if strings.Contains(str, "ShardIndexMap") || strings.Contains(str, "shard_index_map") {
		t.Fatalf("ShardIndexMap leaked in serialized asset: %s", str)
	}
	if !strings.Contains(str, "total_shards") {
		t.Fatalf("serialized asset missing total_shards: %s", str)
	}
	if !strings.Contains(str, "real_count") {
		t.Fatalf("serialized asset missing real_count: %s", str)
	}
}

// lockAssetForTrialDecryption should produce shards without storing the index map.
func TestLockAssetForTrialDecryption_NoIndexMap(t *testing.T) {
	svc := newTestServiceMinimal(t)

	asset, shards, err := svc.lockAssetForTrialDecryption([]byte("test data for indistinguishability"), 4, 8)
	if err != nil {
		t.Fatalf("lockAssetForTrialDecryption failed: %v", err)
	}

	if asset.ShardIndexMap != nil {
		t.Fatalf("ShardIndexMap should not be set, got %v", asset.ShardIndexMap)
	}
	if asset.ShardCount != 4 {
		t.Fatalf("real shard count = %d, want 4", asset.ShardCount)
	}
	if len(shards) != 8 {
		t.Fatalf("expected 8 stored shards, got %d", len(shards))
	}
	for i, sh := range shards {
		if int(sh.Position) != i {
			t.Fatalf("shard %d position = %d", i, sh.Position)
		}
		if len(sh.Nonce) != V2NonceSize {
			t.Fatalf("shard %d nonce length = %d, want %d", i, len(sh.Nonce), V2NonceSize)
		}
	}
}
