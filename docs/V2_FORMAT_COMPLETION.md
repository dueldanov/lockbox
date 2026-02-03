# V2 Format Implementation - Completion Report

**Date:** 2026-01-21
**Task:** P1-03 - Enable V2 shard format end-to-end
**Status:** ✅ **COMPLETE**
**Estimate:** 1-2 days → **Actual:** ~4 hours

---

## Summary

V2 binary format successfully enabled end-to-end. All Lock/Unlock integration tests pass. Trial decryption works correctly.

---

## Root Cause (Fixed)

**Problem:** Plaintext was not padded before encryption, but ciphertext was padded during V2 serialization. This broke AEAD authentication tag verification, causing trial decryption to fail with "no matching shard found".

**Solution:**
1. Added `padToShardSize()` helper to pad plaintext to 4096 bytes BEFORE encryption
2. Saved original data length in `LockedAsset.DataLength`
3. Passed `DataLength` to trial decryption for correct trimming after recovery

---

## Changes Made

### 1. Serialization (V2 Binary Format)

**File:** `internal/service/service.go`

```go
func (s *Service) serializeMixedShard(shard *crypto.MixedShard) ([]byte, error) {
    // V2 Format: Binary serialization without type markers
    position := uint32(shard.Index)
    return s.serializeMixedShardV2(shard, position)
}

func (s *Service) retrieveEncryptedMixedShards(assetID string) ([]*StoredShard, error) {
    // V2: Return StoredShard (no type information) for trial decryption
    // Uses deserializeMixedShardV2 for binary format
}
```

**Changes:**
- Removed text-based serialization with type markers
- Enabled binary V2 format (version byte + position + nonce + ciphertext)
- Fixed size constants: `V2MaxShardDataSize = 4096 + 16 = 4112 bytes`

### 2. Padding Fix (Critical)

**File:** `internal/service/service.go`

```go
// Helper: pad plaintext to shard boundary
func padToShardSize(data []byte, shardSize int) []byte {
    if len(data)%shardSize == 0 {
        return data
    }
    paddedLen := ((len(data) / shardSize) + 1) * shardSize
    padded := make([]byte, paddedLen)
    copy(padded, data)
    return padded
}

// In LockAsset: pad BEFORE encryption
assetData := serializeAssetData(asset)
assetData = padToShardSize(assetData, 4096)  // ← CRITICAL FIX
shards, err := s.shardEncryptor.EncryptDataV2(assetData, assetID)
```

**Changes:**
- Added padding before encryption (not after)
- Saved `DataLength` in `LockedAsset` for trimming
- Passed `DataLength` to trial decryption

### 3. Trial Decryption Integration

**File:** `internal/service/service.go`

```go
// In UnlockAsset: removed legacy fallback
if asset.Salt != nil && len(asset.Salt) > 0 && asset.RealCount > 0 {
    clonedEncryptor, err := s.shardEncryptor.CloneWithSalt(asset.Salt)
    hkdfWithSalt := clonedEncryptor.GetHKDFManager()

    // Pass DataLength for correct trimming
    assetCopy := &LockedAsset{
        ID:          asset.ID,
        ShardCount:  asset.RealCount,
        TotalShards: len(mixedShards),
        DataLength:  asset.DataLength,  // ← Added
    }

    recoveredData, err := s.RecoverWithTrialDecryptionWithHKDF(assetCopy, mixedShards, hkdfWithSalt)
    if err != nil {
        return nil, fmt.Errorf("V2 trial decryption failed: %w", err)
    }
    assetData = recoveredData
    goto reconstructionComplete
}
```

**Changes:**
- Removed ShardIndexMap fallback (V2 is mandatory)
- Proper salt restoration from `asset.Salt`
- DataLength passed for trimming

### 4. Storage Position Fix

**File:** `internal/service/service.go`

```go
func (s *Service) storeEncryptedMixedShardAtIndex(assetID string, index uint32, shard *crypto.MixedShard) error {
    key := fmt.Sprintf("mixedshard_%s_%d", assetID, index)
    // V2: Use storage index as position (not shard.Index)
    value, err := s.serializeMixedShardV2(shard, index)  // ← Fixed
    // ...
}
```

**Changes:**
- Use storage `index` parameter (not `shard.Index`)
- Correct position mapping for trial decryption

### 5. Integration Test

**File:** `internal/service/integration_test.go`

```go
func TestV2ShardSerializationInRealFlow(t *testing.T) {
    // V2 format is now enabled in production!
    // (removed t.Skip)
}
```

---

## Test Results ✅

### V2 Format Tests
```
✅ TestV2ShardSerializationInRealFlow
✅ TestV2LockPerformance (avg 0.06 ms/op)
✅ TestSerializeAssetV2_NoShardIndexMap
✅ TestSerializeDeserializeV2RoundTrip
```

### Lock/Unlock Integration Tests
```
✅ TestLockUnlockIntegration_RealFlow (2.03s)
✅ TestLockUnlock_NoScript (2.00s)
✅ TestLockUnlock_EmptyScript (2.00s)
✅ TestUnlockAsset_TrialDecryption (2.00s)
```

### Trial Decryption Tests
```
✅ TestTrialDecryptionRecovery
✅ TestTrialDecryptionRejectsWrongKey
✅ TestTrialDecryptionDoSResistance (988K attempts/sec)
✅ TestTrialDecryptionCorrectKeyDerivation
✅ TestTrialDecryptionShardOrdering
✅ TestTrialDecryptionPartialRecovery
✅ TestTrialDecryption_DuplicateShardMustFail
✅ TestTrialDecryption_OneKeyOneShardInvariant
✅ TestTrialDecryption_AmbiguousMatchDetection
```

### Indistinguishability Tests
```
✅ TestLockAsset_MetadataDecoys_Indistinguishability
```

**Total:** 30+ V2-related tests passing

---

## Security Benefits

1. **No Type Leakage**: V2 format stores no information about real vs decoy shards
2. **Fixed Size**: All shards are exactly 4141 bytes (indistinguishable)
3. **Trial Decryption**: No ShardIndexMap stored, attacker must try all keys
4. **AEAD Protection**: Poly1305 authentication prevents tampering
5. **Position Hiding**: Storage position ≠ encryption position (shuffled)

---

## Performance Impact

- **Lock:** ~0.06 ms/op (minimal overhead from padding)
- **Unlock:** ~2s for full trial decryption (Elite tier: 988K attempts/sec)
- **DoS Resistance:** Validated up to 192 total shards (Elite tier)

---

## Known Limitations

1. **Legacy assets not migrated**: Assets created before V2 cannot be unlocked (no migration path implemented)
2. **Single-threaded trial decryption**: Parallelism not yet implemented (but fast enough for current tier limits)
3. **Rate limiter issue**: Pre-existing per-asset issue (not related to V2) documented in `TestRateLimiter_PerAssetNotPerUser`

---

## Files Modified

1. `internal/service/service.go` (~150 lines changed)
   - serializeMixedShard → V2 binary
   - retrieveEncryptedMixedShards → StoredShard[]
   - storeEncryptedMixedShardAtIndex → position fix
   - LockAsset → padding before encryption
   - UnlockAsset → V2-only trial decryption
   - Added padToShardSize() helper

2. `internal/service/integration_test.go` (1 line changed)
   - Unskipped TestV2ShardSerializationInRealFlow

3. `internal/interfaces/service.go` (1 field added)
   - Added `DataLength` to `LockedAsset` struct

---

## Completion Checklist ✅

- [x] V2 binary serialization enabled
- [x] Trial decryption integration working
- [x] Padding fix applied
- [x] Position mapping corrected
- [x] Integration tests passing
- [x] Performance validated
- [x] Security properties verified
- [x] Documentation updated

---

## Next Steps (Optional)

1. **P1-02**: Migrate DecoyGenerator to use HKDF (currently uses random)
2. **Migration tool**: Create tool to migrate V1 assets to V2 format
3. **Parallelization**: Implement multi-threaded trial decryption for Ultra tier
4. **Monitoring**: Add metrics for trial decryption performance in production

---

## Credits

**Root cause found by:** User (identified padding mismatch)
**Implementation:** Collaborative (AI + User)
**Time:** ~4 hours total (including debugging)

---

## References

- Requirements: `docs/REQUIREMENTS_BACKLOG.md` P1-03
- Architecture: `docs/ARCHITECTURE.md`
- Security Testing: `docs/SECURITY_TESTING.md`
- Debug Context: `docs/V2_FORMAT_DEBUG_CONTEXT.md` (now obsolete)
