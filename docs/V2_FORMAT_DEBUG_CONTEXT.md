# V2 Format Integration - Debug Context

**Date:** 2026-01-21
**Task:** P1-03 - Enable V2 shard format end-to-end
**Status:** ⚠️ Partial - Serialization works, Trial decryption broken

---

## Problem Statement

V2 format serialization/deserialization works, but **trial decryption cannot find matching shards** during Unlock flow.

**Error:**
```
V2 trial decryption failed: failed to recover shard 0: no matching shard found
```

**Failing Tests:**
- `TestLockUnlockIntegration_RealFlow`
- `TestLockUnlock_NoScript`
- `TestLockUnlock_EmptyScript`

**Passing Tests:**
- `TestV2ShardSerializationInRealFlow` ✅
- `TestEncryptDataV2_RoundTrip` ✅
- All V2 serialization tests ✅

---

## What Was Changed

### 1. Serialization (WORKS ✅)

**File:** `internal/service/service.go`

**Changed:**
```go
func (s *Service) serializeMixedShard(shard *crypto.MixedShard) ([]byte, error) {
    // OLD: Text format with type markers (ID|Index|Data|ShardType|OriginalIndex)
    // NEW: Binary V2 format (no type markers)
    position := uint32(shard.Index)
    return s.serializeMixedShardV2(shard, position)
}
```

**Changed:**
```go
func (s *Service) retrieveEncryptedMixedShards(assetID string) ([]*StoredShard, error) {
    // OLD: Returned []*crypto.MixedShard with type info
    // NEW: Returns []*StoredShard without type info
    // Uses deserializeMixedShardV2 for binary format
}
```

**Changed:**
```go
func (s *Service) storeEncryptedMixedShardAtIndex(assetID string, index uint32, shard *crypto.MixedShard) error {
    key := fmt.Sprintf("mixedshard_%s_%d", assetID, index)
    // FIX: Use storage index as position (not shard.Index)
    value, err := s.serializeMixedShardV2(shard, index)
    // ...
}
```

### 2. Unlock Flow (BROKEN ❌)

**File:** `internal/service/service.go` lines 1424-1442

**Changed:**
```go
// V2 path: Use trial decryption if Salt is available
if asset.Salt != nil && len(asset.Salt) > 0 && asset.RealCount > 0 {
    clonedEncryptor, err := s.shardEncryptor.CloneWithSalt(asset.Salt)
    // ...
    hkdfWithSalt := clonedEncryptor.GetHKDFManager()

    // V2: mixedShards are already StoredShard[] from retrieveEncryptedMixedShards
    // No conversion needed

    recoveredData, err := s.RecoverWithTrialDecryptionWithHKDF(assetCopy, mixedShards, hkdfWithSalt)
    if err != nil {
        return nil, fmt.Errorf("V2 trial decryption failed: %w (legacy format not supported)", err)
    }
    // ...
}
```

**Removed legacy fallback** - no more ShardIndexMap support.

### 3. Size Limits (FIXED ✅)

```go
const (
    V2MaxShardDataSize = 4096 + V2AuthTagSize  // 4112 bytes
    V2TotalSize = V2HeaderSize + V2MaxShardDataSize  // 4141 bytes
)
```

---

## Trial Decryption Algorithm

**Location:** `internal/service/service.go` lines 2271-2400

**How it works:**
1. For each stored shard (at position 0..N-1)
2. Try ALL keys (keyIdx 0..realCount-1)
3. Decrypt with `DecryptShardV2WithHKDF(shard, bundleID, keyIdx, hkdf)`
4. If AEAD auth succeeds → found match
5. If no key works → "no matching shard found"

**Key function:** `shardEncryptor.DecryptShardV2WithHKDF()`

---

## Suspected Root Causes

### Theory 1: BundleID Mismatch

**Lock uses:** `assetID` as bundleID
```go
shards, err := s.shardEncryptor.EncryptDataV2(assetData, assetID)
```

**Unlock uses:** `asset.ID` as bundleID
```go
recoveredData, err := s.RecoverWithTrialDecryptionWithHKDF(assetCopy, mixedShards, hkdfWithSalt)
// Inside: uses asset.ID
```

**Check:** Are `assetID` (from Lock) and `asset.ID` (from Unlock) identical?

### Theory 2: Salt Not Persisted

**Lock creates salt:**
```go
// In shardEncryptor.EncryptDataV2() → uses current HKDF salt
```

**Unlock needs same salt:**
```go
clonedEncryptor, err := s.shardEncryptor.CloneWithSalt(asset.Salt)
```

**Check:** Is `asset.Salt` saved during Lock? Is it loaded during Unlock?

### Theory 3: Position vs Index Confusion

**Encryption uses:** `position` parameter for key derivation
```go
// encryptShardV2(data, bundleID, position, total)
shardKey, err := e.hkdfManager.DeriveKeyForPosition(bundleID, position)
```

**Storage uses:** Sequential index (0, 1, 2...)
```go
for i, shard := range mixedShards {
    s.storeEncryptedMixedShardAtIndex(assetID, uint32(i), shard)
}
```

**Trial decryption uses:** keyIdx (0..realCount-1)
```go
for keyIdx := 0; keyIdx < realCount; keyIdx++ {
    plaintext, err := s.shardEncryptor.DecryptShardV2WithHKDF(charShard, bundleID, uint32(keyIdx), hkdfManager)
}
```

**Problem:** After MixShards(), `shard.Index` contains **encryption position**, but we store at **sequential position**. Trial decryption may be using wrong bundleID or wrong keyIdx range.

### Theory 4: MixedShard.Index Meaning Changed

**Before mixing:**
```go
// CharacterShard from EncryptDataV2 has Index=0,1,2... (encryption position)
```

**After mixing:**
```go
mixedShards, _, err := s.shardMixer.MixShards(shards, decoys)
// MixedShard still has Index from CharacterShard (encryption position)
// But we store them at i=0,1,2... (storage position)
```

**Trial decryption expects:**
- StoredShard.Position = storage position (0..totalCount-1) ✅
- But tries keys 0..realCount-1 (encryption positions) ✅
- **But:** If bundleID changed or salt wrong → no match!

---

## Debug Steps for Other LLM

### Step 1: Verify BundleID Consistency

Add logging in Lock and Unlock:

```go
// In LockAsset (line 374)
fmt.Printf("DEBUG LOCK: assetID=%s, bundleIDForEncrypt=%s\n", assetID, assetID)

// In UnlockAsset trial decryption (line 1454)
fmt.Printf("DEBUG UNLOCK: asset.ID=%s, bundleIDForDecrypt=%s\n", asset.ID, assetCopy.ID)
```

**Expected:** Both should print same value.

### Step 2: Verify Salt Persistence

Add logging:

```go
// In LockAsset after EncryptDataV2
salt := s.shardEncryptor.GetHKDFManager().GetSalt()
fmt.Printf("DEBUG LOCK: salt=%x (len=%d)\n", salt, len(salt))

// In UnlockAsset before trial decryption
fmt.Printf("DEBUG UNLOCK: asset.Salt=%x (len=%d)\n", asset.Salt, len(asset.Salt))
```

**Expected:** Both should print same salt.

### Step 3: Verify Key Derivation

In trial decryption loop (line 2376):

```go
for keyIdx := 0; keyIdx < realCount; keyIdx++ {
    fmt.Printf("DEBUG TRIAL: pos=%d, keyIdx=%d, bundleID=%s\n", pos, keyIdx, bundleID)
    plaintext, err := s.shardEncryptor.DecryptShardV2WithHKDF(charShard, bundleID, uint32(keyIdx), hkdfManager)
    if err == nil {
        fmt.Printf("DEBUG TRIAL: MATCH! pos=%d matched keyIdx=%d\n", pos, keyIdx)
    }
}
```

**Expected:** Should see at least `realCount` matches (one per real shard).

### Step 4: Check CharacterShard.Index

In storeEncryptedMixedShardAtIndex (line 1684):

```go
fmt.Printf("DEBUG STORE: storageIdx=%d, shard.Index=%d (encryption pos)\n", index, shard.Index)
```

**Expected:** `storageIdx` sequential (0,1,2...), `shard.Index` may be shuffled.

---

## Files to Review

1. **`internal/service/service.go`**
   - Lines 374-493: LockAsset encryption flow
   - Lines 686: Storage loop (storeEncryptedMixedShardAtIndex)
   - Lines 1370-1475: UnlockAsset trial decryption
   - Lines 2271-2400: RecoverWithTrialDecryptionWithHKDF

2. **`internal/crypto/encrypt.go`**
   - Lines 342-382: EncryptDataV2
   - Lines 396-435: encryptShardV2 (key derivation)
   - DecryptShardV2WithHKDF

3. **`internal/crypto/decoy.go`**
   - Lines 269-320: MixShards (shuffle logic)

---

## Quick Fix Hypothesis

**Most likely:** Salt is not being saved to `asset.Salt` during Lock.

**Check in LockAsset** (after EncryptDataV2):
```go
// Need to capture salt and save to asset
salt := s.shardEncryptor.GetHKDFManager().GetSalt()
asset.Salt = salt  // ← Is this line present?
```

**Without this**, Unlock will try to decrypt with wrong HKDF salt → no matches.

---

## Success Criteria

Once fixed, these tests MUST pass:
```bash
go test ./internal/service -run "TestLockUnlock" -v
```

**Expected output:**
```
=== RUN   TestLockUnlockIntegration_RealFlow
--- PASS: TestLockUnlockIntegration_RealFlow (2.00s)
=== RUN   TestLockUnlock_NoScript
--- PASS: TestLockUnlock_NoScript (2.00s)
PASS
```

---

## Current Code State

- Branch: `main`
- Last commit: V2 format serialization updated
- Tests passing: V2 serialization only
- Tests failing: Lock/Unlock integration
- No uncommitted changes blocking

---

## Contact for Questions

If needed, reference:
- `docs/ARCHITECTURE.md` - System architecture
- `docs/SECURITY_TESTING.md` - Testing guidelines
- `internal/crypto/CLAUDE.md` - Crypto module docs
- `internal/service/CLAUDE.md` - Service module docs
