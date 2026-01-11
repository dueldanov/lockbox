# LockBox V2 Security Architecture

**Version:** 2.1
**Date:** 2025-12-26
**Status:** Production Ready (under stated assumptions)

---

## Table of Contents

1. [Overview](#overview)
2. [Threat Model](#threat-model)
3. [Cryptographic Primitives](#cryptographic-primitives)
4. [Shard Format](#shard-format)
5. [Security Goals](#security-goals)
6. [Key Derivation](#key-derivation)
7. [AAD Binding](#aad-binding)
8. [Decoy Generation](#decoy-generation)
9. [Trial Decryption Algorithm](#trial-decryption-algorithm)
10. [DoS Protection](#dos-protection)
11. [Implementation Hardening](#implementation-hardening)
12. [API Security Boundary](#api-security-boundary)
13. [Known Limitations](#known-limitations)
14. [References](#references)

---

## Overview

LockBox V2 implements a client-side cryptographic asset locking system with **shard indistinguishability**: storage cannot distinguish real data shards from decoy shards.

### Key Properties

| Property | Description |
|----------|-------------|
| **Confidentiality** | XChaCha20-Poly1305 AEAD |
| **Integrity** | AEAD authentication prevents tampering |
| **Shard indistinguishability** | Real/decoy shards share identical structure & sizes |
| **Cross-bundle unlinkability** | Per-bundle salt prevents correlating keys across bundles |
| **DoS resistance** | Strict bounds on shard count/size + recovery timeout |

---

## Threat Model

### Terminology (Critical)

| Term | Definition |
|------|------------|
| **realIndex** | Logical index of a real shard in the reconstructed sequence, `0..RealCount-1`. Also the key derivation index. |
| **storagePos** | Physical position in the stored shard array after mixing/shuffling, `0..TotalShards-1`. |

### Assets

| Asset | Classification | Notes |
|-------|---------------|-------|
| Plaintext data | SECRET | Never stored |
| Master key | SECRET | Client HSM/KeyStore only |
| Per-bundle salt | STORED | Stored in metadata; required for recovery |
| bundleID | PUBLIC | Used for domain separation |
| Mapping realIndex→storagePos | HIDDEN | NOT stored; derived via trial decryption |

### Attacker Levels

#### Level 1: Passive Storage Read
- Reads all shard bytes + metadata
- Knows bundleID, TotalShards, RealCount, tier
- No master key, no modification, no client observation

#### Level 2: Active Storage + Observation
- Can inject/replace shards
- Can observe I/O and coarse timing of client operations
- Can attempt DoS via shard inflation

#### Level 3: Compromised Client (Out of Scope)
- Master key exposed → full compromise

---

## Cryptographic Primitives

### Encryption: XChaCha20-Poly1305

```
Algorithm:  XChaCha20-Poly1305 AEAD
Key:        32 bytes
Nonce:      24 bytes (random per shard)
Tag:        16 bytes (appended as part of ciphertext)
```

### KDF: HKDF-SHA256 (RFC 5869)

```
IKM:    masterKey (32 bytes)
salt:   bundleSalt (32 bytes, CSPRNG)
info:   "LockBox:shard" || 0x00 || bundleID || 0x00 || realIndexBE32
Output: 32 bytes
```

**Note:** This document uses `realIndex` as the KDF key selector (not `storagePos`).

---

## Shard Format

All shards (real + decoy) are stored in the same binary format.

### ShardBlob (bytes)

```
[ Magic(4) | Ver(1) | Flags(1) | Rsv(2) | Nonce(24) | Ciphertext(N) ]
```

| Field | Size | Value |
|-------|------|-------|
| Magic | 4 | `"LB2S"` (0x4C423253) |
| Ver | 1 | `0x02` |
| Flags | 1 | Reserved, `0x00` |
| Rsv | 2 | Reserved, `0x0000` |
| Nonce | 24 | XChaCha20 nonce (random) |
| Ciphertext | N | `Enc(plaintext) + Tag(16)` |

**Indistinguishability rule:** Decoys MUST match the exact same `plaintextLen` and thus the same `Ciphertext(N)` length.

### Size Calculation

For `plaintextLen = 4096`:
- `CiphertextLen = 4096 + 16 = 4112`
- `HeaderLen = 4 + 1 + 1 + 2 = 8`
- `NonceLen = 24`
- `ShardBlobLen = 8 + 24 + 4112 = 4144`

---

## Security Goals

1. **Indistinguishability:** Without master key, attacker cannot decide if a given shard is real or decoy with advantage beyond negligible.

2. **Binding / Relocation Resistance:** A valid shard must only decrypt under its intended `(bundleID, realIndex)` context.

3. **Constant-Work Recovery:** Unlock performs a **fixed** number of AEAD open attempts (`TotalShards × RealCount`) to reduce timing leakage from early success.

4. **Bounded Resource Usage:** Unlock time and memory are bounded under attacker-controlled storage inputs.

---

## Key Derivation

### Per-realIndex Key

```
PRK = HKDF-Extract(salt=bundleSalt, IKM=masterKey)
key(realIndex) = HKDF-Expand(PRK, info(bundleID, realIndex), 32)
```

### Go-style Info Encoding (Canonical, Unambiguous)

```go
func shardInfo(bundleID string, realIndex uint32) []byte {
    b := make([]byte, 0, 32+len(bundleID)+4)
    b = append(b, []byte("LockBox:shard")...)
    b = append(b, 0x00)
    b = append(b, []byte(bundleID)...)
    b = append(b, 0x00)
    tmp := make([]byte, 4)
    binary.BigEndian.PutUint32(tmp, realIndex)
    b = append(b, tmp...)
    return b
}
```

---

## AAD Binding

AAD binds ciphertext to the bundle + realIndex to prevent relocation/reordering attacks.

### AAD Format (36 bytes)

```
AAD = SHA256(bundleID)[0:32] || realIndexBE32[0:4]
      ────────────────────      ────────────────
           32 bytes                 4 bytes
```

**Rationale:** Full 32-byte hash avoids "32-bit binding" weakness; cost is negligible.

### Go Implementation

```go
func buildAAD(bundleID string, realIndex uint32) []byte {
    aad := make([]byte, 36)
    hash := sha256.Sum256([]byte(bundleID))
    copy(aad[0:32], hash[:])
    binary.BigEndian.PutUint32(aad[32:36], realIndex)
    return aad
}
```

---

## Decoy Generation

### Requirements

1. Same `ShardBlob` format as real shards (including headers, nonce length, ciphertext length)
2. Keys **independent** of master key (pure random)
3. Fixed `plaintextLen` equal to real shards

### Reference Implementation

```go
func GenerateDecoy(plaintextLen int) ShardBlob {
    // Independent from masterKey - pure random
    decoyKey := randBytes(32)
    defer clearBytes(decoyKey)

    nonce := randBytes(24)          // XChaCha nonce
    pt := randBytes(plaintextLen)   // Random plaintext (same size as real)
    defer clearBytes(pt)

    aead, _ := chacha20poly1305.NewX(decoyKey)
    ct := aead.Seal(nil, nonce, pt, nil)  // No AAD for decoys

    return BuildShardBlobV2(nonce, ct)
}
```

### Why Random Decoy Keys?

Eliminates any accidental linkage between decoys and the HKDF structure. Reduces risk of future protocol changes introducing a key-confirmation oracle.

**Attack scenario with derived keys:**
```
Attacker tries: key = HKDF(guessedMasterKey, "decoy", i)
If decryption succeeds → confirms master key guess
```

**With random keys:** No relationship to master key, no oracle attack possible.

---

## Trial Decryption Algorithm

### Design Requirement: Constant-Work

Unlock MUST perform exactly `TotalShards × RealCount` AEAD open attempts.
Finding matches MUST NOT reduce the number of crypto operations.

### Pseudocode (Constant-Work)

```
Recover(bundleID, shardBlobs[], RealCount, bundleSalt):

    PRK = HKDF-Extract(bundleSalt, masterKey)

    // Pre-derive all keys and AADs
    keys[0..RealCount-1] = derive all keys
    aad[0..RealCount-1]  = SHA256(bundleID) || realIndexBE32

    recovered[realIndex] = nil
    matchedShards[realIndex] = -1   // Track which storagePos matched
    shardMatches[storagePos] = -1   // Track which realIndex this shard matched

    // Deterministic permutation (unpredictable to storage attacker)
    permSeed = HMAC-SHA256(PRK, "perm")
    positions = DeterministicShuffle(0..TotalShards-1, permSeed)

    // CONSTANT-WORK: Always execute ALL iterations
    for storagePos in positions:
        shard = ParseShardBlobV2(shardBlobs[storagePos])
        if shard.invalidFormat:
            continue  // Format check is constant-time/cost-bounded

        for realIndex in 0..RealCount-1:
            // ALWAYS execute AEAD open - no skipping
            pt, err = AEAD_Open(
                keys[realIndex],
                shard.nonce,
                shard.ciphertext,
                aad[realIndex]
            )

            // Record result but DO NOT break or skip
            if err == nil:
                if recovered[realIndex] != nil:
                    // FAIL-CLOSED: Multiple shards for same realIndex
                    return ERROR("duplicate match for realIndex")
                if shardMatches[storagePos] != -1:
                    // FAIL-CLOSED: Same shard matches multiple keys
                    return ERROR("shard matches multiple keys")

                recovered[realIndex] = pt
                matchedShards[realIndex] = storagePos
                shardMatches[storagePos] = realIndex

    // Verify complete recovery
    if count(recovered) != RealCount:
        return ERROR("incomplete recovery")

    return Reassemble(recovered[0..RealCount-1])
```

### Fail-Closed Rules

| Condition | Action | Rationale |
|-----------|--------|-----------|
| Same realIndex matches 2+ shards | FAIL | Prevents injection attacks |
| Same shard matches 2+ realIndexes | FAIL | Should be negligible; indicates corruption |
| Missing any realIndex | FAIL | Incomplete recovery |

### Go Implementation with Context Timeout

```go
func (s *Service) RecoverWithTimeout(
    ctx context.Context,
    bundleID string,
    shards []*ShardBlob,
    realCount int,
    salt []byte,
) ([]byte, error) {
    // Enforce timeout
    ctx, cancel := context.WithTimeout(ctx, MaxRecoveryTime)
    defer cancel()

    // Result channels
    resultCh := make(chan recoveryResult, 1)

    go func() {
        result, err := s.recoverConstantWork(bundleID, shards, realCount, salt)
        select {
        case resultCh <- recoveryResult{data: result, err: err}:
        case <-ctx.Done():
            // Timeout - result discarded
        }
    }()

    select {
    case result := <-resultCh:
        return result.data, result.err
    case <-ctx.Done():
        return nil, fmt.Errorf("recovery timeout: %w", ctx.Err())
    }
}

func (s *Service) recoverConstantWork(
    bundleID string,
    shards []*ShardBlob,
    realCount int,
    salt []byte,
) ([]byte, error) {
    hkdf := s.hkdfManager.CloneWithSalt(salt)
    defer hkdf.Clear()

    // Pre-derive all keys
    keys := make([][]byte, realCount)
    aads := make([][]byte, realCount)
    for i := 0; i < realCount; i++ {
        keys[i] = hkdf.DeriveKey(shardInfo(bundleID, uint32(i)))
        aads[i] = buildAAD(bundleID, uint32(i))
        defer clearBytes(keys[i])
    }

    recovered := make(map[int][]byte)
    matchedShards := make(map[int]int)    // realIndex -> storagePos
    shardMatches := make(map[int]int)     // storagePos -> realIndex

    positions := deterministicShuffle(len(shards), hkdf)

    // CONSTANT-WORK LOOP
    for _, storagePos := range positions {
        shard := shards[storagePos]

        for realIndex := 0; realIndex < realCount; realIndex++ {
            // ALWAYS execute - no early exit
            pt, err := aeadOpen(keys[realIndex], shard.Nonce, shard.Ciphertext, aads[realIndex])

            if err == nil {
                // Check fail-closed conditions
                if _, exists := recovered[realIndex]; exists {
                    return nil, errors.New("fail-closed: duplicate match for realIndex")
                }
                if _, exists := shardMatches[storagePos]; exists {
                    return nil, errors.New("fail-closed: shard matches multiple keys")
                }

                recovered[realIndex] = pt
                matchedShards[realIndex] = storagePos
                shardMatches[storagePos] = realIndex
            }
            // Continue regardless of result
        }
    }

    if len(recovered) != realCount {
        return nil, fmt.Errorf("incomplete recovery: got %d, need %d", len(recovered), realCount)
    }

    return reassemble(recovered, realCount), nil
}
```

### Complexity Analysis

| Tier | Real | Total | Attempts | Expected Time* |
|------|------|-------|----------|----------------|
| Basic | 16 | 24 | 384 | ~0.5ms |
| Standard | 32 | 64 | 2,048 | ~2ms |
| Premium | 48 | 120 | 5,760 | ~6ms |
| Elite | 64 | 192 | 12,288 | ~14ms |

*Benchmarked on Apple M1, Go 1.21, shards in RAM, single-thread.

---

## DoS Protection

### Hard Limits (V2)

```go
const (
    // Shard limits
    MaxPlaintextLen      = 4096
    MaxCiphertextLen     = MaxPlaintextLen + 16  // + auth tag
    MaxShardBlobLen      = 8 + 24 + MaxCiphertextLen  // header + nonce + ct

    // Bundle limits
    MaxTotalShards       = 256
    MaxRealCount         = 64
    MaxTotalShardBytes   = MaxTotalShards * MaxShardBlobLen

    // Time limits
    MaxRecoveryTime      = 60 * time.Second
)
```

### Validation Rules

```go
func validateRecoveryInput(shards []*ShardBlob, realCount int) error {
    if len(shards) > MaxTotalShards {
        return ErrTooManyShards
    }
    if realCount > MaxRealCount {
        return ErrTooManyRealShards
    }
    if realCount > len(shards) {
        return ErrInvalidShardCount
    }

    totalBytes := 0
    for i, shard := range shards {
        if len(shard.Raw) > MaxShardBlobLen {
            return fmt.Errorf("shard %d: %w", i, ErrShardTooLarge)
        }
        totalBytes += len(shard.Raw)
    }

    if totalBytes > MaxTotalShardBytes {
        return ErrTotalSizeTooLarge
    }

    return nil
}
```

---

## Implementation Hardening

### Timing / Work Normalization

- Unlock performs **fixed count** of AEAD opens: `TotalShards × RealCount`
- **No break** in either loop
- Avoid data-dependent I/O: load shard blobs uniformly

### I/O Ordering

Use a keyed deterministic permutation:
- **Deterministic** for reproducibility and testing
- **Unpredictable** to storage attacker without master key

```go
func deterministicShuffle(n int, hkdf *HKDFManager) []int {
    seed := hkdf.DeriveKey([]byte("LockBox:perm"))
    defer clearBytes(seed)

    positions := make([]int, n)
    for i := range positions {
        positions[i] = i
    }

    // Fisher-Yates with deterministic PRNG
    rng := newDeterministicRNG(seed)
    for i := n - 1; i > 0; i-- {
        j := rng.Intn(i + 1)
        positions[i], positions[j] = positions[j], positions[i]
    }

    return positions
}
```

### Memory Hygiene

```go
// Zeroize derived keys after use
defer clearBytes(derivedKey)
defer hkdfManager.Clear()

// Avoid logging decryption errors per-key/per-shard
// Only log aggregate failure
```

---

## API Security Boundary

This document covers **shard encryption format + recovery**.

API mechanisms (tokens, request nonces, ZKP ownership proofs) are separate components and must be specified in their own protocol documents.

### Important Distinction

| Concept | Scope | Size | Purpose |
|---------|-------|------|---------|
| **AEAD nonce** | Per-shard encryption | 24 bytes | XChaCha20 IV |
| **API request nonce** | Request authentication | Variable | Replay protection |

**CRITICAL:** These are different concepts. API request nonces MUST NOT reuse AEAD nonce fields or formats.

---

## Known Limitations

### Accepted Leakage

| Leak | Severity | Notes |
|------|----------|-------|
| TotalShards visible | LOW | Observable from storage object count |
| Tier inferable | LOW | Derived from TotalShards |
| Residual client side-channels | MEDIUM | Constant-work reduces but doesn't eliminate |

### Out of Scope

- Compromised client / stolen master key
- Strong side-channel attackers on client hardware
- Post-quantum security (ChaCha20 is not PQ-resistant)

### Recommendations

1. **HSM for master key** in production deployments
2. **Regular key rotation** (re-encrypt with new master key)
3. **Audit logging** for all lock/unlock operations
4. **Network encryption** (TLS 1.3) for API calls

---

## References

- [RFC 8439: ChaCha20-Poly1305](https://tools.ietf.org/html/rfc8439)
- [RFC 5869: HKDF](https://tools.ietf.org/html/rfc5869)
- [XChaCha20-Poly1305 (libsodium spec)](https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)

---

## Changelog

| Version | Date | Changes |
|---------|------|---------|
| 2.1 | 2025-12-26 | Terminology clarification (realIndex/storagePos), 36-byte AAD, constant-work specification, fail-closed rules, ShardBlob format |
| 2.0 | 2025-12-26 | Trial decryption, security hardening |
| 1.0 | 2025-12-20 | Initial V2 encryption format |
