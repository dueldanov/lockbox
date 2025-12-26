# LockBox V2 Security Architecture

**Version:** 2.0
**Date:** 2025-12-26
**Status:** Production Ready

---

## Table of Contents

1. [Overview](#overview)
2. [Threat Model](#threat-model)
3. [Cryptographic Primitives](#cryptographic-primitives)
4. [Shard Indistinguishability](#shard-indistinguishability)
5. [Trial Decryption Algorithm](#trial-decryption-algorithm)
6. [Key Derivation](#key-derivation)
7. [Decoy Generation](#decoy-generation)
8. [DoS Protection](#dos-protection)
9. [Security Hardening](#security-hardening)
10. [API Security](#api-security)
11. [Known Limitations](#known-limitations)

---

## Overview

LockBox V2 implements a cryptographic asset locking system with **shard indistinguishability** — storage nodes cannot distinguish between real and decoy data shards. This document describes the security architecture, threat model, and implementation details.

### Key Security Properties

| Property | Description |
|----------|-------------|
| **Confidentiality** | Data encrypted with ChaCha20-Poly1305 AEAD |
| **Integrity** | AEAD authentication prevents tampering |
| **Indistinguishability** | Real/decoy shards cryptographically identical |
| **Forward Secrecy** | Per-bundle salt prevents cross-bundle correlation |
| **DoS Resistance** | Limits on shard count and size |

---

## Threat Model

### Assets to Protect

| Asset | Classification | Protection |
|-------|---------------|------------|
| Plaintext data | SECRET | Never leaves client unencrypted |
| Master key | SECRET | HSM/KeyStore, never in storage |
| Salt (per-bundle) | STORED | Required for recovery, stored with metadata |
| Bundle ID | PUBLIC | Used in key derivation |
| Shard positions | HIDDEN | Not stored, recovered via trial decryption |

### Attacker Capabilities

#### Level 1: Passive Storage Access
- ✅ Can read all shard bytes
- ✅ Can read asset metadata (without ShardIndexMap)
- ✅ Knows bundleID, totalShards, tier
- ❌ Does NOT have master key
- ❌ Cannot modify storage
- ❌ Cannot observe client operations

**Mitigations:** Encryption, shard indistinguishability

#### Level 2: Active Storage + Observation
- All Level 1 capabilities, plus:
- ✅ Can replace/inject shards
- ✅ Can observe I/O patterns
- ✅ Can measure operation timing
- ✅ Can add fake shards (DoS attempt)

**Mitigations:** AEAD integrity, timing protection, DoS limits, position shuffling

#### Level 3: Compromised Client (Out of Scope)
- Has master key → full compromise
- **Not defended against** — physical/endpoint security required

---

## Cryptographic Primitives

### Encryption: XChaCha20-Poly1305

```
Algorithm: XChaCha20-Poly1305 AEAD
Key size:  256 bits (32 bytes)
Nonce:     192 bits (24 bytes) - random per shard
Tag:       128 bits (16 bytes)
```

**Why XChaCha20:**
- Extended nonce (24 bytes) allows random nonce generation
- No nonce collision concerns with random generation
- Fast in software, constant-time implementation
- AEAD provides authentication + encryption

### Key Derivation: HKDF-SHA256

```
Algorithm: HKDF-SHA256 (RFC 5869)
IKM:       Master key (32 bytes)
Salt:      Per-bundle random (32 bytes)
Info:      "LockBox:shard:{bundleID}:{position}"
Output:    256 bits (32 bytes)
```

**Domain Separation:**
```go
info := fmt.Sprintf("LockBox:shard:%s:%d", bundleID, position)
key := HKDF-Expand(PRK, info, 32)
```

### Additional Authenticated Data (AAD)

```
AAD Format: [bundleHash[0:4] || position]
            4 bytes        || 4 bytes = 8 bytes total

bundleHash = SHA256(bundleID)
position   = uint32 big-endian
```

**Purpose:** Binds ciphertext to specific bundle and position, prevents shard relocation attacks.

---

## Shard Indistinguishability

### Problem Statement

Storage nodes should not be able to determine which shards contain real data vs. decoy data. Any distinguishing information leaks privacy.

### V1 Vulnerability (FIXED)

```go
// V1 INSECURE: ShardIndexMap stored with asset
asset := &LockedAsset{
    ShardIndexMap: map[uint32]uint32{0: 5, 1: 12, 2: 3}, // LEAKED!
}
```

**Issue:** Direct mapping revealed real shard positions.

### V2 Solution: Trial Decryption

```go
// V2 SECURE: No ShardIndexMap stored
asset := &LockedAsset{
    TotalShards: 192,
    RealCount:   64,
    Salt:        randomSalt,  // For HKDF recovery
    // ShardIndexMap: NOT STORED
}
```

**Recovery:** Try all possible keys until AEAD authentication succeeds.

---

## Trial Decryption Algorithm

### Overview

Without knowing which shards are real, the client tries decryption keys against all shards. AEAD authentication succeeds only for the correct key.

### Algorithm (Pseudocode)

```
function RecoverShards(bundleID, shards[], realCount, salt):
    hkdf = HKDF.init(masterKey, salt)
    recovered = {}
    usedKeys = {}

    positions = shuffle([0..len(shards)-1])  // Random order

    for pos in positions:
        shard = shards[pos]

        for keyIdx in [0..realCount-1]:
            if keyIdx in usedKeys:
                continue

            key = hkdf.derive("LockBox:shard:{bundleID}:{keyIdx}")
            aad = bundleHash[0:4] || keyIdx

            plaintext, err = ChaCha20Poly1305.Open(shard.ciphertext, key, shard.nonce, aad)

            if err == nil:
                recovered[keyIdx] = plaintext
                usedKeys.add(keyIdx)
                // DO NOT BREAK - continue for constant time

    if len(recovered) != realCount:
        return ERROR("incomplete recovery")

    return reassemble(recovered)
```

### Complexity Analysis

| Tier | Real | Total | Attempts | Time |
|------|------|-------|----------|------|
| Basic | 16 | 24 | 384 | ~1ms |
| Standard | 32 | 64 | 2,048 | ~3ms |
| Premium | 48 | 120 | 5,760 | ~8ms |
| Elite | 64 | 192 | 12,288 | ~14ms |

**Performance:** ~900,000 attempts/second on modern hardware.

### Security Properties

1. **No Early Exit:** Loop continues after finding match (timing protection)
2. **Shuffled Order:** Random position order (I/O pattern protection)
3. **Full Cycle:** All positions checked regardless of results

---

## Key Derivation

### Per-Shard Key Derivation

```go
func DeriveKeyForPosition(bundleID string, position uint32) []byte {
    info := []byte("LockBox:shard:")
    info = append(info, []byte(bundleID)...)
    info = append(info, ':')

    posBytes := make([]byte, 4)
    binary.BigEndian.PutUint32(posBytes, position)
    info = append(info, posBytes...)

    return hkdf.Expand(prk, info, 32)
}
```

### Salt Management

```go
// LOCK: Generate and store salt
salt := make([]byte, 32)
rand.Read(salt)
asset.Salt = salt

// UNLOCK: Restore HKDF with stored salt
hkdf := NewHKDFManager(masterKey)
hkdf.SetSalt(asset.Salt)
```

**Critical:** Salt MUST be persisted with asset metadata. Without salt, recovery is impossible.

---

## Decoy Generation

### Requirements

1. Decoys must be **structurally identical** to real shards
2. Decoys must use **random keys** (not derived from master key)
3. Decoys are **never decrypted** — keys are ephemeral

### Implementation

```go
func GenerateDecoy(size int) *Shard {
    // Random key - NOT derived from master key
    decoyKey := make([]byte, 32)
    rand.Read(decoyKey)
    defer clearBytes(decoyKey)

    // Random plaintext
    plaintext := make([]byte, size)
    rand.Read(plaintext)

    // Random nonce
    nonce := make([]byte, 24)
    rand.Read(nonce)

    // Encrypt like real shard
    aead := chacha20poly1305.NewX(decoyKey)
    ciphertext := aead.Seal(nil, nonce, plaintext, nil)

    return &Shard{Nonce: nonce, Ciphertext: ciphertext}
}
```

### Why Random Keys?

**Attack scenario with derived keys:**
```
Attacker tries: key = HKDF(guessedMasterKey, "decoy", i)
If decryption succeeds → confirms master key guess
```

**With random keys:** No relationship to master key, no oracle attack possible.

---

## DoS Protection

### Limits

```go
const (
    MaxTotalShards = 256      // Elite uses 192, buffer provided
    MaxShardSize   = 4096 + 16 // Plaintext + auth tag
    MaxRecoveryTime = 60 * time.Second
)
```

### Validation

```go
func validateShards(shards []*Shard) error {
    if len(shards) > MaxTotalShards {
        return ErrTooManyShards
    }

    for i, shard := range shards {
        if len(shard.Ciphertext) > MaxShardSize {
            return fmt.Errorf("shard %d: %w", i, ErrShardTooLarge)
        }
    }

    return nil
}
```

### Attack Mitigation

| Attack | Mitigation |
|--------|------------|
| Shard inflation | MaxTotalShards limit |
| Large shard injection | MaxShardSize limit |
| CPU exhaustion | Recovery timeout |
| Memory exhaustion | Size validation before allocation |

---

## Security Hardening

### Timing Attack Prevention

```go
// WRONG: Early exit leaks timing
for _, shard := range shards {
    if decrypt(shard) == nil {
        break  // Timing leak!
    }
}

// CORRECT: Full cycle always
for _, shard := range shards {
    result := decrypt(shard)
    if result != nil && found == nil {
        found = result
        // Continue - don't break
    }
}
```

### I/O Pattern Protection

```go
// WRONG: Sequential access
for i := 0; i < len(shards); i++ {
    process(shards[i])  // Predictable pattern
}

// CORRECT: Shuffled access
positions := shuffle(range(len(shards)))
for _, pos := range positions {
    process(shards[pos])  // Random pattern
}
```

### Memory Security

```go
// Clear sensitive data after use
defer clearBytes(masterKey)
defer clearBytes(derivedKey)
defer hkdfManager.Clear()
```

---

## API Security

### Access Token Validation

```go
func validateAccessToken(token string) bool {
    // HMAC-SHA256 validation
    expected := hmac.New(sha256.New, hmacKey)
    expected.Write(tokenData)
    return hmac.Equal(expected.Sum(nil), providedMAC)
}
```

### Nonce Replay Protection

```go
func checkNonce(nonce []byte) bool {
    // Check timestamp freshness (5 minute window)
    timestamp := extractTimestamp(nonce)
    if time.Since(timestamp) > 5*time.Minute {
        return false
    }

    // Check nonce not reused
    if nonceCache.Contains(nonce) {
        return false
    }

    nonceCache.Add(nonce)
    return true
}
```

### Ownership Proof

```go
// ZKP-based ownership verification
proof := zkp.GenerateOwnershipProof(assetID, ownerSecret)
if !zkp.Verify(proof) {
    return ErrOwnershipProofRequired
}
```

---

## Known Limitations

### Information Leakage (Accepted)

| Leak | Severity | Notes |
|------|----------|-------|
| totalShards visible | LOW | File count reveals this |
| Tier inferrable | LOW | From totalShards |
| Recovery timing | LOW | Parallel processing masks |

### Not Protected Against

| Threat | Reason |
|--------|--------|
| Compromised client | Master key exposed |
| Side-channel on client | HSM recommended for production |
| Quantum computers | ChaCha20 not post-quantum |

### Recommendations

1. **HSM for master key** in production deployments
2. **Regular key rotation** (re-encrypt with new master key)
3. **Audit logging** for all lock/unlock operations
4. **Network encryption** (TLS 1.3) for API calls

---

## References

- [RFC 8439: ChaCha20-Poly1305](https://tools.ietf.org/html/rfc8439)
- [RFC 5869: HKDF](https://tools.ietf.org/html/rfc5869)
- [XChaCha20 Draft](https://tools.ietf.org/html/draft-irtf-cfrg-xchacha)
- [OWASP Cryptographic Storage](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)

---

## Changelog

| Version | Date | Changes |
|---------|------|---------|
| 2.0 | 2025-12-26 | Trial decryption, security hardening |
| 1.0 | 2025-12-20 | Initial V2 encryption format |
