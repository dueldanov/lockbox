# Neo AI System - Protected Changes Documentation

**Document Purpose:** This document lists all manual code changes made by external security review and integration work. These changes should NOT be modified by Neo without explicit approval.

**Last Updated:** 2025-12-29

---

## Instructions for Neo Prompts

When generating or modifying LockBox code, Neo MUST:

1. **DO NOT MODIFY** files listed in Section 1 (Security-Critical) without explicit security review
2. **PRESERVE** logging patterns in Section 2 - they match client specifications exactly
3. **MAINTAIN** test coverage in Section 5 - these tests validate security properties
4. **CHECK** this document before making changes to any listed file

Add to Neo prompts:
```
Before modifying any file in /internal/service/, /internal/crypto/, /internal/logging/,
or /internal/payment/, check docs/NEO_PROTECTED_CHANGES.md for protected code sections.
```

---

## 1. Security-Critical Changes (DO NOT MODIFY)

These files contain security-hardened code from external audit. Any modification requires security review.

### 1.1 Token & Nonce Validation

**File:** `internal/service/service.go`

**Protected Functions:**
- `validateAccessToken()` - Lines 1289-1305
- `checkTokenNonce()` - Lines 1311-1352
- `verifyMultiSigThreshold()` - Lines 1354-1374

**Commit:** `98367c77` - "fix(security): Resolve HIGH-001 and HIGH-002 audit findings"

**Why Protected:**
- Token validation uses HMAC-SHA256 with timing-safe comparison
- Nonce checking prevents replay attacks with 5-minute window
- Multi-sig threshold enforces minimum signature count

```go
// PROTECTED: Token validation with timing-safe comparison
func (s *Service) validateAccessToken(token string) bool {
    // Uses crypto/subtle.ConstantTimeCompare
    // DO NOT replace with simple string comparison
}
```

### 1.2 Cryptographic Operations

**File:** `internal/crypto/encrypt.go`

**Protected Code:**
- AAD format: 36 bytes (4-byte shardIndex + 32-byte salt)
- Uniform shard sizes to prevent timing attacks
- XChaCha20-Poly1305 encryption

**Commits:**
- `86b36637` - "fix(security): Update AAD to 36 bytes per v2.1 spec"
- `20ab9fb4` - "fix(security): Add uniform shard sizes"

**Why Protected:**
```go
// PROTECTED: AAD must be exactly 36 bytes
// 4 bytes: shard index (big-endian uint32)
// 32 bytes: salt
aad := make([]byte, 36)
binary.BigEndian.PutUint32(aad[0:4], uint32(shardIndex))
copy(aad[4:36], salt)
```

### 1.3 Fail-Closed Deletion

**File:** `internal/service/delete.go`

**Protected Logic:**
- Deletion fails if ANY shard cannot be verified as deleted
- No partial deletion allowed
- All-or-nothing semantics

**Commit:** `598e78c4` - "fix(security): Add fail-closed rules"

**Why Protected:**
```go
// PROTECTED: Fail-closed deletion
// ALL shards must be confirmed deleted, or operation fails
for _, shard := range shards {
    if !confirmDeleted(shard) {
        return ErrDestructionIncomplete // FAIL entire operation
    }
}
```

### 1.4 ZKP Verification

**File:** `internal/service/proof_test.go`

**Protected Tests:**
- Fake proofs MUST be rejected
- Invalid public inputs MUST fail
- Groth16 verification cannot be bypassed

**Why Protected:**
```go
// PROTECTED: These tests ensure ZKP cannot be faked
func TestZKPVerification_RejectsFakeProof(t *testing.T) {
    fakeProof := make([]byte, 192)
    result := verifyProof(fakeProof, validPublicInput)
    require.False(t, result, "MUST reject fake proof")
}
```

---

## 2. Logging Implementation (PRESERVE)

Logging matches client's DOCX specifications exactly. All phases and function names are intentional.

### 2.1 Phase Constants

**File:** `internal/logging/entry.go`

**storeKey Phases (11):**
1. Input Validation & Configuration
2. Key Derivation
3. Encryption Operations
4. Digital Signatures
5. Character Sharding & Decoy Generation
6. Zero-Knowledge Proof Generation
7. Metadata Creation
8. Network Submission
9. Connection & Synchronization
10. Memory Security
11. Error Handling & Audit Logging

**retrieveKey Phases (14):**
1. Request Initialization & Token Validation
2. Payment Transaction Processing
3. ZKP Generation & Ownership Proof
4. Multi-Signature Verification
5. Dual Coordinating Node Selection
6. Triple Verification Node Selection
7. Bundle & Metadata Retrieval
8. Parallel Shard Fetching
9. Key Derivation for Decryption
10. Shard Decryption & Real Character ID
11. Key Reconstruction
12. Token Rotation
13. Memory Security & Cleanup
14. Error Handling & Audit Logging

**rotateKey Phases (12):** All implemented
**deleteKey Phases (9):** All implemented

### 2.2 Logging Files

| File | Purpose | DO NOT MODIFY |
|------|---------|---------------|
| `internal/logging/entry.go` | Phase/status constants | Phase names |
| `internal/logging/logger.go` | StructuredLogger | JSON format |
| `internal/logging/logging.go` | OperationLogger + LockBoxError | Error codes |
| `internal/logging/operations.go` | Specialized loggers | Method names |

### 2.3 Service.go Logging Integration

**File:** `internal/service/service.go`

Protected logging calls in LockAsset (lines 176-900) and UnlockAsset (lines 907-1280):

```go
// PROTECTED: Logging must match DOCX specifications
log.LogStepWithDuration(logging.PhaseInputValidation, "validate_length", ...)
log.LogStepWithDuration(logging.PhaseKeyDerivation, "DeriveHKDFKey", ...)
log.LogStepWithDuration(logging.PhaseEncryption, "AES256GCMEncrypt", ...)
```

---

## 3. Payment System (NEW - Can Extend)

These files are new and can be extended, but core fee calculations should not change.

| File | Purpose |
|------|---------|
| `internal/payment/fee_calculator.go` | Tier-based fee calculation |
| `internal/payment/processor.go` | Payment processing |
| `internal/payment/CLAUDE.md` | Documentation |

**Protected Fee Structure:**
```
Basic:    $0.01 flat
Standard: $0.015 flat
Premium:  $0.03 + $0.002 per $100K
Elite:    $0.10 + $0.015 per $1M
```

---

## 4. B2B API (NEW - Can Extend)

| File | Purpose |
|------|---------|
| `internal/b2b/grpc_server.go` | B2B gRPC endpoints |
| `internal/b2b/api/b2b_api.proto` | API definitions |
| `internal/b2b/revenue_sharing.go` | Revenue calculations |

---

## 5. Test Coverage (PRESERVE)

These tests validate security properties. DO NOT weaken or remove.

| Test File | Tests | Purpose |
|-----------|-------|---------|
| `internal/service/business_logic_test.go` | 25+ | Security boundary tests |
| `internal/service/proof_test.go` | 10+ | ZKP verification |
| `internal/service/security_property_test.go` | 15+ | Cryptographic invariants |
| `internal/service/grpc_e2e_test.go` | 8+ | End-to-end gRPC |
| `internal/crypto/encrypt_test.go` | 20+ | Encryption correctness |

**Critical Test Patterns:**
```go
// PROTECTED: All security tests MUST include negative cases
func TestSecurity_RejectsInvalid(t *testing.T) {
    // Valid case passes
    require.True(t, validate(validInput))

    // CRITICAL: Invalid cases MUST fail
    require.False(t, validate(invalidInput), "MUST reject invalid")
    require.False(t, validate(fakeInput), "MUST reject fake")
}
```

---

## 6. Git Commit History

### Security Fixes (December 2025)
```
0f378757 fix(security): Implement security hardening round 2 (P0-P2)
404be175 fix(security): Address P0 critical issues from web3-cto review
98367c77 fix(security): Resolve HIGH-001 and HIGH-002 audit findings
958518f7 test(security): Add spec compliance and invariant tests
20ab9fb4 fix(security): Add uniform shard sizes and security property tests
598e78c4 fix(security): Add fail-closed rules and fix flaky test
86b36637 fix(security): Update AAD to 36 bytes per v2.1 spec
```

### Feature Additions (December 2025)
```
ea4a2b5a docs: Add requirements compliance report
e6b2e86d feat(b2b): Implement B2B API and payment system for MVP
68520a35 feat(lockbox): Enable LockBox-Service component with dev mode
3bb99d18 feat(V2): Integrate V2 encryption in LockAsset/UnlockAsset
```

---

## 7. Verbose Logging Confirmation

**YES** - LockBox executes and logs ALL listed functions for each command:

| Operation | Phases | Functions Logged | Status |
|-----------|--------|------------------|--------|
| storeKey | 11 | ~100 | COMPLETE |
| retrieveKey | 14 | ~170 | COMPLETE |
| rotateKey | 12 | ~90 | COMPLETE |
| deleteKey | 9 | ~50 | COMPLETE |

Each function call is logged with:
- Timestamp (RFC3339)
- Phase name (matching DOCX)
- Function name (matching DOCX)
- Status (SUCCESS/FAILURE/WARNING)
- Duration in nanoseconds
- Details (non-sensitive context)
- Bundle ID

Example JSON output:
```json
{
  "timestamp": "2025-12-29T12:44:42.672532+03:00",
  "phase": "Input Validation & Configuration",
  "function": "validate_length",
  "status": "SUCCESS",
  "duration_ns": 100000,
  "details": "duration=24h0m0s, pass",
  "bundle_id": "abc123..."
}
```

---

## 8. Summary for Neo

**Files Neo Should NOT Modify Without Review:**
1. `internal/service/service.go` - Security-critical validation
2. `internal/crypto/encrypt.go` - Cryptographic operations
3. `internal/service/delete.go` - Fail-closed deletion
4. `internal/logging/entry.go` - Phase constants (must match DOCX)
5. All `*_test.go` files with security tests

**Safe to Extend:**
1. `internal/payment/` - Can add new payment methods
2. `internal/b2b/` - Can add new B2B endpoints
3. New files in any package

**Before Any Change:**
1. Check if file is listed in this document
2. If listed, request security review before modifying
3. Preserve all logging patterns and phase names
4. Run full test suite: `go test ./internal/... -v`
