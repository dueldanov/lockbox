# NEO.md - Instructions for Neo AI System

**IMPORTANT:** Read this file before generating any code changes for LockBox.

---

## Protected Code - DO NOT MODIFY

The following files contain security-critical code that has been manually reviewed and hardened. **Do not modify these sections without explicit security review.**

### Security-Critical Files

| File | Protected Code | Reason |
|------|----------------|--------|
| `internal/service/service.go` | `validateAccessToken()`, `checkTokenNonce()`, `verifyMultiSigThreshold()` | Security hardening - timing-safe comparison, replay protection |
| `internal/crypto/encrypt.go` | AAD format (36 bytes), uniform shard sizes | Cryptographic security per v2.1 spec |
| `internal/service/delete.go` | Fail-closed deletion logic | Data destruction safety - all-or-nothing |

### Protected Patterns

```go
// PROTECTED: Token validation - DO NOT simplify
func (s *Service) validateAccessToken(token string) bool {
    // Uses crypto/subtle.ConstantTimeCompare
    // NEVER replace with == or strings.Compare
}

// PROTECTED: AAD must be exactly 36 bytes
aad := make([]byte, 36)
binary.BigEndian.PutUint32(aad[0:4], uint32(shardIndex))
copy(aad[4:36], salt)

// PROTECTED: Fail-closed deletion
for _, shard := range shards {
    if !confirmDeleted(shard) {
        return ErrDestructionIncomplete // Fail entire operation
    }
}
```

---

## Logging - PRESERVE Phase Names

Logging phase names **MUST match** the client's DOCX specifications exactly. Do not rename or reorganize.

### storeKey Phases (11)
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

### retrieveKey Phases (14)
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

**Files:** `internal/logging/entry.go`, `internal/service/service.go`

---

## Test Patterns - DO NOT WEAKEN

Security tests **MUST** include negative cases. Never remove or simplify these patterns:

```go
// CORRECT: Tests both valid AND invalid cases
func TestSecurity(t *testing.T) {
    // Valid input passes
    require.True(t, validate(validInput))

    // CRITICAL: Invalid inputs MUST fail
    require.False(t, validate(fakeInput), "MUST reject fake")
    require.False(t, validate(invalidInput), "MUST reject invalid")
}

// WRONG: Only tests happy path - DO NOT DO THIS
func TestSecurity_Bad(t *testing.T) {
    require.True(t, validate(validInput)) // Missing negative tests!
}
```

**Protected test files:**
- `internal/service/business_logic_test.go`
- `internal/service/proof_test.go`
- `internal/service/security_property_test.go`
- `internal/crypto/encrypt_test.go`

---

## Safe to Modify

These areas can be extended or modified:

| Area | Files | Notes |
|------|-------|-------|
| Payment system | `internal/payment/*` | Can add new payment methods |
| B2B API | `internal/b2b/*` | Can add new endpoints |
| New features | Any new files | Follow existing patterns |
| Documentation | `docs/*` | Keep accurate |

---

## B2B Partner API

**Location:** `internal/b2b/grpc_server.go`, `internal/b2b/api/b2b_api.proto`

**Core Methods:**
- `StoreKey` (line 109) - Partner key storage with revenue tracking
- `RetrieveKey` (line 226) - Partner key retrieval with payment processing

**20 RPC endpoints total**, including:
- CompileScript, GetRevenueShare, CreateVault, ListVaults
- GetPaymentStatus, GetNodeStatistics, GetTierCapabilities
- ValidateAddress, CheckHealth, etc.

**Future planned (not implemented):**
- FetchVpnConfig - VPN configuration management
- RegisterUsername - Username registry

**Pattern:** B2B API wraps internal Service API with partner authentication, fee calculation, and revenue tracking.

---

## Before Making Changes

1. Check if file is listed in "Protected Code" section above
2. If protected, do NOT modify without explicit approval
3. Preserve all logging phase names exactly
4. Ensure security tests include negative cases
5. Run tests: `go test ./internal/... -v`

---

## Full Documentation

See `docs/NEO_PROTECTED_CHANGES.md` for complete list of:
- Git commit history of security fixes
- Detailed code sections
- Test coverage requirements
