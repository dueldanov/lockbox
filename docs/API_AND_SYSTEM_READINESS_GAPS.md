# LockBox System-Level Readiness Assessment

**Date:** 2026-01-12
**Status:** Post-Milestone 1 / Pre-Milestone 2
**Scope:** API, Network, Integration, Performance

---

## Executive Summary

**Cryptographic Layer:** ✅ Production Ready ([CRYPTO_AUDIT_SUMMARY.md](CRYPTO_AUDIT_SUMMARY.md))

**System Layer:** ⚠️ **Not Production Ready** - Requires Milestone 2-4 completion

---

## Readiness Matrix

| Layer | Status | Blocker Count | Target |
|-------|--------|---------------|--------|
| Cryptographic Primitives | ✅ **Ready** | 0 | - |
| API Layer | ⚠️ **Partial** | 3 | M2 |
| Network & Security | ❌ **Not Ready** | 4 | M2 |
| Integration Testing | ⚠️ **Partial** | 2 | M3 |
| Performance & Load | ❌ **Not Ready** | 3 | M4 |
| Documentation | ⚠️ **Partial** | 1 | M4 |

**Total Blockers:** 13

---

## 🔴 P0 Blockers (Must Fix Before Launch)

### 1. ❌ mTLS Not Enabled (M2.1)

**Status:** Only server-side TLS configured

**Location:** `internal/service/grpc_server.go:55`

```go
// CURRENT: Server TLS only
creds, err := credentials.NewServerTLSFromFile(certFile, keyFile)

// REQUIRED: Mutual TLS with client cert verification
tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{serverCert},
    ClientAuth:   tls.RequireAndVerifyClientCert,  // ❌ MISSING
    ClientCAs:    caCertPool,                        // ❌ MISSING
    MinVersion:   tls.VersionTLS13,
}
```

**Impact:** High
- Unauthorized nodes can connect
- No client authentication
- Fails security requirements (Section 2.1.2)

**ETA:** M2.1 (Week 3)

---

### 2. ❌ Geographic Separation Not Enforced (M2.2)

**Status:** Tier declares regions, but no 1000km minimum check

**Location:** `internal/storage/shard.go:366`

```go
// CURRENT: Only checks ≥2 regions
if len(uniqueRegions) < 2 {
    return errors.New("insufficient geographic diversity")
}
// ❌ No distance calculation

// REQUIRED: Haversine distance check
for each pair of regions:
    distance := CalculateDistance(region1, region2)
    if distance < 1000.0 {  // ❌ MISSING
        return ErrInsufficientDistance
    }
```

**Impact:** High
- Elite tier can have nodes <1000km apart
- Fails regulatory requirements
- Reduces fault tolerance

**ETA:** M2.2 (Week 3)

---

### 3. ❌ Elite Verification Misconfigured (M2.3)

**Status:** Elite uses only 2 nodes instead of 5

**Location:** `internal/verification/selector.go:61`

```go
switch tier {
case lockbox.TierElite:
    count = 2  // ❌ WRONG - should be 5
}
```

**Impact:** Medium
- Elite tier less secure than Standard (3 nodes)
- Contract breach for Elite customers

**ETA:** M2.3 (Week 4)

---

### 4. ⚠️ ChaCha20 vs AES-256-GCM (M2.4)

**Status:** ChaCha20-Poly1305 used, requirements specify AES-256-GCM

**Location:** `internal/crypto/aead.go:19`

**Security Risk:** None (ChaCha20 equally secure)
**Compliance Risk:** Medium (spec violation)

**Required:** Dual-algorithm support with migration path

**ETA:** M2.4 (Week 4)

---

## 🟠 P1 Issues (Required for B2B)

### 5. ⚠️ Rate Limiter Not Load Tested

**Status:** Integrated but not tested under concurrent load

**Location:** `internal/verification/rate_limiter.go`

**Missing:**
- Concurrent access tests (100+ goroutines)
- Race condition detection (`go test -race`)
- Performance benchmarks

**Impact:** Medium
- May fail under real traffic
- Potential DoS vector

**ETA:** M3.4 (Week 5)

---

### 6. ⚠️ Integration Tests Fail

**Status:** 5/5 Docker-based integration tests failing

**Reason:** Require HORNET node containers

```bash
❌ autopeering  - panic: could not find container '/tester'
❌ common       - panic: could not find container '/tester'
❌ migration    - panic: could not find container '/tester'
❌ snapshot     - panic: could not find container '/tester'
❌ value        - panic: could not find container '/tester'
```

**Impact:** Medium
- No end-to-end validation
- Manual testing only

**ETA:** M3.4 (Week 6)

---

### 7. ⚠️ Metadata Decoys Not Active

**Status:** Generation implemented, not called in LockAsset pipeline

**Location:** `internal/service/service.go:163`

```go
// ❌ Missing after line 373:
// if caps.MetadataDecoyRatio > 0 {
//     metadataDecoys = gen.GenerateDecoyMetadata(realMetadata, caps.MetadataDecoyRatio)
// }
```

**Impact:** Low
- Premium/Elite tier feature not active
- Reduces indistinguishability

**ETA:** M3.1 (Week 5)

---

## 🟡 P2 Enhancements (Pre-Elite Launch)

### 8. HSM Integration (M2.6)

**Status:** File-based KeyStore only

**Required for Elite tier:**
- Windows: TPM 2.0 / CNG integration
- Android: Hardware-backed Keystore
- iOS: Secure Enclave

**ETA:** M2.6 (Week 6)

---

### 9. BIP-39 Seed Phrases (M2.5)

**Status:** Not implemented

**Required:**
- 24-word mnemonic generation
- Passphrase-based key derivation
- Recovery workflow

**ETA:** M2.5 (Week 5)

---

### 10. Software Hash Verification (M3.2)

**Status:** Missing

**Required:**
- Binary hash calculation at startup
- Node-to-node hash verification via gRPC
- Reject mismatched nodes

**ETA:** M3.2 (Week 5)

---

## 🔵 P3 Production Hardening

### 11. Load Tests Not in CI

**Status:** Tests exist with `//go:build load`, not run automatically

**Location:** `internal/testing/load_test.go`

**Required:**
- 100 TPS baseline
- <500ms retrieval latency
- <2s total latency
- CI integration

**ETA:** M4.2 (Week 7)

---

### 12. Timing Variance Tests Missing

**Status:** No automated timing attack detection

**Required:**
- Decoy processing: <1ms variance
- Memory clear: <1s total
- Automated SLA checks

**ETA:** M4.1 (Week 7)

---

### 13. Self-Healing in Simulation Mode

**Status:** `internal/storage/selfheal.go` is placeholder

**Required:**
- Real health checks (periodic ping)
- Failure detection → redistribute
- Prometheus metrics export

**ETA:** M4.3 (Week 8)

---

## Recommendations

### Immediate (This Week)

1. ✅ **Update crypto audit summary** - Done
2. ✅ **Document system gaps** - This document
3. 🔲 **Plan Milestone 2 sprint** - Start Monday

### Short-Term (M2: Week 3-4)

1. Fix P0 blockers (mTLS, geo distance, Elite nodes)
2. AES-256-GCM migration with backward compatibility
3. Update CI to fail on security issues

### Medium-Term (M3-M4: Week 5-8)

1. Complete integration tests
2. Load testing in CI
3. HSM integration
4. Production monitoring

---

## How to Use This Document

### For Stakeholders

"Crypto is DONE and audited. ✅
System integration needs 6-8 more weeks. ⚠️"

### For Engineers

Use this as Milestone 2-4 task breakdown.
Each item has file location and ETA.

### For Auditors

This is the honest gap analysis you requested.
No false "production ready" claims.

---

## Next Steps

1. **Review with team** - Monday standup
2. **Prioritize M2 tasks** - Sprint planning
3. **Create tickets** - JIRA/GitHub issues
4. **Weekly updates** - Track progress vs this doc

---

## Version History

| Date | Author | Changes |
|------|--------|---------|
| 2026-01-12 | qa-crypto-analyzer | Initial gap analysis |

---

**Status:** Living document - update after each milestone
