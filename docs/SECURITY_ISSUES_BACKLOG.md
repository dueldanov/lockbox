# Security Issues & Production Blockers - Prioritized Backlog

**Date:** 2026-01-14
**Status:** Active Sprint Planning
**Compliance:** 2 OK / 14 PARTIAL / 4 MISSING (из 20 требований)

---

## Executive Summary

Проведен security gap analysis на соответствие 20 core requirements. Выявлены **критические блокеры** для production deployment и составлен prioritized backlog.

**Ключевые findings:**
- ✅ 2/20 полностью реализованы (LockScript VM, index-free reconstruction)
- ⚠️ 14/20 частично реализованы (есть код, но не интегрирован или неполон)
- ❌ 4/20 отсутствуют (PaymentToken gRPC, XSD ledger, Metamask, software hash)

**Самый критичный gap:** gRPC UnlockAsset не может передать PaymentToken, но Service.UnlockAsset его требует (`internal/proto/lockbox.proto:33`, `internal/service/service.go:1011`) - **система сломана**.

---

## 🔴 P0 - КРИТИЧНЫЕ БЛОКЕРЫ

### 1. PaymentToken Transmission Missing ⚠️ CRITICAL BUG

**Status:** BROKEN - UnlockAsset не работает с платежами

**Проблема:**
```protobuf
// internal/proto/lockbox.proto:33 - ТЕКУЩЕЕ
message UnlockAssetRequest {
    string asset_id = 1;
    repeated bytes signatures = 2;
    // ❌ НЕТ payment_token!
}
```

```go
// internal/service/service.go:1011 - ТРЕБУЕТ payment_token
if req.PaymentToken == "" {
    return nil, ErrPaymentRequired  // ← ВСЕГДА ПАДАЕТ
}
```

**Impact:** HIGH
- UnlockAsset вообще не работает с оплатой
- Блокирует весь retrieval flow
- Критический bug для B2B

**Fix:**
```protobuf
message UnlockAssetRequest {
    string asset_id = 1;
    repeated bytes signatures = 2;
    string payment_token = 3;  // ✅ ДОБАВИТЬ
    string nonce = 4;           // для replay protection
}
```

**Files to modify:**
- `internal/proto/lockbox.proto:33` - add field
- `internal/proto/generate.sh` - regenerate
- `internal/service/grpc_server.go:171` - map field

**Effort:** 30 minutes
**Priority:** P0 (MUST FIX BEFORE ANY TESTING)

---

### 2. mTLS Not Enabled ⚠️ SECURITY

**Status:** PARTIAL - только server TLS, нет client verification

**Проблема:**
```go
// internal/service/grpc_server.go:55 - ТЕКУЩЕЕ
// SECURITY: TLS is REQUIRED in production per requirements (mutual TLS 1.3)
// Section 2.1.2: "Node authentication via mutual TLS 1.3"

// Line 102: НО реализован только server TLS!
creds, err := credentials.NewServerTLSFromFile(certFile, keyFile)
// ❌ НЕТ client certificate verification
```

**Impact:** HIGH
- Unauthorized nodes can connect
- No client authentication
- Fails security requirements (Section 2.1.2)

**Fix:**
```go
tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{serverCert},
    ClientAuth:   tls.RequireAndVerifyClientCert,  // ✅ REQUIRE
    ClientCAs:    caCertPool,                        // ✅ CA pool
    MinVersion:   tls.VersionTLS13,
}
```

**Resources:**
- [Building Secure gRPC with mTLS in Go](https://liambeeton.com/programming/building-secure-grpc-services-with-mutual-tls-in-go)
- [Official grpc-go mTLS Examples](https://github.com/grpc/grpc-go/tree/master/examples/features/encryption)

**Files to modify:**
- `internal/service/grpc_server.go:55-102` - mTLS config
- `scripts/gen-mtls-certs.sh` - NEW (cert generation)
- `internal/service/grpc_server_test.go` - NEW (mTLS tests)

**Effort:** 3-5 days
**Priority:** P0 (PRODUCTION BLOCKER)

---

### 3. Geographic Separation Not Enforced ⚠️ SECURITY

**Status:** PARTIAL - tier declares regions, но 1000km не проверяется

**Проблема:**
```go
// internal/storage/shard.go:366 - ТЕКУЩЕЕ
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

**Impact:** HIGH
- Elite tier может иметь nodes <1000km
- Reduces fault tolerance
- Fails regulatory requirements

**Fix:**
- Create `internal/storage/geo_distance.go` with Haversine formula
- Add `RegionLocations` map with DC coordinates
- Update `DistributeShards()` with 1000km enforcement

**Effort:** 2-3 hours
**Priority:** P0 (ELITE TIER BLOCKER)

---

### 4. Elite Verification Uses 2 Nodes Instead of 5 ⚠️ CONTRACT BREACH

**Status:** PARTIAL - Elite less secure than Standard

**Проблема:**
```go
// internal/verification/selector.go:61 - ТЕКУЩЕЕ
switch tier {
case lockbox.TierBasic, lockbox.TierStandard, lockbox.TierPremium:
    count = 3 // ✅ Triple verification
case lockbox.TierElite:
    count = 2 // ❌ WRONG - должен быть 5!
}
```

**Impact:** MEDIUM
- Elite tier less secure than Standard (3 nodes)
- Contract breach для Elite customers
- Reputation risk

**Fix:**
```go
case lockbox.TierElite:
    count = 5 // ✅ CORRECT
```

**Files to modify:**
- `internal/verification/selector.go:61` - one line change

**Effort:** 5 minutes
**Priority:** P0 (EASY WIN)

---

## 🟠 P1 - ВАЖНЫЕ (Required for B2B Launch)

### 5. XSD Token Payments Missing ❌ MISSING

**Status:** MISSING - только USD/LOCK, нет XSD ledger integration

**Проблема:**
```go
// internal/payment/fee_calculator.go:30 - ТЕКУЩЕЕ
type Currency string
const (
    CurrencyUSD  Currency = "USD"   // ✅ есть
    CurrencyLOCK Currency = "LOCK"  // ✅ есть
    // ❌ CurrencyXSD отсутствует!
)
```

**Impact:** HIGH
- Нельзя принимать платежи на IOTA ledger
- Блокирует revenue flow
- B2B partner payments не работают

**Fix:**
- Add `CurrencyXSD` constant
- Create `internal/payment/ledger_client.go`
- Integrate with IOTA UTXO Manager
- Add XSD→USD conversion rate

**Resources:**
- [IOTA Rebased Testnet](https://blog.iota.org/iota-rebased-testnet-devnet-guide/)
- [IOTA Networks & Endpoints](https://wiki.iota.org/build/networks-endpoints/)

**Files to create:**
- `internal/payment/ledger_client.go` - IOTA integration
- `internal/payment/xsd_converter.go` - rate conversion
- `tests/integration/xsd_payment_test.go` - E2E test

**Effort:** 1-2 weeks
**Priority:** P1 (B2B REVENUE BLOCKER)

---

### 6. ChaCha20 vs AES-256-GCM ⚠️ COMPLIANCE

**Status:** PARTIAL - ChaCha20 используется, requirements требуют AES-256-GCM

**Проблема:**
```go
// internal/crypto/encrypt.go:405 - ТЕКУЩЕЕ
// AEADEncryptor provides XChaCha20-Poly1305 authenticated encryption.
type AEADEncryptor struct {
    cipher cipher.AEAD  // ← XChaCha20, НЕ AES-GCM!
}
```

**Impact:** MEDIUM
- Security: ChaCha20 equally secure ✅
- Compliance: Does not meet spec ⚠️
- Enterprise contracts may reject

**Fix:**
```go
// Dual-algorithm support для migration
type EncryptionVersion int
const (
    VersionChaCha20  EncryptionVersion = 1  // Legacy
    VersionAES256GCM EncryptionVersion = 2  // Default
)
```

**Resources:**
- [AES-256 vs ChaCha20 Performance](https://vpn.how/en/pages/aes-256-vs-chacha20-in-vpns-in-2026-whats-actually-faster-and-safer-on-pc-and-mobile.html)
- [Go Crypto Performance](https://blog.cloudflare.com/go-crypto-bridging-the-performance-gap/)
- [AES-256-GCM Go Example](https://gist.github.com/kkirsche/e28da6754c39d5e7ea10)

**Files to modify:**
- `internal/crypto/aead.go` - add AES-256-GCM implementation
- `internal/crypto/aead_aes.go` - NEW
- `internal/crypto/encrypt.go:405` - version selection
- `docs/ENCRYPTION_MIGRATION_GUIDE.md` - NEW

**Effort:** 3-5 days
**Priority:** P1 (COMPLIANCE REQUIREMENT)

---

### 7. Rate Limiter Not Connected ⚠️ SECURITY

**Status:** PARTIAL - exists but not used

**Проблема:**
```go
// internal/verification/rate_limiter.go:12 - ЕСТЬ
type RateLimiter struct {
    maxTokens int // 5
    refillRate time.Duration // 12s (5/min)
}

// ❌ НО не используется в UnlockAsset!
```

**Impact:** MEDIUM
- DoS vector - unlimited unlock attempts
- Rate limit bypass
- No throttling protection

**Fix:**
```go
// internal/service/service.go:1009 - ДОБАВИТЬ
func (s *Service) UnlockAsset(ctx context.Context, req *UnlockAssetRequest) (*UnlockAssetResponse, error) {
    // ✅ Rate limit check
    allowed, err := s.rateLimiter.Allow(req.RequesterID)
    if !allowed {
        return nil, &RateLimitError{
            Message:    "rate limit exceeded: max 5 attempts per minute",
            RetryAfter: s.rateLimiter.RetryAfter(req.RequesterID),
        }
    }
    // ... rest
}
```

**Files to modify:**
- `internal/service/service.go:1009` - add rate limit check
- `internal/service/service.go:45` - add rateLimiter field
- `internal/service/service_test.go` - add TestRateLimitUnlock

**Effort:** 1-2 hours
**Priority:** P1 (SECURITY HARDENING)

---

### 8. Metadata Decoys Not Active ⚠️ FEATURE

**Status:** PARTIAL - generation exists, не включена в pipeline

**Проблема:**
```go
// internal/crypto/decoy.go:155 - ГЕНЕРАЦИЯ ЕСТЬ
func (dg *DecoyGenerator) GenerateDecoyMetadata(...) []map[string]interface{} {
    // ✅ Код работает
}

// ❌ НО не вызывается в LockAsset (internal/service/service.go:163)
```

**Impact:** LOW
- Premium/Elite feature not active
- Reduces indistinguishability
- Marketing promise not fulfilled

**Fix:**
```go
// internal/service/service.go:163 - ДОБАВИТЬ
// ✅ Generate metadata decoys (Premium/Elite only)
if caps.MetadataDecoyRatio > 0 {
    realMetadata := map[string]interface{}{
        "assetID":   assetID,
        "timestamp": time.Now().Unix(),
    }
    metadataDecoys = gen.GenerateDecoyMetadata(realMetadata, caps.MetadataDecoyRatio)
}
```

**Files to modify:**
- `internal/service/service.go:163` - add call in LockAsset
- `internal/storage/manager.go` - store metadata decoys
- `internal/service/service_test.go` - add TestMetadataDecoys

**Effort:** 30 minutes
**Priority:** P1 (QUICK WIN)

---

## 🟡 P2 - ЖЕЛАТЕЛЬНО (Pre-Elite Launch)

### 9. Software Hash Verification Missing ❌ MISSING

**Status:** MISSING - no binary hash verification between nodes

**Проблема:** Нет проверки что все ноды используют одинаковый binary.

**Impact:** MEDIUM
- Malicious node может использовать modified code
- No integrity check
- Rogue node detection missing

**Fix:**
- Create `internal/verification/binary_hash.go`
- Add `GetBinaryHash` RPC endpoint
- Periodic verification в NodeSelector
- CI publish binary hash с releases

**Effort:** 2-3 days
**Priority:** P2 (NETWORK INTEGRITY)

---

### 10. Memory Security Timing Not Verified ⚠️ PARTIAL

**Status:** PARTIAL - ClearBytes есть, но <1s не verified

**Проблема:**
```go
// internal/crypto/memory.go:30 - ТЕКУЩЕЕ
func ClearBytes(data []byte) {
    for i := range data {
        data[i] = 0  // ✅ zeroing работает
    }
    runtime.KeepAlive(data)
}

// ❌ НЕТ тестов timing (<1 second)
```

**Impact:** LOW
- Potential timing attack surface
- SLA not verified
- Compliance gap

**Fix:**
```go
// internal/crypto/memory_test.go - ДОБАВИТЬ
func TestMemoryClearTiming(t *testing.T) {
    data := make([]byte, 1024*1024) // 1MB
    start := time.Now()
    ClearBytes(data)
    elapsed := time.Since(start)

    // ✅ Requirement: <1 second
    require.Less(t, elapsed, time.Second)
}
```

**Effort:** 1 day
**Priority:** P2 (SECURITY SLA)

---

### 11. ZKP Test Coverage Weak ⚠️ PARTIAL

**Status:** PARTIAL - Groth16 есть, но often mocked

**Проблема:**
```go
// internal/crypto/zkp.go:45 - ТЕКУЩЕЕ
func (zkp *ZKPManager) GenerateOwnershipProof(...) (*OwnershipProof, error) {
    // ✅ SHA256 commitment работает
    // ❌ НО в тестах часто мокается вместо реального Groth16
}
```

**Impact:** MEDIUM
- Could ship broken ZKP verification
- Security tests не comprehensive
- Fake proofs не tested

**Fix:**
- Integrate gnark library для real Groth16
- Remove mocks from critical tests
- Add negative tests (fake proof MUST fail)

**Resources:**
- [gnark - Fast ZK-SNARK library](https://github.com/ConsenSys/gnark)

**Effort:** 2-3 days
**Priority:** P2 (CRYPTO QUALITY)

---

### 12. Load Tests Not in CI ⚠️ PARTIAL

**Status:** PARTIAL - tests exist with `//go:build load`, не run automatically

**Проблема:**
```go
// internal/testing/load_test.go:1 - ЕСТЬ
//go:build load
// ❌ Build tag = не запускаются в CI!
```

**Impact:** MEDIUM
- Performance regressions undetected
- SLA not enforced
- Production surprises possible

**Fix:**
```yaml
# .github/workflows/load_tests.yml - НОВЫЙ
name: Load Tests
on:
  pull_request:
    paths: ['internal/service/**', 'internal/crypto/**']
  schedule:
    - cron: '0 2 * * *'  # Daily 2 AM

jobs:
  load:
    steps:
      - run: go test -tags=load ./internal/testing/... -v
      - name: Check SLA
        run: |
          # 100 TPS baseline
          # <500ms retrieval
          # <2s total latency
```

**Effort:** 1 day
**Priority:** P2 (QUALITY ASSURANCE)

---

## 🔵 P3 - БУДУЩЕЕ (Post-Launch Improvements)

### 13. Metamask Fork Missing ❌ MISSING

**Status:** MISSING - no wallet integration

**Impact:** HIGH (для E2E user flow)
- E2E lifecycle не работает
- User experience incomplete
- Testing blocked

**Fix:** Параллельная разработка (8-10 недель)
- См. детальный план в отдельном документе
- Не блокирует backend development
- Can use wallet abstraction для тестирования

**Effort:** 8-10 weeks
**Priority:** P3 (PARALLEL DEVELOPMENT)

---

### 14. E2E Lifecycle Tests Missing ❌ MISSING

**Status:** MISSING - no store→retrieve→wipe tests

**Impact:** MEDIUM
- Integration issues may emerge in production
- User flow not validated
- Gap in test coverage

**Fix:** Wait for Metamask completion, then:
- `tests/e2e/lifecycle_test.go` - NEW
- Test full flow: store → pay → retrieve → use → wipe

**Effort:** 1 week (after Metamask)
**Priority:** P3 (DEPENDS ON METAMASK)

---

### 15. Self-healing Production Mode ⚠️ PARTIAL

**Status:** PARTIAL - simulation mode only

**Проблема:**
```go
// internal/storage/selfheal.go:129 - ЕСТЬ
type SelfHealingManager struct {
    // ✅ Базовая структура
}

func (shm *SelfHealingManager) MonitorShards(ctx context.Context) {
    // ❌ Пока симуляция, не production
}
```

**Impact:** LOW
- No automatic failure recovery
- Manual intervention required
- Operational overhead

**Fix:**
- Real health checks (periodic ping)
- Failure detection → redistribute
- Prometheus metrics export
- Alerting integration

**Effort:** 1 week
**Priority:** P3 (OPERATIONAL IMPROVEMENT)

---

## Quick Wins (можно сделать сейчас)

### Sprint 0 - Immediate Fixes (3 hours total)

```
✅ Elite verification fix (5 min)
   - internal/verification/selector.go:61 - change 2 to 5

✅ Metadata decoys activation (30 min)
   - internal/service/service.go:163 - add call

✅ PaymentToken в proto (30 min)
   - internal/proto/lockbox.proto:33 - add field
   - ./generate.sh - regenerate

✅ Rate limiter connection (2 hours)
   - internal/service/service.go:1009 - add check
```

**ROI:** 4 critical fixes за 3 часа работы!

---

## Recommended Sprint Plan

### Sprint 1 (Week 1) - Critical Fixes
**Goal:** Fix P0 blockers

```
Day 1 (3 hours):
✅ Quick wins (4 items above)
✅ Commit + push

Day 2-5 (3-5 days):
🔧 mTLS implementation
🔧 Geographic distance check
🔧 Integration testing

Week 1 Exit Criteria:
- PaymentToken передаётся через gRPC ✅
- Elite uses 5 nodes ✅
- Metadata decoys active ✅
- Rate limiter connected ✅
- mTLS enabled ✅
- Geographic 1000km enforced ✅
```

---

### Sprint 2 (Week 2-3) - Compliance & Security
**Goal:** Address P1 items

```
Week 2:
🔧 ChaCha20 → AES-256-GCM migration (3-5 days)
🔧 Memory timing tests (1 day)
🔧 Load tests в CI (1 day)

Week 3:
🔧 XSD token integration (start, continue with testnet)
🔧 ZKP test coverage improvements
🔧 Software hash verification

Week 2-3 Exit Criteria:
- AES-256-GCM default encryption ✅
- All timing SLAs verified ✅
- Load tests run automatically ✅
- XSD token foundation ready ✅
```

---

### Sprint 3 (Week 4-5) - Testnet Integration
**Goal:** Deploy and test on real network

```
Week 4:
🔧 IOTA testnet deployment
🔧 Multi-region nodes setup
🔧 XSD payment testing

Week 5:
🔧 Network integration tests
🔧 Performance benchmarks
🔧 Security audit repeat

Week 4-5 Exit Criteria:
- Testnet running (3+ regions) ✅
- XSD payments working on ledger ✅
- Load tests pass on testnet ✅
- No P0/P1 issues remaining ✅
```

---

### Sprint 4+ (Week 6-13) - Metamask & Production
**Goal:** Complete E2E flow

```
Week 6-13 (parallel):
🔧 Metamask fork development (8-10 weeks)
🔧 E2E lifecycle tests
🔧 Production hardening
🔧 Self-healing improvements

March Target Exit Criteria:
- Full E2E flow working ✅
- All 20 requirements satisfied ✅
- Security audit passed ✅
- Production deployment ready ✅
```

---

## Detailed Requirement Status

| # | Requirement | Status | Location | Priority |
|---|-------------|--------|----------|----------|
| 1 | LockScript DSL/VM | ✅ OK | `internal/lockscript/builtins.go:19` | - |
| 2 | B2B Partner API | ⚠️ PARTIAL | `internal/service/grpc_server.go:171` | P0 |
| 3 | XSD Ledger Payments | ❌ MISSING | `internal/payment/fee_calculator.go:30` | P1 |
| 4 | Metamask Fork | ❌ MISSING | (no files) | P3 |
| 5 | Crypto (HKDF/Decoys) | ⚠️ PARTIAL | `internal/crypto/hkdf.go:39` | P1 |
| 6 | Index-free Recovery | ✅ OK | `internal/service/service.go:2124` | - |
| 7 | Memory Security | ⚠️ PARTIAL | `internal/crypto/memory.go:30` | P2 |
| 8 | ZKP Groth16 | ⚠️ PARTIAL | `internal/crypto/zkp.go:45` | P2 |
| 9 | SecureHornet/mTLS | ⚠️ PARTIAL | `internal/service/grpc_server.go:55` | P0 |
| 10 | Geographic 1000km | ⚠️ PARTIAL | `internal/storage/shard.go:366` | P0 |
| 11 | Decoy Timing SLA | ⚠️ PARTIAL | `internal/service/indistinguishability_test.go:11` | P2 |
| 12 | Self-healing | ⚠️ PARTIAL | `internal/storage/selfheal.go:129` | P3 |
| 13 | Triple Verification | ⚠️ PARTIAL | `internal/verification/selector.go:61` | P0 |
| 14 | Rate Limiting | ⚠️ PARTIAL | `internal/verification/rate_limiter.go:12` | P1 |
| 15 | Metadata Decoys | ⚠️ PARTIAL | `internal/crypto/decoy.go:155` | P1 |
| 16 | Software Hash | ❌ MISSING | (no files) | P2 |
| 17 | Load Tests | ⚠️ PARTIAL | `internal/testing/load_test.go:1` | P2 |
| 18 | E2E Lifecycle | ❌ MISSING | (no tests) | P3 |
| 19 | Multi-tier Config | ⚠️ PARTIAL | `internal/service/tier.go:28` | P1 |
| 20 | Error Handling | ⚠️ PARTIAL | `internal/errors/errors.go:260` | P2 |

**Summary:** 2 OK / 14 PARTIAL / 4 MISSING

---

## Risk Assessment

### High Risk Items

**1. XSD Token Integration (P1)**
- External dependency on IOTA network
- Testnet availability required
- **Mitigation:** Mock mode для dev, retry logic

**2. mTLS Deployment (P0)**
- Requires cert infrastructure
- Breaks existing connections during rollout
- **Mitigation:** Auto-generated certs для dev, staged rollout

**3. AES-256-GCM Migration (P1)**
- Could break existing encrypted data
- **Mitigation:** Dual-mode support, migration tool, extensive testing

### Medium Risk Items

**4. Metamask Fork (P3)**
- Large scope, 8-10 weeks
- May delay E2E testing
- **Mitigation:** Parallel development, wallet abstraction

**5. Geographic Distance (P0)**
- Requires accurate region coordinates
- May reject valid configurations
- **Mitigation:** Configurable threshold, override flag для dev

### Low Risk Items

**6. Quick Wins (P0/P1)**
- Small code changes (5min - 2 hours)
- Low complexity
- **Mitigation:** Thorough testing, code review

---

## Success Metrics

### Sprint 1 Success:
- ✅ All P0 items resolved
- ✅ CI pipeline green
- ✅ No regression in existing tests

### Sprint 2 Success:
- ✅ All P1 items resolved
- ✅ Compliance audit passed
- ✅ Performance SLAs met

### Sprint 3 Success:
- ✅ Testnet deployed and stable
- ✅ XSD payments working
- ✅ Multi-region verified

### March Target Success:
- ✅ 20/20 requirements satisfied
- ✅ E2E flow working
- ✅ Production deployment approved

---

## Next Actions

1. **Pre-Zoom (today):**
   - Review this document
   - Prepare demo materials
   - List questions for Lance

2. **After Zoom (tomorrow):**
   - Execute Sprint 0 quick wins (3 hours)
   - Commit and push fixes
   - Start Sprint 1 planning

3. **Week 1 focus:**
   - P0 critical fixes
   - mTLS implementation
   - Geographic enforcement

---

**Document Version:** 1.0
**Created:** 2026-01-14
**Updated:** 2026-01-14
**Next Review:** After Lance Zoom (2026-01-15)
