# LockBox Implementation Plan

## Project Timeline Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            LOCKBOX SECURITY REMEDIATION                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  MILESTONE 1          MILESTONE 2          MILESTONE 3          MILESTONE 4 │
│  ───────────          ───────────          ───────────          ─────────── │
│  DEV Ready            Security Core        DoS Protection       PROD Ready  │
│                                                                              │
│  Sprint 1   Sprint 2   Sprint 3   Sprint 4   Sprint 5   Sprint 6   Sprint 7 │
│  ───────────────────   ───────────────────   ───────────────────   ──────── │
│  Core Fixes  Auth/ZKP   Crypto     KMS       Rate Limit  Infra     Audit    │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Milestones

### Milestone 1: DEV Ready
**Objective:** System is functional, data persists correctly

| Deliverable | Description |
|-------------|-------------|
| Working encryption | Shards encrypt/decrypt correctly |
| Data persistence | Serialization/deserialization works |
| Basic auth | Signature verification functional |
| ZKP basics | Commitments use proper hashing |

**Exit Criteria:**
- Integration tests pass
- Manual E2E test: lock → restart → unlock succeeds
- No data loss on restart

---

### Milestone 2: Security Core
**Objective:** Cryptographic primitives are production-grade

| Deliverable | Description |
|-------------|-------------|
| HMAC checksums | XOR replaced with HMAC-SHA256 |
| Constant-time ops | No timing side-channels |
| Strong KDF | Argon2 with proper parameters |
| Secure memory | Keys cleared from pools |

**Exit Criteria:**
- Crypto unit tests pass
- No timing vulnerabilities (tested)
- Memory analysis shows no key leakage

---

### Milestone 3: DoS Protection
**Objective:** System resilient to resource exhaustion attacks

| Deliverable | Description |
|-------------|-------------|
| Rate limiting | Per-IP and per-user limits |
| Resource bounds | Memory pools have limits |
| Input validation | All inputs size-checked |
| Safe math | No integer overflows |

**Exit Criteria:**
- Load tests pass without OOM
- Rate limiting works correctly
- Fuzzing finds no crashes

---

### Milestone 4: PROD Ready
**Objective:** Full production readiness

| Deliverable | Description |
|-------------|-------------|
| KMS integration | Keys managed externally |
| TLS mandatory | No plaintext connections |
| Audit integrity | Hash chain for logs |
| Documentation | Security docs complete |

**Exit Criteria:**
- Security audit passed
- Penetration test passed
- Compliance requirements met

---

## Sprint Breakdown

### Sprint 1: Core Data Fixes
**Focus:** Fix critical bugs blocking basic functionality

| Task | ID | File | Effort |
|------|----|------|--------|
| Fix masterKey copy bug | D1 | `hkdf.go:55-56` | S |
| Implement key persistence | D4 | `service.go:58-62` | M |
| Implement deserializeShard | D2 | `service.go:365-369` | M |
| Implement getOwnershipProof | D3 | `service.go:381-389` | M |

**Deliverables:**
- [ ] HKDF manager creates valid keys
- [ ] Master key survives restart
- [ ] Shards serialize/deserialize correctly
- [ ] Ownership proofs persist

**Tests:**
- Unit tests for serialization roundtrip
- Integration test: lock → restart → unlock

---

### Sprint 2: Authentication & ZKP
**Focus:** Make authorization actually work

| Task | ID | File | Effort |
|------|----|------|--------|
| Implement Ed25519 signature verification | D5 | `vm.go:306-309` | M |
| Replace XOR with SHA256 in commitments | D6 | `zkp.go:353-384` | M |
| Add signature test vectors | — | tests | S |
| Add ZKP test vectors | — | tests | S |

**Deliverables:**
- [ ] LockScript signature verification works
- [ ] ZKP commitments are cryptographically sound
- [ ] Test coverage > 80% for auth code

**Tests:**
- Known-answer tests for Ed25519
- ZKP proof generation/verification tests

---

### Sprint 3: Cryptographic Hardening
**Focus:** Replace weak crypto primitives

| Task | ID | File | Effort |
|------|----|------|--------|
| Replace XOR checksum with HMAC | P1 | `encrypt.go:287-293` | M |
| Add constant-time comparison | P2 | `encrypt.go:296-307` | S |
| Upgrade Argon2 parameters | P4 | `encrypt.go:29-33` | S |
| Clear keys before pool return | P5 | `hkdf.go:72-73` | S |

**Deliverables:**
- [ ] HMAC-SHA256 checksums
- [ ] No timing side-channels
- [ ] Strong KDF parameters
- [ ] Secure memory handling

**Tests:**
- HMAC test vectors
- Timing analysis (statistical)
- Memory leak tests

---

### Sprint 4: Key Management System
**Focus:** Secure key storage and rotation

| Task | ID | Effort |
|------|-----|--------|
| Design KMS interface | P6 | S |
| Implement Vault adapter | P6 | L |
| Implement AWS KMS adapter | P6 | L |
| Persist salt with data | P7 | M |
| Implement key rotation | P8 | L |

**Deliverables:**
- [ ] KMS interface abstraction
- [ ] At least one KMS backend working
- [ ] Salt persisted with encrypted data
- [ ] Key rotation API

**Tests:**
- KMS integration tests
- Key rotation E2E test

---

### Sprint 5: DoS Protection
**Focus:** Resource limits and rate limiting

| Task | ID | File | Effort |
|------|----|------|--------|
| Add pool size limits | P9 | `memory.go:64-73` | S |
| Validate MultiSig array size | P10 | `grpc_server.go:99-106` | S |
| Implement IP-based rate limiting | P11 | `ratelimit.go` | M |
| Fix integer overflow | P12 | `encrypt.go:120` | S |

**Deliverables:**
- [ ] Memory pool bounded
- [ ] Input validation complete
- [ ] IP-based rate limiting
- [ ] Safe integer operations

**Tests:**
- Load tests with resource monitoring
- Fuzzing for input validation

---

### Sprint 6: Infrastructure Hardening
**Focus:** Logging, TLS, and code quality

| Task | ID | File | Effort |
|------|----|------|--------|
| Enforce TLS by default | P13 | `grpc_server.go` | M |
| Replace fmt.Printf with structured logging | P14 | multiple | M |
| Replace math/rand with crypto/rand | P15 | `verification/` | S |
| Implement audit log hash chain | P16 | `security/audit.go` | L |

**Deliverables:**
- [ ] TLS mandatory (warn if disabled)
- [ ] Structured logging throughout
- [ ] Cryptographic RNG everywhere
- [ ] Tamper-evident audit logs

**Tests:**
- TLS connection tests
- Log integrity verification tests

---

### Sprint 7: Audit & Release
**Focus:** Security validation and documentation

| Task | Effort |
|------|--------|
| Internal security review | L |
| External penetration test | XL |
| Security documentation | M |
| Runbook creation | M |
| Release preparation | M |

**Deliverables:**
- [ ] Security review report
- [ ] Pentest report with fixes
- [ ] Security documentation
- [ ] Operational runbook
- [ ] Release candidate

---

## Effort Legend

| Size | Description |
|------|-------------|
| **S** | Small — few hours |
| **M** | Medium — 1-2 days |
| **L** | Large — 3-5 days |
| **XL** | Extra Large — 1+ week |

---

## Risk Register

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| KMS integration complexity | High | Medium | Start early, have fallback to file-based |
| ZKP performance issues | Medium | Medium | Benchmark early, optimize if needed |
| Breaking changes in serialization | High | Low | Version the format, migration path |
| External audit delays | Medium | Medium | Book auditors early |

---

## Dependencies

```
Sprint 1 ─────┬─────► Sprint 2 ─────► Sprint 3
              │
              └─────────────────────► Sprint 4
                                          │
Sprint 5 ◄────────────────────────────────┘
    │
    ▼
Sprint 6 ─────► Sprint 7
```

**Critical Path:** Sprint 1 → Sprint 2 → Sprint 3 → Sprint 4 → Sprint 5 → Sprint 6 → Sprint 7

---

## Success Metrics

### DEV Phase (Milestones 1)
- Zero data loss on restart
- All functional tests pass
- Basic auth working

### PROD Phase (Milestones 2-4)
- Zero critical vulnerabilities
- Pentest passed with no high-severity findings
- < 1% error rate under load
- Key rotation completes in < 1 hour
- Audit logs tamper-evident

---

## Appendix: Task Checklist

### DEV Tasks
- [ ] D1: Fix masterKey copy in hkdf.go
- [ ] D2: Implement deserializeShard
- [ ] D3: Implement getOwnershipProof deserialization
- [ ] D4: Implement key persistence
- [ ] D5: Implement Ed25519 signature verification
- [ ] D6: Replace XOR with SHA256 in ZKP

### PROD Tasks
- [ ] P1: HMAC checksum
- [ ] P2: Constant-time comparison
- [ ] P3: Poseidon/MiMC hash for ZKP
- [ ] P4: Strong Argon2 parameters
- [ ] P5: Clear keys from sync.Pool
- [ ] P6: KMS integration
- [ ] P7: Persist salt
- [ ] P8: Key rotation
- [ ] P9: Pool size limits
- [ ] P10: MultiSig validation
- [ ] P11: IP-based rate limiting
- [ ] P12: Safe integer math
- [ ] P13: Mandatory TLS
- [ ] P14: Structured logging
- [ ] P15: crypto/rand usage
- [ ] P16: Audit log hash chain
