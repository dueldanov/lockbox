# LockBox Security Remediation Plan

## Overview

This document outlines the remediation plan for vulnerabilities discovered during the security code review of the LockBox project. The plan is divided into two phases: DEV (functionality) and PROD (security hardening).

---

## Phase 1: DEV — Working Functionality

**Goal:** System starts, data is correctly saved and retrieved, basic flow works.

### 1.1 Critical Bugs (Block System Operation)

| ID | File | Lines | Issue | Fix |
|----|------|-------|-------|-----|
| **D1** | `internal/crypto/hkdf.go` | 55-56 | masterKey not copied to struct — always zeros | Add `copy(h.masterKey, masterKey)` after slice creation |
| **D2** | `internal/service/service.go` | 365-369 | `deserializeShard()` returns empty shard | Implement parsing matching `serializeShard()` format |
| **D3** | `internal/service/service.go` | 381-389 | `getOwnershipProof()` ignores retrieved data | Implement proof deserialization from storage |
| **D4** | `internal/service/service.go` | 58-62 | Master key generated on each startup and lost | Temporary: save to file/environment variable |

### 1.2 Functional Stubs

| ID | File | Lines | Issue | Fix |
|----|------|-------|-------|-----|
| **D5** | `internal/lockscript/vm.go` | 306-309 | `verifySignature()` is a stub, accepts any signature | Implement Ed25519 verification |
| **D6** | `internal/crypto/zkp.go` | 353-384 | XOR instead of cryptographic hash in commitments | Replace with `crypto/sha256` (temporary, before MiMC) |

### 1.3 Fix Order

```
D1 → D4 → D2 → D3 → D5 → D6

D1: HKDF generates real keys (not zeros)
 ↓
D4: Key persists between restarts
 ↓
D2: Shards deserialize correctly
 ↓
D3: Ownership proofs read from storage
 ↓
D5: LockScript authorization works
 ↓
D6: ZKP commitments are cryptographically correct
```

---

## Phase 2: PROD — Security & Hardening

**Goal:** Protection against attacks, production environment readiness.

### 2.1 Cryptography

| ID | File | Lines | Issue | Fix |
|----|------|-------|-------|-----|
| **P1** | `internal/crypto/encrypt.go` | 287-293 | XOR checksum — trivial collisions | Replace with HMAC-SHA256 using HKDF-derived key |
| **P2** | `internal/crypto/encrypt.go` | 296-307 | Timing attack via early return | Use `crypto/subtle.ConstantTimeCompare()` |
| **P3** | `internal/crypto/zkp.go` | 353-384 | SHA256 is not snark-friendly | Replace with Poseidon or MiMC hash |
| **P4** | `internal/crypto/encrypt.go` | 29-33 | Weak Argon2 parameters | Increase: Time=3, Memory=64MB+, adaptive selection |
| **P5** | `internal/crypto/hkdf.go` | 72-73 | Keys returned to sync.Pool without clearing | Add `clearBytes()` before `Put()` |

### 2.2 Key Management (KMS)

| ID | Issue | Fix |
|----|-------|-----|
| **P6** | Master key stored in file | Integration with HashiCorp Vault / AWS KMS / GCP KMS |
| **P7** | Salt generated randomly and not persisted | Persist salt alongside encrypted data |
| **P8** | No key rotation mechanism | Implement key rotation API with re-encryption |

### 2.3 DoS Protection

| ID | File | Lines | Issue | Fix |
|----|------|-------|-------|-----|
| **P9** | `internal/crypto/memory.go` | 64-73 | Unbounded buffer creation on pool exhaustion | Add maximum limit in `Get()` |
| **P10** | `internal/service/grpc_server.go` | 99-106 | No limit on MultiSigAddresses count | Validation: `len(addresses) ≤ 10` |
| **P11** | `internal/middleware/ratelimit.go` | 43-49 | All anonymous requests share single limit | IP-based rate limiting |
| **P12** | `internal/crypto/encrypt.go` | 120 | Integer overflow on `shardID + index` | Use safe math or uint64 |

### 2.4 Infrastructure

| ID | File/Area | Issue | Fix |
|----|-----------|-------|-----|
| **P13** | `grpc_server.go` | TLS disabled by default | TLS mandatory, warning when disabled |
| **P14** | `service.go:226` | `fmt.Printf` for logging | Structured logging (zap/zerolog) |
| **P15** | `internal/verification/` | Using `math/rand` | Replace with `crypto/rand` |
| **P16** | Audit logging | No log integrity protection | Hash chain for audit records |

---

## Priority Matrix

| Priority | DEV | PROD |
|----------|-----|------|
| **Critical** | D1, D2, D3, D4 | P1, P2, P6 |
| **High** | D5, D6 | P3, P4, P5, P7, P8 |
| **Medium** | — | P9, P10, P11, P12 |
| **Low** | — | P13, P14, P15, P16 |

---

## Definition of Done

### DEV Ready
- [ ] All tests pass
- [ ] Data saves and reads correctly
- [ ] LockScript executes with real verification
- [ ] ZKP proofs generate and verify

### PROD Ready
- [ ] All cryptographic primitives replaced with production-grade
- [ ] KMS integrated
- [ ] Rate limiting configured
- [ ] TLS mandatory
- [ ] Penetration testing passed
- [ ] Security audit completed
