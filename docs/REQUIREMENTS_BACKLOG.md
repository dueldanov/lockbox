# LockBox Requirements Backlog

**Date:** 2026-01-21
**Scope:** Gap-to-requirements backlog with concrete tasks, target files, and rough estimates.
**Notes:** Estimates are engineering time, not calendar time. “NEW” means new file.

---

## P0 — Production Blockers

### P0-01 — Mutual TLS for node-to-node gRPC
**Goal:** Enforce mutual TLS 1.3 (client cert verification) for node RPC.
**Tasks:**
- Add CA bundle support and client cert verification in gRPC server.
- Add client-side TLS config for node calls.
- Provide cert generation scripts and documented rotation.
- Add integration test for mTLS handshake rejection when cert missing.
**Files:**
- `internal/service/grpc_server.go`
- `internal/service/grpc_client.go` (if missing, NEW)
- `config_defaults.json`
- `scripts/gen-mtls-certs.sh` (NEW)
- `internal/service/grpc_server_test.go` (NEW)
**Estimate:** 3–5d

### P0-02 — XSD ledger verification in retrieval flow
**Goal:** Retrieval requires on-ledger confirmation of XSD payment.
**Tasks:**
- Implement real ledger verifier (IOTA client) and wire into PaymentProcessor.
- Persist payment tx hash + status; verify confirmation before unlock.
- Add gRPC endpoint or webhook for async confirmation if needed.
- Add negative tests: unpaid, wrong amount, wrong memo/asset.
**Files:**
- `internal/payment/processor.go`
- `internal/payment/ledger_verifier.go` (NEW)
- `internal/service/service.go`
- `internal/service/grpc_server.go`
- `internal/payment/ledger_test.go`
**Estimate:** 5–8d

### P0-03 — AES-256-GCM per character (replace XChaCha20-Poly1305)
**Goal:** Match requirement: AES-256-GCM per character shard.
**Tasks:**
- Replace XChaCha20-Poly1305 with AES-256-GCM.
- Update nonce size + shard serialization constants.
- Update AAD scheme and tests for V2 format.
- Add migration notes or version bump for shard format.
**Files:**
- `internal/crypto/encrypt.go`
- `internal/service/service.go`
- `internal/crypto/encrypt_test.go`
- `internal/service/indistinguishability_test.go`
**Estimate:** 4–6d

### P0-04 — ZK proofs: switch to zk‑STARK (gnark)
**Goal:** Ownership + shard validity proofs via zk‑STARK as per requirements.
**Tasks:**
- Replace Groth16 circuits with STARK backend.
- Update proof serialization and verification flows.
- Update tests and fixtures.
**Files:**
- `internal/crypto/zkp.go`
- `internal/crypto/zkp_*_test.go`
- `internal/service/service.go`
**Estimate:** 8–12d

### P0-05 — Geographic enforcement: 3+ regions + 1000km minimum
**Goal:** Enforce distance and region count in shard distribution.
**Tasks:**
- Add region coordinates + Haversine calc.
- Require >=3 regions and >=1000km distance between any pair.
- Add errors and tests for insufficient regions/distance.
**Files:**
- `internal/storage/shard.go`
- `internal/storage/geo_distance.go` (NEW)
- `internal/storage/shard_test.go`
**Estimate:** 2–3d

### P0-06 — Rate limiting + single‑use token + nonce replay protection
**Goal:** Enforce 5 attempts/min and single-use token per retrieval.
**Tasks:**
- Integrate `verification/rate_limiter.go` into gRPC flow.
- Add token store with TTL (5 min) and single-use consumption.
- Add nonce tracking on UnlockAsset; reject replays.
**Files:**
- `internal/verification/rate_limiter.go`
- `internal/verification/token_store.go` (NEW)
- `internal/service/grpc_server.go`
- `internal/service/service.go`
- `internal/service/grpc_e2e_test.go`
**Estimate:** 3–5d

### P0-07 — B2B gRPC API wiring (partner flows)
**Goal:** Enable B2B API server and map to core service.
**Tasks:**
- Enable `internal/b2b/server.go.disabled` and `internal/api/grpc.go.disabled`.
- Wire StoreKey/RetrieveKey/RotateKeys/UsageStats to service methods.
- Add auth middleware (API key + mTLS).
- Add smoke tests for B2B RPCs.
**Files:**
- `internal/b2b/server.go.disabled` → `internal/b2b/server.go`
- `internal/api/grpc.go.disabled` → `internal/api/grpc.go`
- `internal/b2b/grpc_server_test.go`
**Estimate:** 4–7d

---

## P1 — Security + Compliance Gaps

### P1-01 — Metadata decoys integrated into Lock/Unlock flow
**Goal:** Metadata fragments distributed across 5+ nodes with decoy metadata.
**Tasks:**
- Integrate metadata decoy generation into service flow.
- Store metadata shard index map only in client context.
- Add tests for Premium/Elite metadata decoy ratios.
**Files:**
- `internal/crypto/decoy.go`
- `internal/service/service.go`
- `internal/service/metadata_decoy_test.go`
**Estimate:** 2–4d

### P1-02 — HKDF usage for decoys per requirements
**Goal:** Derive decoy keys via HKDF (real/decoy char + meta) instead of random.
**Tasks:**
- Modify decoy encryption to use HKDF derivation contexts.
- Ensure “uniform processing” timing remains consistent.
- Update tests to assert HKDF contexts used.
**Files:**
- `internal/crypto/decoy.go`
- `internal/crypto/hkdf.go`
- `internal/crypto/decoy_test.go`
**Estimate:** 2–3d

### P1-03 — Storage indistinguishability (V2 format end‑to‑end)
**Goal:** Ensure production path uses V2 shard format and no type markers.
**Status:** ✅ Done (2026-01-21) — See `docs/V2_FORMAT_COMPLETION.md`.
**Tasks:**
- Enable V2 serialization in real LockAsset flow (remove V1 fallback).
- Validate trial decryption path in production.
- Unskip integration tests for V2.
**Files:**
- `internal/service/service.go`
- `internal/service/integration_test.go`
**Estimate:** 1–2d

### P1-04 — Node shard cap (≤10% of total shards per node)
**Goal:** Enforce per-node shard cap for distribution.
**Tasks:**
- Add cap check in shard distribution algorithm.
- Add tests for cap enforcement.
**Files:**
- `internal/storage/shard.go`
- `internal/storage/shard_test.go`
**Estimate:** 1–2d

### P1-05 — Triple verification across independent nodes
**Goal:** True 3-node verification (not local simulation).
**Tasks:**
- Define verification RPC (VerifyRetrieval) between nodes.
- Add coordinator logic to collect 3 independent signatures.
- Add failure modes and retry logic.
**Files:**
- `internal/proto/lockbox.proto`
- `internal/service/verification_coordinator.go` (NEW)
- `internal/service/service.go`
**Estimate:** 6–10d

### P1-06 — Software hash verification (node binary integrity)
**Goal:** Node-to-node binary integrity check during handshake.
**Status:** ✅ Done (2026-01-21) — See `docs/P1_06_BINARY_VERIFICATION_COMPLETE.md`.
**Tasks:**
- Compute and publish node binary hash in identity.
- Verify hashes against allowlist or signed manifest.
- Add rejection path + tests.
**Files:**
- `internal/service/grpc_server.go`
- `internal/service/node_identity.go` (NEW)
- `internal/service/grpc_server_test.go`
**Estimate:** 3–5d

### P1-07 — No‑logging policy for nodes
**Goal:** Remove sensitive logs from node layer (wallet-only logging).
**Tasks:**
- Audit logging calls; remove or gate under debug flag.
- Add log redaction middleware for gRPC.
**Files:**
- `internal/service/*.go`
- `internal/logging/*`
**Estimate:** 2–3d

---

## P2 — Wallet & Client Delivery

### P2-01 — MetaMask fork integration (extension)
**Goal:** Extension stores keys in LockBox; retrieval for signing; wipe after use.
**Tasks:**
- Create fork repo and add `LockBoxKeyring`.
- Implement Store/Retrieve flows via B2B API or gRPC-web gateway.
- Enforce single-use token + nonce flow in extension.
- Add wipe-on-signing and memory clearing.
**Files:**
- `wallets/metamask-fork/*` (NEW repo or subdir)
- `gateway/` (NEW, if required for browser)
- `internal/b2b/api/b2b_api.proto`
**Estimate:** 10–15d

### P2-02 — WASM LockScript build for extension
**Goal:** Real WASM compilation for in-browser validation.
**Tasks:**
- Implement `generateWASM` (Go→WASM build pipeline).
- Produce `lockbox.wasm` artifact + loader.
- Add tests for deterministic build and size limit.
**Files:**
- `internal/core/compiler.go`
- `scripts/build-wasm.sh` (NEW)
- `wallets/*/lockbox.wasm` (NEW)
**Estimate:** 4–6d

---

## P3 — Reliability & Performance

### P3-01 — Self‑healing shard redistribution
**Goal:** Reassign shards when node failure detected.
**Tasks:**
- Implement health checks and failure detection.
- Trigger shard redistribution and re-replication.
- Add tests with simulated node outages.
**Files:**
- `internal/storage/selfheal.go`
- `internal/storage/health.go` (NEW)
- `internal/storage/selfheal_test.go`
**Estimate:** 5–7d

### P3-02 — Performance baselines & load tests
**Goal:** 100 TPS, <500ms shard retrieval, <2s total latency.
**Tasks:**
- Wire load test harness into CI or scripts.
- Add metrics collection and thresholds.
- Document baseline results.
**Files:**
- `internal/testing/load_test.go`
- `scripts/run-load-test.sh` (NEW)
- `docs/PERFORMANCE_BASELINE.md` (NEW)
**Estimate:** 3–5d

### P3-03 — SecureHornet bootstrap + DAG validation tests
**Goal:** Validate network bootstrap, DAG tx flow, gossip correctness.
**Tasks:**
- Add integration tests for node bootstrap and DAG transaction flow.
- Add gossip protocol validation tests.
**Files:**
- `integration-tests/*`
- `internal/service/network_test.go` (NEW)
**Estimate:** 4–6d

---

## P4 — Quality & UX

### P4-01 — LockScript function coverage (complete missing builtins)
**Goal:** All required LockScript functions implemented and documented.
**Tasks:**
- Compare `docs/LOCKSCRIPT_COMMANDS_STATUS.md` with requirements list.
- Implement missing builtins and tests.
- Update docs.
**Files:**
- `internal/lockscript/*`
- `docs/LOCKSCRIPT_COMMANDS_STATUS.md`
**Estimate:** 2–4d

### P4-02 — End‑to‑end key lifecycle tests
**Goal:** Store → Retrieve → Use → Wipe flows (incl. MetaMask fork).
**Tasks:**
- Add E2E tests across service + wallet flow.
- Verify wipe within 1s post-sign.
**Files:**
- `tests/e2e/*` (NEW)
- `internal/service/grpc_e2e_test.go`
**Estimate:** 4–6d

---

## Dependencies & Ordering Notes
- P0-01 (mTLS) is a dependency for P1-05 (multi-node verification) and P3-03 (network tests).
- P0-02 (ledger verification) is a dependency for P2-01 (MetaMask flow) and E2E tests.
- P0-03 (AES-256-GCM) impacts shard format; complete before P1-03 V2 rollout.
- P0-06 (rate limit + tokens) should land before any public API exposure (P0-07).
