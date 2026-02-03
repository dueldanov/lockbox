# Metamask Fork Plan (LockBox Chrome Extension)

**Date:** 2026-01-21
**Scope:** Project 1.5 (Chrome Extension, Basic/Standard tiers only)
**Repo:** Separate fork (standalone, own CI/CD)

---

## Requirements Anchors (must comply)

- **Wallet apps scope:** `docs/requirements/01_OVERVIEW.md` (Project 1.5, Chrome extension only)
- **UI requirements:** `docs/requirements/06_API_UI_REQUIREMENTS.md` (8.1 Common UI, 8.2 Chrome Extension UI)
- **Workflow requirements:** `docs/requirements/03_WORKFLOWS.md` (wallet retrieval/signing steps)
- **Security mechanisms:** `docs/requirements/02_SECURITY_MECHANISMS.md` (trial decryption, shard access)
- **Full spec:** `docs/LOCKBOX_REQUIREMENTS.md`

---

## Assumptions / Non-goals (MVP)

- Basic/Standard tiers only (per Chrome extension constraints).
- No desktop/mobile UI in this repo.
- No hardware wallet support in MVP.
- No price API UI (not required for MVP extension).
- Key export disabled (no private key exfiltration).

---

## Architecture (MVP)

- **Keyring:** Custom LockBox Keyring adapter inside the fork.
- **Transport:** gRPC-web or REST gateway to LockBox node (browser cannot speak raw gRPC).
- **Key storage:** Only metadata and `assetID` stored locally. No private keys persisted.
- **Signing flow:**
  1) Request unlock (`UnlockAsset`) with access token + nonce.
  2) Receive private key material in memory only.
  3) Sign transaction, then clear memory immediately.
- **UI:** Chrome popup with required tabs (Home/Swap/Activity/NFTs/Settings),
  limited functionality for Basic/Standard tiers (per 8.2.1/8.2.2).

---

## Phase Plan

### Phase 0: Scope lock + repo setup (1-2d)
- Fork MetaMask, pin base version, document licensing.
- Create repo, CI (build, lint, unit), baseline pass.
- Define exact feature set and UX flows.

### Phase 1: Transport + auth (2-4d)
- Implement gateway (gRPC-web or REST).
- Add API key + token + nonce handling.
- Add TLS requirements for all requests.

### Phase 2: LockBox Keyring (4-7d)
- Implement custom Keyring:
  - listAccounts
  - signTransaction / signMessage
  - addAccount (LockAsset) / removeAccount
- Store only `assetID`, address, tier, network in extension storage.

### Phase 3: IOTA chain adapter (5-10d)
- Address formatting (bech32), network config.
- Transaction builder + signing flow.
- Fee estimation + nonce handling.

### Phase 4: UI implementation (5-10d)
- Chrome extension UI constraints (8.2.x).
- Lock/Unlock/Sign flows, status indicators.
- Settings + tier banner (Basic/Standard).

### Phase 5: Security hardening (3-6d)
- Zero sensitive logging, redact all identifiers.
- Clear sensitive buffers after signing.
- Replay protection checks, nonce expiry handling.

### Phase 6: Tests + QA (5-10d)
- Unit tests for keyring + signing.
- Integration tests via gateway stub.
- E2E on testnet (send/receive).

### Phase 7: Release (2-4d)
- Manifest V3 compliance.
- Build signing + release artifacts.
- Publish testnet build to internal QA.

---

## Dependencies / Blockers

- gRPC-web or REST gateway for browser transport.
- Accessible testnet nodes for real signing tests.
- IOTA network client libs for tx building and broadcast.

---

## Acceptance Criteria

- Chrome extension works for Basic/Standard tiers only.
- UI matches required tabs and minimal actions (8.1/8.2).
- No private key persistence in storage.
- Transactions are signed through LockBox retrieval + in-memory use only.
- All flows protected by token + nonce.

---

## Risks

- Browser transport constraints (gRPC-web vs REST).
- Latency/timeouts for unlock flow.
- UX complexity around time-lock / payment gating.

---

## Optional Enhancements (post-MVP)

- Hardware wallet integration.
- Advanced Swap UI.
- Username management UI (resolve/register).
- Multi-sig workflows for Premium/Elite (future extension).
