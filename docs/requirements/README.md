# LockBox Requirements Documentation

This directory contains the comprehensive LockBox requirements split into logical sections for easier navigation and AI analysis.

## Document Structure

| File | Section | Contents |
|------|---------|----------|
| [01_OVERVIEW.md](01_OVERVIEW.md) | 1-2 | Introduction, System Components, Architecture |
| [02_SECURITY_MECHANISMS.md](02_SECURITY_MECHANISMS.md) | 3 | HKDF, Decoys, ZKP, Tokens, Seed Phrases, Tiers |
| [03_WORKFLOWS.md](03_WORKFLOWS.md) | 4 | Storage, Retrieval, Rotation, Bridging, Username workflows |
| [04_TECHNICAL_IMPLEMENTATION.md](04_TECHNICAL_IMPLEMENTATION.md) | 5 | SecureHornet, Chrome Extension, Desktop, Mobile, Bridge |
| [05_TOKEN_ECONOMICS.md](05_TOKEN_ECONOMICS.md) | 6 | Token supply, Fees, B2B API, Referral programs |
| [06_API_UI_REQUIREMENTS.md](06_API_UI_REQUIREMENTS.md) | 7-8 | Price API, Wallet UI (Chrome, Desktop, Mobile) |
| [07_PERFORMANCE.md](07_PERFORMANCE.md) | 9 | Throughput, Latency, Node specs, Stress tests |
| [08_APPENDICES.md](08_APPENDICES.md) | 10-11 | LockScript grammar, Error codes, Hash verification |

## Quick Reference

### Security Tiers

| Tier | Shard Copies | Decoy Ratio | Metadata Decoys |
|------|-------------|-------------|-----------------|
| Basic | 3 | 0.5x | None |
| Standard | 5 | 1.0x | None |
| Premium | 7 | 1.5x | 1:1 |
| Elite | 10+ | 2.0x | 2:1 |

### HKDF Purpose Keys

| Purpose | Info Parameter | Index Type |
|---------|---------------|------------|
| Real Characters | `LockBox:real-char:<N>` | Numeric (0, 1, 2...) |
| Decoy Characters | `LockBox:decoy-char:<X>` | Alphabetic (A, B, C...) |
| Real Metadata | `LockBoxMeta:real-meta:<N>` | Numeric |
| Decoy Metadata | `LockBoxMeta:decoy-meta:<X>` | Alphabetic |

### Core gRPC Methods

```
StoreKey          - Store private key in DAG
RetrieveKey       - Get key using single-use token
RotateAndReassign - Re-encrypt and redistribute shards
GetRevenueShare   - Fetch B2B partner revenue data
RegisterUsername  - Register LockBox@username
ResolveUsername   - Resolve username to address
```

### Fee Structure

| Tier | Retrieval Fee | Setup Fee | Rotation Fee |
|------|--------------|-----------|--------------|
| Basic | $0.01 | $0 | $5 |
| Standard | $0.015 | $50 | $5 |
| Premium | $0.03 + $0.002/100K | $500 | $10 |
| Elite | $0.10 + $0.015/1M | $2,500 | $25 |

---

*Source: LockBox Requirements.docx (2342 lines)*
*Last updated: 2025-12-21*
