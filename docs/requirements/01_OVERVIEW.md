# LockBox Requirements - Overview

## 1. Introduction

LockBox is a decentralized solution for secure private key management in cryptocurrency ecosystems. It ensures "Decentralized Custody" by splitting private keys into character-level shards distributed across a geographically diverse network, using decoy mechanisms, zero-knowledge proofs, and multiple verification steps to maintain security.

## 1.1 System Components

| Component | Description |
|-----------|-------------|
| **LockSmith Network (SecureHornet)** | DAG-based network forked from IOTA Hornet v2.0.2 for storing encrypted key shards and managing a native cryptocurrency ledger |
| **LockScript DSL** | Security-focused language for key operations, compiled to Go and WebAssembly |
| **Wallet Applications** | Chrome Extension (Basic/Standard), Windows Desktop (all tiers), Android Mobile (all tiers) |
| **Native Token** | Facilitates retrieval fees and cross-chain bridging |
| **B2B Integration** | gRPC API for wallet providers with revenue sharing |

## 1.2 Development Phases

| Phase | Description |
|-------|-------------|
| **Project 1** | Network Development (LockSmith/SecureHornet) - CURRENT FOCUS |
| **Project 1.5** | Chrome Extension Wallet (Basic/Standard tiers) |
| **Project 2** | Windows Desktop Wallet (All tiers) |
| **Project 3** | Android Mobile Wallet (All tiers) |
| **Projects 4-8** | Future extensions (DEX, RWA, Insurance, Messaging, Payment Processing) |

**Note:** LockSmith Node software is closed source and operates as a private network. All wallet software is open source and white-labeled for B2B partners.

---

## 2. System Architecture

### 2.1 LockSmith Network (SecureHornet)

#### Foundation
- Fork of IOTA Hornet v2.0.2 (May 24, 2024)
- Operating **without a coordinator** (Coordicide upgrade)
- DAG consensus: Each transaction references and validates at least two previous transactions
- No proof-of-work required

#### Core Features
- Stores encrypted key shards and metadata fragments across nodes
- Maintains ledger for LockBox cryptocurrency
- Manages decentralized username registry
- Enforces no-logging policy (logs generated in wallet software only)
- Node authentication via mutual TLS 1.3
- Stores encrypted key shards without distinguishing between real and decoy components

#### Geographic Distribution Rules
- Shards distributed across **minimum three regions**, 1000km apart
- **Shard limit**: No node stores more than 10% of a key's shards (20% if fewer than five nodes available)
- **Self-healing**: Detects node failures (three failed pings) and redistributes affected shards
- Provides anonymous aggregate statistics (total wallet count)

#### Multi-Cloud Dispersal
- Minimum 5 nodes across 3+ cloud providers (e.g., AWS, Azure, GCP)
- zk-STARK proofs for geographic verification
- Ed25519-signed receipts for distribution validation
- Scaling to 5+ cloud providers for Elite tier

### 2.2 LockScript DSL

#### Purpose
- Declarative, security-first domain-specific language for key operations
- **Compilation**: Statically compiled to Go using compiler in `core/compiler.go`; compiled to WebAssembly for browsers
- **Memory safety**: Automatically clears sensitive data types when they exit scope
- No direct file/network I/O permitted

#### Key Functions
- Operations: `storeKey`, `getKey`, `rotate`, `registerUsername`, `resolveUsername`
- HKDF Functions: Specialized functions for HKDF-based key derivation with purpose-specific parameters
- Support for all security tiers with appropriate configurations

### 2.3 Wallet Applications

| Platform | Tiers | Technology | Size Limits |
|----------|-------|------------|-------------|
| **Chrome Extension** | Basic, Standard | WASM-compiled LockScript | <6MB WASM, <20MB total |
| **Windows Desktop** | All | CLI (optional Qt GUI later), TPM/CNG for Elite | - |
| **Android Mobile** | All | Kotlin UI + Go backend (gomobile), Android Keystore for Elite | - |
