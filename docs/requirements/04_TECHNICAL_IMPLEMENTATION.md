# LockBox Requirements - Technical Implementation

## 5. Technical Implementation

### 5.1 Project 1: SecureHornet Network

#### 5.1.1 Base Code Modifications (from IOTA Hornet v2.0.2)

| File | Modifications |
|------|--------------|
| `tangle.go` | ZKP validation plugin, two-prior-approval enforcement |
| `database.go` | Metadata sharding and distribution |
| `ledger.go` | LedgerTx for LockBox token transactions |
| `node.go/peering.go` | Node authentication, geographic verification |
| `health.go` | Self-healing triggers, monitoring |

#### 5.1.2 New Files (in lockbox/ directory)

| File | Purpose |
|------|---------|
| `main.go` | Main entry point integrating with Hornet core |
| `api/grpc.go` | B2B integration API endpoints |
| `core/lockscript.go` | LockScript DSL implementation |
| `core/compiler.go` | Compiler for LockScript to Go/WASM |
| `crypto/zkp.go` | ZKP implementation using gnark |
| `crypto/encrypt.go` | Encryption with HKDF keys |
| `dag/submit.go` | Transaction bundle submission |
| `models/shard.go` | Character shard data structures |
| `storage/shard.go` | Geographic distribution logic |
| `storage/ledger.go` | Cryptocurrency implementation |
| `admin_alert.go` | Administrative alerting system |

---

### 5.2 Project 1.5: Chrome Extension

#### 5.2.1 Chrome Manifest

- Version: Manifest V3
- Permissions: storage, alarms, notifications, https://securehornet.lockbox.network/*
- Content Security Policy: Restricts scripts, allows WASM execution

#### 5.2.2 File Structure

| File | Purpose |
|------|---------|
| `manifest.json` | Configuration |
| `popup.html` | UI entry point |
| `popup.js` | UI logic and WASM bridge |
| `background.js` | Network calls, scheduling |
| `lockbox.wasm` | WASM-compiled LockScript (<6MB) |
| `wasm_exec.js` | WASM runtime loader |
| `assets/style.css` | Styling |

#### 5.2.3 B2B Integration

- LockScript SDK for B2B extensions
- Precompiled WASM binary and runtime
- Documentation for gRPC API endpoints
- Semantic versioning (e.g., 1.0.0 initial release)

---

### 5.3 Project 2: Windows Desktop Application (Future)

#### 5.3.1 Base

- Fork of Firefly v2.0.12, renamed to LockBox
- Files to modify: main.ts, preload.ts, wallet.ts, network.ts
- New files in lockbox/ directory

#### 5.3.2 Implementation

- CLI initially, possible Qt GUI later
- Hardware security module integration (TPM/CNG)
- Offline recovery functionality

---

### 5.4 Project 3: Android Mobile Application (Future)

#### 5.4.1 Implementation

- Native app with Kotlin UI, Go backend via gomobile
- Package: lockbox-mobile.aar (compiled with gomobile bind)
- Functions: storeKey, retrieveKey, rotateKey, destroyKey

#### 5.4.2 Features

- Biometric authentication
- Android Keystore integration
- Embedded OpenVPN/Tor networking

---

### 5.5 Network Communication

#### 5.5.1 VPN/Tor Integration

- OpenVPN as default network layer (Implement in later version, not version 1.)
- Tor as optional feature (Implement in later version, not version 1.)
- TLS 1.3 enforcement regardless of transport

#### 5.5.2 Failure Handling

- Three retries with exponential backoff
- Automatic fallback between VPN and Tor
- Operation queueing during extended outages
- Reconnection detection and automatic resume

---

### 5.6 Cross-Chain Bridging

#### 5.6.1 Bridge Contracts

- Smart contracts on external chains (Ethereum, BSC)
- User-driven claim model with cryptographic proofs
- 5-minute timelock with challenge window
- Maximum transfer: $50K (Admin configurable)
- Maximum buy or sell of LockBox tokens $50k (Admin configurable)

#### 5.6.2 Liquidity Management

- Single DAG-based pool serving all supported blockchains
- Volume-adjusted weighted pricing (VWAP) for supported native blockchain token prices
- 10-minute TWAP for LockBox token
- Minimum 1 LockBox token permanent reserve

---

### 5.7 Error Handling and Logging

#### 5.7.1 No Network Logging

- All logging occurs in wallet software only
- Structured error types returned to wallet
- No server-side error storage

#### 5.7.2 Error Structure

```go
type LockBoxError struct {
    Code        string    // Machine-readable error code
    Message     string    // Human-readable description
    Details     string    // Optional context (non-sensitive)
    Severity    string    // "CRITICAL", "WARNING", or "INFO"
    Recoverable bool      // Whether automatic recovery is possible
    RetryAfter  int       // Suggested retry delay in seconds
    Component   string    // Which component generated the error
    Timestamp   time.Time // When the error occurred
}
```

#### 5.7.3 Retry Mechanisms and Backoff

| Operation | Retries | Backoff | Timeout |
|-----------|---------|---------|---------|
| Shard Retrieval | 3 | Exponential (100ms, 200ms, 400ms) | 5s per attempt |
| DAG Submission | 3 | Exponential (1s, 2s, 4s) | 10s per attempt |
| Network Authentication | 5 | Linear (1s) | 3s |
| ZKP Verification | 3 | Exponential (2s, 4s, 8s) | 15s |
| Bridge Operations | 4 | Exponential (5s, 10s, 20s, 40s) | 30s |

---

### 5.8 Bridge Flash Loan Protection

#### Block Confirmation Requirements

- **Universal Confirmation Rule**: 15 blocks must pass on ALL supported blockchains before bridge proof generation
- **Uniform Implementation**: Same 15-block requirement applies to Ethereum, Binance Smart Chain, and all future supported chains
- **Flash Loan Prevention**: 15-block delay makes flash loan attacks impossible as flash loans cannot span multiple blocks

#### Bridge Security Implementation

1. **Deposit Detection**: LockBox servers detect bridge contract deposit events but do not generate cryptographic proofs immediately
2. **Confirmation Monitoring**: System monitors for 15 block confirmations before proof generation begins
3. **Proof Generation**: Cryptographic proofs only created after 15-block confirmation threshold is met
4. **Claim Authorization**: Users can only claim bridged tokens after valid proof is generated post-confirmation

#### Transaction Flow Security

```
User Deposit → Contract Lock → Deposit Event → Wait 15 Blocks → Generate Proof → User Claims → Verify & Release
```

#### Bridge Fee Structure

- **No LockBox Bridge Fees**: LockBox charges no fees for cross-chain bridging operations
- **User Responsibility**: Users pay only standard blockchain gas fees on source and destination chains
- **Revenue Model**: Bridge operations generate no direct revenue for LockBox; revenue comes from key retrieval and other services

#### Security Monitoring

- **Reorg Detection**: Monitor for blockchain reorganizations that might affect confirmed transactions
- **Proof Expiration**: Generated proofs expire after 24 hours if unused to prevent stale claims
- **Transaction Finality**: Verify transactions remain in finalized blocks throughout confirmation period
