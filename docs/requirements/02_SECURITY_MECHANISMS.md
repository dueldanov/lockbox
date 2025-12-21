# LockBox Requirements - Security Mechanisms

## 3. Security Mechanisms

### 3.1 Character-Level Sharding with HKDF

#### 3.1.1 Process

- Private keys (up to 256 characters) split into individual character shards
- Encryption: Each real character encrypted with unique key derived via HKDF using:
  - Master key
  - "LockBox" identifier
  - Purpose-specific parameter ("real-char")
  - Numeric index (0, 1, 2, etc.)

#### 3.1.2 Example

For key "WXYZ":
- "W" uses key derived from master key, "LockBox:real-char:0"
- "X" uses key derived from master key, "LockBox:real-char:1"
- "Y" uses key derived from master key, "LockBox:real-char:2"
- "Z" uses key derived from master key, "LockBox:real-char:3"

#### 3.1.3 Redundancy

- Tier-dependent: 3 copies (Basic), 5 (Standard), 7 (Premium), 10+ (Elite)
- Node Limit: Maximum 10% of key's shards per node (20% if fewer than 5 nodes)

---

### 3.2 Decoy System

#### 3.2.1 Character Decoys

| Tier | Decoy Ratio |
|------|-------------|
| Basic | 0.5x real characters |
| Standard | 1x real characters |
| Premium | 1.5x real characters |
| Elite | 2x real characters |

- Encryption: Decoys encrypted with unique keys derived via HKDF using:
  - Master key
  - "LockBox:decoy-char" purpose
  - Alphabetic index (A, B, C, etc.)

#### 3.2.2 Metadata Decoys

| Tier | Metadata Decoy Ratio |
|------|---------------------|
| Basic/Standard | No decoy metadata |
| Premium | 1:1 ratio (one decoy per real fragment) |
| Elite | 2:1 ratio (two decoys per real fragment) |

- Metadata split into 5+ real fragments with tier-based decoy fragments
- HKDF: Real metadata encrypted with keys derived using:
  - Master key
  - "LockBoxMeta:real-meta" purpose
  - Numeric index (0, 1, 2, etc.)
- Decoy metadata encrypted with:
  - Master key
  - "LockBoxMeta:decoy-meta" purpose
  - Alphabetic index (A, B, C, etc.)

#### 3.2.3 Uniform Processing

- Real and decoy characters/fragments processed identically to prevent pattern analysis
- Same retry mechanisms apply to both real and decoy data
- Memory clearing occurs uniformly for all character types
- Error handling is consistent across real and decoy data

#### 3.2.4 Simplified Metadata Structure

- The HKDF with index approach eliminates the need for a character map in the metadata
- Position information is encoded directly in the HKDF keys:
  - Numeric indices (0, 1, 2...) for real characters
  - Alphabetic indices (A, B, C...) for decoys
- Metadata contains only:
  - Total character count
  - Real character count
  - Reconstruction rules
  - Decoy parameters
  - Access control parameters
- Wallet identifies real characters by attempting decryption with numerically-indexed keys
- Character positioning based on the successful key's index

---

### 3.3 Zero-Knowledge Proofs (ZKPs)

#### 3.3.1 Implementation

- zk-STARKs via gnark library in crypto/zkp.go
- Quantum-resistant security with efficient verification

#### 3.3.2 Applications

- Shard validity proofs
- Ownership proofs
- Decoy distribution proofs
- Multi-signature proofs for higher tiers

#### 3.3.3 Performance

| Tier | ZKP Verification Time |
|------|----------------------|
| Basic | ~50ms (lightweight) |
| Standard | ~100ms (medium) |
| Premium/Elite | ~200ms (enhanced) |

- Each ZKP includes a unique nonce to prevent replay attacks

---

### 3.4 Single-Use Token System

#### 3.4.1 Structure

- 64-byte token containing:
  - Hashed Bundle ID (never exposed directly)
  - Unique identifier for validation
  - Nonce/timestamp to prevent replay attacks
  - Optional metadata for tier-specific features

#### 3.4.2 Management

- Tokens encrypted and stored locally in the wallet
- Invalidated after use
- Replaced with new token after each successful retrieval

#### 3.4.3 Authentication

- Nonce-based with 5-minute validation window
- Rate limiting: 5 attempts per minute per user ID

#### 3.4.4 Rotation

- Two-phase commit process:
  - Node proposes new token (encrypted with SEK)
  - Wallet verifies and signs approval
  - Node commits via LedgerTx

---

### 3.5 Seed Phrase System

#### 3.5.1 Access Recovery Seed Phrase (Master Key)

- 24-word BIP-39 mnemonic seed
- Combined with mandatory passphrase (minimum 12 characters)
- Derives 32-byte master key via Argon2id (64MB memory, 4 iterations)
- Used for authenticating to the LockBox network

#### 3.5.2 Direct Key Recovery Seed Phrase

- Separate 24-word mnemonic for each stored private key
- Enables direct reconstruction without network access
- Deterministically derived using HKDF
- Presented to user during key storage

#### 3.5.3 Local Storage

- Optional; users encouraged to record phrases physically
- Can be stored encrypted in wallet database
- Always requires passphrase for usage

---

### 3.6 Geographic Distribution

#### 3.6.1 Requirements

- Minimum three geographic regions
- Minimum 1000km separation between nodes storing the same shard
- Multi-cloud: Minimum five nodes across three+ cloud providers

#### 3.6.2 Verification

- Latency-based routing or zk-STARK proofs of coordinates
- Geographic verification enforced during shard distribution

#### 3.6.3 Fallback

- New key storage halts if fewer than three regions are available
- Error: "INSUFFICIENT_REGIONS"

---

### 3.7 Decentralized Verification for Retrieval

#### 3.7.1 Bundle-Level Triple Verification

- Two coordinating nodes oversee three verification nodes
- Each verification node independently validates:
  - Zero-knowledge proof authenticity
  - Payment transaction confirmation
  - Single-use token validity
  - User tier authorization

#### 3.7.2 Elite Tier Enhancement

- Shard-Level Dual Verification (Elite tier only)
- Each shard request triggers a deterministic verification node selection
- Both the shard-holding node and its verification node must approve the request
- Processed in parallel batches (10-20 shards at a time)

#### 3.7.3 Decentralized Custody

- Shards and metadata are never consolidated on any network node
- Wallet connects directly to each shard-holding node
- Reconstruction occurs only on the client device

---

### 3.8 Tiered Security Levels

#### Basic Tier

| Feature | Specification |
|---------|---------------|
| Decoy Characters | 0.5x the number of real characters |
| Decoy Metadata | No decoy metadata fragments |
| Redundancy | 3 copies of each shard |
| Encryption | Single-layer AES-256-GCM |
| ZKP Validation | Lightweight (~50ms) |
| Retrieval Processing | Sequential processing |
| Network Security | Basic TLS 1.3 |
| Audit | Encrypted wallet logs locally |
| Emergency Response | Key destruction only |
| HSM/Enclave | No hardware security module |

#### Standard Tier

| Feature | Specification |
|---------|---------------|
| Decoy Characters | 1x the number of real characters |
| Decoy Metadata | No decoy metadata fragments |
| Redundancy | 5 copies of each shard |
| Encryption | Single-layer AES-256-GCM |
| ZKP Validation | Standard (~100ms) |
| Retrieval Processing | Parallel processing |
| Network Security | TLS 1.3 + rate limiting |
| Audit | Encrypted wallet logs locally |
| Emergency Response | Key destruction + notifications |
| HSM/Enclave | No hardware security module |

#### Premium Tier

| Feature | Specification |
|---------|---------------|
| Decoy Characters | 1.5x the number of real characters |
| Decoy Metadata | 1:1 ratio |
| Redundancy | 7 copies of each shard |
| Encryption | Single-layer AES-256-GCM |
| ZKP Validation | Multi-sig enhanced (~200ms) |
| Retrieval Processing | Caching + parallel |
| Network Security | Reputation scoring + rate limiting |
| Audit | Blockchain-anchored logs |
| Emergency Response | Key destruction + lockdown |
| HSM/Enclave | No hardware security module |

#### Elite Tier

| Feature | Specification |
|---------|---------------|
| Decoy Characters | 2x the number of real characters |
| Decoy Metadata | 2:1 ratio |
| Redundancy | 10+ copies with anchor nodes |
| Encryption | Dual-layer AES-256-GCM |
| ZKP Validation | Enhanced multi-sig zk-STARKs |
| Retrieval Processing | Full caching + parallel + predictive |
| Network Security | Traffic analysis prevention + blacklisting |
| Audit | Tamper-proof blockchain logs |
| Emergency Response | Key destruction + lockdown + backup |
| HSM/Enclave | TPM/CNG on Windows, Keystore on Android |

---

### 3.9 Cold Wallet Storage Security Model

#### 3.9.1 Session Security

- Session Initialization: Requires 24-word seed phrase and passphrase
- Key Management: Master key derived via Argon2id, seed phrase immediately cleared
- Memory Protection: Master key in protected memory during active session only
- Session Termination: Cryptographic materials wiped on logout/timeout
- Zero-Knowledge State: Maintained between sessions to reduce attack surface
- Re-authentication: Complete seed phrase re-entry required for subsequent sessions

#### 3.9.2 Hardware Security Integration

| Platform | Hardware Integration |
|----------|---------------------|
| Windows | TPM/CNG for Elite tier |
| Android | Hardware-backed Keystore for Elite tier |
| Chrome | No hardware integration (Basic/Standard only) |

---

### 3.10 Software Trust Mechanisms

#### 3.10.1 Binary Verification

- User-configurable software lock (users lock binary versions)
- Independent signing by 3+ third parties (e.g., Trail of Bits)
- All signatures verified at application launch
- **Note:** This will not be a part of the development environment to make testing easier and implemented before we publicly launch.
