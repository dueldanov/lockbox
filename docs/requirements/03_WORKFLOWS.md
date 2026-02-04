# LockBox Requirements - System Workflows

## 4. System Workflows

### 4.1 Private Key Storage Workflow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         KEY STORAGE WORKFLOW                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  [1] User Initiates                                                          │
│       │                                                                      │
│       ├── Enters private key                                                 │
│       └── Selects tier via wallet interface                                  │
│                                                                              │
│  [2] Client-Side Encryption                                                  │
│       │                                                                      │
│       ├── Wallet derives master key from seed phrase using Argon2id         │
│       └── Generates a 32-byte random salt for this bundle                   │
│                                                                              │
│  [3] Sharding and Decoy Generation                                          │
│       │                                                                      │
│       ├── Key split into individual characters                              │
│       ├── Each real character assigned unique HKDF key with numeric index   │
│       ├── Decoy characters generated based on tier ratio                    │
│       ├── Each decoy assigned HKDF key with alphabetic index                │
│       └── All shards encrypted with AES-256-GCM                             │
│                                                                              │
│  [4] Transaction Bundle Creation                                             │
│       │                                                                      │
│       ├── Main transaction with unique Bundle ID                            │
│       ├── Separate encrypted transactions for each shard (real + decoy)     │
│       ├── Metadata split into 5+ fragments with tier-based decoy fragments  │
│       └── All fragments encrypted with purpose-specific HKDF keys           │
│                                                                              │
│  [5] Distribution                                                            │
│       │                                                                      │
│       ├── Bundle submitted to DAG                                           │
│       ├── Distributed across 3-10+ nodes in 3+ regions                      │
│       └── Following geographic and shard limit rules                        │
│                                                                              │
│  [6] Token Generation                                                        │
│       │                                                                      │
│       ├── 64-byte single-use token returned to wallet                       │
│       └── Stored encrypted in wallet local storage                          │
│                                                                              │
│  [7] Seed Phrase Generation                                                  │
│       │                                                                      │
│       ├── Direct Key Recovery Seed Phrase generated                         │
│       ├── Displayed to user for recording                                   │
│       └── Optionally stored encrypted in wallet                             │
│                                                                              │
│  [8] Network Confirmation                                                    │
│       │                                                                      │
│       ├── Bundle submitted using iota.go's SubmitMessage function           │
│       └── Required references and approvals verified                        │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

### 4.2 Private Key Retrieval Workflow

1. **User Request:**
   - Selects key to retrieve in wallet
   - Wallet submits request with:
     - Single-use token
     - Zero-knowledge proof of ownership
     - Payment transaction

2. **Dual Coordination:**
   - Primary coordinating node randomly selected
   - Selects three geographically diverse verification nodes
   - Secondary coordinating node also selected for oversight

3. **Triple Verification:**
   - Each verification node independently validates:
     - ZKP authenticity
     - Payment transaction confirmation
     - Token validity and nonce
     - User tier authorization
   - Returns Ed25519 signatures to primary node

4. **Coordination Validation:**
   - Primary node aggregates verification signatures
   - Secondary node validates primary's work
   - Both must reach consensus

5. **Wallet Approval:**
   - Primary node sends encrypted data and all signatures to wallet
   - Wallet verifies signatures before proceeding

6. **Metadata Retrieval:**
   - Wallet retrieves metadata fragments directly from their respective nodes
   - Decrypts fragments using master key and numeric HKDF indices
   - Identifies real fragments (ignores decoys)

7. **Shard Retrieval:**
   - Wallet retrieves shards directly from their holding nodes
   - Elite tier: Each shard undergoes additional dual verification

8. **Key Reconstruction:**
   - Wallet attempts decryption of each shard with numerically-indexed keys
   - Successfully decrypted shards identified as real
   - Characters ordered by the index of successful decryption key
   - Full key assembled in wallet memory only

9. **Token Update:**
   - New single-use token generated and returned to wallet
   - Old token invalidated
   - New token stored encrypted for future retrievals

10. **Memory Clearing:**
    - Private key cleared from memory within 1 second after use
    - All intermediate buffers explicitly zeroed

---

### 4.3 Key Rotation and Reassignment Workflow

1. **Trigger:**
   - Mandatory: System-initiated every 6 months (±7 days random variation)
   - Voluntary: User-prompted monthly (30 days ±3 days random variation)

2. **User Initiation:**
   - User approves prompted rotation or
   - System initiates automatically for mandatory rotation

3. **Verification:**
   - Wallet generates ZKP to prove ownership
   - Node validates proof

4. **Retrieval:**
   - System retrieves existing shards using current token
   - Verifies integrity of retrieved data

5. **Re-Encryption:**
   - All shards (real and decoy) re-encrypted with fresh HKDF keys
   - New salt generated for the bundle

6. **Redistribution:**
   - Shards reassigned to new nodes
   - Following geographic distribution rules
   - Maintaining tier-specific redundancy

7. **Metadata Update:**
   - New main transaction created with updated references
   - Version identifier incremented (e.g., 'v1' to 'v2')

8. **Token Issuance:**
   - New single-use token generated and returned
   - Old token invalidated

9. **Garbage Collection:**
   - Old shards marked for deletion with 24-hour delay
   - Securely removed after delay period

---

### 4.4 Cross-Chain Bridging Workflow

1. **User Deposit:**
   - User sends cryptocurrency to bridge smart contract on source chain
   - Contract locks tokens and emits Deposit event

2. **Event Detection:**
   - LockBox servers detect and validate the deposit event
   - Record bridge request in internal ledger

3. **Proof Generation:**
   - Server generates cryptographic proof of the deposit
   - Makes proof available through API

4. **User Claim Process:**
   - User connects wallet to destination chain
   - Requests to claim bridged assets
   - Provides the cryptographic proof

5. **Contract Verification:**
   - Bridge contract on destination chain verifies the proof
   - If valid, releases equivalent tokens to user
   - Marks proof as used to prevent double-claiming

6. **Key Retrieval:**
   - Wallet retrieves private keys for signing transactions
   - Following standard key retrieval workflow
   - Keys used to sign transactions on both chains

---

### 4.5 Username Registration Workflow

1. **User Request:**
   - Submits username for registration
   - Provides public key and privacy setting
   - Includes ZKP proving ownership of public key

2. **Uniqueness Check:**
   - Node checks for existing registrations
   - Returns USERNAME_TAKEN error if already registered

3. **Transaction Submission:**
   - Username registration submitted as LedgerTx
   - Includes:
     - Username (with "LockBox@" prefix)
     - Owner's public key
     - Privacy setting ("Public" or "Private")
     - Timestamp

4. **Confirmation:**
   - Transaction requires multiple approvals via DAG
   - Confirmed based on timestamp priority in case of conflicts

5. **Storage:**
   - Public usernames stored openly in the DAG
   - Private usernames encrypted with key derived from owner's master key

---

### 4.6 Username Resolution Workflow

1. **User Request:**
   - Wallet submits resolution request with username
   - Includes optional ZKP for private username resolution

2. **Data Retrieval:**
   - Node fetches corresponding LedgerTx from DAG
   - If private, validates ZKP before decrypting

3. **Response:**
   - Returns username with "LockBox@" prefix
   - Includes owner public key
   - Provides derived address for the user

---

### 4.7 Node Failure and Self-Healing Workflow

1. **Failure Detection:**
   - Network flags node as failed after three consecutive ping failures
   - Health monitoring system (health.go) detects issues

2. **Shard Identification:**
   - System identifies all shards stored on the failed node
   - Prioritizes based on tier (Elite first, then Premium, etc.)

3. **Redistribution:**
   - Shards replicated to healthy nodes
   - Following geographic distribution rules
   - Maintaining tier-specific redundancy
   - Respecting shard limits per node

4. **Map Update:**
   - Shard location map updated in the DAG
   - New references created for redirecting requests

5. **Notification:**
   - Wallet notified to retry if retrieval pending
   - Log entry created in wallet software

---

### 4.8 Network Bootstrap Process

1. **Genesis Node Setup:**
   - Minimum three genesis nodes deployed across diverse regions
   - Each configured with known peer identities
   - Establish initial TLS connections and verify certificates
   - Genesis transaction created and signed by admin key

2. **Initial DAG Formation:**
   - Genesis nodes establish transaction structure with cross-references
   - Each submits initial transactions referencing others
   - Required approvals (3 prior) established within genesis group
   - Network parameters set in these transactions

3. **Node Expansion:**
   - New nodes join by connecting to at least 3 existing nodes
   - Download current DAG state from peers
   - Authenticate via TLS with certificate validation
   - Verify entire DAG from genesis to current tip
   - Binary hash will be used when deploying to production

4. **Trust Establishment:**
   - New nodes enter probation period (100 transactions or 1 hour)
   - Extra verification for transactions from probationary nodes
   - Full participation rights granted after probation
   - Continuous peer behavior monitoring

5. **Scaling Process:**

| Tier | Minimum Nodes Required |
|------|----------------------|
| Basic | 5 nodes |
| Standard | 10 nodes |
| Premium | 15 nodes |
| Elite | 20+ nodes |

   - Shard distribution adjusts automatically as nodes join

---

### 4.9 Three-Phase Token Distribution Strategy

#### Phase 1: Fair Launch to $50M USD (Months 1-18)

**Objectives:**
- Achieve $50M USD in treasury funding through fair market token sales
- Establish initial market price discovery and liquidity base
- Fund core development, marketing, and operational requirements
- Build initial user and B2B partner community

**Implementation:**
- **Treasury Target**: $50M USD collected in Treasury Wallet through token sales
- **Sales Method**: Exclusively through liquidity pool purchases using supported native blockchain tokens
- **Pricing Mechanism**: Automated market maker pricing with no preferential rates or bulk discounts
- **Market Protection**: Enhanced transaction limits (default $10K max for first 30 days, then $50K max) and cooling periods

**Success Metrics:**
- Revenue Milestone: $50M USD collected and verified in Treasury Wallet
- Distribution Health: No single wallet holding more than 2% of circulating supply
- Platform Adoption: Minimum 10,000 active wallets and 100 B2B integrations
- Price Stability: Average daily volatility less than 15% over 30-day periods

#### Phase 2: Stabilization Period (Months 19-30)

**Objectives:**
- Allow market maturation and price stabilization
- Await regulatory clarity on Clarity Act passage and implementation
- Optimize platform performance and user experience
- Prepare systematic distribution infrastructure for Phase 3

**Transition Criteria:**
- Time Requirement: Minimum 6 months, maximum 12 months duration
- Market Stability: 90-day average daily volatility less than 10%
- Regulatory Clarity: Clarity Act passage and implementation guidance available
- Technical Readiness: Platform security audits completed and systematic distribution system tested

#### Phase 3: Compliance Distribution (Months 31-54)

**Objectives:**
- Reduce admin token ownership from 95% to 19.99% to achieve Clarity Act "mature blockchain system" status
- Distribute 750.1M tokens through systematic, transparent process
- Maintain market stability during large-scale distribution
- Achieve commodity classification under CFTC jurisdiction

**Implementation:**
- **Distribution Schedule**: Quarterly releases of approximately 31.25M tokens over 24 months
- **Distribution Methods**:
  - 40% through liquidity pool market sales
  - 30% through ecosystem development grants
  - 20% through B2B partnership incentives
  - 10% through community rewards and governance programs

**Success Criteria:**
- Regulatory Compliance: Admin ownership reduced to exactly 19.99% of total supply
- Market Stability: Distribution completed without greater than 30% price volatility in any 30-day period
- Ecosystem Growth: Active user base growth maintained or increased throughout distribution period
- Legal Recognition: "Mature blockchain system" status achieved and commodity classification confirmed
