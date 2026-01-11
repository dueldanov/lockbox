![Logo Description automatically generated](media/image1.png){width="5.470833333333333in" height="1.2882174103237096in"}

**LockBox Requirements Document**

**1. Introduction**

LockBox is a decentralized solution for secure private key management in cryptocurrency ecosystems. It ensures \"Decentralized Custody\" by splitting private keys into character-level shards distributed across a geographically diverse network, using decoy mechanisms, zero-knowledge proofs, and multiple verification steps to maintain security.

**1.1 System Components**

-   **LockSmith Network (SecureHornet)**: A DAG-based network forked from IOTA Hornet for storing encrypted key shards and managing a native cryptocurrency ledger.

<https://github.com/iotaledger/hornet> (v2.0.2 from May 24, 2024)

-   **LockScript DSL**: A security-focused language for key operations, compiled to Go and WebAssembly.

-   **Wallet Applications**: Chrome Extension (Basic/Standard tiers), Windows Desktop (all tiers), and Android Mobile (all tiers). (We will integrate other open-source wallets first to offer LockBox-enabled wallets to existing wallet users like Rabby Wallet users can now use a LockBox-enabled version of Rabby.)

-   **Native Token**: Facilitates retrieval fees and cross-chain bridging.

-   **B2B Integration**: gRPC API for wallet providers with revenue sharing.

**1.2 Development Phases**

Development will proceed in phases, with initial focus exclusively on Project 1 (LockSmith Network and B2B integration). The LockSmith Node software will be closed source and operate as a private network. All wallet software will be open source and white-labeled for B2B partners.

-   **Project 1**: Network Development (LockSmith/SecureHornet)

-   **Project 1.5**: Chrome Extension Wallet (Basic/Standard tiers)

-   **Project 2**: Windows Desktop Wallet (All tiers)

-   **Project 3**: Android Mobile Wallet (All tiers)

-   **Projects 4-8**: Future extensions (DEX, RWA, Insurance, Messaging, Payment Processing)

**2. System Architecture**

**2.1 LockSmith Network (SecureHornet)**

**2.1.1 Foundation**

-   Fork of IOTA Hornet v2.0.2 (May 24, 2024)

-   Operating **without a coordinator** (Coordicide upgrade)

-   DAG consensus: Each transaction references and validates at least two previous transactions

-   No proof-of-work required

**2.1.2 Core Features**

-   Stores encrypted key shards and metadata fragments across nodes

-   Maintains ledger for LockBox cryptocurrency

-   Manages decentralized username registry

-   Enforces no-logging policy (logs generated in wallet software only)

-   Node authentication via mutual TLS 1.3

-   Stores encrypted key shards without distinguishing between real and decoy components

-   Geographic distribution: Shards distributed across minimum three regions, 1000km apart

-   Shard limit: No node stores more than 10% of a key\'s shards (20% if fewer than five nodes available)

-   Self-healing: Detects node failures (three failed pings) and redistributes affected shards

-   Provides anonymous aggregate statistics (total wallet count)

**2.1.3 Multi-Cloud Dispersal**

-   Minimum 5 nodes across 3+ cloud providers to have an operational network (e.g., AWS, Azure, GCP)

-   zk-STARK proofs for geographic verification

-   Ed25519-signed receipts for distribution validation

-   Scaling to 5+ cloud providers for Elite tier

**2.2 LockScript DSL**

**2.2.1 Purpose**

-   Declarative, security-first domain-specific language for key operations

-   Compilation: Statically compiled to Go using compiler in core/compiler.go; compiled to WebAssembly for browsers

-   Memory safety: Automatically clears sensitive data types when they exit scope

-   No direct file/network I/O permitted

**2.2.2 Key Functions**

-   Operations like storeKey, getKey, rotate, registerUsername, resolveUsername

-   HKDF Functions: Specialized functions for HKDF-based key derivation with purpose-specific parameters

-   Support for all security tiers with appropriate configurations

**2.3 Wallet Applications**

**2.3.1 Chrome Extension (Project 1.5)**

-   Supports Basic and Standard tiers only

-   Uses WASM-compiled LockScript

-   Target size: \<6MB for WebAssembly bundle, \<20MB for full extension

-   Memory usage: \<200MB peak for key reconstruction

**2.3.2 Windows Desktop (Project 2)**

-   Initially CLI supporting all tiers

-   Optional Qt-based GUI may be added later

-   Hardware security module integration for Elite tier (TPM/CNG)

**2.3.3 Android Mobile (Project 3)**

-   Native application supporting all tiers

-   Kotlin UI with Go backend via gomobile

-   Android Keystore integration for Elite tier

**3. Security Mechanisms**

**3.1 Character-Level Sharding with HKDF**

**3.1.1 Process**

-   Private keys (up to 256 characters) split into individual character shards

-   Encryption: Each real character encrypted with unique key derived via HKDF using:

    -   Master key

    -   \"LockBox\" identifier

    -   Purpose-specific parameter (\"real-char\")

    -   Numeric index (0, 1, 2, etc.)

**3.1.2 Example**

For key \"WXYZ\":

-   \"W\" uses key derived from master key, \"LockBox:real-char:0\"

-   \"X\" uses key derived from master key, \"LockBox:real-char:1\"

-   \"Y\" uses key derived from master key, \"LockBox:real-char:2\"

-   \"Z\" uses key derived from master key, \"LockBox:real-char:3\"

**3.1.3 Redundancy**

-   Tier-dependent: 3 copies (Basic), 5 (Standard), 7 (Premium), 10+ (Elite)

-   Node Limit: Maximum 10% of key\'s shards per node (20% if fewer than 5 nodes)

**3.2 Decoy System**

**3.2.1 Character Decoys**

-   Tier-based ratio of decoy characters:

    -   Basic: 0.5x real characters

    -   Standard: 1x real characters

    -   Premium: 1.5x real characters

    -   Elite: 2x real characters

-   Encryption: Decoys encrypted with unique keys derived via HKDF using:

    -   Master key

    -   \"LockBox:decoy-char\" purpose

    -   Alphabetic index (A, B, C, etc.)

**3.2.2 Metadata Decoys**

-   Metadata split into 5+ real fragments with tier-based decoy fragments:

    -   Basic/Standard: No decoy metadata

    -   Premium: 1:1 ratio (one decoy per real fragment)

    -   Elite: 2:1 ratio (two decoys per real fragment)

-   HKDF: Real metadata encrypted with keys derived using:

    -   Master key

    -   \"LockBoxMeta:real-meta\" purpose

    -   Numeric index (0, 1, 2, etc.)

-   Decoy metadata encrypted with:

    -   Master key

    -   \"LockBoxMeta:decoy-meta\" purpose

    -   Alphabetic index (A, B, C, etc.)

**3.2.3 Uniform Processing**

-   Real and decoy characters/fragments processed identically to prevent pattern analysis

-   Same retry mechanisms apply to both real and decoy data

-   Memory clearing occurs uniformly for all character types

-   Error handling is consistent across real and decoy data

**3.2.4 Simplified Metadata Structure**

-   The HKDF with index approach eliminates the need for a character map in the metadata

-   Position information is encoded directly in the HKDF keys:

    -   Numeric indices (0, 1, 2\...) for real characters

    -   Alphabetic indices (A, B, C\...) for decoys

-   Metadata contains only:

    -   Total character count

    -   Real character count

    -   Reconstruction rules

    -   Decoy parameters

    -   Access control parameters

-   Wallet identifies real characters by attempting decryption with numerically-indexed keys

-   Character positioning based on the successful key\'s index

**3.3 Zero-Knowledge Proofs (ZKPs)**

**3.3.1 Implementation**

-   zk-STARKs via gnark library in crypto/zkp.go

-   Quantum-resistant security with efficient verification

**3.3.2 Applications**

-   Shard validity proofs

-   Ownership proofs

-   Decoy distribution proofs

-   Multi-signature proofs for higher tiers

**3.3.3 Performance**

-   Tier-dependent verification times:

    -   Basic: \~50ms (lightweight)

    -   Standard: \~100ms (medium)

    -   Premium/Elite: \~200ms (enhanced)

-   Each ZKP includes a unique nonce to prevent replay attacks

**3.4 Single-Use Token System**

**3.4.1 Structure**

-   64-byte token containing:

    -   Hashed Bundle ID (never exposed directly)

    -   Unique identifier for validation

    -   Nonce/timestamp to prevent replay attacks

    -   Optional metadata for tier-specific features

**3.4.2 Management**

-   Tokens encrypted and stored locally in the wallet

-   Invalidated after use

-   Replaced with new token after each successful retrieval

**3.4.3 Authentication**

-   Nonce-based with 5-minute validation window

-   Rate limiting: 5 attempts per minute per user ID

**3.4.4 Rotation**

-   Two-phase commit process:

    -   Node proposes new token (encrypted with SEK)

    -   Wallet verifies and signs approval

    -   Node commits via LedgerTx

**3.5 Seed Phrase System**

**3.5.1 Access Recovery Seed Phrase (Master Key)**

-   24-word BIP-39 mnemonic seed

-   Combined with mandatory passphrase (minimum 12 characters)

-   Derives 32-byte master key via Argon2id (64MB memory, 4 iterations)

-   Used for authenticating to the LockBox network

**3.5.2 Direct Key Recovery Seed Phrase**

-   Separate 24-word mnemonic for each stored private key

-   Enables direct reconstruction without network access

-   Deterministically derived using HKDF

-   Presented to user during key storage

**3.5.3 Local Storage**

-   Optional; users encouraged to record phrases physically

-   Can be stored encrypted in wallet database

-   Always requires passphrase for usage

**3.6 Geographic Distribution**

**3.6.1 Requirements**

-   Minimum three geographic regions

-   Minimum 1000km separation between nodes storing the same shard

-   Multi-cloud: Minimum five nodes across three+ cloud providers

**3.6.2 Verification**

-   Latency-based routing or zk-STARK proofs of coordinates

-   Geographic verification enforced during shard distribution

**3.6.3 Fallback**

-   New key storage halts if fewer than three regions are available

-   Error: \"INSUFFICIENT_REGIONS\"

**3.7 Decentralized Verification for Retrieval**

**3.7.1 Bundle-Level Triple Verification**

-   Two coordinating nodes oversee three verification nodes

-   Each verification node independently validates:

    -   Zero-knowledge proof authenticity

    -   Payment transaction confirmation

    -   Single-use token validity

    -   User tier authorization

**3.7.2 Elite Tier Enhancement**

-   Shard-Level Dual Verification (Elite tier only)

-   Each shard request triggers a deterministic verification node selection

-   Both the shard-holding node and its verification node must approve the request

-   Processed in parallel batches (10-20 shards at a time)

**3.7.3 Decentralized Custody**

-   Shards and metadata are never consolidated on any network node

-   Wallet connects directly to each shard-holding node

-   Reconstruction occurs only on the client device

**3.8 Tiered Security Levels**

**Basic Tier**

The Basic tier provides fundamental security features suitable for users with modest storage needs and lower security requirements:

-   **Decoy Characters**: 0.5x the number of real characters (half as many decoy characters as real characters)

-   **Decoy Metadata**: No decoy metadata fragments included

-   **Redundancy**: 3 copies of each shard distributed across the network

-   **Encryption**: Single-layer AES-256-GCM encryption

-   **ZKP Validation**: Lightweight zero-knowledge proof validation (\~50ms processing time)

-   **Retrieval Processing**: Sequential processing of shard requests

-   **Network Security**: Basic TLS 1.3 encryption for all communications

-   **Audit**: Encrypted wallet logs stored locally

-   **Emergency Response**: Key destruction capability only

-   **HSM/Enclave**: No hardware security module integration

**Standard Tier**

The Standard tier enhances security with improved redundancy and parallel processing capabilities:

-   **Decoy Characters**: 1x the number of real characters (equal number of decoy characters to real characters)

-   **Decoy Metadata**: No decoy metadata fragments included

-   **Redundancy**: 5 copies of each shard distributed across the network

-   **Encryption**: Single-layer AES-256-GCM encryption

-   **ZKP Validation**: Standard zero-knowledge proof validation (\~100ms processing time)

-   **Retrieval Processing**: Parallel processing of shard requests for improved performance

-   **Network Security**: TLS 1.3 encryption plus rate limiting protections

-   **Audit**: Encrypted wallet logs stored locally

-   **Emergency Response**: Key destruction plus automated notifications

-   **HSM/Enclave**: No hardware security module integration

**Premium Tier**

The Premium tier provides enhanced security suitable for high-value storage with advanced obfuscation and caching:

-   **Decoy Characters**: 1.5x the number of real characters (one and a half times as many decoy characters as real characters)

-   **Decoy Metadata**: 1:1 ratio (one decoy metadata fragment per real metadata fragment)

-   **Redundancy**: 7 copies of each shard distributed across the network

-   **Encryption**: Single-layer AES-256-GCM encryption

-   **ZKP Validation**: Multi-signature enhanced zero-knowledge proof validation (\~200ms processing time)

-   **Retrieval Processing**: Caching plus parallel processing for optimized performance

-   **Network Security**: Reputation scoring system for nodes and advanced rate limiting

-   **Audit**: Blockchain-anchored logs for tamper-proof audit trails

-   **Emergency Response**: Key destruction plus automatic system lockdown capabilities

-   **HSM/Enclave**: No hardware security module integration

**Elite Tier**

The Elite tier delivers maximum security with enterprise-grade features and hardware integration:

-   **Decoy Characters**: 2x the number of real characters (twice as many decoy characters as real characters)

-   **Decoy Metadata**: 2:1 ratio (two decoy metadata fragments per real metadata fragment)

-   **Redundancy**: 10+ copies of each shard distributed across the network with anchor nodes

-   **Encryption**: Dual-layer AES-256-GCM encryption for enhanced protection

-   **ZKP Validation**: Enhanced multi-signature zk-STARKs validation for maximum security

-   **Retrieval Processing**: Full caching, parallel processing, and predictive node selection

-   **Network Security**: Traffic analysis prevention, reputation scoring, and blacklisting capabilities

-   **Audit**: Tamper-proof blockchain-anchored logs with comprehensive audit trails

-   **Emergency Response**: Key destruction, system lockdown, and distributed anchor backup systems

-   **HSM/Enclave**: Hardware security module integration (TPM/CNG on Windows, Android Keystore on mobile platforms)

**3.9 Cold Wallet Storage Security Model**

**3.9.1 Session Security**

-   Session Initialization: Requires 24-word seed phrase and passphrase

-   Key Management: Master key derived via Argon2id, seed phrase immediately cleared

-   Memory Protection: Master key in protected memory during active session only

-   Session Termination: Cryptographic materials wiped on logout/timeout

-   Zero-Knowledge State: Maintained between sessions to reduce attack surface

-   Re-authentication: Complete seed phrase re-entry required for subsequent sessions

**3.9.2 Hardware Security Integration**

-   Windows: TPM/CNG for Elite tier

-   Android: Hardware-backed Keystore for Elite tier

-   Chrome: No hardware integration (Basic/Standard only)

**3.10 Software Trust Mechanisms**

**3.10.1 Binary Verification**

-   User-configurable software lock (users lock binary versions)

-   Independent signing by 3+ third parties (e.g., Trail of Bits)

-   All signatures verified at application launch

-   This will not be a part of the development environment to make testing easier and implemented before we publicly launch.

**4. System Workflows**

**4.1 Private Key Storage Workflow**

1.  **User Initiates:**

    -   Enters private key

    -   Selects tier via wallet interface

2.  **Client-Side Encryption:**

    -   Wallet derives master key from seed phrase using Argon2id

    -   Generates a 32-byte random salt for this bundle

3.  **Sharding and Decoy Generation:**

    -   Key split into individual characters

    -   Each real character assigned unique HKDF key with numeric index

    -   Decoy characters generated based on tier ratio

    -   Each decoy assigned HKDF key with alphabetic index

    -   All shards encrypted with AES-256-GCM

4.  **Transaction Bundle Creation:**

    -   Main transaction with unique Bundle ID

    -   Separate encrypted transactions for each shard (real + decoy)

    -   Metadata split into 5+ fragments with tier-based decoy fragments

    -   All fragments encrypted with purpose-specific HKDF keys

5.  **Distribution:**

    -   Bundle submitted to DAG

    -   Distributed across 3-10+ nodes in 3+ regions

    -   Following geographic and shard limit rules

6.  **Token Generation:**

    -   64-byte single-use token returned to wallet

    -   Stored encrypted in wallet local storage

7.  **Seed Phrase Generation:**

    -   Direct Key Recovery Seed Phrase generated

    -   Displayed to user for recording

    -   Optionally stored encrypted in wallet

8.  **Network Confirmation:**

    -   Bundle submitted using iota.go\'s SubmitMessage function

    -   Required references and approvals verified

**4.2 Private Key Retrieval Workflow**

1.  **User Request:**

    -   Selects key to retrieve in wallet

    -   Wallet submits request with:

        -   Single-use token

        -   Zero-knowledge proof of ownership

        -   Payment transaction

2.  **Dual Coordination:**

    -   Primary coordinating node randomly selected

    -   Selects three geographically diverse verification nodes

    -   Secondary coordinating node also selected for oversight

3.  **Triple Verification:**

    -   Each verification node independently validates:

        -   ZKP authenticity

        -   Payment transaction confirmation

        -   Token validity and nonce

        -   User tier authorization

    -   Returns Ed25519 signatures to primary node

4.  **Coordination Validation:**

    -   Primary node aggregates verification signatures

    -   Secondary node validates primary\'s work

    -   Both must reach consensus

5.  **Wallet Approval:**

    -   Primary node sends encrypted data and all signatures to wallet

    -   Wallet verifies signatures before proceeding

6.  **Metadata Retrieval:**

    -   Wallet retrieves metadata fragments directly from their respective nodes

    -   Decrypts fragments using master key and numeric HKDF indices

    -   Identifies real fragments (ignores decoys)

7.  **Shard Retrieval:**

    -   Wallet retrieves shards directly from their holding nodes

    -   Elite tier: Each shard undergoes additional dual verification

8.  **Key Reconstruction:**

    -   Wallet attempts decryption of each shard with numerically-indexed keys

    -   Successfully decrypted shards identified as real

    -   Characters ordered by the index of successful decryption key

    -   Full key assembled in wallet memory only

9.  **Token Update:**

    -   New single-use token generated and returned to wallet

    -   Old token invalidated

    -   New token stored encrypted for future retrievals

10. **Memory Clearing:**

    -   Private key cleared from memory within 1 second after use

    -   All intermediate buffers explicitly zeroed

**4.3 Key Rotation and Reassignment Workflow**

1.  **Trigger:**

    -   Mandatory: System-initiated every 6 months (±7 days random variation)

    -   Voluntary: User-prompted monthly (30 days ±3 days random variation)

2.  **User Initiation:**

    -   User approves prompted rotation or

    -   System initiates automatically for mandatory rotation

3.  **Verification:**

    -   Wallet generates ZKP to prove ownership

    -   Node validates proof

4.  **Retrieval:**

    -   System retrieves existing shards using current token

    -   Verifies integrity of retrieved data

5.  **Re-Encryption:**

    -   All shards (real and decoy) re-encrypted with fresh HKDF keys

    -   New salt generated for the bundle

6.  **Redistribution:**

    -   Shards reassigned to new nodes

    -   Following geographic distribution rules

    -   Maintaining tier-specific redundancy

7.  **Metadata Update:**

    -   New main transaction created with updated references

    -   Version identifier incremented (e.g., \'v1\' to \'v2\')

8.  **Token Issuance:**

    -   New single-use token generated and returned

    -   Old token invalidated

9.  **Garbage Collection:**

    -   Old shards marked for deletion with 24-hour delay

    -   Securely removed after delay period

**4.4 Cross-Chain Bridging Workflow**

1.  **User Deposit:**

    -   User sends cryptocurrency to bridge smart contract on source chain

    -   Contract locks tokens and emits Deposit event

2.  **Event Detection:**

    -   LockBox servers detect and validate the deposit event

    -   Record bridge request in internal ledger

3.  **Proof Generation:**

    -   Server generates cryptographic proof of the deposit

    -   Makes proof available through API

4.  **User Claim Process:**

    -   User connects wallet to destination chain

    -   Requests to claim bridged assets

    -   Provides the cryptographic proof

5.  **Contract Verification:**

    -   Bridge contract on destination chain verifies the proof

    -   If valid, releases equivalent tokens to user

    -   Marks proof as used to prevent double-claiming

6.  **Key Retrieval:**

    -   Wallet retrieves private keys for signing transactions

    -   Following standard key retrieval workflow

    -   Keys used to sign transactions on both chains

**4.5 Username Registration Workflow**

1.  **User Request:**

    -   Submits username for registration

    -   Provides public key and privacy setting

    -   Includes ZKP proving ownership of public key

2.  **Uniqueness Check:**

    -   Node checks for existing registrations

    -   Returns USERNAME_TAKEN error if already registered

3.  **Transaction Submission:**

    -   Username registration submitted as LedgerTx

    -   Includes:

        -   Username (with \"LockBox@\" prefix)

        -   Owner\'s public key

        -   Privacy setting (\"Public\" or \"Private\")

        -   Timestamp

4.  **Confirmation:**

    -   Transaction requires multiple approvals via DAG

    -   Confirmed based on timestamp priority in case of conflicts

5.  **Storage:**

    -   Public usernames stored openly in the DAG

    -   Private usernames encrypted with key derived from owner\'s master key

**4.6 Username Resolution Workflow**

1.  **User Request:**

    -   Wallet submits resolution request with username

    -   Includes optional ZKP for private username resolution

2.  **Data Retrieval:**

    -   Node fetches corresponding LedgerTx from DAG

    -   If private, validates ZKP before decrypting

3.  **Response:**

    -   Returns username with \"LockBox@\" prefix

    -   Includes owner public key

    -   Provides derived address for the user

**4.7 Node Failure and Self-Healing Workflow**

1.  **Failure Detection:**

    -   Network flags node as failed after three consecutive ping failures

    -   Health monitoring system (health.go) detects issues

2.  **Shard Identification:**

    -   System identifies all shards stored on the failed node

    -   Prioritizes based on tier (Elite first, then Premium, etc.)

3.  **Redistribution:**

    -   Shards replicated to healthy nodes

    -   Following geographic distribution rules

    -   Maintaining tier-specific redundancy

    -   Respecting shard limits per node

4.  **Map Update:**

    -   Shard location map updated in the DAG

    -   New references created for redirecting requests

5.  **Notification:**

    -   Wallet notified to retry if retrieval pending

    -   Log entry created in wallet software

**4.8 Network Bootstrap Process**

1.  **Genesis Node Setup:**

    -   Minimum three genesis nodes deployed across diverse regions

    -   Each configured with known peer identities

    -   Establish initial TLS connections and verify certificates

    -   Genesis transaction created and signed by admin key

2.  **Initial DAG Formation:**

    -   Genesis nodes establish transaction structure with cross-references

    -   Each submits initial transactions referencing others

    -   Required approvals (2 prior) established within genesis group

    -   Network parameters set in these transactions

3.  **Node Expansion:**

    -   New nodes join by connecting to at least 3 existing nodes

    -   Download current DAG state from peers

    -   Authenticate via TLS with certificate validation

    -   Verify entire DAG from genesis to current tip

    -   Binary hash will be used when deploying to production. Nodes only talk to other nodes and to wallets retrieving keys when the hash is correct.

4.  **Trust Establishment:**

    -   New nodes enter probation period (100 transactions or 1 hour)

    -   Extra verification for transactions from probationary nodes

    -   Full participation rights granted after probation

    -   Continuous peer behavior monitoring

5.  **Scaling Process:**

    -   Network starts with minimum 5 nodes for Basic tier

    -   Expansion to 10 nodes enables Standard tier

    -   Premium tier requires at least 15 nodes

    -   Elite tier requires 20+ nodes

    -   Shard distribution adjusts automatically as nodes join

**4.9 Three-Phase Token Distribution Strategy**

The LockBox system shall implement a structured three-phase approach for token distribution, regulatory compliance, and sustainable growth funding.

**Phase 1: Fair Launch to \$50M USD (Months 1-18)**

**Objectives:**

-   Achieve \$50M USD in treasury funding through fair market token sales

-   Establish initial market price discovery and liquidity base

-   Fund core development, marketing, and operational requirements

-   Build initial user and B2B partner community

**Implementation:**

-   **Treasury Target**: \$50M USD collected in Treasury Wallet through token sales

-   **Sales Method**: Exclusively through liquidity pool purchases using supported native blockchain tokens

-   **Pricing Mechanism**: Automated market maker pricing with no preferential rates or bulk discounts

-   **Market Protection**: Enhanced transaction limits (default \$10K max for first 30 days, then \$50K max) and cooling periods

-   **Revenue Recognition**: All token sales constitute LockBox revenue collected in Treasury Wallet

**Success Metrics:**

-   **Revenue Milestone**: \$50M USD collected and verified in Treasury Wallet

-   **Distribution Health**: No single wallet holding more than 2% of circulating supply

-   **Platform Adoption**: Minimum 10,000 active wallets and 100 B2B integrations

-   **Price Stability**: Average daily volatility less than 15% over 30-day periods

**Phase 2: Stabilization Period (Months 19-30)**

**Objectives:**

-   Allow market maturation and price stabilization

-   Await regulatory clarity on Clarity Act passage and implementation

-   Optimize platform performance and user experience

-   Prepare systematic distribution infrastructure for Phase 3

**Implementation:**

-   **Market Monitoring**: Continuous analysis of trading patterns, whale accumulation, and price stability

-   **Platform Development**: Focus on feature enhancement, security audits, and scalability improvements

-   **Regulatory Preparation**: Legal compliance review and preparation for \"mature blockchain system\" certification

-   **Community Building**: Enhanced B2B partner onboarding and user adoption programs

**Transition Criteria:**

-   **Time Requirement**: Minimum 6 months, maximum 12 months duration

-   **Market Stability**: 90-day average daily volatility less than 10%

-   **Regulatory Clarity**: Clarity Act passage and implementation guidance available

-   **Technical Readiness**: Platform security audits completed and systematic distribution system tested

**Phase 3: Compliance Distribution (Months 31-54)**

**Objectives:**

-   Reduce admin token ownership from 95% to 19.99% to achieve Clarity Act \"mature blockchain system\" status

-   Distribute 750.1M tokens through systematic, transparent process

-   Maintain market stability during large-scale distribution

-   Achieve commodity classification under CFTC jurisdiction

**Implementation:**

-   **Distribution Schedule**: Quarterly releases of approximately 31.25M tokens over 24 months

-   **Distribution Methods**:

    -   40% through liquidity pool market sales

    -   30% through ecosystem development grants

    -   20% through B2B partnership incentives

    -   10% through community rewards and governance programs

-   **Market Protection**: Maintain transaction limits and implement progressive release schedules to prevent price manipulation

-   **Transparency Requirements**: Pre-announce distribution schedules and provide real-time progress reporting

**Compliance Verification:**

-   **Ownership Tracking**: Real-time monitoring of admin wallet ownership percentage

-   **Legal Certification**: Submit \"mature blockchain system\" certification to relevant authorities upon reaching 19.99% threshold

-   **Audit Trail**: Complete documentation of distribution process for regulatory review

-   **Community Governance**: Transition appropriate system governance functions to community voting mechanisms

**Success Criteria:**

-   **Regulatory Compliance**: Admin ownership reduced to exactly 19.99% of total supply

-   **Market Stability**: Distribution completed without greater than 30% price volatility in any 30-day period

-   **Ecosystem Growth**: Active user base growth maintained or increased throughout distribution period

-   **Legal Recognition**: \"Mature blockchain system\" status achieved and commodity classification confirmed

**5. Technical Implementation**

**5.1 Project 1: SecureHornet Network**

**5.1.1 Base Code Modifications (from IOTA Hornet v2.0.2)**

-   **tangle.go:** ZKP validation plugin, two-prior-approval enforcement

-   **database.go:** Metadata sharding and distribution

-   **ledger.go:** LedgerTx for LockBox token transactions

-   **node.go/peering.go:** Node authentication, geographic verification

-   **health.go:** Self-healing triggers, monitoring

**5.1.2 New Files (in lockbox/ directory)**

-   **main.go:** Main entry point integrating with Hornet core

-   **api/grpc.go:** B2B integration API endpoints

-   **core/lockscript.go:** LockScript DSL implementation

-   **core/compiler.go:** Compiler for LockScript to Go/WASM

-   **crypto/zkp.go:** ZKP implementation using gnark

-   **crypto/encrypt.go:** Encryption with HKDF keys

-   **dag/submit.go:** Transaction bundle submission

-   **models/shard.go:** Character shard data structures

-   **storage/shard.go:** Geographic distribution logic

-   **storage/ledger.go:** Cryptocurrency implementation

-   **admin_alert.go:** Administrative alerting system

**5.2 Project 1.5: Chrome Extension**

**5.2.1 Chrome Manifest**

-   Version: Manifest V3

-   Permissions: storage, alarms, notifications, <https://securehornet.lockbox.network/>\*

-   Content Security Policy: Restricts scripts, allows WASM execution

**5.2.2 File Structure**

-   **manifest.json:** Configuration

-   **popup.html:** UI entry point

-   **popup.js:** UI logic and WASM bridge

-   **background.js:** Network calls, scheduling

-   **lockbox.wasm:** WASM-compiled LockScript (\<6MB)

-   **wasm_exec.js:** WASM runtime loader

-   **assets/style.css:** Styling

**5.2.3 B2B Integration**

-   LockScript SDK for B2B extensions

-   Precompiled WASM binary and runtime

-   Documentation for gRPC API endpoints

-   Semantic versioning (e.g., 1.0.0 initial release)

**5.3 Project 2: Windows Desktop Application (Future)**

**5.3.1 Base**

-   Fork of Firefly v2.0.12, renamed to LockBox

-   Files to modify: main.ts, preload.ts, wallet.ts, network.ts

-   New files in lockbox/ directory

**5.3.2 Implementation**

-   CLI initially, possible Qt GUI later

-   Hardware security module integration (TPM/CNG)

-   Offline recovery functionality

**5.4 Project 3: Android Mobile Application (Future)**

**5.4.1 Implementation**

-   Native app with Kotlin UI, Go backend via gomobile

-   Package: lockbox-mobile.aar (compiled with gomobile bind)

-   Functions: storeKey, retrieveKey, rotateKey, destroyKey

**5.4.2 Features**

-   Biometric authentication

-   Android Keystore integration

-   Embedded OpenVPN/Tor networking

**5.5 Network Communication**

**5.5.1 VPN/Tor Integration**

-   OpenVPN as default network layer (Implement in later version, not version 1.)

-   Tor as optional feature (Implement in later version, not version 1.)

-   TLS 1.3 enforcement regardless of transport

**5.5.2 Failure Handling**

-   Three retries with exponential backoff

-   Automatic fallback between VPN and Tor

-   Operation queueing during extended outages

-   Reconnection detection and automatic resume

**5.6 Cross-Chain Bridging**

**5.6.1 Bridge Contracts**

-   Smart contracts on external chains (Ethereum, BSC)

-   User-driven claim model with cryptographic proofs

-   5-minute timelock with challenge window

-   Maximum transfer: \$50K (Admin configurable)

-   Maximum buy or sell of LockBox tokens \$50k (Admin configurable)

**5.6.2 Liquidity Management**

-   Single DAG-based pool serving all supported blockchains

-   Volume-adjusted weighted pricing (VWAP) for supported native blockchain token prices

-   10-minute TWAP for LockBox token

-   Minimum 1 LockBox token permanent reserve

**5.7 Error Handling and Logging**

**5.7.1 No Network Logging**

-   All logging occurs in wallet software only

-   Structured error types returned to wallet

-   No server-side error storage

**5.7.2 Error Structure**

type LockBoxError struct {

Code string // Machine-readable error code

Message string // Human-readable description

Details string // Optional context (non-sensitive)

Severity string // \"CRITICAL\", \"WARNING\", or \"INFO\"

Recoverable bool // Whether automatic recovery is possible

RetryAfter int // Suggested retry delay in seconds

Component string // Which component generated the error

Timestamp time.Time // When the error occurred

}

**5.7.3 Retry Mechanisms and Backoff**

-   **Shard Retrieval:** 3 retries, exponential backoff (100ms, 200ms, 400ms), 5s timeout per attempt

-   **DAG Submission:** 3 retries, exponential backoff (1s, 2s, 4s), 10s timeout per attempt

-   **Network Authentication:** 5 retries, linear backoff (1s), 3s timeout

-   **ZKP Verification:** 3 retries, exponential backoff (2s, 4s, 8s), 15s timeout

-   **Bridge Operations:** 4 retries, exponential backoff (5s, 10s, 20s, 40s), 30s timeout

**5.8 Bridge Flash Loan Protection**

The LockBox cross-chain bridge system shall implement robust security measures to prevent flash loan attacks and ensure transaction finality before processing bridge operations.

**Block Confirmation Requirements:**

-   **Universal Confirmation Rule**: 15 blocks must pass on ALL supported blockchains before bridge proof generation

-   **Uniform Implementation**: Same 15-block requirement applies to Ethereum, Binance Smart Chain, and all future supported chains

-   **Flash Loan Prevention**: 15-block delay makes flash loan attacks impossible as flash loans cannot span multiple blocks

**Bridge Security Implementation:**

-   **Deposit Detection**: LockBox servers detect bridge contract deposit events but do not generate cryptographic proofs immediately

-   **Confirmation Monitoring**: System monitors for 15 block confirmations before proof generation begins

-   **Proof Generation**: Cryptographic proofs only created after 15-block confirmation threshold is met

-   **Claim Authorization**: Users can only claim bridged tokens after valid proof is generated post-confirmation

**Transaction Flow Security:**

1.  User deposits crypto to bridge contract on source chain

2.  Contract locks tokens and emits Deposit event

3.  LockBox servers detect event but wait for 15 block confirmations

4.  After 15 blocks, servers generate cryptographic proof of valid deposit

5.  User claims equivalent tokens on destination chain using proof

6.  Destination contract verifies proof and releases tokens

**Bridge Fee Structure:**

-   **No LockBox Bridge Fees**: LockBox charges no fees for cross-chain bridging operations

-   **User Responsibility**: Users pay only standard blockchain gas fees on source and destination chains

-   **Revenue Model**: Bridge operations generate no direct revenue for LockBox; revenue comes from key retrieval and other services

**Security Monitoring:**

-   **Reorg Detection**: Monitor for blockchain reorganizations that might affect confirmed transactions

-   **Proof Expiration**: Generated proofs expire after 24 hours if unused to prevent stale claims

-   **Transaction Finality**: Verify transactions remain in finalized blocks throughout confirmation period

**6. Token Economics and B2B Integration**

**6.1 Token Economics**

**6.1.1 Supply and Distribution**

-   Fixed 1 billion tokens (no additional issuance)

-   100M tokens in liquidity pool at launch

-   900M tokens in admin reserve

-   1 token minimum permanently in liquidity pool

**6.1.2 Fees and Incentives**

-   **Private Key Retrieval Fees:**

    -   Basic: \$0.01 flat

    -   Standard: \$0.015 flat

    -   Premium: \$0.03 + \$0.002 per \$100K stored

    -   Elite: \$0.10 + \$0.015 per \$1M stored

-   **Setup/Rotation Fees:**

    -   Setup: \$0 (Basic), \$50 (Standard), \$500 (Premium), \$2,500 (Elite)

    -   Rotation: \$5 (Basic/Standard), \$10 (Premium), \$25 (Elite)

-   **Discount:** 10% for LockBox token payments (admin adjustable 0-100%)

**6.1.3 Launch Promotion**

-   First 10,000 wallets receive 100 LockBox tokens each

-   First three retrievals free for new wallets forever

-   Promotional wallet funded with 1M tokens from admin reserve

**6.1.4 Admin Control**

-   Single Ed25519 keypair stored offline

-   Optional multisig support configurable via ledger.go

-   Can transfer additional tokens to pool as needed

**6.1.5 Multi-Wallet Architecture**

The LockBox system shall implement a segregated wallet architecture to ensure security, auditability, and operational clarity:

**Primary Wallet Types:**

-   **Admin Control Wallet**: Single Ed25519 keypair for system governance, emergency functions, and protocol upgrades. Stores no tokens for operational purposes.

-   **Liquidity Management Wallet**: Dedicated wallet holding tokens designated for systematic distribution phases, pool management, and compliance operations. Initially holds 900M tokens post-launch.

-   **Promotional Wallet**: Separate wallet pre-funded with 1M LockBox tokens for launch promotion rewards to first 10,000 users.

-   **Treasury Wallet**: Collects revenue from token sales during fundraising phases and ongoing operational revenue including key retrieval fees, setup fees, and rotation fees. Targets \$50M USD collection during Phase 1.

**Wallet Separation Requirements:**

-   Each wallet type shall use distinct Ed25519 keypairs with separate private key management

-   All inter-wallet transfers shall be recorded as distinct LedgerTx transactions on the SecureHornet DAG

-   Wallet roles cannot overlap; no single wallet shall perform multiple operational functions

-   All wallet addresses shall be publicly verifiable on the DAG for transparency

**Security and Access Controls:**

-   Admin Control Wallet: Offline cold storage, air-gapped environment for signing

-   Liquidity Management Wallet: Multi-signature capability for compliance distribution phases

-   Promotional Wallet: Automated distribution system with predefined limits

-   Treasury Wallet: Real-time balance tracking for fundraising milestone verification and revenue collection

**6.1.6 LockBox Token Trading Limits**

The LockBox system shall implement comprehensive transaction limits to ensure fair distribution, prevent market manipulation, and protect against whale accumulation during all operational phases.

**Per-Transaction Limits:**

-   **Buy Limit**: Default maximum \$50,000 USD equivalent per transaction (admin configurable)

-   **Sell Limit**: Default maximum \$50,000 USD equivalent per transaction (admin configurable)

-   **Launch Period Override**: Default reduced to \$10,000 USD equivalent maximum for first 30 days post-launch (admin configurable)

-   **Elite Tier Exception**: Verified institutional users may request increased limits up to default \$100,000 USD equivalent (admin configurable)

**Timing and Cooling Periods:**

-   **Maximum Transaction Cooling Period**: Default 1 hour minimum between consecutive maximum-limit transactions per wallet address (admin configurable)

-   **Daily Aggregate Limit**: Default no single wallet may exceed \$200,000 USD equivalent in combined buy/sell volume per 24-hour period (admin configurable)

-   **Rolling Window**: Limits calculated on rolling 24-hour basis, not calendar days (admin configurable)

**Implementation Requirements:**

-   **Real-Time USD Conversion**: Transaction limits enforced using real-time oracle pricing (Chainlink) converted to LockBox token amounts

-   **Wallet-Based Tracking**: Limits applied per unique wallet address, not IP address or device

-   **Bridge Contract Enforcement**: Limits enforced at smart contract level on all supported blockchains

-   **Cross-Chain Coordination**: Limits apply across all supported blockchains collectively per wallet

**Pool Protection Mechanisms:**

-   **Maximum Pool Impact**: Default no single transaction may exceed 5% of current liquidity pool depth (admin configurable)

**Administrative Controls:**

-   **Real-Time Adjustment**: Admin Control Wallet can modify all limits and time intervals without system restart

-   **Complete Disable Option**: Admin can permanently disable all transaction limits for mature system operation when natural market forces provide adequate protection

-   **Emergency Override**: Admin can temporarily disable limits during critical maintenance or emergency situations

-   **Compliance Logging**: All limit modifications logged as LedgerTx with timestamp and justification

-   **Gradual Limit Increases**: Systematic increase of limits allowed as market matures and liquidity grows

**6.1.7 Fair Launch Protocol**

The LockBox token shall implement a fair launch mechanism ensuring equal access and preventing preferential allocation to any participants.

**Fair Launch Principles:**

-   **No Private Sales**: Zero tokens allocated to private investors, institutions, or pre-sale participants prior to public launch

-   **No Pre-Mining**: All tokens exist in predefined allocations; no additional tokens generated through pre-launch mining

-   **Equal Access**: All participants access tokens through identical mechanism (liquidity pool purchases)

-   **Transparent Pricing**: All purchases subject to identical automated market maker pricing without preferential rates

**Purchase Mechanism:**

-   **Exclusive Liquidity Pool Access**: All LockBox token acquisitions must occur through the central liquidity pool

-   **Supported Payment Methods**: Purchases payable only in supported native blockchain tokens (ETH, BNB, etc.)

-   **No Direct Admin Sales Outside Market**: All admin token sales occur through liquidity pool or systematic distribution, with proceeds constituting LockBox revenue

-   **Public Price Discovery**: Token price determined solely by automated market maker algorithms based on supply/demand

**Launch Configuration:**

-   **Initial Liquidity Pool**: 50M LockBox tokens allocated to liquidity pool at launch

-   **Circulating Supply**: Only tokens in liquidity pool considered circulating supply until systematic distribution begins

-   **Administrative Reserve**: 950M tokens held in Liquidity Management Wallet, not considered circulating until distributed

-   **Market Cap Calculation**: Based exclusively on circulating supply, not total supply

**Anti-Manipulation Safeguards:**

-   **Transaction Limits**: Per-transaction and cooling period limits prevent large accumulations

-   **No Bulk Allocations**: No mechanism exists for bulk token transfers outside of systematic compliance distribution

-   **Public Audit Trail**: All token movements recorded on SecureHornet DAG for public verification

-   **Real-Time Transparency**: Current token distribution visible through public DAG explorer

**6.2 B2B gRPC API**

**6.2.1 Methods**

service LockboxService {

// StoreKey: Stores a private key in the SecureHornet DAG.

rpc StoreKey(StoreKeyRequest) returns (StoreKeyResponse);

// GetKey: Retrieves a private key using a single-use token.

rpc RetrieveKey(RetrieveKeyRequest) returns (RetrieveKeyResponse);

// Rotate: Rotates encryption and reassigns shards.

rpc RotateAndReassign(RotateAndReassignRequest) returns (RotateAndReassignResponse);

// GetRevenueShare: Fetches revenue share data for a provider.

rpc GetRevenueShare(GetRevenueShareRequest) returns (GetRevenueShareResponse);

// FetchVpnConfig: Updates VPN configuration for wallet connectivity.

rpc FetchVpnConfig(FetchVpnConfigRequest) returns (FetchVpnConfigResponse);

// RegisterUsername: Registers a LockBox@username.

rpc RegisterUsername(RegisterUsernameRequest) returns (RegisterUsernameResponse);

// ResolveUsername: Resolves a LockBox@username to an address.

rpc ResolveUsername(ResolveUsernameRequest) returns (ResolveUsernameResponse);

}

**6.2.2 Revenue Sharing**

-   50% of retrieval fees shared with B2B providers (modified by referral program)

-   Tracked via unique provider ID in ledger

-   Daily batch payments in LockBox tokens

-   Verifiable via GetRevenueShare API

**6.2.3 SDK Access**

-   Providers receive SDK access via private repository

-   WASM binary for browser extensions

-   Documentation for API endpoints

-   Quarterly updates or critical fixes

**6.2.4 Daily Payment Distribution**

The LockBox system implements a daily automatic payment distribution for B2B partner revenue sharing.

**Payment Schedule and Processing**

-   **Daily Processing Cycle**: All B2B partner payments are processed automatically at 00:01 UTC each day

-   **Earnings Calculation**: The system aggregates each partner\'s revenue share from the previous 24-hour period (00:00 UTC to 23:59 UTC)

-   **Payment Eligibility**: Partners receive payments if their accumulated earnings for the day are greater than zero LockBox tokens. No minimum threshold applies.

-   **No Payment Scenarios**: Partners receive no payment only when their daily earnings equal zero (no user retrievals occurred through their integration)

**Technical Implementation**

-   **Aggregation Process**: At 23:59 UTC, the system queries the SecureHornet ledger for all retrieval fee transactions associated with each B2B partner ID from the previous 24-hour period

-   **Payment Calculation**: For each qualifying partner, calculate their share of total retrieval fees collected through their integration during the previous day (modified by referral program structure)

-   **Batch Transaction Execution**: At 00:01 UTC, execute a single LockBox token transaction distributing payments to all partners with earnings \> 0

-   **Confirmation and Logging**: Update partner dashboards with payment confirmations by 00:05 UTC

**Payment Distribution Examples**

-   Partner with 40 LockBox tokens earned: Receives 40 tokens

-   Partner with 0.5 LockBox tokens earned: Receives 0.5 tokens

-   Partner with zero earnings: No payment transaction (no retrieval activity)

-   Partner with 1,000 LockBox tokens earned: Receives 1,000 tokens

**Error Handling and Retry Logic**

-   **Failed Payments**: If the daily batch payment transaction fails, the system retries once at 01:00 UTC

-   **Persistent Failures**: After two failed attempts, the system queues failed payments for manual administrative review

-   **Partner Notification**: Partners can view payment status and any pending payments through their dashboard

-   **Recovery Process**: Failed payments are included in the next successful daily payment cycle

**Partner Dashboard Integration**

-   **Real-Time Tracking**: Partners view earnings accumulation throughout the current day

-   **Daily Notifications**: Automatic notifications when daily payments are processed

-   **Payment History**: Complete transaction history showing all daily payments received

-   **Status Visibility**: Clear indication of payment processing status and any pending amounts

**API Integration**

-   **GetRevenueShare Enhancement**: The existing API method is updated to support daily payment queries with date range parameters

-   **Daily Payment Endpoint**: New endpoint GetDailyPaymentStatus provides real-time status of current day\'s payment processing

-   **Webhook Support**: Optional webhook notifications when daily payments are processed successfully

**System Benefits**

-   **Improved Cash Flow**: Partners receive predictable daily income instead of waiting for monthly payments

-   **Enhanced Transparency**: Complete visibility into daily earnings and payment processing

-   **Operational Simplicity**: Eliminates complex monthly aggregation and reduces administrative overhead

-   **Network Efficiency**: Single daily batch transaction per payment cycle minimizes network congestion

-   **Partner Satisfaction**: Immediate gratification through daily payment delivery without arbitrary minimum thresholds

**6.2.5 Dual Referral Program Implementation**

The LockBox system implements two distinct referral programs to incentivize user acquisition and B2B partner onboarding. Both programs utilize the LockBox username system for simple referral link generation and tracking.

**Reserved Username System**

-   **Corporate Username**: \@LockBox is permanently reserved and hardcoded in the system

-   **Implementation**: Username \"@LockBox\" is embedded in server code and cannot be registered by users

-   **Purpose**: Ensures corporate identity protection and prevents unauthorized use

**Referral Link Structure**

-   **Universal Format**: All referral links follow the pattern [www.LockBox.io/@username](http://www.LockBox.io/@username)

-   **Example**: A user with username \"lance\" has referral link [www.LockBox.io/@lance](http://www.LockBox.io/@lance)

-   **Requirement**: Referrers must have a LockBox account with a registered username to participate

-   **Tracking**: The username in the URL automatically associates referrals with the referring user\'s wallet

**Permanent Referral Association**

-   **Immutable Relationship**: When a user or B2B partner clicks a referral link, they are permanently associated with that referrer in the LockBox system

-   **Ledger Storage**: All referral relationships are stored permanently on the SecureHornet ledger

-   **No Expiration**: Referral associations never expire and cannot be changed or transferred

-   **First-Click Priority**: If multiple referral links are used, only the first valid referral association is recorded

**Program 1: Token Purchase Referral Program**

**Program Structure**

-   **Commission Rate**: 10% of token purchase value paid to referrer

-   **Payment Source**: Commissions paid from LockBox treasury address, not from liquidity pool

-   **Payment Method**: Immediate payment in LockBox tokens at time of purchase

-   **Program Cap**: Active until \$50M USD worth of LockBox tokens are purchased (admin configurable)

-   **Default Status**: Enabled by default (admin can disable)

**Cap Implementation**

-   **Threshold Monitoring**: System tracks cumulative token purchases against \$50M cap

-   **Final Purchase Handling**: If a purchase exceeds the \$50M threshold, the referrer still receives full commission on the complete purchase amount

-   **Example**: If \$49.9M has been reached and someone purchases \$200K worth of tokens, the referrer receives commission on the full \$200K

-   **Post-Cap Behavior**: After cap is exceeded, no new referrals generate commissions, but existing purchases complete normally

**Admin Controls - Program 1**

-   **Commission Percentage**: Adjustable (default: 10%)

-   **Program Cap**: Configurable USD amount (default: \$50M)

-   **Program Toggle**: Enable/disable setting (default: enabled)

-   **No Grandfathering**: Changes apply immediately to all future transactions

**Program 2: B2B Partner Referral Program**

**Program Structure**

-   **Revenue Distribution**: Modified revenue sharing structure when referrer exists:

    -   50% to B2B partner

    -   10% to referrer

    -   40% to LockBox

-   **Payment Duration**: Forever (no time limits)

-   **Payment Schedule**: Daily payments integrated with existing B2B Revenue Sharing system

-   **Default Status**: Enabled by default (admin can disable)

**Revenue Calculation Examples**

-   **Without Referrer**: \$100 retrieval fees → \$50 to partner, \$50 to LockBox

-   **With Referrer**: \$100 retrieval fees → \$50 to partner, \$10 to referrer, \$40 to LockBox

**Admin Controls - Program 2**

-   **Commission Percentage**: Adjustable (default: 10%)

-   **Program Toggle**: Enable/disable setting (default: enabled)

-   **No Grandfathering**: Changes apply immediately to all future daily payments

**Technical Implementation Requirements**

**Database Schema Updates**

Referral_Relationships {

referrer_username: String (indexed)

referrer_wallet_address: String

referred_entity_id: String (user ID or B2B partner ID)

referred_entity_type: Enum\[\"TOKEN_BUYER\", \"B2B_PARTNER\"\]

first_click_timestamp: UnixNano

referral_url: String

ledger_tx_hash: String (permanent storage reference)

status: \"ACTIVE\" (no expiration states)

}

Program_Settings {

program_1_enabled: Bool (default: true)

program_1_commission_rate: Float (default: 0.10)

program_1_cap_usd: BigInt (default: 50000000)

program_1_total_paid_usd: BigInt (running total)

program_2_enabled: Bool (default: true)

program_2_commission_rate: Float (default: 0.10)

}

**Token Purchase Referral Implementation**

-   **Treasury Integration**: Commission payments sourced from designated LockBox treasury wallet address

-   **Immediate Processing**: Commission calculated and paid within same transaction as token purchase

-   **Cap Verification**: Check running total before payment, allow final purchase to exceed cap

-   **Treasury Balance**: Ensure sufficient LockBox tokens in treasury for commission payments

**B2B Referral Integration**

-   **Daily Payment Modification**: Update existing daily payment system to include three-way split when referrer exists

-   **Commission Calculation**: 10% of total retrieval fees (not 10% of partner\'s 50% share)

-   **Payment Processing**: Include referrer payments in 00:01 UTC daily batch transaction

**Admin Configuration System**

**Settings Management**

-   **Real-Time Updates**: Admin setting changes take effect immediately for new transactions

-   **No Retroactive Changes**: Existing pending payments process under previous settings

-   **Validation Rules**: Commission rates cannot exceed 50%, caps must be positive values

-   **Audit Trail**: All admin setting changes logged with timestamp and admin identifier

**Cap Management - Program 1**

-   **Running Total Tracking**: Maintain accurate cumulative purchase amount in USD

-   **Threshold Logic**:

-   if (current_total + new_purchase \<= cap) {

-   process_referral_commission();

-   update_running_total();

-   } else if (current_total \< cap) {

-   process_referral_commission(); // Final purchase gets full commission

-   disable_future_referrals();

}

**Error Handling Requirements**

**Treasury Insufficient Funds**

-   **Detection**: Verify treasury balance before processing referral payments

-   **Fallback**: If insufficient funds, queue commission payment for admin funding

-   **Notification**: Alert admin when treasury requires refilling

-   **User Experience**: Token purchase completes successfully, referral payment queued

**Referral System Failures**

-   **Invalid Username**: Ignore referral if username doesn\'t exist, process purchase normally

-   **Self-Referral**: Block self-referral attempts, process purchase without commission

-   **Duplicate Association**: Honor first valid referral association, ignore subsequent attempts

**Integration Points**

**Website Landing Page**

-   **URL Processing**: Extract username from referral URLs and validate against username registry

-   **Cookie/Session Storage**: Temporarily store referral information during user registration process

-   **Association Creation**: Link referral data to new accounts upon successful registration

**Wallet Application Integration**

-   **Referral Dashboard**: Display section showing referral earnings from both programs

-   **Link Generator**: Built-in feature to generate personalized referral links

-   **Commission Notifications**: Real-time alerts when referral commissions are received

**Reserved Username Implementation**

-   **Server Code Integration**: Hardcode \"@LockBox\" reservation in username registration validation

-   **Registration Blocking**: Prevent any user registration attempts for \"@LockBox\" username

-   **System Usage**: Reserve for official LockBox communications and corporate functions

**6.3 Username Registry**

**6.3.1 Structure**

-   LedgerTx entries with:

    -   username: String (e.g., \"LockBox@alice\")

    -   owner_pubkey: Ed25519 public key (32 bytes)

    -   privacy: Enum\[Public, Private\]

    -   verified: Bool (for future premium features)

    -   timestamp: UnixNano (int64)

    -   tx_hash: TransactionID

**6.3.2 Privacy Settings**

-   Public: Openly resolvable by any wallet or B2B provider

-   Private: Encrypted with key derived from owner\'s master key

**6.3.3 Registration Rules**

-   First-come-first-serve basis for unique usernames

-   Requires at least three future node approvals

-   Conflicts resolved by timestamp priority

**7. API Requirements**

**7.1 Price API**

**7.1.1 Endpoints**

-   **/api/lockcoin/price:** Current price, supply, volume, market cap

-   **/api/lockcoin/market_chart:** OHLCV data with configurable intervals

**7.1.2 Data Source**

-   LockBox DAG\'s internal liquidity pool and transaction activities

-   No dependency on external exchanges

**7.1.3 Format**

-   JSON, compatible with CoinGecko/CoinMarketCap

-   Standard fields for interoperability

**7.1.4 Security**

-   API keys for authentication

-   Rate limits to prevent abuse

-   TLS 1.3 for all connections

**8. User Interface Requirements**

**8.1 Common Wallet UI Elements Across All Platforms**

**8.1.1 Navigation Structure**

-   **Home:** Account overview and main actions

-   **Swap:** Trading interface

-   **Activity:** Transaction history

-   **NFTs:** Non-fungible token management

-   **Settings:** Account preferences and security

**8.1.2 Core Functionality**

-   Portfolio value display

-   Token list with balances

-   Send/receive functionality

-   Username display and management

**8.2 Chrome Extension UI**

**8.2.1 Constraints**

-   Limited screen space (popup interface)

-   Focus on essential actions

-   Basic and Standard tier features only

**8.2.2 Components**

-   Compact header with account selector

-   Streamlined token list

-   Simplified swap interface

-   Limited activity/history view

-   Upgrade prompt for Premium/Elite tiers

**8.3 Desktop Application UI**

**8.3.1 Features**

-   Full screen real estate

-   Support for all tiers

-   Advanced swap interface

-   Comprehensive activity views

-   Security center for Elite tier

**8.3.2 CLI Interface**

-   Command-line operations for all key functions

-   Structured output formats

-   Non-interactive mode for scripts

**8.4 Mobile Application UI**

**8.4.1 Design**

-   Touch-oriented interface

-   Variable screen sizes

-   On-the-go usage patterns

-   Battery and data considerations

**8.4.2 Components**

-   Bottom tab navigation

-   Biometric integration

-   Mobile-optimized swap interface

-   Push notifications

-   Offline capabilities

**9. Performance Requirements (This section not necessary for development or our first version in production.)**

**9.1 Transaction Throughput**

**9.1.1 Initial Target**

-   100 TPS sustained for 10 minutes

-   50% node participation

-   64-character keys, Standard tier

-   90% success rate without retries

-   Across ≥20 nodes

**9.1.2 Scaling Target**

-   Linear scaling to 1000+ TPS with additional nodes

-   \~10 TPS per node at 100 nodes

**9.2 Latency Requirements**

**9.2.1 Storage Operations**

-   \<1s for 95% of transactions

**9.2.2 Retrieval Operations**

-   \<500ms for 90% of transactions

-   Individual shard: \<100ms (95%)

-   Full bundle (e.g., 96 shards): \<300ms (90%)

**9.3 Node Requirements**

**9.3.1 Minimum Specifications**

-   CPU: 1 GHz dual-core (e.g., ARM Cortex-A53)

-   RAM: 2 GB

-   Storage: 20 GB SSD

-   Network: 10 Mbps, \<50ms latency to peers

-   OS: Linux (e.g., Ubuntu 22.04) or Docker

**9.3.2 High-Performance Specifications (1000+ TPS)**

-   CPU: 4-core

-   RAM: 8 GB

-   Storage: 100 GB SSD

-   Network: 100 Mbps

**9.4 Stress Test Scenarios**

**9.4.1 Node Failure**

-   50% node failure (10/20 nodes)

-   Must sustain ≥50 TPS

-   Redistribute shards in \<60s

-   100% key retrieval success

**9.4.2 High Load**

-   500 TPS with 256-character keys, Elite tier

-   \<2s latency (90%)

-   \<500ms shard retrieval (85%)

-   ≤5% failures

**9.4.3 Network Partitioning**

-   Split 20 nodes into 10/10 for 2 minutes

-   ≥40 TPS per segment

-   Resume full retrieval in \<30s

**9.4.4 Malicious Node Attack**

-   3/20 nodes compromised

-   Blacklist in \<10s

-   ≥80 TPS

-   ≤1% retrieval failure

**9.4.5 Resource Saturation**

-   1 node at \>90% CPU/memory

-   Migrate shards in \<60s

-   No data loss

-   \<200ms latency increase

**10. Appendices**

**10.1 LockScript Grammar**

**10.1.1 Syntax Rules**

-   Scripts consist of secure_operation blocks within secure_context

-   Case-sensitive identifiers and keywords

-   Single-line comments with //

-   Whitespace ignored except in string literals

**10.1.2 Keywords and Constructs**

-   **secure_operation:** Defines a function with inputs and outputs

-   **secure_context:** Wraps operations with automatic memory clearing

-   **if, else:** Conditional branching

-   **for:** Iteration over arrays or ranges

-   **return:** Returns value, clears sensitive locals

-   **throw:** Raises structured error

**10.1.3 Data Types**

-   **Primitive:** int, float, Bool, String

-   **Security-Focused:** SecureString, SecureChar, SecureShard, ZKPProof, BundleID, TransactionID, SecureData

**10.1.4 Example Operation**

secure_operation store_key(key: SecureString) -\> BundleID {

validate_length(key, max: 256)

real_chars = to_char_array(key)

decoys = create_decoys(real_chars, ratio: get_tier_ratio())

shards = split_key(key, decoys)

tx_ids = assign_shards(shards, tier: get_current_tier())

bundle_id = generate_bundle_id()

secure_context {

log_operation(\"store\", true)

}

return bundle_id

}

**10.2 Error Codes**

**10.2.1 Core Error Codes**

-   **SHARD_UNAVAILABLE:** \"Shard retrieval failed\"

-   **ACCESS_DENIED:** \"Authentication failed\"

-   **PROOF_INVALID:** \"ZKP validation failed\"

-   **TOKEN_INVALID:** \"Token invalid or expired\"

-   **INSUFFICIENT_REGIONS:** \"Fewer than 3 regions available\"

-   **USERNAME_TAKEN:** \"Username already registered\"

-   **INSUFFICIENT_SHARD_MATCHES:** \"Fewer shards decrypted than expected\"

-   **NETWORK_PARTITIONED:** \"Network experiencing partition\"

-   **TIER_VIOLATION:** \"Operation not permitted for user\'s tier\"

-   **BUNDLE_NOT_FOUND:** \"Requested bundle ID doesn\'t exist\"

-   **METADATA_CORRUPT:** \"Metadata cannot be processed\"

-   **RATE_LIMITED:** \"Too many requests in time period\"

**10.2.2 Error Severity Levels**

-   **CRITICAL:** Operation failed, cannot proceed

-   **WARNING:** Operation succeeded but with issues

-   **INFO:** Informational message about operation

**10.3 Security Enhancements**

**10.3.1 Purpose-Specific HKDF**

-   Enhanced info parameter with domain, purpose, and index

-   Salt addition: Unique purpose-specific salt for key derivation

-   Memory management: Enhanced secure wiping for all byte slices

**10.3.2 Metadata Optimization**

-   Reduced footprint with only essential fields

-   Ephemeral ZKPs: Store hashes only, wipe full proofs

-   Transaction bundle salt: Unique 32-byte random salt per bundle

**10.3.3 Alerting**

-   Encryption alerting: Triggered on character shard encryption failures

-   Admin notifications: For critical node count and network issues

**11. Software Hash Verification System for LockSmith Nodes**

**This requirement is only done after we have completed the code, tested and ready to go into production.**

**Node Integrity Verification**

The LockBox system implements a robust node integrity verification system to ensure only authentic, unmodified LockSmith node software participates in the private key storage network, while keeping token transactions accessible through standard blockchain protocols.

**Node-to-Node Verification**

-   All LockSmith nodes verify each other\'s software integrity during connection establishment using SHA-256 cryptographic hashes

-   During initial connection handshake, nodes exchange software version information and binary hashes

-   Nodes validate received hashes against official signed hashes for corresponding versions

-   Connections are only established between nodes with matching verified hashes

-   Periodic re-verification occurs during ongoing operation to ensure continued integrity

-   Failed verification results in connection termination with \"INVALID_SOFTWARE_VERSION\" error

**Hash Generation and Distribution**

-   Official release process generates cryptographic hash (SHA-256) of LockSmith binaries

-   LockBox signs this hash with its private key to create verifiable signed hashes

-   Signed hashes are distributed to all LockBox-operated nodes through the secure internal update management system

-   Hash verification uses standard cryptographic libraries with tamper-resistant implementations

-   The verification process validates the entire binary, not just selected portions

**Dual-Party Verification**

-   Each official LockSmith software release is verified and signed by two parties:

    1.  LockBox administration (primary signature)

    2.  An independent security audit firm (secondary signature)

-   Both signatures are required for node software to be considered valid

-   This dual-signature approach prevents a single compromised entity from approving malicious software

-   The verification process includes comprehensive security audit before signing

-   The identity of the security firm is publicly disclosed to enhance transparency

**Software Update Mechanism**

-   New software versions add their hashes to the approved list via the dual-signature process

-   Older versions can be deprecated by removing their hashes from the approved list

-   Nodes regularly check for hash list updates through the internal update system

-   Update mechanism includes version transition periods to prevent network disruption

**Separation of Concerns for Token Accessibility**

-   Hash verification is limited to private key storage functions (LockSmith nodes)

-   Token transactions use standard blockchain protocols without additional verification

-   This separation ensures widespread token accessibility through existing wallets and exchanges

-   Exchange and third-party wallet integrations can use standard token APIs without custom verification

**Admin Signing Workflow**

As LockBox admin, the binary signing process includes:

1.  **Final Build Preparation**: Release candidate prepared in secure, isolated build environment

2.  **Hash Generation**: SHA-256 hash calculated for the complete binary

3.  **Admin Signing Process**:

    -   Admin private key (stored in offline, secure hardware device) used to sign the hash

    -   Ed25519 algorithm used for security and efficiency

4.  **Secondary Verification**: Release candidate and hash provided to security firm for verification and secondary signature

5.  **Release Package Creation**: Final package contains binary, hash, both signatures, and manifest file

6.  **Deployment**: Package deployed to LockBox-operated nodes via secure internal systems

7.  **Key Management**: Admin signing key secured in hardware security module, used only in air-gapped environment

This approach maintains the security and integrity of the LockBox private key storage network while ensuring the LockBox token can be freely traded through standard cryptocurrency infrastructure.
