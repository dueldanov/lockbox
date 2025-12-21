# LockBox Requirements - Token Economics & B2B Integration

## 6. Token Economics and B2B Integration

### 6.1 Token Economics

#### 6.1.1 Supply and Distribution

| Allocation | Amount |
|------------|--------|
| Fixed Total Supply | 1 billion tokens (no additional issuance) |
| Liquidity Pool at Launch | 100M tokens |
| Admin Reserve | 900M tokens |
| Minimum Pool Reserve | 1 token permanently |

#### 6.1.2 Fees and Incentives

**Private Key Retrieval Fees:**

| Tier | Fee Structure |
|------|--------------|
| Basic | $0.01 flat |
| Standard | $0.015 flat |
| Premium | $0.03 + $0.002 per $100K stored |
| Elite | $0.10 + $0.015 per $1M stored |

**Setup/Rotation Fees:**

| Tier | Setup Fee | Rotation Fee |
|------|-----------|--------------|
| Basic | $0 | $5 |
| Standard | $50 | $5 |
| Premium | $500 | $10 |
| Elite | $2,500 | $25 |

- **Discount:** 10% for LockBox token payments (admin adjustable 0-100%)

#### 6.1.3 Launch Promotion

- First 10,000 wallets receive 100 LockBox tokens each
- First three retrievals free for new wallets forever
- Promotional wallet funded with 1M tokens from admin reserve

#### 6.1.4 Admin Control

- Single Ed25519 keypair stored offline
- Optional multisig support configurable via ledger.go
- Can transfer additional tokens to pool as needed

---

### 6.1.5 Multi-Wallet Architecture

**Primary Wallet Types:**

| Wallet | Purpose |
|--------|---------|
| Admin Control Wallet | System governance, emergency functions, protocol upgrades. Stores no tokens. |
| Liquidity Management Wallet | Systematic distribution, pool management, compliance. Initially holds 900M tokens. |
| Promotional Wallet | Launch promotion rewards. Pre-funded with 1M tokens. |
| Treasury Wallet | Collects revenue from token sales and fees. Targets $50M USD in Phase 1. |

**Wallet Separation Requirements:**
- Each wallet type uses distinct Ed25519 keypairs with separate private key management
- All inter-wallet transfers recorded as distinct LedgerTx transactions on the SecureHornet DAG
- Wallet roles cannot overlap; no single wallet performs multiple operational functions
- All wallet addresses publicly verifiable on the DAG for transparency

**Security and Access Controls:**
- Admin Control Wallet: Offline cold storage, air-gapped environment for signing
- Liquidity Management Wallet: Multi-signature capability for compliance distribution phases
- Promotional Wallet: Automated distribution system with predefined limits
- Treasury Wallet: Real-time balance tracking for fundraising milestone verification

---

### 6.1.6 LockBox Token Trading Limits

**Per-Transaction Limits:**

| Limit Type | Default Value |
|------------|---------------|
| Buy Limit | $50,000 USD equivalent per transaction |
| Sell Limit | $50,000 USD equivalent per transaction |
| Launch Period Override | $10,000 USD equivalent for first 30 days |
| Elite Tier Exception | Up to $100,000 USD equivalent (configurable) |

**Timing and Cooling Periods:**
- Maximum Transaction Cooling Period: 1 hour minimum between max-limit transactions
- Daily Aggregate Limit: $200,000 USD combined buy/sell per 24-hour period per wallet
- Rolling Window: Limits calculated on rolling 24-hour basis, not calendar days

**Implementation Requirements:**
- Real-Time USD Conversion using Chainlink oracle pricing
- Wallet-Based Tracking (not IP address or device)
- Bridge Contract Enforcement at smart contract level
- Cross-Chain Coordination across all supported blockchains

**Pool Protection:**
- No single transaction may exceed 5% of current liquidity pool depth

---

### 6.1.7 Fair Launch Protocol

**Fair Launch Principles:**
- **No Private Sales**: Zero tokens allocated to private investors prior to public launch
- **No Pre-Mining**: All tokens exist in predefined allocations
- **Equal Access**: All participants access tokens through identical mechanism (liquidity pool)
- **Transparent Pricing**: All purchases subject to identical AMM pricing

**Launch Configuration:**
- Initial Liquidity Pool: 50M LockBox tokens at launch
- Only tokens in liquidity pool considered circulating supply
- Administrative Reserve: 950M tokens, not considered circulating until distributed
- Market Cap Calculation: Based exclusively on circulating supply

---

### 6.2 B2B gRPC API

#### 6.2.1 Methods

```protobuf
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
```

#### 6.2.2 Revenue Sharing

- 50% of retrieval fees shared with B2B providers (modified by referral program)
- Tracked via unique provider ID in ledger
- Daily batch payments in LockBox tokens
- Verifiable via GetRevenueShare API

#### 6.2.3 SDK Access

- Providers receive SDK access via private repository
- WASM binary for browser extensions
- Documentation for API endpoints
- Quarterly updates or critical fixes

---

### 6.2.4 Daily Payment Distribution

**Payment Schedule:**
- Daily Processing Cycle: All B2B partner payments processed at 00:01 UTC each day
- Earnings Calculation: Aggregates each partner's revenue from previous 24-hour period
- Payment Eligibility: Partners receive payments if earnings > 0. No minimum threshold.

**Technical Implementation:**
- Aggregation Process: Query ledger for all retrieval fees at 23:59 UTC
- Batch Transaction Execution: Single transaction at 00:01 UTC
- Confirmation: Partner dashboards updated by 00:05 UTC

**Error Handling:**
- Failed Payments: Retry once at 01:00 UTC
- Persistent Failures: Queued for manual administrative review
- Recovery: Failed payments included in next successful cycle

---

### 6.2.5 Dual Referral Program Implementation

#### Reserved Username System

- **Corporate Username**: @LockBox is permanently reserved and hardcoded
- **Implementation**: Cannot be registered by users
- **Purpose**: Corporate identity protection

#### Referral Link Structure

- **Universal Format**: `www.LockBox.io/@username`
- **Requirement**: Referrers must have registered LockBox username
- **Tracking**: Username in URL automatically associates referrals
- **Permanent Association**: First-click priority, never expires

---

#### Program 1: Token Purchase Referral Program

| Setting | Default Value |
|---------|---------------|
| Commission Rate | 10% of token purchase value |
| Payment Source | LockBox treasury address |
| Payment Method | Immediate, in LockBox tokens |
| Program Cap | Active until $50M USD purchased |

**Cap Implementation:**
- Final purchase gets full commission even if exceeds cap
- Post-cap: No new referrals generate commissions

---

#### Program 2: B2B Partner Referral Program

**Revenue Distribution (with referrer):**

| Recipient | Share |
|-----------|-------|
| B2B Partner | 50% |
| Referrer | 10% |
| LockBox | 40% |

**Without Referrer:**

| Recipient | Share |
|-----------|-------|
| B2B Partner | 50% |
| LockBox | 50% |

- Payment Duration: Forever (no time limits)
- Payment Schedule: Daily, integrated with B2B Revenue Sharing system

---

### 6.3 Username Registry

#### 6.3.1 Structure

```go
type UsernameEntry struct {
    Username    string   // e.g., "LockBox@alice"
    OwnerPubkey [32]byte // Ed25519 public key
    Privacy     string   // "Public" or "Private"
    Verified    bool     // For future premium features
    Timestamp   int64    // UnixNano
    TxHash      string   // TransactionID
}
```

#### 6.3.2 Privacy Settings

- **Public**: Openly resolvable by any wallet or B2B provider
- **Private**: Encrypted with key derived from owner's master key

#### 6.3.3 Registration Rules

- First-come-first-serve basis for unique usernames
- Requires at least three future node approvals
- Conflicts resolved by timestamp priority
