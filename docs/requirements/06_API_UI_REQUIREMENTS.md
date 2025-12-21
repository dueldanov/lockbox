# LockBox Requirements - API & UI Requirements

## 7. API Requirements

### 7.1 Price API

#### 7.1.1 Endpoints

| Endpoint | Purpose |
|----------|---------|
| `/api/lockcoin/price` | Current price, supply, volume, market cap |
| `/api/lockcoin/market_chart` | OHLCV data with configurable intervals |

#### 7.1.2 Data Source

- LockBox DAG's internal liquidity pool and transaction activities
- No dependency on external exchanges

#### 7.1.3 Format

- JSON, compatible with CoinGecko/CoinMarketCap
- Standard fields for interoperability

#### 7.1.4 Security

- API keys for authentication
- Rate limits to prevent abuse
- TLS 1.3 for all connections

---

## 8. User Interface Requirements

### 8.1 Common Wallet UI Elements Across All Platforms

#### 8.1.1 Navigation Structure

| Tab | Description |
|-----|-------------|
| Home | Account overview and main actions |
| Swap | Trading interface |
| Activity | Transaction history |
| NFTs | Non-fungible token management |
| Settings | Account preferences and security |

#### 8.1.2 Core Functionality

- Portfolio value display
- Token list with balances
- Send/receive functionality
- Username display and management

---

### 8.2 Chrome Extension UI

#### 8.2.1 Constraints

- Limited screen space (popup interface)
- Focus on essential actions
- Basic and Standard tier features only

#### 8.2.2 Components

| Component | Description |
|-----------|-------------|
| Header | Compact with account selector |
| Token List | Streamlined display |
| Swap Interface | Simplified |
| Activity View | Limited history |
| Upgrade Prompt | For Premium/Elite tiers |

---

### 8.3 Desktop Application UI

#### 8.3.1 Features

- Full screen real estate
- Support for all tiers
- Advanced swap interface
- Comprehensive activity views
- Security center for Elite tier

#### 8.3.2 CLI Interface

- Command-line operations for all key functions
- Structured output formats
- Non-interactive mode for scripts

---

### 8.4 Mobile Application UI

#### 8.4.1 Design

- Touch-oriented interface
- Variable screen sizes
- On-the-go usage patterns
- Battery and data considerations

#### 8.4.2 Components

| Component | Description |
|-----------|-------------|
| Navigation | Bottom tab navigation |
| Authentication | Biometric integration |
| Swap Interface | Mobile-optimized |
| Notifications | Push notifications |
| Offline | Offline capabilities |
