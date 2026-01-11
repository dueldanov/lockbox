# Module: payment

## Purpose

Fee calculation and payment processing for LockBox.

Implements the fee structure from requirements (Section 6.1.2).

## Files

| File | Description |
|------|-------------|
| `fee_calculator.go` | Tier-based fee calculation |
| `processor.go` | Payment creation, verification, single-use enforcement |
| `*_test.go` | Tests (28 tests, all passing) |

## Fee Structure

### Retrieval Fees

| Tier | Fee |
|------|-----|
| Basic | $0.01 flat |
| Standard | $0.015 flat |
| Premium | $0.03 + $0.002 per $100K stored |
| Elite | $0.10 + $0.015 per $1M stored |

### Setup Fees (One-time)

| Tier | Fee |
|------|-----|
| Basic | Free |
| Standard | $50 |
| Premium | $500 |
| Elite | $2,500 |

### Key Rotation Fees

| Tier | Fee |
|------|-----|
| Basic | $5 |
| Standard | $5 |
| Premium | $10 |
| Elite | $25 |

### Token Discount

10% discount for payments in LOCK token.

## Usage

### Fee Calculator

```go
// Create calculator
calc := payment.NewFeeCalculator()

// Calculate retrieval fee
result, err := calc.CalculateRetrievalFee(
    interfaces.TierStandard,
    0,                    // stored value (for Premium/Elite)
    payment.CurrencyUSD,  // or CurrencyLOCK for 10% discount
)
// result.FinalFeeUSD = 0.015

// Calculate with token discount
resultLock, _ := calc.CalculateRetrievalFee(
    interfaces.TierStandard,
    0,
    payment.CurrencyLOCK,
)
// resultLock.FinalFeeUSD = 0.0135 (10% discount)

// Get all fees for a tier
allFees := calc.GetAllFees(interfaces.TierPremium, 500000)
```

### Payment Processor

```go
// Create processor (nil = mock mode)
processor := payment.NewPaymentProcessor(nil)

// 1. Create payment for unlock request
createResp, err := processor.CreatePayment(ctx, payment.CreatePaymentRequest{
    AssetID:  assetID,
    Tier:     interfaces.TierStandard,
    FeeType:  payment.FeeTypeRetrieval,
    Currency: payment.CurrencyUSD,
})
// createResp.PaymentToken - single-use token (expires in 15 min)
// createResp.AmountUSD - required amount

// 2. User makes payment on ledger...

// 3. Confirm payment (when ledger confirms)
err = processor.ConfirmPayment(ctx, createResp.PaymentToken, "tx123")

// 4. Verify payment before unlock
verifyResp, err := processor.VerifyPayment(ctx, payment.VerifyPaymentRequest{
    PaymentToken: createResp.PaymentToken,
    AssetID:      assetID,
})
if !verifyResp.Valid {
    return errors.New(verifyResp.Error)
}

// 5. Mark payment as used after successful unlock
err = processor.MarkPaymentUsed(ctx, createResp.PaymentToken)
```

## Payment Flow

```
┌─────────────┐     ┌────────────────┐     ┌──────────────┐
│   Client    │────▶│ CreatePayment  │────▶│   Payment    │
│             │     │                │     │   Token      │
└─────────────┘     └────────────────┘     └──────────────┘
       │                                          │
       │         Pay on ledger                    │
       ▼                                          ▼
┌─────────────┐     ┌────────────────┐     ┌──────────────┐
│   Ledger    │────▶│ ConfirmPayment │────▶│  Confirmed   │
│             │     │                │     │              │
└─────────────┘     └────────────────┘     └──────────────┘
                                                  │
                                                  ▼
┌─────────────┐     ┌────────────────┐     ┌──────────────┐
│   Unlock    │◀────│ VerifyPayment  │◀────│   Valid      │
│   Request   │     │                │     │              │
└─────────────┘     └────────────────┘     └──────────────┘
       │
       ▼
┌─────────────┐     ┌────────────────┐     ┌──────────────┐
│   Success   │────▶│ MarkPaymentUsed│────▶│    Used      │
│             │     │                │     │  (Single-use)│
└─────────────┘     └────────────────┘     └──────────────┘
```

## Payment States

| Status | Description |
|--------|-------------|
| `pending` | Created, waiting for ledger confirmation |
| `confirmed` | Payment confirmed on ledger |
| `used` | Payment used for unlock (single-use) |
| `expired` | Token expired before use (15 min) |
| `failed` | Payment verification failed |

## Security

- **Single-use tokens**: Each payment token can only be used once
- **Asset binding**: Token is bound to specific asset ID
- **Time-limited**: Tokens expire after 15 minutes
- **Replay protection**: Used tokens are marked and rejected

## Dependencies

- **From:** `interfaces` (Tier)
- **Used by:** `service` (UnlockAsset)

## Tests

```bash
go test ./internal/payment/... -v  # 28 tests
```

## TODO

- [ ] LOCK/USD price oracle integration
- [x] Payment processor (verify actual payment)
- [ ] Integration with UnlockAsset
- [ ] Persistent payment storage (currently in-memory)
