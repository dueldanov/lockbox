package payment

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dueldanov/lockbox/v2/internal/interfaces"
)

func TestPaymentProcessor_CreatePayment(t *testing.T) {
	processor := NewPaymentProcessor(nil)
	ctx := context.Background()

	resp, err := processor.CreatePayment(ctx, CreatePaymentRequest{
		AssetID:  "asset123",
		Tier:     interfaces.TierStandard,
		FeeType:  FeeTypeRetrieval,
		Currency: CurrencyUSD,
	})
	require.NoError(t, err)

	assert.NotEmpty(t, resp.PaymentID)
	assert.NotEmpty(t, resp.PaymentToken)
	assert.Equal(t, 0.015, resp.AmountUSD) // Standard retrieval fee
	assert.Equal(t, CurrencyUSD, resp.Currency)
	assert.True(t, resp.ExpiresAt.After(time.Now()))
	assert.NotEmpty(t, resp.Breakdown)
}

func TestPaymentProcessor_CreatePayment_WithTokenDiscount(t *testing.T) {
	processor := NewPaymentProcessor(nil)
	ctx := context.Background()

	resp, err := processor.CreatePayment(ctx, CreatePaymentRequest{
		AssetID:  "asset123",
		Tier:     interfaces.TierStandard,
		FeeType:  FeeTypeRetrieval,
		Currency: CurrencyLOCK,
	})
	require.NoError(t, err)

	// $0.015 with 10% discount = $0.0135
	assert.InDelta(t, 0.0135, resp.AmountUSD, 0.0001)
	assert.Equal(t, CurrencyLOCK, resp.Currency)
}

func TestPaymentProcessor_VerifyPayment_Valid(t *testing.T) {
	processor := NewPaymentProcessor(nil)
	ctx := context.Background()

	// Create payment
	createResp, err := processor.CreatePayment(ctx, CreatePaymentRequest{
		AssetID:  "asset123",
		Tier:     interfaces.TierStandard,
		FeeType:  FeeTypeRetrieval,
		Currency: CurrencyUSD,
	})
	require.NoError(t, err)

	// Confirm payment (simulate ledger confirmation)
	err = processor.ConfirmPayment(ctx, createResp.PaymentToken, "tx123")
	require.NoError(t, err)

	// Verify payment
	verifyResp, err := processor.VerifyPayment(ctx, VerifyPaymentRequest{
		PaymentToken: createResp.PaymentToken,
		AssetID:      "asset123",
	})
	require.NoError(t, err)

	assert.True(t, verifyResp.Valid)
	assert.Equal(t, createResp.PaymentID, verifyResp.PaymentID)
	assert.Equal(t, 0.015, verifyResp.AmountUSD)
}

func TestPaymentProcessor_VerifyPayment_NotConfirmed(t *testing.T) {
	processor := NewPaymentProcessor(nil)
	ctx := context.Background()

	// Create payment but don't confirm
	createResp, err := processor.CreatePayment(ctx, CreatePaymentRequest{
		AssetID:  "asset123",
		Tier:     interfaces.TierStandard,
		FeeType:  FeeTypeRetrieval,
		Currency: CurrencyUSD,
	})
	require.NoError(t, err)

	// Verify payment (should fail - not confirmed)
	verifyResp, err := processor.VerifyPayment(ctx, VerifyPaymentRequest{
		PaymentToken: createResp.PaymentToken,
		AssetID:      "asset123",
	})
	require.NoError(t, err)

	assert.False(t, verifyResp.Valid)
	assert.Contains(t, verifyResp.Error, "not confirmed")
}

func TestPaymentProcessor_VerifyPayment_WrongAsset(t *testing.T) {
	processor := NewPaymentProcessor(nil)
	ctx := context.Background()

	// Create payment for asset123
	createResp, err := processor.CreatePayment(ctx, CreatePaymentRequest{
		AssetID:  "asset123",
		Tier:     interfaces.TierStandard,
		FeeType:  FeeTypeRetrieval,
		Currency: CurrencyUSD,
	})
	require.NoError(t, err)

	err = processor.ConfirmPayment(ctx, createResp.PaymentToken, "tx123")
	require.NoError(t, err)

	// Try to verify for different asset
	verifyResp, err := processor.VerifyPayment(ctx, VerifyPaymentRequest{
		PaymentToken: createResp.PaymentToken,
		AssetID:      "different_asset",
	})
	require.NoError(t, err)

	assert.False(t, verifyResp.Valid)
	assert.Contains(t, verifyResp.Error, "not valid for this asset")
}

func TestPaymentProcessor_VerifyPayment_TokenNotFound(t *testing.T) {
	processor := NewPaymentProcessor(nil)
	ctx := context.Background()

	verifyResp, err := processor.VerifyPayment(ctx, VerifyPaymentRequest{
		PaymentToken: "invalid_token",
		AssetID:      "asset123",
	})
	require.NoError(t, err)

	assert.False(t, verifyResp.Valid)
	assert.Contains(t, verifyResp.Error, "not found")
}

func TestPaymentProcessor_MarkPaymentUsed(t *testing.T) {
	processor := NewPaymentProcessor(nil)
	ctx := context.Background()

	// Create and confirm payment
	createResp, err := processor.CreatePayment(ctx, CreatePaymentRequest{
		AssetID:  "asset123",
		Tier:     interfaces.TierStandard,
		FeeType:  FeeTypeRetrieval,
		Currency: CurrencyUSD,
	})
	require.NoError(t, err)

	err = processor.ConfirmPayment(ctx, createResp.PaymentToken, "tx123")
	require.NoError(t, err)

	// Mark as used
	err = processor.MarkPaymentUsed(ctx, createResp.PaymentToken)
	require.NoError(t, err)

	// Verify it's now marked as used
	payment, err := processor.GetPayment(ctx, createResp.PaymentID)
	require.NoError(t, err)
	assert.Equal(t, PaymentStatusUsed, payment.Status)
	assert.NotNil(t, payment.UsedAt)
}

func TestPaymentProcessor_MarkPaymentUsed_SingleUse(t *testing.T) {
	processor := NewPaymentProcessor(nil)
	ctx := context.Background()

	// Create and confirm payment
	createResp, err := processor.CreatePayment(ctx, CreatePaymentRequest{
		AssetID:  "asset123",
		Tier:     interfaces.TierStandard,
		FeeType:  FeeTypeRetrieval,
		Currency: CurrencyUSD,
	})
	require.NoError(t, err)

	err = processor.ConfirmPayment(ctx, createResp.PaymentToken, "tx123")
	require.NoError(t, err)

	// Mark as used first time - success
	err = processor.MarkPaymentUsed(ctx, createResp.PaymentToken)
	require.NoError(t, err)

	// Try to mark as used again - should fail
	err = processor.MarkPaymentUsed(ctx, createResp.PaymentToken)
	require.Error(t, err)
	assert.Equal(t, ErrPaymentAlreadyUsed, err)
}

func TestPaymentProcessor_VerifyPayment_AlreadyUsed(t *testing.T) {
	processor := NewPaymentProcessor(nil)
	ctx := context.Background()

	// Create and confirm payment
	createResp, err := processor.CreatePayment(ctx, CreatePaymentRequest{
		AssetID:  "asset123",
		Tier:     interfaces.TierStandard,
		FeeType:  FeeTypeRetrieval,
		Currency: CurrencyUSD,
	})
	require.NoError(t, err)

	err = processor.ConfirmPayment(ctx, createResp.PaymentToken, "tx123")
	require.NoError(t, err)

	// Mark as used
	err = processor.MarkPaymentUsed(ctx, createResp.PaymentToken)
	require.NoError(t, err)

	// Try to verify again - should fail
	verifyResp, err := processor.VerifyPayment(ctx, VerifyPaymentRequest{
		PaymentToken: createResp.PaymentToken,
		AssetID:      "asset123",
	})
	require.NoError(t, err)

	assert.False(t, verifyResp.Valid)
	assert.Contains(t, verifyResp.Error, "already used")
}

func TestPaymentProcessor_GetPaymentByToken(t *testing.T) {
	processor := NewPaymentProcessor(nil)
	ctx := context.Background()

	createResp, err := processor.CreatePayment(ctx, CreatePaymentRequest{
		AssetID:  "asset123",
		Tier:     interfaces.TierStandard,
		FeeType:  FeeTypeRetrieval,
		Currency: CurrencyUSD,
	})
	require.NoError(t, err)

	payment, err := processor.GetPaymentByToken(ctx, createResp.PaymentToken)
	require.NoError(t, err)

	assert.Equal(t, createResp.PaymentID, payment.ID)
	assert.Equal(t, "asset123", payment.AssetID)
}

func TestPaymentProcessor_GetPaymentByToken_NotFound(t *testing.T) {
	processor := NewPaymentProcessor(nil)
	ctx := context.Background()

	_, err := processor.GetPaymentByToken(ctx, "invalid_token")
	require.Error(t, err)
	assert.Equal(t, ErrPaymentNotFound, err)
}

func TestPayment_IsValid(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name    string
		payment Payment
		wantErr error
	}{
		{
			name: "valid confirmed payment",
			payment: Payment{
				Status:    PaymentStatusConfirmed,
				ExpiresAt: now.Add(10 * time.Minute),
			},
			wantErr: nil,
		},
		{
			name: "already used",
			payment: Payment{
				Status:    PaymentStatusUsed,
				ExpiresAt: now.Add(10 * time.Minute),
			},
			wantErr: ErrPaymentAlreadyUsed,
		},
		{
			name: "expired status",
			payment: Payment{
				Status:    PaymentStatusExpired,
				ExpiresAt: now.Add(-10 * time.Minute),
			},
			wantErr: ErrPaymentExpired,
		},
		{
			name: "expired by time",
			payment: Payment{
				Status:    PaymentStatusConfirmed,
				ExpiresAt: now.Add(-1 * time.Minute),
			},
			wantErr: ErrPaymentExpired,
		},
		{
			name: "pending (not confirmed)",
			payment: Payment{
				Status:    PaymentStatusPending,
				ExpiresAt: now.Add(10 * time.Minute),
			},
			wantErr: nil, // Returns error but not one of our defined errors
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.payment.IsValid()
			if tc.wantErr != nil {
				require.Error(t, err)
				assert.Equal(t, tc.wantErr, err)
			} else if tc.name == "pending (not confirmed)" {
				// Pending should return an error
				require.Error(t, err)
				assert.Contains(t, err.Error(), "not confirmed")
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestMockLedgerVerifier(t *testing.T) {
	ctx := context.Background()

	verifier := &MockLedgerVerifier{
		Payments: map[string]string{
			"token123": "tx_abc",
		},
	}

	// Found
	txID, err := verifier.VerifyPayment(ctx, "token123", 0.015, CurrencyUSD)
	require.NoError(t, err)
	assert.Equal(t, "tx_abc", txID)

	// Not found
	_, err = verifier.VerifyPayment(ctx, "invalid", 0.015, CurrencyUSD)
	require.Error(t, err)
	assert.Equal(t, ErrPaymentNotFound, err)
}

func TestPaymentProcessor_ConfirmPayment_AlreadyProcessed(t *testing.T) {
	processor := NewPaymentProcessor(nil)
	ctx := context.Background()

	createResp, err := processor.CreatePayment(ctx, CreatePaymentRequest{
		AssetID:  "asset123",
		Tier:     interfaces.TierStandard,
		FeeType:  FeeTypeRetrieval,
		Currency: CurrencyUSD,
	})
	require.NoError(t, err)

	// Confirm first time
	err = processor.ConfirmPayment(ctx, createResp.PaymentToken, "tx123")
	require.NoError(t, err)

	// Try to confirm again
	err = processor.ConfirmPayment(ctx, createResp.PaymentToken, "tx456")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already processed")
}
