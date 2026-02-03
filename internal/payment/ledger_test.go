package payment

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestValidatedMockLedgerVerifier_AmountValidation(t *testing.T) {
	ctx := context.Background()
	verifier := NewValidatedMockLedgerVerifier()

	// Add payment to mock ledger (paymentToken → txID mapping)
	verifier.AddPayment("payment-token-123", LedgerPayment{
		TxID:      "tx-123",
		AssetID:   "asset-1",
		AmountUSD: 15.00,
		Currency:  CurrencyUSD,
		Timestamp: time.Now(),
		Confirmed: true,
	})

	// Test 1: Valid verification - amount matches
	txID, err := verifier.VerifyPayment(ctx, "payment-token-123", 15.00, CurrencyUSD)
	require.NoError(t, err)
	require.Equal(t, "tx-123", txID)

	// Test 2: Wrong amount - MUST FAIL
	txID, err = verifier.VerifyPayment(ctx, "payment-token-123", 10.00, CurrencyUSD)
	require.Error(t, err)
	require.Contains(t, err.Error(), "amount mismatch")
	require.Empty(t, txID)

	// Test 3: Wrong currency - MUST FAIL
	txID, err = verifier.VerifyPayment(ctx, "payment-token-123", 15.00, CurrencyXSD)
	require.Error(t, err)
	require.Contains(t, err.Error(), "currency mismatch")
	require.Empty(t, txID)
}

func TestValidatedMockLedgerVerifier_FloatingPointTolerance(t *testing.T) {
	ctx := context.Background()
	verifier := NewValidatedMockLedgerVerifier()

	// Add payment with floating point amount
	verifier.AddPayment("payment-token-456", LedgerPayment{
		TxID:      "tx-456",
		AssetID:   "asset-2",
		AmountUSD: 15.003,
		Currency:  CurrencyUSD,
		Timestamp: time.Now(),
		Confirmed: true,
	})

	// Test: Amount within 0.01 tolerance should pass
	txID, err := verifier.VerifyPayment(ctx, "payment-token-456", 15.00, CurrencyUSD)
	require.NoError(t, err)
	require.Equal(t, "tx-456", txID)

	// Test: Amount outside 0.01 tolerance should fail
	txID, err = verifier.VerifyPayment(ctx, "payment-token-456", 14.00, CurrencyUSD)
	require.Error(t, err)
	require.Contains(t, err.Error(), "amount mismatch")
	require.Empty(t, txID)
}

func TestValidatedMockLedgerVerifier_ConfirmedStatus(t *testing.T) {
	ctx := context.Background()
	verifier := NewValidatedMockLedgerVerifier()

	// Add UNCONFIRMED payment
	verifier.AddPayment("payment-token-789", LedgerPayment{
		TxID:      "tx-789",
		AssetID:   "asset-3",
		AmountUSD: 20.00,
		Currency:  CurrencyLOCK,
		Timestamp: time.Now(),
		Confirmed: false, // NOT CONFIRMED
	})

	// Test: Unconfirmed payment MUST FAIL
	txID, err := verifier.VerifyPayment(ctx, "payment-token-789", 20.00, CurrencyLOCK)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not confirmed")
	require.Empty(t, txID)
}

func TestValidatedMockLedgerVerifier_PaymentNotFound(t *testing.T) {
	ctx := context.Background()
	verifier := NewValidatedMockLedgerVerifier()

	// Don't add any payments

	// Test: Non-existent payment MUST FAIL
	txID, err := verifier.VerifyPayment(ctx, "payment-token-999", 10.00, CurrencyUSD)
	require.Error(t, err)
	require.Equal(t, ErrPaymentNotFound, err)
	require.Empty(t, txID)
}

func TestValidatedMockLedgerVerifier_MultipleCurrencies(t *testing.T) {
	ctx := context.Background()
	verifier := NewValidatedMockLedgerVerifier()

	// Add payments in different currencies
	verifier.AddPayment("token-usd", LedgerPayment{
		TxID:      "tx-usd",
		AssetID:   "asset-usd",
		AmountUSD: 10.00,
		Currency:  CurrencyUSD,
		Timestamp: time.Now(),
		Confirmed: true,
	})

	verifier.AddPayment("token-lock", LedgerPayment{
		TxID:      "tx-lock",
		AssetID:   "asset-lock",
		AmountUSD: 9.00, // 10% discount for LOCK
		Currency:  CurrencyLOCK,
		Timestamp: time.Now(),
		Confirmed: true,
	})

	verifier.AddPayment("token-xsd", LedgerPayment{
		TxID:      "tx-xsd",
		AssetID:   "asset-xsd",
		AmountUSD: 15.00,
		Currency:  CurrencyXSD,
		Timestamp: time.Now(),
		Confirmed: true,
	})

	// Test: Verify USD payment
	txID, err := verifier.VerifyPayment(ctx, "token-usd", 10.00, CurrencyUSD)
	require.NoError(t, err)
	require.Equal(t, "tx-usd", txID)

	// Test: Verify LOCK payment
	txID, err = verifier.VerifyPayment(ctx, "token-lock", 9.00, CurrencyLOCK)
	require.NoError(t, err)
	require.Equal(t, "tx-lock", txID)

	// Test: Verify XSD payment
	txID, err = verifier.VerifyPayment(ctx, "token-xsd", 15.00, CurrencyXSD)
	require.NoError(t, err)
	require.Equal(t, "tx-xsd", txID)
}

func TestValidatedMockLedgerVerifier_ThreadSafety(t *testing.T) {
	ctx := context.Background()
	verifier := NewValidatedMockLedgerVerifier()

	// Add initial payment
	verifier.AddPayment("token-concurrent", LedgerPayment{
		TxID:      "tx-concurrent",
		AssetID:   "asset-concurrent",
		AmountUSD: 25.00,
		Currency:  CurrencyUSD,
		Timestamp: time.Now(),
		Confirmed: true,
	})

	// Test concurrent reads and writes
	done := make(chan bool)

	// Concurrent readers - reading the same payment
	for i := 0; i < 10; i++ {
		go func() {
			_, err := verifier.VerifyPayment(ctx, "token-concurrent", 25.00, CurrencyUSD)
			require.NoError(t, err)
			done <- true
		}()
	}

	// Concurrent writers - adding DIFFERENT payments (not overwriting)
	for i := 0; i < 5; i++ {
		go func(idx int) {
			token := fmt.Sprintf("token-%d", idx)
			verifier.AddPayment(token, LedgerPayment{
				TxID:      txID(idx),
				AssetID:   assetID(idx),
				AmountUSD: 30.00,
				Currency:  CurrencyUSD,
				Timestamp: time.Now(),
				Confirmed: true,
			})
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 15; i++ {
		<-done
	}

	// No panics = success
}

// Helper functions
func txID(idx int) string {
	return fmt.Sprintf("tx-%d", idx)
}

func assetID(idx int) string {
	return fmt.Sprintf("asset-%d", idx)
}
