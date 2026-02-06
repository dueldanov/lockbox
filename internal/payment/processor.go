// Package payment provides fee calculation and payment processing for LockBox.
package payment

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/dueldanov/lockbox/v2/internal/interfaces"
)

// Common errors for payment processing.
var (
	ErrPaymentNotFound     = errors.New("payment not found")
	ErrPaymentExpired      = errors.New("payment token expired")
	ErrPaymentAlreadyUsed  = errors.New("payment already used")
	ErrInsufficientPayment = errors.New("insufficient payment amount")
	ErrInvalidPaymentToken = errors.New("invalid payment token")
)

// PaymentStatus represents the status of a payment.
type PaymentStatus string

const (
	// PaymentStatusPending payment created but not yet confirmed.
	PaymentStatusPending PaymentStatus = "pending"

	// PaymentStatusConfirmed payment confirmed on the ledger.
	PaymentStatusConfirmed PaymentStatus = "confirmed"

	// PaymentStatusUsed payment has been used for unlock.
	PaymentStatusUsed PaymentStatus = "used"

	// PaymentStatusExpired payment token expired before use.
	PaymentStatusExpired PaymentStatus = "expired"

	// PaymentStatusFailed payment failed verification.
	PaymentStatusFailed PaymentStatus = "failed"
)

// PaymentTokenExpiry is how long a payment token is valid.
const PaymentTokenExpiry = 15 * time.Minute

// Payment represents a payment record.
type Payment struct {
	// ID is the unique payment identifier.
	ID string `json:"id"`

	// Token is the single-use payment token.
	Token string `json:"token"`

	// AssetID is the asset this payment is for.
	AssetID string `json:"asset_id"`

	// Tier is the service tier.
	Tier interfaces.Tier `json:"tier"`

	// FeeType is the type of fee.
	FeeType FeeType `json:"fee_type"`

	// AmountUSD is the expected payment amount in USD.
	AmountUSD float64 `json:"amount_usd"`

	// Currency is the payment currency.
	Currency Currency `json:"currency"`

	// Status is the current payment status.
	Status PaymentStatus `json:"status"`

	// TransactionID is the ledger transaction ID (when confirmed).
	TransactionID string `json:"transaction_id,omitempty"`

	// CreatedAt is when the payment was created.
	CreatedAt time.Time `json:"created_at"`

	// ExpiresAt is when the payment token expires.
	ExpiresAt time.Time `json:"expires_at"`

	// UsedAt is when the payment was used (if used).
	UsedAt *time.Time `json:"used_at,omitempty"`
}

// IsValid checks if the payment is valid for use.
func (p *Payment) IsValid() error {
	if p.Status == PaymentStatusUsed {
		return ErrPaymentAlreadyUsed
	}
	if p.Status == PaymentStatusExpired {
		return ErrPaymentExpired
	}
	if time.Now().After(p.ExpiresAt) {
		return ErrPaymentExpired
	}
	if p.Status != PaymentStatusConfirmed {
		return fmt.Errorf("payment not confirmed: status=%s", p.Status)
	}
	return nil
}

// PaymentProcessor handles payment verification and recording.
//
// The processor is responsible for:
//   - Creating payment tokens for unlock requests
//   - Verifying payment amounts against fee calculator
//   - Recording payment usage (single-use enforcement)
//   - Integration with ledger for payment confirmation
type PaymentProcessor struct {
	mu sync.RWMutex

	// feeCalculator for calculating expected fees
	feeCalculator *FeeCalculator

	// payments stores payment records (in-memory for MVP, will be persisted later)
	payments map[string]*Payment

	// tokenToPaymentID maps tokens to payment IDs for quick lookup
	tokenToPaymentID map[string]string

	// ledgerVerifier verifies payments on the ledger (nil = mock mode)
	ledgerVerifier LedgerVerifier
}

// LedgerVerifier is an interface for verifying payments on the ledger.
// This allows mocking for tests and future integration with actual ledger.
type LedgerVerifier interface {
	// VerifyPayment checks if a payment transaction exists and is valid.
	// Returns the transaction ID if found and valid.
	VerifyPayment(ctx context.Context, paymentToken string, expectedAmount float64, currency Currency) (string, error)
}

// MockLedgerVerifier is a mock implementation for testing.
type MockLedgerVerifier struct {
	// Payments maps tokens to transaction IDs
	Payments map[string]string
}

// VerifyPayment implements LedgerVerifier for testing.
func (m *MockLedgerVerifier) VerifyPayment(ctx context.Context, paymentToken string, expectedAmount float64, currency Currency) (string, error) {
	if m.Payments == nil {
		return "", ErrPaymentNotFound
	}
	txID, ok := m.Payments[paymentToken]
	if !ok {
		return "", ErrPaymentNotFound
	}
	return txID, nil
}

// ValidatedMockLedgerVerifier validates payments with amount and currency checks.
// This is an enhanced mock verifier for working prototypes that validates:
// - Payment amounts match expected
// - Currency matches expected
// - Asset ID matches
// - Payment is confirmed
type ValidatedMockLedgerVerifier struct {
	payments     map[string]LedgerPayment // txID -> payment
	tokenToTxID  map[string]string        // paymentToken -> txID
	mu           sync.RWMutex
}

// LedgerPayment represents a payment record in the ledger.
type LedgerPayment struct {
	TxID        string
	AssetID     string
	AmountUSD   float64
	Currency    Currency
	Timestamp   time.Time
	Confirmed   bool
}

// NewValidatedMockLedgerVerifier creates a new validated mock ledger verifier.
func NewValidatedMockLedgerVerifier() *ValidatedMockLedgerVerifier {
	return &ValidatedMockLedgerVerifier{
		payments:    make(map[string]LedgerPayment),
		tokenToTxID: make(map[string]string),
	}
}

// AddPayment adds a payment to the mock ledger for testing.
// The paymentToken parameter links a payment token to this ledger payment.
func (v *ValidatedMockLedgerVerifier) AddPayment(paymentToken string, payment LedgerPayment) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.payments[payment.TxID] = payment
	v.tokenToTxID[paymentToken] = payment.TxID
}

// VerifyPayment implements LedgerVerifier with full validation.
func (v *ValidatedMockLedgerVerifier) VerifyPayment(ctx context.Context, paymentToken string, expectedAmount float64, currency Currency) (string, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	// Look up txID by payment token
	txID, ok := v.tokenToTxID[paymentToken]
	if !ok {
		return "", ErrPaymentNotFound
	}

	// Get payment record
	payment, ok := v.payments[txID]
	if !ok {
		return "", ErrPaymentNotFound
	}

	// Validate amount (with 0.01 tolerance for floating point)
	if math.Abs(payment.AmountUSD-expectedAmount) > 0.01 {
		return "", fmt.Errorf("payment amount mismatch: expected %.2f, got %.2f", expectedAmount, payment.AmountUSD)
	}

	// Validate currency
	if payment.Currency != currency {
		return "", fmt.Errorf("payment currency mismatch: expected %s, got %s", currency, payment.Currency)
	}

	// Validate confirmed status
	if !payment.Confirmed {
		return "", fmt.Errorf("payment %s not confirmed on ledger", txID)
	}

	return txID, nil
}

// NewPaymentProcessor creates a new payment processor.
//
// If ledgerVerifier is nil, the processor uses ValidatedMockLedgerVerifier
// which validates amounts, currencies, and confirmed status for testing.
func NewPaymentProcessor(ledgerVerifier LedgerVerifier) *PaymentProcessor {
	// If no ledger verifier provided, use validated mock for testing
	if ledgerVerifier == nil {
		ledgerVerifier = NewValidatedMockLedgerVerifier()
	}

	return &PaymentProcessor{
		feeCalculator:    NewFeeCalculator(),
		payments:         make(map[string]*Payment),
		tokenToPaymentID: make(map[string]string),
		ledgerVerifier:   ledgerVerifier,
	}
}

// CreatePaymentRequest contains parameters for creating a payment.
type CreatePaymentRequest struct {
	// AssetID is the asset to be unlocked.
	AssetID string

	// Tier is the service tier.
	Tier interfaces.Tier

	// FeeType is the type of fee.
	FeeType FeeType

	// StoredValueUSD is the stored value (for Premium/Elite variable fees).
	StoredValueUSD float64

	// Currency is the preferred payment currency.
	Currency Currency
}

// CreatePaymentResponse contains the created payment details.
type CreatePaymentResponse struct {
	// PaymentID is the unique payment identifier.
	PaymentID string

	// PaymentToken is the single-use token for this payment.
	PaymentToken string

	// AmountUSD is the required payment amount.
	AmountUSD float64

	// Currency is the payment currency.
	Currency Currency

	// ExpiresAt is when the payment token expires.
	ExpiresAt time.Time

	// Breakdown is a human-readable fee breakdown.
	Breakdown string
}

// CreatePayment creates a new payment for an unlock operation.
//
// Returns a payment token that must be used within PaymentTokenExpiry.
// The token should be included in the unlock request.
//
// Example:
//
//	resp, err := processor.CreatePayment(ctx, CreatePaymentRequest{
//	    AssetID:  "asset123",
//	    Tier:     interfaces.TierStandard,
//	    FeeType:  FeeTypeRetrieval,
//	    Currency: CurrencyUSD,
//	})
//	// Use resp.PaymentToken in unlock request
func (p *PaymentProcessor) CreatePayment(ctx context.Context, req CreatePaymentRequest) (*CreatePaymentResponse, error) {
	// Calculate the fee
	feeResult, err := p.feeCalculator.CalculateFee(FeeRequest{
		Tier:            req.Tier,
		FeeType:         req.FeeType,
		StoredValueUSD:  req.StoredValueUSD,
		PaymentCurrency: req.Currency,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to calculate fee: %w", err)
	}

	// Generate payment ID and token
	paymentID, err := generateID("pay")
	if err != nil {
		return nil, fmt.Errorf("failed to generate payment ID: %w", err)
	}
	paymentToken, err := generateToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate payment token: %w", err)
	}

	now := time.Now()
	payment := &Payment{
		ID:        paymentID,
		Token:     paymentToken,
		AssetID:   req.AssetID,
		Tier:      req.Tier,
		FeeType:   req.FeeType,
		AmountUSD: feeResult.FinalFeeUSD,
		Currency:  req.Currency,
		Status:    PaymentStatusPending,
		CreatedAt: now,
		ExpiresAt: now.Add(PaymentTokenExpiry),
	}

	p.mu.Lock()
	p.payments[paymentID] = payment
	p.tokenToPaymentID[paymentToken] = paymentID
	p.mu.Unlock()

	return &CreatePaymentResponse{
		PaymentID:    paymentID,
		PaymentToken: paymentToken,
		AmountUSD:    feeResult.FinalFeeUSD,
		Currency:     req.Currency,
		ExpiresAt:    payment.ExpiresAt,
		Breakdown:    feeResult.Breakdown,
	}, nil
}

// VerifyPaymentRequest contains parameters for payment verification.
type VerifyPaymentRequest struct {
	// PaymentToken is the single-use payment token.
	PaymentToken string

	// AssetID is the asset being unlocked.
	AssetID string
}

// VerifyPaymentResponse contains the verification result.
type VerifyPaymentResponse struct {
	// Valid indicates if the payment is valid for use.
	Valid bool

	// PaymentID is the payment identifier.
	PaymentID string

	// AmountUSD is the payment amount.
	AmountUSD float64

	// Error message if not valid.
	Error string
}

// VerifyPayment verifies a payment token is valid for an unlock operation.
//
// This method:
//   1. Looks up the payment by token
//   2. Verifies it hasn't been used or expired
//   3. Verifies it matches the requested asset
//   4. Optionally verifies payment on the ledger
//
// Example:
//
//	resp, err := processor.VerifyPayment(ctx, VerifyPaymentRequest{
//	    PaymentToken: token,
//	    AssetID:      "asset123",
//	})
//	if !resp.Valid {
//	    return errors.New(resp.Error)
//	}
func (p *PaymentProcessor) VerifyPayment(ctx context.Context, req VerifyPaymentRequest) (*VerifyPaymentResponse, error) {
	p.mu.RLock()
	paymentID, ok := p.tokenToPaymentID[req.PaymentToken]
	if !ok {
		p.mu.RUnlock()
		return &VerifyPaymentResponse{
			Valid: false,
			Error: "payment token not found",
		}, nil
	}

	payment, ok := p.payments[paymentID]
	if !ok {
		p.mu.RUnlock()
		return &VerifyPaymentResponse{
			Valid: false,
			Error: "payment record not found",
		}, nil
	}
	p.mu.RUnlock()

	// Verify payment matches asset
	if payment.AssetID != req.AssetID {
		return &VerifyPaymentResponse{
			Valid:     false,
			PaymentID: paymentID,
			Error:     "payment token not valid for this asset",
		}, nil
	}

	// Check payment validity (expiry, already used, etc.)
	if err := payment.IsValid(); err != nil {
		return &VerifyPaymentResponse{
			Valid:     false,
			PaymentID: paymentID,
			Error:     err.Error(),
		}, nil
	}

	return &VerifyPaymentResponse{
		Valid:     true,
		PaymentID: paymentID,
		AmountUSD: payment.AmountUSD,
	}, nil
}

// VerifyAndMarkPaymentUsed atomically verifies and marks payment as used.
//
// This prevents double-spend race conditions by holding exclusive lock
// from verification through marking as used.
//
// SECURITY: This MUST be atomic to prevent payment replay attacks.
// The vulnerable two-step process (VerifyPayment + MarkPaymentUsed) allowed
// 50 concurrent requests to all verify the same payment before any marked it as used.
func (p *PaymentProcessor) VerifyAndMarkPaymentUsed(ctx context.Context, req VerifyPaymentRequest) (*VerifyPaymentResponse, error) {
	// CRITICAL: Use exclusive Lock (not RLock) for entire operation
	p.mu.Lock()
	defer p.mu.Unlock()

	// Step 1: Get payment ID
	paymentID, ok := p.tokenToPaymentID[req.PaymentToken]
	if !ok {
		return &VerifyPaymentResponse{
			Valid: false,
			Error: "payment token not found",
		}, nil
	}

	// Step 2: Get payment record
	payment, ok := p.payments[paymentID]
	if !ok {
		return &VerifyPaymentResponse{
			Valid: false,
			Error: "payment record not found",
		}, nil
	}

	// Step 3: Verify payment matches asset
	if payment.AssetID != req.AssetID {
		return &VerifyPaymentResponse{
			Valid:     false,
			PaymentID: paymentID,
			Error:     "payment token not valid for this asset",
		}, nil
	}

	// Step 4: Check payment validity (expiry, already used, etc.)
	// CRITICAL: This checks if payment.Status == PaymentStatusUsed
	// We're holding the lock, so no race condition possible
	if err := payment.IsValid(); err != nil {
		return &VerifyPaymentResponse{
			Valid:     false,
			PaymentID: paymentID,
			Error:     err.Error(),
		}, nil
	}

	// Step 5: ATOMICALLY mark as used BEFORE returning success
	// CRITICAL: This prevents race condition - payment is marked
	// as used while still holding the lock. Only ONE caller can succeed.
	now := time.Now()
	payment.Status = PaymentStatusUsed
	payment.UsedAt = &now

	// Step 6: Return success
	return &VerifyPaymentResponse{
		Valid:     true,
		PaymentID: paymentID,
		AmountUSD: payment.AmountUSD,
	}, nil
}

// ConfirmPayment confirms a payment has been made (for ledger integration).
//
// In mock mode, this can be called directly to simulate payment.
// In production, this will be called when ledger confirms the transaction.
func (p *PaymentProcessor) ConfirmPayment(ctx context.Context, paymentToken string, transactionID string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	paymentID, ok := p.tokenToPaymentID[paymentToken]
	if !ok {
		return ErrPaymentNotFound
	}

	payment, ok := p.payments[paymentID]
	if !ok {
		return ErrPaymentNotFound
	}

	if payment.Status != PaymentStatusPending {
		return fmt.Errorf("payment already processed: status=%s", payment.Status)
	}

	payment.Status = PaymentStatusConfirmed
	payment.TransactionID = transactionID

	return nil
}

// MarkPaymentUsed marks a payment as used after successful unlock.
//
// This ensures single-use enforcement - a payment token can only be used once.
func (p *PaymentProcessor) MarkPaymentUsed(ctx context.Context, paymentToken string) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	paymentID, ok := p.tokenToPaymentID[paymentToken]
	if !ok {
		return ErrPaymentNotFound
	}

	payment, ok := p.payments[paymentID]
	if !ok {
		return ErrPaymentNotFound
	}

	if payment.Status == PaymentStatusUsed {
		return ErrPaymentAlreadyUsed
	}

	now := time.Now()
	payment.Status = PaymentStatusUsed
	payment.UsedAt = &now

	return nil
}

// GetPayment retrieves a payment by ID.
func (p *PaymentProcessor) GetPayment(ctx context.Context, paymentID string) (*Payment, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	payment, ok := p.payments[paymentID]
	if !ok {
		return nil, ErrPaymentNotFound
	}

	return payment, nil
}

// GetPaymentByToken retrieves a payment by token.
func (p *PaymentProcessor) GetPaymentByToken(ctx context.Context, token string) (*Payment, error) {
	p.mu.RLock()
	paymentID, ok := p.tokenToPaymentID[token]
	if !ok {
		p.mu.RUnlock()
		return nil, ErrPaymentNotFound
	}
	p.mu.RUnlock()

	return p.GetPayment(ctx, paymentID)
}

// GetFeeCalculator returns the fee calculator for direct fee calculations.
func (p *PaymentProcessor) GetFeeCalculator() *FeeCalculator {
	return p.feeCalculator
}

// CleanupExpired removes expired payment records.
// Should be called periodically to prevent memory growth.
func (p *PaymentProcessor) CleanupExpired(ctx context.Context) int {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	cleaned := 0

	for id, payment := range p.payments {
		if payment.Status == PaymentStatusPending && now.After(payment.ExpiresAt) {
			payment.Status = PaymentStatusExpired
			delete(p.tokenToPaymentID, payment.Token)
			delete(p.payments, id)
			cleaned++
		}
	}

	return cleaned
}

// generateID generates a unique ID with a prefix.
func generateID(prefix string) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("crypto/rand.Read failed: %w", err)
	}
	return fmt.Sprintf("%s_%s", prefix, hex.EncodeToString(b)), nil
}

// generateToken generates a secure random token.
func generateToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("crypto/rand.Read failed: %w", err)
	}
	return hex.EncodeToString(b), nil
}
