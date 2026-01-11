// Package payment provides fee calculation and payment processing for LockBox.
//
// This package implements the fee structure defined in the LockBox requirements:
//   - Retrieval fees (tier-based)
//   - Setup fees (one-time)
//   - Key rotation fees
//   - Token payment discounts
package payment

import (
	"fmt"

	"github.com/dueldanov/lockbox/v2/internal/interfaces"
)

// FeeType represents different types of fees in the system.
type FeeType string

const (
	// FeeTypeRetrieval is the fee for retrieving (unlocking) an asset.
	FeeTypeRetrieval FeeType = "retrieval"

	// FeeTypeSetup is the one-time setup fee for new accounts.
	FeeTypeSetup FeeType = "setup"

	// FeeTypeRotation is the fee for key rotation operations.
	FeeTypeRotation FeeType = "rotation"
)

// Currency represents the payment currency.
type Currency string

const (
	// CurrencyUSD is US Dollar (stablecoin equivalent).
	CurrencyUSD Currency = "USD"

	// CurrencyLOCK is LockBox native token.
	CurrencyLOCK Currency = "LOCK"

	// CurrencyXSD is XSD token used for retrieval fees on IOTA ledger.
	// Conversion rate: 1 USD = 10,000 XSD ($0.01 = 100 XSD)
	CurrencyXSD Currency = "XSD"
)

// Fee structure constants from requirements (Section 6.1.2).
const (
	// Retrieval fees (USD cents)
	RetrievalFeeBasicCents    = 1   // $0.01 flat
	RetrievalFeeStandardCents = 1.5 // $0.015 flat
	RetrievalFeePremiumBase   = 3   // $0.03 base
	RetrievalFeeEliteBase     = 10  // $0.10 base

	// Variable retrieval fees (per stored value)
	RetrievalFeePremiumPer100K = 0.2 // $0.002 per $100K stored
	RetrievalFeeElitePer1M     = 1.5 // $0.015 per $1M stored

	// Retrieval fees in XSD token (1 USD = 100 XSD)
	RetrievalFeeBasicXSD    = 100  // $0.01 = 100 XSD
	RetrievalFeeStandardXSD = 150  // $0.015 = 150 XSD
	RetrievalFeePremiumXSD  = 300  // $0.03 base = 300 XSD
	RetrievalFeeEliteXSD    = 1000 // $0.10 base = 1000 XSD

	// Variable retrieval fees in XSD (per stored value)
	RetrievalFeePremiumPer100KXSD = 20  // $0.002 per $100K = 20 XSD
	RetrievalFeeElitePer1MXSD     = 150 // $0.015 per $1M = 150 XSD

	// Setup fees (USD)
	SetupFeeBasic    = 0    // Free
	SetupFeeStandard = 50   // $50
	SetupFeePremium  = 500  // $500
	SetupFeeElite    = 2500 // $2,500

	// Key rotation fees (USD)
	RotationFeeBasic    = 5  // $5
	RotationFeeStandard = 5  // $5
	RotationFeePremium  = 10 // $10
	RotationFeeElite    = 25 // $25

	// Token payment discount
	TokenPaymentDiscount = 0.10 // 10% discount for LOCK token payments

	// XSD/USD conversion rate
	XSDPerUSD = 10000 // 1 USD = 10,000 XSD ($0.01 = 100 XSD)
)

// FeeCalculator calculates fees based on tier and operation type.
//
// The calculator implements the fee structure from the LockBox requirements:
//   - Basic tier: flat $0.01 retrieval fee
//   - Standard tier: flat $0.015 retrieval fee
//   - Premium tier: $0.03 + $0.002 per $100K stored
//   - Elite tier: $0.10 + $0.015 per $1M stored
//
// All fees can be paid in USD (stablecoin) or LOCK token (10% discount).
type FeeCalculator struct {
	// Future: price oracle for LOCK/USD conversion
}

// NewFeeCalculator creates a new fee calculator instance.
func NewFeeCalculator() *FeeCalculator {
	return &FeeCalculator{}
}

// FeeRequest contains parameters for fee calculation.
type FeeRequest struct {
	// Tier is the service tier level.
	Tier interfaces.Tier

	// FeeType is the type of fee to calculate.
	FeeType FeeType

	// StoredValueUSD is the value of assets stored (for Premium/Elite variable fees).
	// Only used for retrieval fees on Premium and Elite tiers.
	StoredValueUSD float64

	// PaymentCurrency is the currency used for payment.
	// LOCK token payments receive a 10% discount.
	PaymentCurrency Currency
}

// FeeResult contains the calculated fee information.
type FeeResult struct {
	// BaseFeeUSD is the fee before any discounts (in USD).
	BaseFeeUSD float64

	// DiscountPercent is the discount percentage applied.
	DiscountPercent float64

	// FinalFeeUSD is the final fee after discounts (in USD).
	FinalFeeUSD float64

	// FinalFeeXSD is the final fee in XSD tokens (only set if Currency is XSD).
	// Conversion: 1 USD = 10,000 XSD ($0.01 = 100 XSD)
	FinalFeeXSD float64

	// Tier is the tier used for calculation.
	Tier interfaces.Tier

	// FeeType is the type of fee calculated.
	FeeType FeeType

	// Currency is the payment currency.
	Currency Currency

	// Breakdown provides a human-readable breakdown of the fee.
	Breakdown string
}

// CalculateFee calculates the fee for a given request.
//
// Example:
//
//	calc := NewFeeCalculator()
//	result, err := calc.CalculateFee(FeeRequest{
//	    Tier:            interfaces.TierStandard,
//	    FeeType:         FeeTypeRetrieval,
//	    PaymentCurrency: CurrencyUSD,
//	})
//	// result.FinalFeeUSD = 0.015
func (fc *FeeCalculator) CalculateFee(req FeeRequest) (*FeeResult, error) {
	var baseFee float64
	var breakdown string

	switch req.FeeType {
	case FeeTypeRetrieval:
		baseFee, breakdown = fc.calculateRetrievalFee(req.Tier, req.StoredValueUSD)
	case FeeTypeSetup:
		baseFee, breakdown = fc.calculateSetupFee(req.Tier)
	case FeeTypeRotation:
		baseFee, breakdown = fc.calculateRotationFee(req.Tier)
	default:
		return nil, fmt.Errorf("unknown fee type: %s", req.FeeType)
	}

	// Apply token discount if applicable
	discountPercent := 0.0
	if req.PaymentCurrency == CurrencyLOCK {
		discountPercent = TokenPaymentDiscount * 100 // Convert to percentage
	}

	finalFee := baseFee * (1 - discountPercent/100)

	// Convert to XSD if payment currency is XSD
	finalFeeXSD := 0.0
	if req.PaymentCurrency == CurrencyXSD {
		finalFeeXSD = finalFee * XSDPerUSD
	}

	return &FeeResult{
		BaseFeeUSD:      baseFee,
		DiscountPercent: discountPercent,
		FinalFeeUSD:     finalFee,
		FinalFeeXSD:     finalFeeXSD,
		Tier:            req.Tier,
		FeeType:         req.FeeType,
		Currency:        req.PaymentCurrency,
		Breakdown:       breakdown,
	}, nil
}

// calculateRetrievalFee calculates the retrieval (unlock) fee.
//
// Fee structure (from requirements):
//   - Basic:    $0.01 flat
//   - Standard: $0.015 flat
//   - Premium:  $0.03 + $0.002 per $100K stored
//   - Elite:    $0.10 + $0.015 per $1M stored
func (fc *FeeCalculator) calculateRetrievalFee(tier interfaces.Tier, storedValueUSD float64) (float64, string) {
	switch tier {
	case interfaces.TierBasic:
		fee := RetrievalFeeBasicCents / 100.0
		return fee, fmt.Sprintf("Basic flat fee: $%.4f", fee)

	case interfaces.TierStandard:
		fee := RetrievalFeeStandardCents / 100.0
		return fee, fmt.Sprintf("Standard flat fee: $%.4f", fee)

	case interfaces.TierPremium:
		baseFee := RetrievalFeePremiumBase / 100.0
		variableFee := (storedValueUSD / 100000.0) * (RetrievalFeePremiumPer100K / 100.0)
		totalFee := baseFee + variableFee
		return totalFee, fmt.Sprintf("Premium: $%.4f base + $%.6f (per $100K on $%.2f stored) = $%.4f",
			baseFee, variableFee, storedValueUSD, totalFee)

	case interfaces.TierElite:
		baseFee := RetrievalFeeEliteBase / 100.0
		variableFee := (storedValueUSD / 1000000.0) * (RetrievalFeeElitePer1M / 100.0)
		totalFee := baseFee + variableFee
		return totalFee, fmt.Sprintf("Elite: $%.4f base + $%.6f (per $1M on $%.2f stored) = $%.4f",
			baseFee, variableFee, storedValueUSD, totalFee)

	default:
		// Unknown tier gets Basic pricing
		fee := RetrievalFeeBasicCents / 100.0
		return fee, fmt.Sprintf("Unknown tier, using Basic: $%.4f", fee)
	}
}

// calculateSetupFee calculates the one-time setup fee.
//
// Fee structure (from requirements):
//   - Basic:    $0 (free)
//   - Standard: $50
//   - Premium:  $500
//   - Elite:    $2,500
func (fc *FeeCalculator) calculateSetupFee(tier interfaces.Tier) (float64, string) {
	switch tier {
	case interfaces.TierBasic:
		return SetupFeeBasic, "Basic: Free setup"
	case interfaces.TierStandard:
		return SetupFeeStandard, fmt.Sprintf("Standard: $%.2f setup fee", float64(SetupFeeStandard))
	case interfaces.TierPremium:
		return SetupFeePremium, fmt.Sprintf("Premium: $%.2f setup fee", float64(SetupFeePremium))
	case interfaces.TierElite:
		return SetupFeeElite, fmt.Sprintf("Elite: $%.2f setup fee", float64(SetupFeeElite))
	default:
		return SetupFeeBasic, "Unknown tier: Free setup"
	}
}

// calculateRotationFee calculates the key rotation fee.
//
// Fee structure (from requirements):
//   - Basic:    $5
//   - Standard: $5
//   - Premium:  $10
//   - Elite:    $25
func (fc *FeeCalculator) calculateRotationFee(tier interfaces.Tier) (float64, string) {
	switch tier {
	case interfaces.TierBasic:
		return RotationFeeBasic, fmt.Sprintf("Basic: $%.2f rotation fee", float64(RotationFeeBasic))
	case interfaces.TierStandard:
		return RotationFeeStandard, fmt.Sprintf("Standard: $%.2f rotation fee", float64(RotationFeeStandard))
	case interfaces.TierPremium:
		return RotationFeePremium, fmt.Sprintf("Premium: $%.2f rotation fee", float64(RotationFeePremium))
	case interfaces.TierElite:
		return RotationFeeElite, fmt.Sprintf("Elite: $%.2f rotation fee", float64(RotationFeeElite))
	default:
		return RotationFeeBasic, fmt.Sprintf("Unknown tier: $%.2f rotation fee", float64(RotationFeeBasic))
	}
}

// CalculateRetrievalFee is a convenience method for calculating retrieval fees.
//
// Example:
//
//	fee, err := calc.CalculateRetrievalFee(interfaces.TierStandard, 0, CurrencyUSD)
//	// fee.FinalFeeUSD = 0.015
func (fc *FeeCalculator) CalculateRetrievalFee(tier interfaces.Tier, storedValueUSD float64, currency Currency) (*FeeResult, error) {
	return fc.CalculateFee(FeeRequest{
		Tier:            tier,
		FeeType:         FeeTypeRetrieval,
		StoredValueUSD:  storedValueUSD,
		PaymentCurrency: currency,
	})
}

// CalculateSetupFee is a convenience method for calculating setup fees.
func (fc *FeeCalculator) CalculateSetupFee(tier interfaces.Tier, currency Currency) (*FeeResult, error) {
	return fc.CalculateFee(FeeRequest{
		Tier:            tier,
		FeeType:         FeeTypeSetup,
		PaymentCurrency: currency,
	})
}

// CalculateRotationFee is a convenience method for calculating rotation fees.
func (fc *FeeCalculator) CalculateRotationFee(tier interfaces.Tier, currency Currency) (*FeeResult, error) {
	return fc.CalculateFee(FeeRequest{
		Tier:            tier,
		FeeType:         FeeTypeRotation,
		PaymentCurrency: currency,
	})
}

// GetAllFees returns all fees for a tier (useful for displaying pricing).
func (fc *FeeCalculator) GetAllFees(tier interfaces.Tier, storedValueUSD float64) map[FeeType]*FeeResult {
	result := make(map[FeeType]*FeeResult)

	if retrieval, err := fc.CalculateRetrievalFee(tier, storedValueUSD, CurrencyUSD); err == nil {
		result[FeeTypeRetrieval] = retrieval
	}
	if setup, err := fc.CalculateSetupFee(tier, CurrencyUSD); err == nil {
		result[FeeTypeSetup] = setup
	}
	if rotation, err := fc.CalculateRotationFee(tier, CurrencyUSD); err == nil {
		result[FeeTypeRotation] = rotation
	}

	return result
}
