package payment

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dueldanov/lockbox/v2/internal/interfaces"
)

func TestFeeCalculator_RetrievalFee_Basic(t *testing.T) {
	calc := NewFeeCalculator()

	result, err := calc.CalculateRetrievalFee(interfaces.TierBasic, 0, CurrencyUSD)
	require.NoError(t, err)

	// Basic tier: $0.01 flat
	assert.Equal(t, 0.01, result.BaseFeeUSD)
	assert.Equal(t, 0.01, result.FinalFeeUSD)
	assert.Equal(t, 0.0, result.DiscountPercent)
	assert.Equal(t, interfaces.TierBasic, result.Tier)
	assert.Equal(t, FeeTypeRetrieval, result.FeeType)
}

func TestFeeCalculator_RetrievalFee_Standard(t *testing.T) {
	calc := NewFeeCalculator()

	result, err := calc.CalculateRetrievalFee(interfaces.TierStandard, 0, CurrencyUSD)
	require.NoError(t, err)

	// Standard tier: $0.015 flat
	assert.Equal(t, 0.015, result.BaseFeeUSD)
	assert.Equal(t, 0.015, result.FinalFeeUSD)
}

func TestFeeCalculator_RetrievalFee_Premium(t *testing.T) {
	calc := NewFeeCalculator()

	// Premium with $1M stored value
	// $0.03 base + $0.002 * 10 (per $100K) = $0.03 + $0.02 = $0.05
	result, err := calc.CalculateRetrievalFee(interfaces.TierPremium, 1000000, CurrencyUSD)
	require.NoError(t, err)

	// $0.03 + ($1M / $100K) * $0.002 = $0.03 + 10 * 0.002 = $0.03 + $0.02 = $0.05
	assert.InDelta(t, 0.05, result.BaseFeeUSD, 0.0001)
	assert.InDelta(t, 0.05, result.FinalFeeUSD, 0.0001)
}

func TestFeeCalculator_RetrievalFee_Premium_NoStoredValue(t *testing.T) {
	calc := NewFeeCalculator()

	// Premium with $0 stored value
	result, err := calc.CalculateRetrievalFee(interfaces.TierPremium, 0, CurrencyUSD)
	require.NoError(t, err)

	// $0.03 base only
	assert.Equal(t, 0.03, result.BaseFeeUSD)
}

func TestFeeCalculator_RetrievalFee_Elite(t *testing.T) {
	calc := NewFeeCalculator()

	// Elite with $10M stored value
	// $0.10 base + $0.015 * 10 (per $1M) = $0.10 + $0.15 = $0.25
	result, err := calc.CalculateRetrievalFee(interfaces.TierElite, 10000000, CurrencyUSD)
	require.NoError(t, err)

	// $0.10 + ($10M / $1M) * $0.015 = $0.10 + 10 * 0.015 = $0.10 + $0.15 = $0.25
	assert.InDelta(t, 0.25, result.BaseFeeUSD, 0.0001)
}

func TestFeeCalculator_TokenPaymentDiscount(t *testing.T) {
	calc := NewFeeCalculator()

	// Standard tier with LOCK token payment should get 10% discount
	result, err := calc.CalculateRetrievalFee(interfaces.TierStandard, 0, CurrencyLOCK)
	require.NoError(t, err)

	// Base: $0.015, Discount: 10%, Final: $0.0135
	assert.Equal(t, 0.015, result.BaseFeeUSD)
	assert.Equal(t, 10.0, result.DiscountPercent)
	assert.InDelta(t, 0.0135, result.FinalFeeUSD, 0.0001)
	assert.Equal(t, CurrencyLOCK, result.Currency)
}

func TestFeeCalculator_SetupFee(t *testing.T) {
	calc := NewFeeCalculator()

	tests := []struct {
		tier     interfaces.Tier
		expected float64
	}{
		{interfaces.TierBasic, 0},      // Free
		{interfaces.TierStandard, 50},  // $50
		{interfaces.TierPremium, 500},  // $500
		{interfaces.TierElite, 2500},   // $2,500
	}

	for _, tc := range tests {
		result, err := calc.CalculateSetupFee(tc.tier, CurrencyUSD)
		require.NoError(t, err)
		assert.Equal(t, tc.expected, result.BaseFeeUSD,
			"Setup fee for tier %s should be $%.2f", tc.tier.String(), tc.expected)
	}
}

func TestFeeCalculator_RotationFee(t *testing.T) {
	calc := NewFeeCalculator()

	tests := []struct {
		tier     interfaces.Tier
		expected float64
	}{
		{interfaces.TierBasic, 5},     // $5
		{interfaces.TierStandard, 5},  // $5
		{interfaces.TierPremium, 10},  // $10
		{interfaces.TierElite, 25},    // $25
	}

	for _, tc := range tests {
		result, err := calc.CalculateRotationFee(tc.tier, CurrencyUSD)
		require.NoError(t, err)
		assert.Equal(t, tc.expected, result.BaseFeeUSD,
			"Rotation fee for tier %s should be $%.2f", tc.tier.String(), tc.expected)
	}
}

func TestFeeCalculator_UnknownFeeType(t *testing.T) {
	calc := NewFeeCalculator()

	_, err := calc.CalculateFee(FeeRequest{
		Tier:            interfaces.TierBasic,
		FeeType:         FeeType("unknown"),
		PaymentCurrency: CurrencyUSD,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown fee type")
}

func TestFeeCalculator_GetAllFees(t *testing.T) {
	calc := NewFeeCalculator()

	fees := calc.GetAllFees(interfaces.TierStandard, 500000)

	require.NotNil(t, fees[FeeTypeRetrieval])
	require.NotNil(t, fees[FeeTypeSetup])
	require.NotNil(t, fees[FeeTypeRotation])

	// Standard retrieval fee
	assert.Equal(t, 0.015, fees[FeeTypeRetrieval].BaseFeeUSD)

	// Standard setup fee
	assert.Equal(t, 50.0, fees[FeeTypeSetup].BaseFeeUSD)

	// Standard rotation fee
	assert.Equal(t, 5.0, fees[FeeTypeRotation].BaseFeeUSD)
}

func TestFeeCalculator_BreakdownPresent(t *testing.T) {
	calc := NewFeeCalculator()

	result, err := calc.CalculateRetrievalFee(interfaces.TierPremium, 500000, CurrencyUSD)
	require.NoError(t, err)

	// Breakdown should contain useful information
	assert.Contains(t, result.Breakdown, "Premium")
	assert.Contains(t, result.Breakdown, "base")
	assert.Contains(t, result.Breakdown, "stored")
}

// TestFeeCalculator_Requirements verifies all fees match requirements document
func TestFeeCalculator_Requirements(t *testing.T) {
	calc := NewFeeCalculator()

	t.Run("Retrieval fees match requirements", func(t *testing.T) {
		// Requirements Section 6.1.2:
		// Basic: $0.01 flat
		basic, _ := calc.CalculateRetrievalFee(interfaces.TierBasic, 0, CurrencyUSD)
		assert.Equal(t, 0.01, basic.FinalFeeUSD, "Basic should be $0.01")

		// Standard: $0.015 flat
		standard, _ := calc.CalculateRetrievalFee(interfaces.TierStandard, 0, CurrencyUSD)
		assert.Equal(t, 0.015, standard.FinalFeeUSD, "Standard should be $0.015")

		// Premium: $0.03 base (no stored value)
		premium, _ := calc.CalculateRetrievalFee(interfaces.TierPremium, 0, CurrencyUSD)
		assert.Equal(t, 0.03, premium.FinalFeeUSD, "Premium base should be $0.03")

		// Elite: $0.10 base (no stored value)
		elite, _ := calc.CalculateRetrievalFee(interfaces.TierElite, 0, CurrencyUSD)
		assert.Equal(t, 0.10, elite.FinalFeeUSD, "Elite base should be $0.10")
	})

	t.Run("Token discount is 10%", func(t *testing.T) {
		usd, _ := calc.CalculateRetrievalFee(interfaces.TierStandard, 0, CurrencyUSD)
		lock, _ := calc.CalculateRetrievalFee(interfaces.TierStandard, 0, CurrencyLOCK)

		discount := (usd.FinalFeeUSD - lock.FinalFeeUSD) / usd.FinalFeeUSD
		assert.InDelta(t, 0.10, discount, 0.001, "Token discount should be 10%")
	})
}

func TestFeeCalculator_XSD_Currency(t *testing.T) {
	calc := NewFeeCalculator()

	t.Run("Standard tier with XSD payment", func(t *testing.T) {
		result, err := calc.CalculateRetrievalFee(interfaces.TierStandard, 0, CurrencyXSD)
		require.NoError(t, err)

		// Standard: $0.015 = 150 XSD (1 USD = 100 XSD)
		assert.Equal(t, 0.015, result.BaseFeeUSD, "Base fee should be $0.015")
		assert.Equal(t, 0.015, result.FinalFeeUSD, "Final USD fee should be $0.015")
		assert.Equal(t, 150.0, result.FinalFeeXSD, "Final XSD fee should be 150 XSD")
		assert.Equal(t, CurrencyXSD, result.Currency)
		assert.Equal(t, 0.0, result.DiscountPercent, "XSD payments have no discount")
	})

	t.Run("Basic tier with XSD payment", func(t *testing.T) {
		result, err := calc.CalculateRetrievalFee(interfaces.TierBasic, 0, CurrencyXSD)
		require.NoError(t, err)

		// Basic: $0.01 = 100 XSD
		assert.Equal(t, 0.01, result.FinalFeeUSD)
		assert.Equal(t, 100.0, result.FinalFeeXSD, "Basic tier should be 100 XSD")
	})

	t.Run("Premium tier with XSD and stored value", func(t *testing.T) {
		// Premium with $500K stored
		// $0.03 + ($500K / $100K) * $0.002 = $0.03 + 5 * 0.002 = $0.04
		result, err := calc.CalculateRetrievalFee(interfaces.TierPremium, 500000, CurrencyXSD)
		require.NoError(t, err)

		assert.InDelta(t, 0.04, result.FinalFeeUSD, 0.0001)
		assert.InDelta(t, 400.0, result.FinalFeeXSD, 0.1, "Premium $0.04 = 400 XSD")
	})

	t.Run("Elite tier with XSD and stored value", func(t *testing.T) {
		// Elite with $5M stored
		// $0.10 + ($5M / $1M) * $0.015 = $0.10 + 5 * 0.015 = $0.175
		result, err := calc.CalculateRetrievalFee(interfaces.TierElite, 5000000, CurrencyXSD)
		require.NoError(t, err)

		assert.InDelta(t, 0.175, result.FinalFeeUSD, 0.0001)
		assert.InDelta(t, 1750.0, result.FinalFeeXSD, 0.1, "Elite $0.175 = 1750 XSD")
	})

	t.Run("XSD conversion rate is 100 per USD", func(t *testing.T) {
		result, err := calc.CalculateRetrievalFee(interfaces.TierStandard, 0, CurrencyXSD)
		require.NoError(t, err)

		// Verify conversion: FinalFeeXSD = FinalFeeUSD * 100
		expectedXSD := result.FinalFeeUSD * XSDPerUSD
		assert.Equal(t, expectedXSD, result.FinalFeeXSD, "XSD conversion should be 100:1")
	})
}
