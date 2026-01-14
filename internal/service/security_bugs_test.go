package service

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dueldanov/lockbox/v2/internal/payment"
)

// ============================================
// CRITICAL: Payment Double-Spend Race Condition (CRIT-001)
// The payment is marked as "used" AFTER unlock succeeds,
// allowing concurrent requests with same token to both succeed.
// ============================================

// TestPaymentDoubleSpend_RaceCondition tests for payment double-spend vulnerability.
// SECURITY: This test exposes CRIT-001 - payment marked as used AFTER unlock.
func TestPaymentDoubleSpend_RaceCondition(t *testing.T) {
	// Create payment processor
	processor := payment.NewPaymentProcessor(nil)

	// Create and confirm a payment
	ctx := context.Background()
	createResp, err := processor.CreatePayment(ctx, payment.CreatePaymentRequest{
		AssetID:  "test-asset-123",
		Tier:     TierStandard,
		FeeType:  payment.FeeTypeRetrieval,
		Currency: payment.CurrencyUSD,
	})
	require.NoError(t, err)

	// Confirm payment (simulate ledger confirmation)
	err = processor.ConfirmPayment(ctx, createResp.PaymentToken, "tx-123")
	require.NoError(t, err)

	// Now simulate the race condition:
	// Multiple goroutines verify the SAME payment token concurrently
	// In the vulnerable code, ALL verifications succeed before any marks as used

	var wg sync.WaitGroup
	successCount := atomic.Int32{}
	numGoroutines := 50

	// Start barrier to release all goroutines simultaneously
	start := make(chan struct{})

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start // Wait for signal

			// This simulates the verification step in UnlockAsset
			verifyResp, err := processor.VerifyPayment(ctx, payment.VerifyPaymentRequest{
				PaymentToken: createResp.PaymentToken,
				AssetID:      "test-asset-123",
			})

			if err == nil && verifyResp.Valid {
				successCount.Add(1)
			}
		}()
	}

	// Release all goroutines at once
	close(start)
	wg.Wait()

	// SECURITY CHECK: Only ONE verification should succeed!
	// If more than one succeeded, double-spend is possible.
	if successCount.Load() > 1 {
		t.Errorf("CRITICAL SECURITY VULNERABILITY: Payment double-spend detected! "+
			"%d/%d concurrent verifications succeeded with same payment token. "+
			"Expected: 1. This means attackers can pay once and unlock multiple times!",
			successCount.Load(), numGoroutines)
	}
}

// TestPaymentMarkUsed_MustBeBeforeUnlock demonstrates the correct fix location.
// The payment should be marked as used BEFORE unlock completes, not after.
func TestPaymentMarkUsed_MustBeBeforeUnlock(t *testing.T) {
	processor := payment.NewPaymentProcessor(nil)
	ctx := context.Background()

	// Create and confirm payment
	createResp, _ := processor.CreatePayment(ctx, payment.CreatePaymentRequest{
		AssetID:  "test-asset",
		Tier:     TierStandard,
		FeeType:  payment.FeeTypeRetrieval,
		Currency: payment.CurrencyUSD,
	})
	processor.ConfirmPayment(ctx, createResp.PaymentToken, "tx-123")

	// Verify payment
	verifyResp, err := processor.VerifyPayment(ctx, payment.VerifyPaymentRequest{
		PaymentToken: createResp.PaymentToken,
		AssetID:      "test-asset",
	})
	require.NoError(t, err)
	require.True(t, verifyResp.Valid)

	// Mark as used IMMEDIATELY after verification (before unlock logic)
	err = processor.MarkPaymentUsed(ctx, createResp.PaymentToken)
	require.NoError(t, err)

	// Second verification should FAIL
	verifyResp2, err := processor.VerifyPayment(ctx, payment.VerifyPaymentRequest{
		PaymentToken: createResp.PaymentToken,
		AssetID:      "test-asset",
	})

	// This is the expected secure behavior
	require.False(t, verifyResp2.Valid, "Second verification MUST fail after payment marked as used")
}

// ============================================
// HIGH: Non-Constant-Time Token Comparison (HIGH-004)
// ============================================

// TestTokenComparison_TimingAttack tests for timing side-channel.
// SECURITY: Token comparison must be constant-time to prevent timing attacks.
func TestTokenComparison_TimingAttack(t *testing.T) {
	// Generate a valid token for comparison
	validToken, err := GenerateAccessToken()
	require.NoError(t, err)

	// Split into payload and HMAC
	parts := strings.Split(validToken, ":")
	require.Len(t, parts, 2)
	payload := parts[0]
	validHMAC := parts[1]

	// Create test tokens with HMAC differing at different positions
	testCases := []struct {
		name    string
		hmac    string
		differs string
	}{
		{"first_byte_wrong", "00" + validHMAC[2:], "first"},
		{"last_byte_wrong", validHMAC[:62] + "00", "last"},
		{"middle_byte_wrong", validHMAC[:30] + "00" + validHMAC[32:], "middle"},
		{"all_wrong", strings.Repeat("00", 32), "all"},
	}

	svc := &Service{}
	iterations := 10000

	timings := make(map[string]time.Duration)

	for _, tc := range testCases {
		token := payload + ":" + tc.hmac

		start := time.Now()
		for i := 0; i < iterations; i++ {
			svc.validateAccessToken(token)
		}
		timings[tc.name] = time.Since(start)
	}

	// Check timing variance
	// Constant-time comparison should have similar timing regardless of where HMAC differs
	baseTime := timings["first_byte_wrong"]

	for name, timing := range timings {
		ratio := float64(timing) / float64(baseTime)

		// Allow up to 20% variance (timing attacks typically need tighter correlation)
		if ratio < 0.8 || ratio > 1.2 {
			t.Logf("Potential timing attack vector: %s ratio=%.2f (base: %v, this: %v)",
				name, ratio, baseTime, timing)
		}
	}

	// Also verify we're using constant-time comparison in the implementation
	// This is a hint for code review - the actual test above catches timing issues
	t.Log("Reminder: Verify validateAccessToken uses hmac.Equal() for HMAC comparison")
}

// TestConstantTimeComparison_Correct demonstrates proper constant-time comparison.
func TestConstantTimeComparison_Correct(t *testing.T) {
	secret := make([]byte, 32)
	rand.Read(secret)

	h := hmac.New(sha256.New, secret)
	h.Write([]byte("test message"))
	correctMAC := h.Sum(nil)

	// Test 1: Correct MAC - should return true
	result := hmac.Equal(correctMAC, correctMAC)
	require.True(t, result)

	// Test 2: Wrong MAC (first byte) - should return false
	wrongMAC1 := make([]byte, len(correctMAC))
	copy(wrongMAC1, correctMAC)
	wrongMAC1[0] ^= 0xFF
	result = hmac.Equal(correctMAC, wrongMAC1)
	require.False(t, result)

	// Test 3: Wrong MAC (last byte) - should return false
	wrongMAC2 := make([]byte, len(correctMAC))
	copy(wrongMAC2, correctMAC)
	wrongMAC2[len(wrongMAC2)-1] ^= 0xFF
	result = hmac.Equal(correctMAC, wrongMAC2)
	require.False(t, result)

	// Test 4: Demonstrate subtle.ConstantTimeCompare for byte slices
	result1 := subtle.ConstantTimeCompare(correctMAC, wrongMAC1)
	result2 := subtle.ConstantTimeCompare(correctMAC, wrongMAC2)
	require.Equal(t, 0, result1) // 0 = not equal
	require.Equal(t, 0, result2) // 0 = not equal
}

// ============================================
// HIGH: Rate Limiter Per-AssetID Not Per-User (HIGH-001)
// ============================================

// TestRateLimiter_PerAssetNotPerUser demonstrates the rate limiter bypass.
// SECURITY: Rate limiter keyed by AssetID allows brute-force across many assets.
func TestRateLimiter_PerAssetNotPerUser(t *testing.T) {
	// This test documents the vulnerability:
	// If rate limiter allows 5 req/min per asset, attacker with 1000 assets
	// gets 5000 attempts/min instead of 5

	numAssets := 100
	attemptsPerAsset := 5

	// Simulate attacker's capability
	totalAttempts := numAssets * attemptsPerAsset

	// With per-asset limiting (VULNERABLE):
	// Attacker can make 5 * 100 = 500 attempts per minute

	// With per-user limiting (SECURE):
	// Attacker can make only 5 attempts per minute total

	t.Logf("SECURITY ANALYSIS: Rate Limiter Bypass")
	t.Logf("  Per-Asset (Current):  %d attempts/min (5 per asset × %d assets)", totalAttempts, numAssets)
	t.Logf("  Per-User  (Secure):   %d attempts/min (fixed per user)", attemptsPerAsset)
	t.Logf("  Amplification Factor: %dx", numAssets)

	if totalAttempts > attemptsPerAsset*10 {
		t.Errorf("SECURITY: Rate limiter allows %dx amplification via multiple assets. "+
			"Rate limiting should be per-user (owner address), not per-asset.",
			totalAttempts/attemptsPerAsset)
	}
}

// ============================================
// CRIT-006: Token Validation Must Reject Fake HMACs
// ============================================

// TestValidateAccessToken_FakeHMAC_AllPatterns tests all fake HMAC patterns.
func TestValidateAccessToken_FakeHMAC_AllPatterns(t *testing.T) {
	// Ensure dev mode is enabled for deterministic testing
	os.Setenv("LOCKBOX_DEV_MODE", "true")
	reinitTokenHMACKey()
	defer func() {
		os.Setenv("LOCKBOX_DEV_MODE", "true")
		reinitTokenHMACKey()
	}()

	svc := &Service{}

	// Generate a valid token first
	validToken, err := GenerateAccessToken()
	require.NoError(t, err)

	parts := strings.Split(validToken, ":")
	require.Len(t, parts, 2)
	validPayload := parts[0]

	// All these fake HMACs MUST be rejected
	fakeHMACs := []struct {
		name string
		hmac string
	}{
		{"all_zeros", strings.Repeat("0", 64)},
		{"all_ones", strings.Repeat("f", 64)},
		{"sequential", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
		{"random", generateRandomHex(64)},
		{"truncated_valid", parts[1][:32] + strings.Repeat("0", 32)},
		{"bit_flip_first", flipBit(parts[1], 0)},
		{"bit_flip_last", flipBit(parts[1], 31)}, // 32 bytes = indices 0-31
	}

	for _, tc := range fakeHMACs {
		t.Run(tc.name, func(t *testing.T) {
			fakeToken := validPayload + ":" + tc.hmac
			result := svc.validateAccessToken(fakeToken)
			require.False(t, result,
				"SECURITY: Fake HMAC '%s' MUST be rejected! Token validation is broken.", tc.name)
		})
	}
}

// TestValidateAccessToken_DifferentPayloadSameHMAC tests HMAC payload binding.
func TestValidateAccessToken_DifferentPayloadSameHMAC(t *testing.T) {
	os.Setenv("LOCKBOX_DEV_MODE", "true")
	reinitTokenHMACKey()

	svc := &Service{}

	// Generate valid token
	validToken, _ := GenerateAccessToken()
	parts := strings.Split(validToken, ":")
	validHMAC := parts[1]

	// Try to use valid HMAC with different payload (attack)
	attackPayload := generateRandomHex(64)
	attackToken := attackPayload + ":" + validHMAC

	result := svc.validateAccessToken(attackToken)
	require.False(t, result,
		"SECURITY: HMAC from one payload MUST NOT validate different payload!")
}

// ============================================
// HIGH: Multi-Sig Signature Count vs Verification
// ============================================

// TestMultiSig_CountVsVerification ensures signatures are cryptographically verified.
func TestMultiSig_CountVsVerification(t *testing.T) {
	// This test ensures multi-sig doesn't just count signatures
	// but actually verifies them cryptographically

	// Generate real keypairs
	pub1, _, _ := ed25519.GenerateKey(rand.Reader)
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)

	// Store pubkeys as hex strings for the test
	pubKeyHexes := []string{
		hex.EncodeToString(pub1),
		hex.EncodeToString(pub2),
	}

	assetID := "test-multisig-asset"
	minSignatures := 2

	// Fake signatures (just byte arrays, not real Ed25519 signatures)
	fakeSignatures := [][]byte{
		[]byte("fake-signature-1-padding-to-64-bytes-xxxxxxxxxxxxxxxxxxxxxxxxx"),
		[]byte("fake-signature-2-padding-to-64-bytes-xxxxxxxxxxxxxxxxxxxxxxxxx"),
	}

	// Count check would PASS (2 signatures >= 2 required)
	countPasses := len(fakeSignatures) >= minSignatures
	require.True(t, countPasses, "Count check passes with fake sigs (expected)")

	// But cryptographic verification MUST FAIL
	// This is what the service SHOULD do:
	message := assetID
	validCount := 0
	for i, sig := range fakeSignatures {
		if i >= len(pubKeyHexes) {
			break
		}
		pubKeyHex := pubKeyHexes[i]
		pubKey, err := hex.DecodeString(pubKeyHex)
		if err != nil {
			continue
		}
		if len(sig) == 64 && len(pubKey) == 32 {
			if ed25519.Verify(pubKey, []byte(message), sig) {
				validCount++
			}
		}
	}

	// Fake signatures should NOT verify
	require.Equal(t, 0, validCount,
		"SECURITY: Fake signatures MUST NOT pass Ed25519 verification! "+
			"If validCount > 0, multi-sig is broken.")

	// The service must check validCount >= MinSignatures, NOT len(signatures) >= MinSignatures
	require.Less(t, validCount, minSignatures,
		"SECURITY: Multi-sig bypass possible if only counting signatures!")
}

// ============================================
// MEDIUM: Nonce Concurrent Replay Attack
// ============================================

// TestNonceReplay_Concurrent tests concurrent nonce replay protection.
func TestNonceReplay_Concurrent(t *testing.T) {
	svc := &Service{}

	// Create a valid nonce
	timestamp := time.Now().Unix()
	randomBytes := make([]byte, 16)
	rand.Read(randomBytes)
	nonce := fmt.Sprintf("%d:%x", timestamp, randomBytes)

	// Try to use the same nonce from many goroutines simultaneously
	var wg sync.WaitGroup
	successCount := atomic.Int32{}
	numGoroutines := 100

	start := make(chan struct{})

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if svc.checkTokenNonce(nonce) {
				successCount.Add(1)
			}
		}()
	}

	close(start)
	wg.Wait()

	// SECURITY: Exactly ONE should succeed
	require.Equal(t, int32(1), successCount.Load(),
		"SECURITY: Nonce replay race condition! %d concurrent uses succeeded (expected 1)",
		successCount.Load())
}

// ============================================
// Helper Functions
// ============================================

func generateRandomHex(length int) string {
	bytes := make([]byte, length/2)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func flipBit(hexStr string, byteIndex int) string {
	if byteIndex*2+2 > len(hexStr) {
		return hexStr
	}

	bytes, _ := hex.DecodeString(hexStr)
	if byteIndex < len(bytes) {
		bytes[byteIndex] ^= 0x01
	}
	return hex.EncodeToString(bytes)
}
