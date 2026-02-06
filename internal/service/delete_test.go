package service

import (
	"crypto/rand"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func init() {
	// Set dev mode for tests to allow deterministic HMAC key
	DevMode = true
	// Force reinit of HMAC key with dev mode enabled
	reinitTokenHMACKey()
}

// ============================================
// Token Validation Tests (HMAC format: payload:hmac)
// ============================================

func TestValidateAccessToken_Empty(t *testing.T) {
	svc := &Service{}
	result := svc.validateAccessToken("")
	require.False(t, result, "Empty token should be invalid")
}

func TestValidateAccessToken_TooShort(t *testing.T) {
	svc := &Service{}
	result := svc.validateAccessToken("abc123")
	require.False(t, result, "Short token should be invalid")
}

func TestValidateAccessToken_InvalidHex(t *testing.T) {
	svc := &Service{}
	// Invalid hex in payload
	token := "ghijklmnopqrstuvwxyz12345678901234567890123456789012345678901234:0000000000000000000000000000000000000000000000000000000000000000"
	result := svc.validateAccessToken(token)
	require.False(t, result, "Invalid hex should be rejected")
}

func TestValidateAccessToken_LegacyFormatRejected(t *testing.T) {
	svc := &Service{}
	// Legacy 64-char hex token without HMAC - MUST be rejected for security
	token := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	result := svc.validateAccessToken(token)
	require.False(t, result, "Legacy format without HMAC should be rejected")
}

func TestValidateAccessToken_Valid(t *testing.T) {
	svc := &Service{}
	// Generate a valid HMAC-signed token
	token, err := GenerateAccessToken()
	require.NoError(t, err)
	result := svc.validateAccessToken(token)
	require.True(t, result, "Valid HMAC-signed token should be accepted")
}

func TestValidateAccessToken_InvalidHMAC(t *testing.T) {
	svc := &Service{}
	// Valid payload but wrong HMAC
	token := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef:0000000000000000000000000000000000000000000000000000000000000000"
	result := svc.validateAccessToken(token)
	require.False(t, result, "Token with invalid HMAC should be rejected")
}

func TestValidateAccessToken_TamperedPayload(t *testing.T) {
	svc := &Service{}
	// Generate valid token, then tamper with payload
	token, err := GenerateAccessToken()
	require.NoError(t, err)

	// Tamper with first character of payload
	// Use a different character that's guaranteed to be different
	firstChar := token[0]
	var tamperedChar byte
	if firstChar == 'a' {
		tamperedChar = 'b'
	} else {
		tamperedChar = 'a'
	}
	tampered := string(tamperedChar) + token[1:]
	result := svc.validateAccessToken(tampered)
	require.False(t, result, "Tampered payload should be rejected")
}

func TestGenerateAccessToken_Format(t *testing.T) {
	token, err := GenerateAccessToken()
	require.NoError(t, err)
	require.Contains(t, token, ":", "Token should have payload:hmac format")
	require.Len(t, token, 129, "Token should be 64 + 1 + 64 = 129 chars")
}

// ============================================
// HMAC Key Security Tests
// ============================================

func TestLoadTokenHMACKey_ErrorOnMissingKey(t *testing.T) {
	// Save original values
	origKey := os.Getenv("LOCKBOX_TOKEN_HMAC_KEY")
	origDevMode := DevMode
	defer func() {
		os.Setenv("LOCKBOX_TOKEN_HMAC_KEY", origKey)
		DevMode = origDevMode
		reinitTokenHMACKey() // Restore for other tests
	}()

	// Clear key and disable dev mode
	os.Unsetenv("LOCKBOX_TOKEN_HMAC_KEY")
	DevMode = false

	_, err := loadTokenHMACKey()
	require.Error(t, err, "SECURITY: Must return error when HMAC key is missing in production")
	require.Contains(t, err.Error(), "LOCKBOX_TOKEN_HMAC_KEY")
}

func TestLoadTokenHMACKey_ErrorOnInvalidHex(t *testing.T) {
	origKey := os.Getenv("LOCKBOX_TOKEN_HMAC_KEY")
	defer func() {
		os.Setenv("LOCKBOX_TOKEN_HMAC_KEY", origKey)
		reinitTokenHMACKey()
	}()

	os.Setenv("LOCKBOX_TOKEN_HMAC_KEY", "not-valid-hex-string!")

	_, err := loadTokenHMACKey()
	require.Error(t, err, "SECURITY: Must return error when HMAC key is invalid hex")
	require.Contains(t, err.Error(), "not valid hex")
}

func TestLoadTokenHMACKey_ErrorOnShortKey(t *testing.T) {
	origKey := os.Getenv("LOCKBOX_TOKEN_HMAC_KEY")
	defer func() {
		os.Setenv("LOCKBOX_TOKEN_HMAC_KEY", origKey)
		reinitTokenHMACKey()
	}()

	// Only 16 bytes (32 hex chars) - too short
	os.Setenv("LOCKBOX_TOKEN_HMAC_KEY", "0123456789abcdef0123456789abcdef")

	_, err := loadTokenHMACKey()
	require.Error(t, err, "SECURITY: Must return error when HMAC key is less than 32 bytes")
	require.Contains(t, err.Error(), "at least 32 bytes")
}

func TestLoadTokenHMACKey_ErrorOnAllZeros(t *testing.T) {
	origKey := os.Getenv("LOCKBOX_TOKEN_HMAC_KEY")
	origDevMode := DevMode
	defer func() {
		os.Setenv("LOCKBOX_TOKEN_HMAC_KEY", origKey)
		DevMode = origDevMode
		reinitTokenHMACKey()
	}()

	// All zeros key in production
	os.Setenv("LOCKBOX_TOKEN_HMAC_KEY", "0000000000000000000000000000000000000000000000000000000000000000")
	DevMode = false

	_, err := loadTokenHMACKey()
	require.Error(t, err, "SECURITY: Must return error when HMAC key is all zeros in production")
	require.Contains(t, err.Error(), "all zeros")
}

func TestLoadTokenHMACKey_ValidKey(t *testing.T) {
	origKey := os.Getenv("LOCKBOX_TOKEN_HMAC_KEY")
	defer func() {
		os.Setenv("LOCKBOX_TOKEN_HMAC_KEY", origKey)
		reinitTokenHMACKey()
	}()

	// Valid 32-byte key
	os.Setenv("LOCKBOX_TOKEN_HMAC_KEY", "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")

	key, err := loadTokenHMACKey()
	require.NoError(t, err, "Valid key should not return error")
	require.Len(t, key, 32, "Key should be 32 bytes")
}

// ============================================
// Nonce Validation Tests
// ============================================

func TestCheckTokenNonce_Empty(t *testing.T) {
	svc := &Service{}
	result := svc.checkTokenNonce("")
	require.False(t, result, "Empty nonce should be invalid")
}

func TestCheckTokenNonce_TooShort(t *testing.T) {
	svc := &Service{}
	result := svc.checkTokenNonce("short")
	require.False(t, result, "Short nonce should be invalid")
}

func TestCheckTokenNonce_ValidFormat(t *testing.T) {
	svc := &Service{}
	// Format: "timestamp:random" with fresh timestamp
	timestamp := time.Now().Unix()
	nonce := fmt.Sprintf("%d:abcdef1234567890", timestamp)
	result := svc.checkTokenNonce(nonce)
	require.True(t, result, "Valid fresh nonce should be accepted")
}

func TestCheckTokenNonce_ExpiredTimestamp(t *testing.T) {
	svc := &Service{}
	// Timestamp from 10 minutes ago (beyond 5 min window)
	timestamp := time.Now().Add(-10 * time.Minute).Unix()
	nonce := fmt.Sprintf("%d:abcdef1234567890", timestamp)
	result := svc.checkTokenNonce(nonce)
	require.False(t, result, "Expired nonce should be rejected")
}

func TestCheckTokenNonce_FutureTimestamp(t *testing.T) {
	svc := &Service{}
	// Timestamp 5 minutes in the future (beyond 60s clock skew)
	timestamp := time.Now().Add(5 * time.Minute).Unix()
	nonce := fmt.Sprintf("%d:abcdef1234567890", timestamp)
	result := svc.checkTokenNonce(nonce)
	require.False(t, result, "Future nonce should be rejected")
}

func TestCheckTokenNonce_ReplayAttack(t *testing.T) {
	svc := &Service{}
	// Valid fresh nonce
	timestamp := time.Now().Unix()
	nonce := fmt.Sprintf("%d:replay_test_nonce", timestamp)

	// First use should succeed
	result1 := svc.checkTokenNonce(nonce)
	require.True(t, result1, "First use of nonce should succeed")

	// Second use should fail (replay attack)
	result2 := svc.checkTokenNonce(nonce)
	require.False(t, result2, "Replay of nonce should be rejected")
}

func TestCheckTokenNonce_LegacyFormatRejected(t *testing.T) {
	svc := &Service{}
	// Legacy nonce without timestamp should be rejected (fail-closed).
	randomBytes := make([]byte, 8)
	rand.Read(randomBytes)
	nonce := fmt.Sprintf("legacy_nonce_%x", randomBytes)
	result := svc.checkTokenNonce(nonce)
	require.False(t, result, "Legacy nonce format should be rejected")
}

func TestCheckTokenNonce_LegacyReplayRejected(t *testing.T) {
	svc := &Service{}
	// Legacy nonce with unique suffix should still fail on first use.
	randomBytes := make([]byte, 8)
	rand.Read(randomBytes)
	nonce := fmt.Sprintf("legacy_replay_%x", randomBytes)

	// First use should fail.
	result1 := svc.checkTokenNonce(nonce)
	require.False(t, result1, "Legacy nonce should be rejected")

	// Second use should also fail.
	result2 := svc.checkTokenNonce(nonce)
	require.False(t, result2, "Legacy nonce replay should stay rejected")
}

func TestCheckTokenNonce_ShortRandom(t *testing.T) {
	svc := &Service{}
	// Valid timestamp but random part too short
	timestamp := time.Now().Unix()
	nonce := fmt.Sprintf("%d:short", timestamp)
	result := svc.checkTokenNonce(nonce)
	require.False(t, result, "Nonce with short random part should be rejected")
}

func TestCheckTokenNonce_InvalidRandomCharacters(t *testing.T) {
	svc := &Service{}
	timestamp := time.Now().Unix()
	nonce := fmt.Sprintf("%d:abc1234567890|\n", timestamp)
	result := svc.checkTokenNonce(nonce)
	require.False(t, result, "Nonce with unsafe characters should be rejected")
}

// TestCheckTokenNonce_ConcurrentReplay tests that concurrent requests with
// the same nonce are properly rejected (only one succeeds).
//
// SECURITY: This test verifies the fix for HIGH-002 (TOCTOU race condition).
// Before the fix, two concurrent requests could both pass validation.
func TestCheckTokenNonce_ConcurrentReplay(t *testing.T) {
	svc := &Service{}

	// Create a valid nonce
	timestamp := time.Now().Unix()
	randomBytes := make([]byte, 16)
	rand.Read(randomBytes)
	nonce := fmt.Sprintf("%d:%x", timestamp, randomBytes)

	// Number of concurrent goroutines trying to use the same nonce
	numGoroutines := 100
	successCount := int32(0)

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	// Start all goroutines at the same time
	start := make(chan struct{})

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			<-start // Wait for signal
			if svc.checkTokenNonce(nonce) {
				atomic.AddInt32(&successCount, 1)
			}
		}()
	}

	// Release all goroutines simultaneously
	close(start)
	wg.Wait()

	// SECURITY: Exactly ONE request should succeed
	require.Equal(t, int32(1), successCount,
		"SECURITY: Exactly one concurrent request should succeed, got %d", successCount)
}
