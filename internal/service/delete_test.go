package service

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// ============================================
// Token Validation Tests
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
	// 64 chars but not valid hex
	token := "ghijklmnopqrstuvwxyz123456789012345678901234567890123456789012"
	result := svc.validateAccessToken(token)
	require.False(t, result, "Invalid hex should be rejected")
}

func TestValidateAccessToken_Valid(t *testing.T) {
	svc := &Service{}
	// Valid 64-char hex token (32 bytes)
	token := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	result := svc.validateAccessToken(token)
	require.True(t, result, "Valid hex token should be accepted")
}

func TestValidateAccessToken_ValidUppercase(t *testing.T) {
	svc := &Service{}
	// Valid uppercase hex
	token := "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
	result := svc.validateAccessToken(token)
	require.True(t, result, "Valid uppercase hex token should be accepted")
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

func TestCheckTokenNonce_LegacyFormat(t *testing.T) {
	svc := &Service{}
	// Legacy nonce without timestamp (at least 16 chars)
	nonce := "legacy_nonce_1234567890"
	result := svc.checkTokenNonce(nonce)
	require.True(t, result, "Legacy nonce with sufficient length should be accepted")
}

func TestCheckTokenNonce_LegacyReplay(t *testing.T) {
	svc := &Service{}
	// Legacy nonce
	nonce := "legacy_replay_test_1234"

	// First use should succeed
	result1 := svc.checkTokenNonce(nonce)
	require.True(t, result1, "First use of legacy nonce should succeed")

	// Second use should fail
	result2 := svc.checkTokenNonce(nonce)
	require.False(t, result2, "Replay of legacy nonce should be rejected")
}

func TestCheckTokenNonce_ShortRandom(t *testing.T) {
	svc := &Service{}
	// Valid timestamp but random part too short
	timestamp := time.Now().Unix()
	nonce := fmt.Sprintf("%d:short", timestamp)
	result := svc.checkTokenNonce(nonce)
	require.False(t, result, "Nonce with short random part should be rejected")
}
