package verification

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/dueldanov/lockbox/v2/internal/interfaces"
	"github.com/iotaledger/hive.go/app/configuration"
	appLogger "github.com/iotaledger/hive.go/app/logger"
	"github.com/iotaledger/hive.go/logger"
	"github.com/stretchr/testify/require"
)

var initLoggerOnce sync.Once

// initTestLogger initializes the global logger for tests
func initTestLogger() {
	initLoggerOnce.Do(func() {
		cfg := configuration.New()
		// Ignore error - global logger may already be initialized
		_ = appLogger.InitGlobalLogger(cfg)
	})
}

// TestNodeSelection tests the selection of nodes for verification based on tier.
func TestNodeSelection(t *testing.T) {
	selector := setupTestNodeSelector(t)
	nodes, err := selector.SelectNodes(context.Background(), interfaces.TierStandard, []string{"us-east", "eu-west"})
	require.NoError(t, err)
	require.Len(t, nodes, 3) // Standard tier requires 3 nodes
	regions := make(map[string]bool)
	for _, node := range nodes {
		regions[node.Region] = true
	}
	require.GreaterOrEqual(t, len(regions), 2) // Ensure geographic diversity
}

// TestTokenRotation tests token rotation functionality.
func TestTokenRotation(t *testing.T) {
	initTestLogger()
	tokenMgr := NewTokenManager(logger.NewLogger("test"), time.Second, 5*time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go tokenMgr.Start(ctx)

	// Wait for initial token generation
	time.Sleep(100 * time.Millisecond)
	initialToken := tokenMgr.GetCurrentToken()
	require.NotNil(t, initialToken)

	// Wait for rotation
	time.Sleep(1100 * time.Millisecond)
	newToken := tokenMgr.GetCurrentToken()
	require.NotNil(t, newToken)
	require.NotEqual(t, initialToken.ID, newToken.ID)
	require.True(t, tokenMgr.ValidateToken(newToken.ID))
	// Old token is still valid within grace period (tokenValidity = 5s)
	// This is intentional - grace period prevents race conditions during rotation
	require.True(t, tokenMgr.ValidateToken(initialToken.ID))
}

// TestRetryMechanism tests the retry mechanism for verification failures.
func TestRetryMechanism(t *testing.T) {
	initTestLogger()
	retryMgr := NewRetryManager(logger.NewLogger("test"), DefaultRetryConfig())
	attempts := 0
	err := retryMgr.RetryWithBackoff(context.Background(), "test-retry", func(ctx context.Context) error {
		attempts++
		if attempts < 3 {
			return errors.New("temporary failure")
		}
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, 3, attempts)
}

// setupTestNodeSelector sets up a test node selector with mock nodes.
func setupTestNodeSelector(t *testing.T) *NodeSelector {
	initTestLogger()
	selector := NewNodeSelector(logger.NewLogger("test"))
	// Add mock nodes for different regions
	helper := &VerificationTestHelper{}
	helper.AddNode("us-east", 100, 50*time.Millisecond)
	helper.AddNode("us-west", 100, 60*time.Millisecond)
	helper.AddNode("eu-west", 100, 70*time.Millisecond)
	for _, node := range helper.nodes {
		err := selector.RegisterNode(node)
		require.NoError(t, err)
	}
	return selector
}

// VerificationTestHelper helps create test nodes for verification tests
type VerificationTestHelper struct {
	nodes []*VerificationNode
}

// AddNode adds a test node with given region, reliability and latency
func (h *VerificationTestHelper) AddNode(region string, reliability int, latency time.Duration) {
	h.nodes = append(h.nodes, &VerificationNode{
		ID:         region + "-node",
		Region:     region,
		Capacity:   100,
		Latency:    latency,
		Reputation: float64(reliability) / 100.0,
		Available:  true,
	})
}

// ============================================
// VerifySignature Tests (Ed25519)
// ============================================

func setupTestVerifier(t *testing.T) *Verifier {
	initTestLogger()
	return &Verifier{
		WrappedLogger: logger.NewWrappedLogger(logger.NewLogger("test")),
	}
}

func TestVerifySignature_Valid(t *testing.T) {
	v := setupTestVerifier(t)

	// Generate Ed25519 key pair
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	message := []byte("test message for signing")
	signature := ed25519.Sign(privKey, message)

	// Verify with correct signature
	result := v.VerifySignature(message, signature, pubKey)
	require.True(t, result, "Valid signature should verify")
}

func TestVerifySignature_Invalid(t *testing.T) {
	v := setupTestVerifier(t)

	// Generate Ed25519 key pair
	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	message := []byte("test message for signing")
	// Create a fake signature (64 bytes of zeros)
	fakeSignature := make([]byte, ed25519.SignatureSize)

	// Verify with fake signature
	result := v.VerifySignature(message, fakeSignature, pubKey)
	require.False(t, result, "Invalid signature should not verify")
}

func TestVerifySignature_WrongKey(t *testing.T) {
	v := setupTestVerifier(t)

	// Generate two different key pairs
	_, privKey1, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pubKey2, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	message := []byte("test message for signing")
	signature := ed25519.Sign(privKey1, message)

	// Verify with wrong public key
	result := v.VerifySignature(message, signature, pubKey2)
	require.False(t, result, "Signature should not verify with wrong key")
}

func TestVerifySignature_WrongKeySize(t *testing.T) {
	v := setupTestVerifier(t)

	// Wrong size public key
	wrongSizePubKey := make([]byte, 16) // Should be 32
	message := []byte("test message")
	signature := make([]byte, ed25519.SignatureSize)

	result := v.VerifySignature(message, signature, wrongSizePubKey)
	require.False(t, result, "Wrong size public key should fail")
}

func TestVerifySignature_WrongSignatureSize(t *testing.T) {
	v := setupTestVerifier(t)

	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	message := []byte("test message")
	wrongSizeSignature := make([]byte, 32) // Should be 64

	result := v.VerifySignature(message, wrongSizeSignature, pubKey)
	require.False(t, result, "Wrong size signature should fail")
}

// ============================================
// Token Replay Tests (SECURITY_TESTING.md compliance)
// ============================================

// TestTokenManager_AfterGracePeriod tests that old tokens are invalid after grace period
func TestTokenManager_AfterGracePeriod(t *testing.T) {
	initTestLogger()

	// Create token manager with very short rotation and validity for testing
	// rotationInterval = 100ms, tokenValidity = 200ms
	tokenMgr := NewTokenManager(logger.NewLogger("test"), 100*time.Millisecond, 200*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go tokenMgr.Start(ctx)

	// Wait for initial token generation
	time.Sleep(50 * time.Millisecond)
	initialToken := tokenMgr.GetCurrentToken()
	require.NotNil(t, initialToken, "Initial token should be generated")

	// Wait for rotation + grace period expiry (100ms rotation + 200ms validity + buffer)
	time.Sleep(350 * time.Millisecond)

	// Old token should now be invalid (past grace period)
	valid := tokenMgr.ValidateToken(initialToken.ID)
	require.False(t, valid, "SECURITY: Old token after grace period MUST be invalid!")

	// New token should be valid
	newToken := tokenMgr.GetCurrentToken()
	require.NotNil(t, newToken, "New token should exist")
	require.NotEqual(t, initialToken.ID, newToken.ID, "Token should have rotated")
	require.True(t, tokenMgr.ValidateToken(newToken.ID), "Current token should be valid")
}

// TestTokenManager_ReplayAttack tests that tokens cannot be replayed after rotation
func TestTokenManager_ReplayAttack(t *testing.T) {
	initTestLogger()

	// Very short timers for testing
	tokenMgr := NewTokenManager(logger.NewLogger("test"), 50*time.Millisecond, 100*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go tokenMgr.Start(ctx)

	// Wait for initial token
	time.Sleep(30 * time.Millisecond)
	token1 := tokenMgr.GetCurrentToken()
	require.NotNil(t, token1)

	// Store the token ID for "replay"
	stolenTokenID := token1.ID

	// Wait for multiple rotations
	time.Sleep(200 * time.Millisecond)

	// Attempt to "replay" the old token - MUST fail
	replayValid := tokenMgr.ValidateToken(stolenTokenID)
	require.False(t, replayValid, "SECURITY: Replayed token MUST be rejected!")
}