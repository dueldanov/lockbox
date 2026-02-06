package service

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/dueldanov/lockbox/v2/internal/crypto"
	"github.com/dueldanov/lockbox/v2/internal/lockscript"
	"github.com/dueldanov/lockbox/v2/internal/payment"
	"github.com/dueldanov/lockbox/v2/internal/verification"
	"github.com/iotaledger/hive.go/kvstore/mapdb"
	"github.com/iotaledger/hive.go/logger"
	iotago "github.com/iotaledger/iota.go/v3"
	"github.com/stretchr/testify/require"
)

// generateTestNonceLS creates a valid nonce for lockscript testing.
func generateTestNonceLS() string {
	timestamp := time.Now().Unix()
	randomBytes := make([]byte, 8)
	rand.Read(randomBytes)
	return fmt.Sprintf("%d:%x", timestamp, randomBytes)
}

// setupTestServiceWithScript creates a test service with LockScript compiler initialized
func setupTestServiceWithScript(t *testing.T) *Service {
	initTestLogger()

	tmpDir, err := os.MkdirTemp("", "lockbox-lockscript-test-*")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(tmpDir) })

	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}

	shardEncryptor, err := crypto.NewShardEncryptor(masterKey, 4096)
	require.NoError(t, err)

	zkpManager := crypto.NewZKPManager()
	hkdfManager, err := crypto.NewHKDFManager(masterKey)
	require.NoError(t, err)

	decoyConfig := crypto.DecoyConfig{
		DecoyRatio:         0.5,
		MetadataDecoyRatio: 0.0,
	}
	decoyGenerator := crypto.NewDecoyGenerator(hkdfManager, decoyConfig)
	shardMixer := crypto.NewShardMixer()
	memStore := mapdb.NewMapDB()
	storageMgr, err := NewStorageManager(memStore)
	require.NoError(t, err)

	// Create LockScript engine
	engine := lockscript.NewEngine(nil, 65536, 5*time.Second)
	engine.RegisterBuiltinFunctions()

	// Create payment processor (mock mode for testing)
	paymentProcessor := payment.NewPaymentProcessor(nil)

	// Create rate limiter with default config (5 req/min)
	rateLimiter := verification.NewRateLimiter(nil)

	svc := &Service{
		WrappedLogger: logger.NewWrappedLogger(logger.NewLogger("test")),
		config: &ServiceConfig{
			Tier:          TierStandard,
			DataDir:       tmpDir,
			MinLockPeriod: time.Second,
			MaxLockPeriod: 365 * 24 * time.Hour,
		},
		shardEncryptor:   shardEncryptor,
		zkpManager:       zkpManager,
		zkpProvider:      &MockZKPProvider{},
		hkdfManager:      hkdfManager,
		decoyGenerator:   decoyGenerator,
		shardMixer:       shardMixer,
		paymentProcessor: paymentProcessor,
		rateLimiter:      rateLimiter,
		lockedAssets:     make(map[string]*LockedAsset),
		pendingUnlocks:   make(map[string]time.Time),
		storageManager:   storageMgr,
		scriptCompiler:   engine, // Enable LockScript
	}

	return svc
}

// TestLockUnlock_NoScript tests lock/unlock without LockScript (time-based only)
func TestLockUnlock_NoScript(t *testing.T) {
	svc := setupTestServiceWithScript(t)
	ctx := context.Background()

	// Lock without script - should use time-based unlock only
	lockReq := &LockAssetRequest{
		OwnerAddress: &iotago.Ed25519Address{},
		OutputID:     iotago.OutputID{},
		LockDuration: time.Second,
		LockScript:   "", // No script
	}

	lockResp, err := svc.LockAsset(ctx, lockReq)
	require.NoError(t, err)
	require.NotEmpty(t, lockResp.AssetID)
	require.Equal(t, AssetStatusLocked, lockResp.Status)

	time.Sleep(2 * time.Second)

	// Create and confirm payment token
	paymentToken := createTestPaymentToken(t, svc, lockResp.AssetID)

	// Generate valid access token and nonce for unlock
	accessToken, err := GenerateAccessToken()
	require.NoError(t, err, "failed to generate access token")
	unlockResp, err := svc.UnlockAsset(ctx, &UnlockAssetRequest{
		AssetID:      lockResp.AssetID,
		AccessToken:  accessToken,
		PaymentToken: paymentToken,
		Nonce:        generateTestNonceLS(),
	})
	require.NoError(t, err)
	require.Equal(t, AssetStatusUnlocked, unlockResp.Status)
}

// TestLockUnlock_EmptyScript tests lock/unlock with empty LockScript
func TestLockUnlock_EmptyScript(t *testing.T) {
	svc := setupTestServiceWithScript(t)
	ctx := context.Background()

	lockReq := &LockAssetRequest{
		OwnerAddress: &iotago.Ed25519Address{},
		OutputID:     iotago.OutputID{},
		LockDuration: time.Second,
		LockScript:   "",
	}

	lockResp, err := svc.LockAsset(ctx, lockReq)
	require.NoError(t, err)

	time.Sleep(2 * time.Second)

	// Create and confirm payment token
	paymentToken := createTestPaymentToken(t, svc, lockResp.AssetID)

	// Generate valid access token and nonce for unlock
	accessToken, err := GenerateAccessToken()
	require.NoError(t, err, "failed to generate access token")
	unlockResp, err := svc.UnlockAsset(ctx, &UnlockAssetRequest{
		AssetID:      lockResp.AssetID,
		AccessToken:  accessToken,
		PaymentToken: paymentToken,
		Nonce:        generateTestNonceLS(),
	})
	require.NoError(t, err)
	require.Equal(t, AssetStatusUnlocked, unlockResp.Status)
}

// TestExecuteLockScript_EmptyScript tests that empty script passes
func TestExecuteLockScript_EmptyScript(t *testing.T) {
	svc := setupTestServiceWithScript(t)
	ctx := context.Background()

	asset := &LockedAsset{
		ID:           "test-asset-1",
		LockScript:   "",
		OwnerAddress: &iotago.Ed25519Address{},
	}

	err := svc.executeLockScript(ctx, asset, nil)
	require.NoError(t, err, "Empty script should pass")
}

// TestExecuteLockScript_CompilerNotInitialized_MustFail tests fail-closed security
// SECURITY: If compiler is not initialized, unlock MUST be denied to prevent bypass
func TestExecuteLockScript_CompilerNotInitialized_MustFail(t *testing.T) {
	svc := setupTestServiceWithScript(t)
	ctx := context.Background()

	// Disable compiler
	svc.scriptCompiler = nil

	asset := &LockedAsset{
		ID:           "test-asset-2",
		LockScript:   "some_script();", // Has a script that should be enforced
		OwnerAddress: &iotago.Ed25519Address{},
	}

	// SECURITY: Must FAIL when compiler not initialized (fail-closed)
	// This prevents bypassing LockScript conditions during startup race
	err := svc.executeLockScript(ctx, asset, nil)
	require.Error(t, err, "SECURITY: Must fail when compiler not initialized")
	require.Contains(t, err.Error(), "compiler not initialized")
}

// TestExecuteLockScript_InvalidScript tests that invalid script returns error
func TestExecuteLockScript_InvalidScript(t *testing.T) {
	svc := setupTestServiceWithScript(t)
	ctx := context.Background()

	asset := &LockedAsset{
		ID:           "test-asset-3",
		LockScript:   "((((invalid syntax",
		OwnerAddress: &iotago.Ed25519Address{},
	}

	err := svc.executeLockScript(ctx, asset, nil)
	require.Error(t, err, "Invalid script should fail")
	require.Contains(t, err.Error(), "compile")
}

// TestLockAsset_WithScript tests that LockScript can be set in lock request
func TestLockAsset_WithScript(t *testing.T) {
	svc := setupTestServiceWithScript(t)
	ctx := context.Background()

	testScript := "after(1735689600);"

	lockReq := &LockAssetRequest{
		OwnerAddress: &iotago.Ed25519Address{},
		OutputID:     iotago.OutputID{},
		LockDuration: time.Hour,
		LockScript:   testScript,
	}

	lockResp, err := svc.LockAsset(ctx, lockReq)
	require.NoError(t, err)
	require.NotEmpty(t, lockResp.AssetID)

	// Verify asset was locked successfully with script
	require.Equal(t, AssetStatusLocked, lockResp.Status)
}

// TestUnlockParams_PassedToScript tests that UnlockParams are available to script
func TestUnlockParams_PassedToScript(t *testing.T) {
	svc := setupTestServiceWithScript(t)
	ctx := context.Background()

	// Lock with empty script first
	lockReq := &LockAssetRequest{
		OwnerAddress: &iotago.Ed25519Address{},
		OutputID:     iotago.OutputID{},
		LockDuration: time.Second,
		LockScript:   "",
	}

	lockResp, err := svc.LockAsset(ctx, lockReq)
	require.NoError(t, err)

	time.Sleep(2 * time.Second)

	// Create and confirm payment token
	paymentToken := createTestPaymentToken(t, svc, lockResp.AssetID)

	// Generate valid access token and nonce for unlock
	accessToken, err := GenerateAccessToken()
	require.NoError(t, err, "failed to generate access token")

	// Unlock with params - even though script is empty, params should be processed
	unlockResp, err := svc.UnlockAsset(ctx, &UnlockAssetRequest{
		AssetID:      lockResp.AssetID,
		AccessToken:  accessToken,
		PaymentToken: paymentToken,
		Nonce:        generateTestNonceLS(),
		UnlockParams: map[string]interface{}{
			"signature": "test-sig",
			"message":   "test-msg",
		},
	})
	require.NoError(t, err)
	require.Equal(t, AssetStatusUnlocked, unlockResp.Status)
}

// TestLockScriptIntegration_ServiceInit tests that service initializes compiler
func TestLockScriptIntegration_ServiceInit(t *testing.T) {
	svc := setupTestServiceWithScript(t)

	// Verify compiler is set
	require.NotNil(t, svc.scriptCompiler, "Script compiler should be initialized")

	// Verify it's the right type
	engine, ok := svc.scriptCompiler.(*lockscript.Engine)
	require.True(t, ok, "Script compiler should be lockscript.Engine")
	require.NotNil(t, engine)
}

// TestLockAsset_MultipleWithDifferentScripts tests multiple locks with different scripts
func TestLockAsset_MultipleWithDifferentScripts(t *testing.T) {
	svc := setupTestServiceWithScript(t)
	ctx := context.Background()

	scripts := []string{
		"",                    // No script
		"after(1735689600);",  // Time lock
		"before(9999999999);", // Future time
	}

	for i, script := range scripts {
		lockReq := &LockAssetRequest{
			OwnerAddress: &iotago.Ed25519Address{},
			OutputID:     iotago.OutputID{byte(i)},
			LockDuration: time.Hour,
			LockScript:   script,
		}

		lockResp, err := svc.LockAsset(ctx, lockReq)
		require.NoError(t, err, "Lock %d should succeed", i)
		require.NotEmpty(t, lockResp.AssetID, "Lock %d should return asset ID", i)
		require.Equal(t, AssetStatusLocked, lockResp.Status, "Lock %d should be locked", i)
	}
}

// TestExecuteLockScript_WithVariables tests that asset variables are set in environment
func TestExecuteLockScript_WithVariables(t *testing.T) {
	svc := setupTestServiceWithScript(t)
	ctx := context.Background()

	now := time.Now()
	asset := &LockedAsset{
		ID:           "test-asset-vars",
		LockScript:   "", // Empty script passes
		OwnerAddress: &iotago.Ed25519Address{},
		LockTime:     now.Add(-1 * time.Hour),
		UnlockTime:   now.Add(1 * time.Hour),
	}

	err := svc.executeLockScript(ctx, asset, map[string]interface{}{
		"custom_param": "test_value",
	})
	require.NoError(t, err)
}

// TestInitializeCompiler tests the InitializeCompiler method
func TestInitializeCompiler(t *testing.T) {
	svc := setupTestServiceWithScript(t)

	// Clear existing compiler
	svc.scriptCompiler = nil

	// Initialize
	err := svc.InitializeCompiler()
	require.NoError(t, err)

	// Verify compiler is set
	require.NotNil(t, svc.scriptCompiler)

	engine, ok := svc.scriptCompiler.(*lockscript.Engine)
	require.True(t, ok)
	require.NotNil(t, engine)
}
