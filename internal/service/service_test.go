package service

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/dueldanov/lockbox/v2/internal/crypto"
	"github.com/dueldanov/lockbox/v2/internal/interfaces"
	"github.com/dueldanov/lockbox/v2/internal/lockscript"
	"github.com/dueldanov/lockbox/v2/internal/payment"
	"github.com/dueldanov/lockbox/v2/internal/verification"
	"github.com/iotaledger/hive.go/app/configuration"
	appLogger "github.com/iotaledger/hive.go/app/logger"
	"github.com/iotaledger/hive.go/kvstore/mapdb"
	"github.com/iotaledger/hive.go/logger"
	iotago "github.com/iotaledger/iota.go/v3"
	"github.com/stretchr/testify/require"
)

// MockZKPProvider implements interfaces.ZKPProvider for testing
// Returns deterministic mock proofs without actual ZKP computation
type MockZKPProvider struct{}

func (m *MockZKPProvider) GenerateOwnershipProof(assetID []byte, ownerSecret []byte) (*interfaces.OwnershipProof, error) {
	return &interfaces.OwnershipProof{
		AssetCommitment: assetID,       // Mock: use assetID as commitment
		OwnerAddress:    ownerSecret,   // Mock: use secret as address
		Timestamp:       time.Now().Unix(),
	}, nil
}

func (m *MockZKPProvider) VerifyOwnershipProof(proof *interfaces.OwnershipProof) error {
	return nil // Always valid in tests
}

func (m *MockZKPProvider) GenerateUnlockProof(unlockSecret, assetID, additionalData []byte, unlockTime int64) (*interfaces.UnlockProof, error) {
	return &interfaces.UnlockProof{
		UnlockCommitment: assetID,
		UnlockTime:       unlockTime,
		CurrentTime:      time.Now().Unix(),
	}, nil
}

func (m *MockZKPProvider) VerifyUnlockProof(proof *interfaces.UnlockProof) error {
	return nil // Always valid in tests
}

var initLoggerOnce sync.Once

// initTestLogger initializes the global logger for tests and enables dev mode.
func initTestLogger() {
	initLoggerOnce.Do(func() {
		DevMode = true
		cfg := configuration.New()
		// Ignore error - global logger may already be initialized
		_ = appLogger.InitGlobalLogger(cfg)
	})
}

// TestLockAsset tests the locking of an asset via the LockBox service.
func TestLockAsset(t *testing.T) {
	svc := setupTestService(t)
	addr := &iotago.Ed25519Address{}
	outputID := iotago.OutputID{}
	lockReq := &LockAssetRequest{
		OwnerAddress: addr,
		OutputID:     outputID,
		LockDuration: 24 * time.Hour,
	}
	lockResp, err := svc.LockAsset(context.Background(), lockReq)
	require.NoError(t, err)
	require.NotEmpty(t, lockResp.AssetID)
	require.Equal(t, AssetStatusLocked, lockResp.Status)
}

// TestUnlockAsset tests the unlocking of an asset after lock duration.
func TestUnlockAsset(t *testing.T) {
	svc := setupTestService(t)
	addr := &iotago.Ed25519Address{}
	outputID := iotago.OutputID{}
	// Lock asset with short duration for testing
	lockReq := &LockAssetRequest{
		OwnerAddress: addr,
		OutputID:     outputID,
		LockDuration: time.Second,
	}
	lockResp, err := svc.LockAsset(context.Background(), lockReq)
	require.NoError(t, err)

	// Wait for lock duration to expire
	time.Sleep(2 * time.Second)

	// Create and confirm payment token
	paymentToken := createTestPaymentToken(t, svc, lockResp.AssetID)

	// Generate valid access token and nonce for unlock
	accessToken, err := GenerateAccessToken()
	require.NoError(t, err, "failed to generate access token")
	nonce := generateTestNonce()
	unlockReq := &UnlockAssetRequest{
		AssetID:      lockResp.AssetID,
		AccessToken:  accessToken,  // SECURITY: Use generated HMAC token
		PaymentToken: paymentToken, // SECURITY: Single-use payment token
		Nonce:        nonce,        // SECURITY: Required for replay protection
	}
	unlockResp, err := svc.UnlockAsset(context.Background(), unlockReq)
	require.NoError(t, err)
	require.Equal(t, AssetStatusUnlocked, unlockResp.Status)
}

// generateTestNonce creates a valid nonce for testing.
// Format: timestamp_random (current time + random suffix)
func generateTestNonce() string {
	timestamp := time.Now().Unix()
	randomBytes := make([]byte, 8)
	rand.Read(randomBytes)
	return fmt.Sprintf("%d_%x", timestamp, randomBytes)
}

// TestScriptCompilation tests the compilation of a lock script.
func TestScriptCompilation(t *testing.T) {
	engine := lockscript.NewEngine(nil, 65536, 5*time.Second)
	// Simple time-lock script
	script := `after(1700000000);`
	compiled, err := engine.CompileScript(context.Background(), script)
	require.NoError(t, err)
	require.NotNil(t, compiled)
}

// setupTestService creates a test instance of the LockBox service.
func setupTestService(t *testing.T) *Service {
	// Initialize global logger for tests
	initTestLogger()

	// Create a temporary directory for test data
	tmpDir, err := os.MkdirTemp("", "lockbox-test-*")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(tmpDir) })

	// Create master key for encryption
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}

	// Initialize crypto components
	shardEncryptor, err := crypto.NewShardEncryptor(masterKey, 4096)
	require.NoError(t, err)

	zkpManager := crypto.NewZKPManager()

	// Add HKDF manager
	hkdfManager, err := crypto.NewHKDFManager(masterKey)
	require.NoError(t, err)

	// Add decoy generator with Basic tier config (0.5 ratio)
	decoyConfig := crypto.DecoyConfig{
		DecoyRatio:         0.5,
		MetadataDecoyRatio: 0.0,
	}
	decoyGenerator := crypto.NewDecoyGenerator(hkdfManager, decoyConfig)

	// Add shard mixer
	shardMixer := crypto.NewShardMixer()

	// Create in-memory storage for testing using mapdb
	memStore := mapdb.NewMapDB()

	// Create storage manager
	storageMgr, err := NewStorageManager(memStore)
	require.NoError(t, err)

	// Create payment processor (mock mode for testing)
	paymentProcessor := payment.NewPaymentProcessor(nil)

	// Create rate limiter with default config (5 req/min)
	rateLimiter := verification.NewRateLimiter(nil)

	return &Service{
		WrappedLogger: logger.NewWrappedLogger(logger.NewLogger("test")),
		config: &ServiceConfig{
			Tier:          TierBasic,
			DataDir:       tmpDir,
			MinLockPeriod: time.Second,
			MaxLockPeriod: 365 * 24 * time.Hour,
		},
		shardEncryptor:   shardEncryptor,
		zkpManager:       zkpManager,
		zkpProvider:      &MockZKPProvider{}, // Use mock for tests - avoids gnark constraint issues
		hkdfManager:      hkdfManager,
		decoyGenerator:   decoyGenerator,
		shardMixer:       shardMixer,
		paymentProcessor: paymentProcessor,
		rateLimiter:      rateLimiter,
		lockedAssets:     make(map[string]*LockedAsset),
		pendingUnlocks:   make(map[string]time.Time),
		storageManager:   storageMgr,
	}
}