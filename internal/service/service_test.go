package service

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/dueldanov/lockbox/v2/internal/crypto"
	"github.com/dueldanov/lockbox/v2/internal/lockscript"
	"github.com/iotaledger/hive.go/app/configuration"
	appLogger "github.com/iotaledger/hive.go/app/logger"
	"github.com/iotaledger/hive.go/kvstore/mapdb"
	"github.com/iotaledger/hive.go/logger"
	"github.com/stretchr/testify/require"
	iotago "github.com/iotaledger/iota.go/v3"
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

	unlockReq := &UnlockAssetRequest{AssetID: lockResp.AssetID}
	unlockResp, err := svc.UnlockAsset(context.Background(), unlockReq)
	require.NoError(t, err)
	require.Equal(t, AssetStatusUnlocked, unlockResp.Status)
}

// TestScriptCompilation tests the compilation of a lock script.
func TestScriptCompilation(t *testing.T) {
	engine := lockscript.NewEngine(nil, 65536, 5*time.Second)
	// Simple time-lock script
	script := `after(1700000000)`
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

	// Create in-memory storage for testing using mapdb
	memStore := mapdb.NewMapDB()

	// Create storage manager
	storageMgr, err := NewStorageManager(memStore)
	require.NoError(t, err)

	return &Service{
		WrappedLogger: logger.NewWrappedLogger(logger.NewLogger("test")),
		config: &ServiceConfig{
			Tier:          TierBasic,
			DataDir:       tmpDir,
			MinLockPeriod: time.Second,
			MaxLockPeriod: 365 * 24 * time.Hour,
		},
		shardEncryptor: shardEncryptor,
		zkpManager:     zkpManager,
		lockedAssets:   make(map[string]*LockedAsset),
		pendingUnlocks: make(map[string]time.Time),
		storageManager: storageMgr,
	}
}