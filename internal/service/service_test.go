package service

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/dueldanov/lockbox/v2/internal/lockscript"
	iotago "github.com/iotaledger/iota.go/v3"
)

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
	require.Equal(t, string(AssetStatusLocked), lockResp.Status)
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
	require.Equal(t, string(AssetStatusUnlocked), unlockResp.Status)
}

// TestScriptCompilation tests the compilation of a lock script.
func TestScriptCompilation(t *testing.T) {
	engine := lockscript.NewEngine(nil, 65536, 5*time.Second)
	script := `require(after(1700000000), "Too early to unlock")
	transfer(sender, amount, "IOTA")`
	compiled, err := engine.CompileScript(context.Background(), script)
	require.NoError(t, err)
	require.NotNil(t, compiled)
}

// TestAssetVerification tests the verification system for asset retrieval.
func TestAssetVerification(t *testing.T) {
	svc := setupTestService(t)
	addr := &iotago.Ed25519Address{}
	outputID := iotago.OutputID{}
	lockReq := &LockAssetRequest{
		OwnerAddress: addr,
		OutputID:     outputID,
		LockDuration: time.Second,
	}
	lockResp, err := svc.LockAsset(context.Background(), lockReq)
	require.NoError(t, err)

	// Wait for lock duration to expire
	time.Sleep(2 * time.Second)

	result, err := svc.VerifyAssetRetrieval(context.Background(), lockResp.AssetID, addr)
	require.NoError(t, err)
	require.True(t, result.Valid)
}

// setupTestService creates a test instance of the LockBox service.
func setupTestService(t *testing.T) *Service {
	// Mock or setup necessary dependencies for testing
	// This is a placeholder; actual implementation may require mocks or test DB setup
	return &Service{
		WrappedLogger: logger.NewWrappedLogger(logger.NewLogger("test")),
		config: &ServiceConfig{
			Tier: TierBasic,
		},
	}
}