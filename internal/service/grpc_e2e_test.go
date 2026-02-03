package service

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/dueldanov/lockbox/v2/internal/crypto"
	"github.com/dueldanov/lockbox/v2/internal/interfaces"
	pb "github.com/dueldanov/lockbox/v2/internal/proto"
	"github.com/dueldanov/lockbox/v2/pkg/tpkg"
	"github.com/iotaledger/hive.go/kvstore/mapdb"
	"github.com/iotaledger/hive.go/logger"
	iotago "github.com/iotaledger/iota.go/v3"
)

// mockZKPProvider implements interfaces.ZKPProvider for E2E testing
// Returns deterministic mock proofs without actual ZKP computation
type mockZKPProvider struct{}

func (m *mockZKPProvider) GenerateOwnershipProof(assetID []byte, ownerSecret []byte) (*interfaces.OwnershipProof, error) {
	return &interfaces.OwnershipProof{
		AssetCommitment: assetID,
		OwnerAddress:    ownerSecret,
		Timestamp:       time.Now().Unix(),
	}, nil
}

func (m *mockZKPProvider) VerifyOwnershipProof(proof *interfaces.OwnershipProof) error {
	return nil
}

func (m *mockZKPProvider) GenerateUnlockProof(unlockSecret, assetID, additionalData []byte, unlockTime int64) (*interfaces.UnlockProof, error) {
	return &interfaces.UnlockProof{
		UnlockCommitment: assetID,
		UnlockTime:       unlockTime,
		CurrentTime:      time.Now().Unix(),
	}, nil
}

func (m *mockZKPProvider) VerifyUnlockProof(proof *interfaces.UnlockProof) error {
	return nil
}

// TestGRPC_GetServiceInfo tests the GetServiceInfo endpoint via gRPC
func TestGRPC_GetServiceInfo(t *testing.T) {
	// Enable dev mode for insecure gRPC
	os.Setenv("LOCKBOX_DEV_MODE", "true")
	defer os.Unsetenv("LOCKBOX_DEV_MODE")

	// Create test service
	svc := createTestService(t)

	// Start gRPC server on random port
	addr := listenTestGRPC(t)

	grpcServer, err := NewGRPCServer(svc, nil, addr, false, "", "")
	require.NoError(t, err)

	// Start server in goroutine
	go func() {
		if err := grpcServer.Start(); err != nil {
			t.Logf("gRPC server stopped: %v", err)
		}
	}()
	defer grpcServer.Stop()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Create client
	conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	client := pb.NewLockBoxServiceClient(conn)

	// Test GetServiceInfo
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	resp, err := client.GetServiceInfo(ctx, &pb.GetServiceInfoRequest{})
	require.NoError(t, err)
	require.NotNil(t, resp)

	t.Logf("Service Info: version=%s, tier=%s, maxLockTime=%d",
		resp.Version, resp.Tier, resp.MaxLockTime)

	require.Equal(t, "1.0.0", resp.Version)
	require.NotEmpty(t, resp.Tier)
	require.True(t, resp.MaxLockTime > 0)
}

// TestGRPC_LockAsset_Flow tests the Lock → GetStatus flow via gRPC
func TestGRPC_LockAsset_Flow(t *testing.T) {
	os.Setenv("LOCKBOX_DEV_MODE", "true")
	defer os.Unsetenv("LOCKBOX_DEV_MODE")

	svc := createTestService(t)

	// Start gRPC server
	addr := listenTestGRPC(t)

	grpcServer, err := NewGRPCServer(svc, nil, addr, false, "", "")
	require.NoError(t, err)

	go func() {
		grpcServer.Start()
	}()
	defer grpcServer.Stop()
	time.Sleep(100 * time.Millisecond)

	// Create client
	conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	client := pb.NewLockBoxServiceClient(conn)
	ctx := context.Background()

	// Test LockAsset
	// Generate a valid IOTA Ed25519 address
	iotaAddr := tpkg.RandAddress(iotago.AddressEd25519)
	ownerAddr := iotaAddr.Bech32(iotago.PrefixTestnet)
	outputID := make([]byte, 34) // IOTA OutputID is 34 bytes

	lockResp, err := client.LockAsset(ctx, &pb.LockAssetRequest{
		OwnerAddress:        ownerAddr,
		OutputId:            outputID,
		LockDurationSeconds: 3600, // 1 hour
		LockScript:          "after(unlock_time)",
	})
	require.NoError(t, err, "LockAsset should succeed")
	require.NotEmpty(t, lockResp.AssetId)
	require.Equal(t, "locked", lockResp.Status)

	t.Logf("Locked asset: ID=%s, LockTime=%d, UnlockTime=%d, Status=%s",
		lockResp.AssetId, lockResp.LockTime, lockResp.UnlockTime, lockResp.Status)

	// Test GetAssetStatus
	statusResp, err := client.GetAssetStatus(ctx, &pb.GetAssetStatusRequest{
		AssetId: lockResp.AssetId,
	})
	require.NoError(t, err, "GetAssetStatus should succeed")
	require.Equal(t, lockResp.AssetId, statusResp.AssetId)
	require.Equal(t, "locked", statusResp.Status)

	t.Logf("Asset status: ID=%s, Status=%s, Owner=%s",
		statusResp.AssetId, statusResp.Status, statusResp.OwnerAddress)
}

// TestGRPC_UnlockAsset_BeforeTime tests that unlock fails before unlock_time
func TestGRPC_UnlockAsset_BeforeTime(t *testing.T) {
	os.Setenv("LOCKBOX_DEV_MODE", "true")
	defer os.Unsetenv("LOCKBOX_DEV_MODE")

	svc := createTestService(t)

	// Start gRPC server
	addr := listenTestGRPC(t)

	grpcServer, err := NewGRPCServer(svc, nil, addr, false, "", "")
	require.NoError(t, err)

	go func() {
		grpcServer.Start()
	}()
	defer grpcServer.Stop()
	time.Sleep(100 * time.Millisecond)

	conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	client := pb.NewLockBoxServiceClient(conn)
	ctx := context.Background()

	// Lock asset for 1 hour
	iotaAddr := tpkg.RandAddress(iotago.AddressEd25519)
	ownerAddr := iotaAddr.Bech32(iotago.PrefixTestnet)
	outputID := make([]byte, 34)

	lockResp, err := client.LockAsset(ctx, &pb.LockAssetRequest{
		OwnerAddress:        ownerAddr,
		OutputId:            outputID,
		LockDurationSeconds: 3600,
	})
	require.NoError(t, err)

	// Try to unlock immediately (should fail - asset still locked)
	_, err = client.UnlockAsset(ctx, &pb.UnlockAssetRequest{
		AssetId:     lockResp.AssetId,
		AccessToken: "test-token",
		Nonce:       fmt.Sprintf("nonce-%d", time.Now().UnixNano()),
	})
	require.Error(t, err, "UnlockAsset should fail before unlock_time")
	t.Logf("Expected error: %v", err)
}

// TestGRPC_EmergencyUnlock tests the emergency unlock endpoint
func TestGRPC_EmergencyUnlock(t *testing.T) {
	os.Setenv("LOCKBOX_DEV_MODE", "true")
	defer os.Unsetenv("LOCKBOX_DEV_MODE")

	// Create service with emergency unlock enabled (uses createTestService)
	svc := createTestService(t)

	// Start gRPC server
	addr := listenTestGRPC(t)

	grpcServer, err := NewGRPCServer(svc, nil, addr, false, "", "")
	require.NoError(t, err)

	go func() {
		grpcServer.Start()
	}()
	defer grpcServer.Stop()
	time.Sleep(100 * time.Millisecond)

	conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	client := pb.NewLockBoxServiceClient(conn)
	ctx := context.Background()

	// Lock asset
	iotaAddr := tpkg.RandAddress(iotago.AddressEd25519)
	ownerAddr := iotaAddr.Bech32(iotago.PrefixTestnet)
	outputID := make([]byte, 34)

	lockResp, err := client.LockAsset(ctx, &pb.LockAssetRequest{
		OwnerAddress:        ownerAddr,
		OutputId:            outputID,
		LockDurationSeconds: 86400, // 1 day
	})
	require.NoError(t, err)

	// Emergency unlock
	emergencyResp, err := client.EmergencyUnlock(ctx, &pb.EmergencyUnlockRequest{
		AssetId: lockResp.AssetId,
		Reason:  "Test emergency unlock",
	})
	require.NoError(t, err)
	require.Equal(t, "emergency", emergencyResp.Status)

	t.Logf("Emergency unlock: ID=%s, Status=%s, UnlockTime=%d",
		emergencyResp.AssetId, emergencyResp.Status, emergencyResp.UnlockTime)
}

// createTestService creates a properly initialized service for testing
func createTestService(t *testing.T) *Service {
	t.Helper()

	// Initialize test logger
	initTestLogger()

	// Generate a test master key
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}

	// Initialize crypto components
	shardEncryptor, err := crypto.NewShardEncryptor(masterKey, 4096)
	require.NoError(t, err)

	hkdfManager, err := crypto.NewHKDFManager(masterKey)
	require.NoError(t, err)

	tierCaps := GetCapabilities(TierStandard)
	decoyConfig := crypto.DecoyConfig{
		DecoyRatio:         tierCaps.DecoyRatio,
		MetadataDecoyRatio: tierCaps.MetadataDecoyRatio,
	}
	decoyGenerator := crypto.NewDecoyGenerator(hkdfManager, decoyConfig)
	shardMixer := crypto.NewShardMixer()

	// Create in-memory storage for testing
	memStore := mapdb.NewMapDB()
	storageMgr, err := NewStorageManager(memStore)
	require.NoError(t, err)

	return &Service{
		WrappedLogger: logger.NewWrappedLogger(logger.NewLogger("test")),
		config: &ServiceConfig{
			Tier:                  TierStandard,
			DataDir:               t.TempDir(),
			MinLockPeriod:         time.Minute,
			MaxLockPeriod:         365 * 24 * time.Hour,
			EnableEmergencyUnlock: true,
			EmergencyDelayDays:    7,
		},
		lockedAssets:   make(map[string]*LockedAsset),
		pendingUnlocks: make(map[string]time.Time),
		storageManager: storageMgr,
		shardEncryptor: shardEncryptor,
		hkdfManager:    hkdfManager,
		decoyGenerator: decoyGenerator,
		shardMixer:     shardMixer,
		zkpProvider:    &mockZKPProvider{}, // Use mock for tests - avoids gnark constraint issues
	}
}
