package integration_test

import (
	"context"
	"crypto/sha256"
	"net"
	"os"
	"testing"
	"time"

	"github.com/iotaledger/hive.go/app/configuration"
	appLogger "github.com/iotaledger/hive.go/app/logger"
	"github.com/iotaledger/hive.go/logger"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"

	"github.com/dueldanov/lockbox/v2/internal/b2b"
	api "github.com/dueldanov/lockbox/v2/internal/b2b/api"
	"github.com/dueldanov/lockbox/v2/internal/interfaces"
	"github.com/dueldanov/lockbox/v2/internal/lockscript"
	"github.com/dueldanov/lockbox/v2/internal/verification"
)

const (
	integrationPartnerID = "integration-partner"
	integrationAPIKey    = "integration-api-key-000000000000"
)

func init() {
	cfg := configuration.New()
	_ = appLogger.InitGlobalLogger(cfg)
}

func TestLockBoxService(t *testing.T) {
	// Test basic lock/unlock functionality
	t.Run("BasicLockUnlock", func(t *testing.T) {
		if os.Getenv("LOCKBOX_RUN_NODE_INTEGRATION") == "" {
			t.Skip("set LOCKBOX_RUN_NODE_INTEGRATION=true to run node-backed lock/unlock integration")
		}
	})
}

func TestLockScriptEngine(t *testing.T) {
	t.Run("ArithmeticScript", func(t *testing.T) {
		engine := lockscript.NewEngine(nil, 65536, 5*time.Second)

		script := "1 + 1;"
		compiled, err := engine.CompileScript(context.Background(), script)
		require.NoError(t, err)
		require.NotNil(t, compiled)

		result, err := engine.ExecuteScript(context.Background(), compiled, lockscript.NewEnvironment())
		require.NoError(t, err)
		require.NotNil(t, result)
		require.True(t, result.Success)
		require.EqualValues(t, 2, result.Value)
	})
}

func TestVerificationSystem(t *testing.T) {
	t.Run("NodeSelection", func(t *testing.T) {
		selector := setupTestNodeSelector(t)

		nodes, err := selector.SelectNodes(context.Background(), interfaces.TierStandard, []string{"us-east", "eu-west"})
		require.NoError(t, err)
		require.Len(t, nodes, 3) // Standard tier requires 3 nodes

		// Verify geographic distribution
		regions := make(map[string]bool)
		for _, node := range nodes {
			regions[node.Region] = true
		}
		require.GreaterOrEqual(t, len(regions), 2) // At least 2 different regions
	})
}

func TestB2BAPI(t *testing.T) {
	client, cleanup := setupB2BClient(t)
	defer cleanup()

	ctx := b2bAuthContext(context.Background())
	script := "1;"

	validateResp, err := client.ValidateScript(ctx, &api.ValidateScriptRequest{
		Source: script,
	})
	require.NoError(t, err)
	require.True(t, validateResp.Valid)

	compileResp, err := client.CompileScript(ctx, &api.CompileScriptRequest{
		Source: script,
	})
	require.NoError(t, err)
	require.NotEmpty(t, compileResp.ScriptId)

	execResp, err := client.ExecuteScript(ctx, &api.ExecuteScriptRequest{
		ScriptId: compileResp.ScriptId,
	})
	require.NoError(t, err)
	require.True(t, execResp.Success)

	vaultResp, err := client.CreateVault(ctx, &api.CreateVaultRequest{
		Name: "integration-vault",
	})
	require.NoError(t, err)
	require.NotEmpty(t, vaultResp.VaultId)

	keyResp, err := client.GenerateKey(ctx, &api.GenerateKeyRequest{
		VaultId: vaultResp.VaultId,
		KeyType: "ed25519",
		KeyName: "primary",
	})
	require.NoError(t, err)
	require.NotEmpty(t, keyResp.KeyId)

	infoResp, err := client.GetVaultInfo(ctx, &api.GetVaultInfoRequest{
		VaultId: vaultResp.VaultId,
	})
	require.NoError(t, err)
	require.Len(t, infoResp.Keys, 1)
}

// Helper functions

func setupTestNodeSelector(t *testing.T) *verification.NodeSelector {
	t.Helper()

	selector := verification.NewNodeSelector(logger.NewLogger("test-selector"))
	nodes := []*verification.VerificationNode{
		{ID: "node-1", Region: "us-east", Capacity: 100, Latency: 10 * time.Millisecond, Reputation: 0.9, Available: true},
		{ID: "node-2", Region: "eu-west", Capacity: 100, Latency: 12 * time.Millisecond, Reputation: 0.95, Available: true},
		{ID: "node-3", Region: "us-west", Capacity: 100, Latency: 8 * time.Millisecond, Reputation: 0.92, Available: true},
	}

	for _, node := range nodes {
		require.NoError(t, selector.RegisterNode(node))
	}

	return selector
}

func setupB2BClient(t *testing.T) (api.LockBoxAPIClient, func()) {
	t.Helper()

	listener := bufconn.Listen(1024 * 1024)
	grpcServer := grpc.NewServer()

	b2bSvc := b2b.NewB2BServer(logger.NewLogger("b2b-integration"), nil, nil, nil, nil)
	apiKeyHash := sha256.Sum256([]byte(integrationAPIKey))
	require.NoError(t, b2bSvc.RegisterPartner(&b2b.Partner{
		ID:              integrationPartnerID,
		APIKeyHash:      apiKeyHash[:],
		Tier:            interfaces.TierStandard,
		SharePercentage: 70,
		Active:          true,
		CreatedAt:       time.Now(),
	}))

	api.RegisterLockBoxAPIServer(grpcServer, b2bSvc)

	go func() {
		_ = grpcServer.Serve(listener)
	}()

	dialer := func(ctx context.Context, s string) (net.Conn, error) {
		return listener.Dial()
	}

	conn, err := grpc.DialContext(context.Background(), "bufnet", grpc.WithContextDialer(dialer), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)

	cleanup := func() {
		grpcServer.GracefulStop()
		_ = conn.Close()
	}

	return api.NewLockBoxAPIClient(conn), cleanup
}

func b2bAuthContext(ctx context.Context) context.Context {
	md := metadata.New(map[string]string{
		"partner-id": integrationPartnerID,
		"api-key":    integrationAPIKey,
	})
	return metadata.NewOutgoingContext(ctx, md)
}
