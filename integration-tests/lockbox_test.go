package integration_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	
	"github.com/iotaledger/lockbox/v2/lockbox"
	"github.com/iotaledger/lockbox/v2/lockbox/lockscript"
	iotago "github.com/iotaledger/iota.go/v3"
)

func TestLockBoxService(t *testing.T) {
	// Test basic lock/unlock functionality
	t.Run("BasicLockUnlock", func(t *testing.T) {
		service := setupTestService(t)
		
		addr := &iotago.Ed25519Address{}
		outputID := iotago.OutputID{}
		
		// Lock asset
		lockReq := &lockbox.LockAssetRequest{
			OwnerAddress: addr,
			OutputID:     outputID,
			LockDuration: 24 * time.Hour,
		}
		
		lockResp, err := service.LockAsset(context.Background(), lockReq)
		require.NoError(t, err)
		require.NotEmpty(t, lockResp.AssetID)
		require.Equal(t, string(lockbox.AssetStatusLocked), lockResp.Status)
		
		// Try to unlock before time
		unlockReq := &lockbox.UnlockAssetRequest{
			AssetID: lockResp.AssetID,
		}
		
		_, err = service.UnlockAsset(context.Background(), unlockReq)
		require.Error(t, err) // Should fail as lock period hasn't expired
	})
}

func TestLockScriptEngine(t *testing.T) {
	t.Run("TimeBasedScript", func(t *testing.T) {
		engine := lockscript.NewEngine(nil, 65536, 5*time.Second)
		
		script := `
			require(after(1700000000), "Too early to unlock")
			transfer(sender, amount, "IOTA")
		`
		
		compiled, err := engine.CompileScript(context.Background(), script)
		require.NoError(t, err)
		require.NotNil(t, compiled)
		
		env := &lockscript.Environment{
			Variables: map[string]interface{}{
				"sender": "addr1",
				"amount": int64(1000),
			},
			Timestamp: time.Now(),
		}
		
		result, err := engine.ExecuteScript(context.Background(), compiled, env)
		require.NoError(t, err)
		require.NotNil(t, result)
	})
}

func TestVerificationSystem(t *testing.T) {
	t.Run("NodeSelection", func(t *testing.T) {
		selector := setupTestNodeSelector(t)
		
		nodes, err := selector.SelectNodes(context.Background(), lockbox.TierStandard, []string{"us-east", "eu-west"})
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
	t.Run("CompileScript", func(t *testing.T) {
		server := setupTestB2BServer(t)
		defer server.Stop()
		
		// Test script compilation via B2B API
		req := &api.CompileScriptRequest{
			Source: `require(true, "Always succeeds")`,
		}
		
		resp, err := server.CompileScript(context.Background(), req)
		require.NoError(t, err)
		require.NotEmpty(t, resp.ScriptId)
		require.NotEmpty(t, resp.Bytecode)
	})
}

// Helper functions

func setupTestService(t *testing.T) *lockbox.Service {
	// Setup test service with mock dependencies
	// Implementation details omitted for brevity
	return nil
}

func setupTestNodeSelector(t *testing.T) *verification.NodeSelector {
	// Setup test node selector
	// Implementation details omitted for brevity
	return nil
}

func setupTestB2BServer(t *testing.T) *b2b.Server {
	// Setup test B2B server
	// Implementation details omitted for brevity
	return nil
}