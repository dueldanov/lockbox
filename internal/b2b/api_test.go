package b2b

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/dueldanov/lockbox/v2/internal/b2b/api"
)

// TestCompileScript tests the gRPC endpoint for script compilation.
func TestCompileScript(t *testing.T) {
	server := setupTestB2BServer(t)
	defer server.Stop()

	req := &api.CompileScriptRequest{
		Source: `require(true, "Always succeeds")`,
	}
	resp, err := server.CompileScript(context.Background(), req)
	require.NoError(t, err)
	require.NotEmpty(t, resp.ScriptId)
	require.NotEmpty(t, resp.Bytecode)
}

// TestExecuteScript tests the execution of a compiled script via gRPC.
func TestExecuteScript(t *testing.T) {
	server := setupTestB2BServer(t)
	defer server.Stop()

	// First compile a script
	compileReq := &api.CompileScriptRequest{
		Source: `require(true, "Always succeeds")`,
	}
	compileResp, err := server.CompileScript(context.Background(), compileReq)
	require.NoError(t, err)

	// Then execute it
	execReq := &api.ExecuteScriptRequest{
		ScriptId: compileResp.ScriptId,
	}
	execResp, err := server.ExecuteScript(context.Background(), execReq)
	require.NoError(t, err)
	require.True(t, execResp.Success)
}

// setupTestB2BServer sets up a test B2B server for gRPC testing.
func setupTestB2BServer(t *testing.T) *Server {
	// Mock or setup necessary dependencies
	// This is a placeholder; actual implementation may require mocks
	return &Server{
		// Add necessary fields or mocks
	}
}