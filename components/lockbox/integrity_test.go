package lockbox

import (
	"os"
	"testing"

	"github.com/dueldanov/lockbox/v2/internal/crypto"
	"github.com/stretchr/testify/require"
)

// TestVerifyBinaryIntegrity_DevMode tests dev mode (no hash set)
func TestVerifyBinaryIntegrity_DevMode(t *testing.T) {
	// Get current executable path
	execPath, err := os.Executable()
	require.NoError(t, err)

	// Empty hash = dev mode
	err = verifyBinaryIntegrityWithLogger(execPath, "", nil)
	require.NoError(t, err, "Dev mode should not fail verification")
}

// TestVerifyBinaryIntegrity_ProductionMode tests production mode with valid hash
func TestVerifyBinaryIntegrity_ProductionMode_ValidHash(t *testing.T) {
	// Get current executable path
	execPath, err := os.Executable()
	require.NoError(t, err)

	// Calculate actual hash
	actualHash, err := crypto.CalculateBinaryHash(execPath)
	require.NoError(t, err)

	// Should succeed with correct hash
	err = verifyBinaryIntegrityWithLogger(execPath, actualHash, nil)
	require.NoError(t, err, "Production mode should succeed with correct hash")
}

// TestVerifyBinaryIntegrity_ProductionMode_InvalidHash tests production mode with wrong hash
func TestVerifyBinaryIntegrity_ProductionMode_InvalidHash(t *testing.T) {
	// Get current executable path
	execPath, err := os.Executable()
	require.NoError(t, err)

	// WRONG hash
	fakeHash := "0000000000000000000000000000000000000000000000000000000000000000"

	// Should FAIL with wrong hash
	err = verifyBinaryIntegrityWithLogger(execPath, fakeHash, nil)
	require.Error(t, err, "Production mode MUST fail with incorrect hash")
	require.Contains(t, err.Error(), "hash mismatch", "Error should mention hash mismatch")
}

// TestBinaryHashCalculation tests that hash calculation is deterministic
func TestBinaryHashCalculation(t *testing.T) {
	execPath, err := os.Executable()
	require.NoError(t, err)

	// Calculate hash twice
	hash1, err := crypto.CalculateBinaryHash(execPath)
	require.NoError(t, err)

	hash2, err := crypto.CalculateBinaryHash(execPath)
	require.NoError(t, err)

	// Should be identical
	require.Equal(t, hash1, hash2, "Hash calculation should be deterministic")
	require.Len(t, hash1, 64, "SHA-256 hash should be 64 hex characters")
}
