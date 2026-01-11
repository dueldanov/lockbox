package logging

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewOperationLogger(t *testing.T) {
	logger := NewOperationLogger(OpStoreKey, "bundle-123", "req-456")

	assert.Equal(t, OpStoreKey, logger.operation)
	assert.Equal(t, "bundle-123", logger.bundleID)
	assert.Equal(t, "req-456", logger.requestID)
	assert.Empty(t, logger.entries)
}

func TestOperationLogger_Log(t *testing.T) {
	var buf bytes.Buffer
	logger := NewOperationLogger(OpStoreKey, "bundle-123", "req-456")
	logger.SetOutput(&buf)

	logger.Log(PhaseEncryption, "AES256GCMEncrypt()", StatusSuccess, 100*time.Millisecond, "test details")

	// Check entry was recorded
	entries := logger.GetEntries()
	require.Len(t, entries, 1)

	entry := entries[0]
	assert.Equal(t, OpStoreKey, entry.Operation)
	assert.Equal(t, PhaseEncryption, entry.Phase)
	assert.Equal(t, "AES256GCMEncrypt()", entry.Function)
	assert.Equal(t, StatusSuccess, entry.Status)
	assert.Equal(t, int64(100*time.Millisecond), entry.DurationNs)
	assert.Equal(t, "test details", entry.Details)
	assert.Equal(t, "bundle-123", entry.BundleID)
	assert.Equal(t, "req-456", entry.RequestID)

	// Check JSON output
	output := buf.String()
	assert.Contains(t, output, "Encryption")
	assert.Contains(t, output, "AES256GCMEncrypt")
	assert.Contains(t, output, "SUCCESS")
}

func TestOperationLogger_LogSuccess(t *testing.T) {
	var buf bytes.Buffer
	logger := NewOperationLogger(OpRetrieveKey, "bundle-123", "req-456")
	logger.SetOutput(&buf)

	logger.LogSuccess(PhaseTokenValidation, "validate_access_token()", 50*time.Millisecond, "token valid")

	entries := logger.GetEntries()
	require.Len(t, entries, 1)
	assert.Equal(t, StatusSuccess, entries[0].Status)
}

func TestOperationLogger_LogFailure(t *testing.T) {
	var buf bytes.Buffer
	logger := NewOperationLogger(OpRetrieveKey, "bundle-123", "req-456")
	logger.SetOutput(&buf)

	logger.LogFailure(PhasePayment, "validate_payment_tx()", 50*time.Millisecond, "payment invalid")

	entries := logger.GetEntries()
	require.Len(t, entries, 1)
	assert.Equal(t, StatusFailure, entries[0].Status)
}

func TestOperationLogger_LogWarning(t *testing.T) {
	var buf bytes.Buffer
	logger := NewOperationLogger(OpStoreKey, "bundle-123", "req-456")
	logger.SetOutput(&buf)

	logger.LogWarning(PhaseMemorySecurity, "tryLockMemory()", 10*time.Millisecond, "lock failed")

	entries := logger.GetEntries()
	require.Len(t, entries, 1)
	assert.Equal(t, StatusWarning, entries[0].Status)
}

func TestOperationLogger_LogWithExtras(t *testing.T) {
	var buf bytes.Buffer
	logger := NewOperationLogger(OpRotateKey, "bundle-old", "req-456")
	logger.SetOutput(&buf)

	logger.LogWithExtras(PhaseMetadataUpdate, "increment_version()", StatusSuccess, 100*time.Millisecond,
		map[string]interface{}{
			"new_bundle_id":  "bundle-new",
			"version_from":   "v1",
			"version_to":     "v2",
			"nodes_selected": 5,
			"shards_count":   24,
		})

	entries := logger.GetEntries()
	require.Len(t, entries, 1)

	entry := entries[0]
	assert.Equal(t, "bundle-new", entry.NewBundleID)
	assert.Equal(t, "v1", entry.VersionFrom)
	assert.Equal(t, "v2", entry.VersionTo)
	assert.Equal(t, 5, entry.NodesSelected)
	assert.Equal(t, 24, entry.ShardsCount)
}

func TestOperationLogger_SecurityAlert(t *testing.T) {
	var buf bytes.Buffer
	logger := NewOperationLogger(OpStoreKey, "bundle-123", "req-456")
	logger.SetOutput(&buf)

	logger.SecurityAlert(PhaseEncryption, "AES256GCMEncrypt()", "Encryption failed")

	entries := logger.GetEntries()
	require.Len(t, entries, 1)

	entry := entries[0]
	assert.Equal(t, StatusFailure, entry.Status)
	assert.Contains(t, entry.Details, "SECURITY ALERT")

	output := buf.String()
	assert.Contains(t, output, "SECURITY ALERT")
}

func TestOperationLogger_Summary(t *testing.T) {
	logger := NewOperationLogger(OpStoreKey, "bundle-123", "req-456")

	logger.LogSuccess(PhaseEncryption, "encrypt1", 10*time.Millisecond, "")
	logger.LogSuccess(PhaseEncryption, "encrypt2", 10*time.Millisecond, "")
	logger.LogFailure(PhaseSharding, "shard1", 5*time.Millisecond, "")
	logger.LogWarning(PhaseMetadata, "meta1", 5*time.Millisecond, "")

	summary := logger.Summary()

	assert.Contains(t, summary, "STORE_KEY")
	assert.Contains(t, summary, "bundle-123")
	assert.Contains(t, summary, "Total: 4")
	assert.Contains(t, summary, "Success: 2")
	assert.Contains(t, summary, "Failures: 1")
	assert.Contains(t, summary, "Warnings: 1")
}

func TestOperationLogger_JSONOutput(t *testing.T) {
	var buf bytes.Buffer
	logger := NewOperationLogger(OpStoreKey, "bundle-123", "req-456")
	logger.SetOutput(&buf)

	logger.Log(PhaseEncryption, "test_func()", StatusSuccess, 100*time.Millisecond, "test")

	// Parse the JSON output
	var entry LogEntry
	err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &entry)
	require.NoError(t, err)

	assert.Equal(t, OpStoreKey, entry.Operation)
	assert.Equal(t, PhaseEncryption, entry.Phase)
	assert.Equal(t, "test_func()", entry.Function)
	assert.Equal(t, StatusSuccess, entry.Status)
}

func TestLockBoxError(t *testing.T) {
	err := NewError(ErrCodeTokenInvalid, "Token is invalid", "service", SeverityCritical, false)

	assert.Equal(t, ErrCodeTokenInvalid, err.Code)
	assert.Equal(t, "Token is invalid", err.Message)
	assert.Equal(t, "service", err.Component)
	assert.Equal(t, SeverityCritical, err.Severity)
	assert.False(t, err.Recoverable)

	// Test Error() interface
	errStr := err.Error()
	assert.Contains(t, errStr, "CRITICAL")
	assert.Contains(t, errStr, "TOKEN_INVALID")
	assert.Contains(t, errStr, "Token is invalid")
}

func TestNewCriticalError(t *testing.T) {
	err := NewCriticalError(ErrCodeEncryptionFailed, "Encryption failed", "crypto")

	assert.Equal(t, SeverityCritical, err.Severity)
	assert.False(t, err.Recoverable)
}

func TestNewRecoverableError(t *testing.T) {
	err := NewRecoverableError(ErrCodeNodeUnavailable, "Node temporarily unavailable", "network", 30)

	assert.Equal(t, SeverityWarning, err.Severity)
	assert.True(t, err.Recoverable)
	assert.Equal(t, 30, err.RetryAfter)
}

func TestStoreKeyLogger(t *testing.T) {
	var buf bytes.Buffer
	logger := NewStoreKeyLogger("bundle-123", "req-456")
	logger.SetOutput(&buf)

	// Test various phase logs
	logger.LogValidateLength(10*time.Millisecond, 64, true)
	logger.LogSetTierConfig(5*time.Millisecond, "Standard", 1.0)
	logger.LogGenerateBundleID(2*time.Millisecond, "bundle-123")
	logger.LogDeriveHKDFKey(50*time.Millisecond, "real-char")
	logger.LogEncrypt(100*time.Millisecond, "shard", true)
	logger.LogSplitKey(200*time.Millisecond, 24)
	logger.LogCreateDecoys(50*time.Millisecond, 12, 0.5)
	logger.LogGenerateZKP(150*time.Millisecond, "ownership", "Standard", true)
	logger.LogSubmitBundle(500*time.Millisecond, 5, true)
	logger.LogSecureWipe(10*time.Millisecond, 256, true)

	entries := logger.GetEntries()
	assert.Len(t, entries, 10)

	// All should be success
	for _, entry := range entries {
		assert.Equal(t, StatusSuccess, entry.Status)
	}
}

func TestStoreKeyLogger_EncryptionFailure(t *testing.T) {
	var buf bytes.Buffer
	logger := NewStoreKeyLogger("bundle-123", "req-456")
	logger.SetOutput(&buf)

	logger.LogEncrypt(100*time.Millisecond, "shard", false)

	entries := logger.GetEntries()
	// Should have 2 entries: security alert + failure log
	assert.Len(t, entries, 2)

	// Check security alert was logged
	output := buf.String()
	assert.Contains(t, output, "SECURITY ALERT")
}

func TestRetrieveKeyLogger(t *testing.T) {
	var buf bytes.Buffer
	logger := NewRetrieveKeyLogger("bundle-123", "req-456")
	logger.SetOutput(&buf)

	logger.LogValidateAccessToken(10*time.Millisecond, true)
	logger.LogCheckTokenNonce(5*time.Millisecond, true)
	logger.LogValidatePayment(100*time.Millisecond, "LockBox", true)
	logger.LogCalculateFee(5*time.Millisecond, 0.015, "USD")
	logger.LogRecordRevenueShare(10*time.Millisecond, "partner-1", 0.0075)
	logger.LogGenerateOwnershipZKP(150*time.Millisecond, "ownership", "Standard", true)
	logger.LogParallelFetch(500*time.Millisecond, 24, true)
	logger.LogAssembleKey(10*time.Millisecond, 64, true)
	logger.LogGenerateNewToken(20*time.Millisecond, true)

	entries := logger.GetEntries()
	assert.Len(t, entries, 9)
}

func TestRotateKeyLogger(t *testing.T) {
	var buf bytes.Buffer
	logger := NewRotateKeyLogger("bundle-old", "req-456")
	logger.SetOutput(&buf)
	logger.SetNewBundleID("bundle-new")

	logger.LogVerifyInterval(10*time.Millisecond, 35, true)
	logger.LogReencryptShards(1*time.Second, 24, true)
	logger.LogIncrementVersion(5*time.Millisecond, "v1", "v2")
	logger.LogGarbageCollect(10*time.Millisecond, true)

	entries := logger.GetEntries()
	assert.Len(t, entries, 4)

	// Check version increment entry
	versionEntry := entries[2]
	assert.Equal(t, "v1", versionEntry.VersionFrom)
	assert.Equal(t, "v2", versionEntry.VersionTo)
}

func TestDeleteKeyLogger(t *testing.T) {
	var buf bytes.Buffer
	logger := NewDeleteKeyLogger("bundle-123", "req-456")
	logger.SetOutput(&buf)

	logger.LogEnumerateShards(50*time.Millisecond, 24)
	logger.LogDistributeDestruction(200*time.Millisecond, 5, true)
	logger.LogConfirmDestruction(100*time.Millisecond, true)
	logger.LogCleanupTokens(10*time.Millisecond, true)

	entries := logger.GetEntries()
	assert.Len(t, entries, 4)

	// Check nodes affected
	distEntry := entries[1]
	assert.Equal(t, 5, distEntry.NodesAffected)
}

func TestFormatDetails(t *testing.T) {
	tests := []struct {
		input    []interface{}
		expected string
	}{
		{[]interface{}{}, ""},
		{[]interface{}{"key", "value"}, "key=value"},
		{[]interface{}{"a", 1, "b", 2}, "a=1, b=2"},
		{[]interface{}{"tier", "Standard", "ratio", 1.5}, "tier=Standard, ratio=1.5"},
	}

	for _, tt := range tests {
		result := formatDetails(tt.input...)
		assert.Equal(t, tt.expected, result)
	}
}

func TestConcurrentLogging(t *testing.T) {
	var buf bytes.Buffer
	logger := NewOperationLogger(OpStoreKey, "bundle-123", "req-456")
	logger.SetOutput(&buf)

	// Log from multiple goroutines
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(idx int) {
			logger.Log(PhaseEncryption, "concurrent_func()", StatusSuccess, time.Millisecond, "")
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	entries := logger.GetEntries()
	assert.Len(t, entries, 10)
}

func TestErrorCodes(t *testing.T) {
	codes := []string{
		ErrCodeTokenInvalid,
		ErrCodeTokenExpired,
		ErrCodeNonceInvalid,
		ErrCodeOwnershipInvalid,
		ErrCodePaymentInvalid,
		ErrCodePaymentInsufficient,
		ErrCodeIntervalTooShort,
		ErrCodeRotationFailed,
		ErrCodeDestructionIncomplete,
		ErrCodeEncryptionFailed,
		ErrCodeDecryptionFailed,
		ErrCodeZKPFailed,
		ErrCodeSignatureFailed,
		ErrCodeNodeUnavailable,
		ErrCodeShardFetchFailed,
		ErrCodeMemoryWipeFailed,
	}

	for _, code := range codes {
		assert.NotEmpty(t, code)
	}
}

func TestOperationConstants(t *testing.T) {
	assert.Equal(t, Operation("STORE_KEY"), OpStoreKey)
	assert.Equal(t, Operation("RETRIEVE_KEY"), OpRetrieveKey)
	assert.Equal(t, Operation("ROTATE_KEY"), OpRotateKey)
	assert.Equal(t, Operation("DELETE_KEY"), OpDeleteKey)
}

func TestPhaseConstants(t *testing.T) {
	// Test some key phases exist
	phases := []string{
		PhaseInputValidation,
		PhaseKeyDerivation,
		PhaseEncryption,
		PhaseDigitalSignatures,
		PhaseSharding,
		PhaseZKP,
		PhaseMetadata,
		PhaseNetworkSubmission,
		PhaseConnection,
		PhaseMemorySecurity,
		PhaseAudit,
		PhaseTokenValidation,
		PhasePayment,
		PhaseOwnership,
		PhaseMultiSig,
		PhaseCoordinator,
		PhaseTripleVerification,
		PhaseBundleRetrieval,
		PhaseShardFetch,
		PhaseKeyReconstruction,
		PhaseTokenRotation,
		PhaseIntervalValidation,
		PhaseShardRetrieval,
		PhaseNewKeyGeneration,
		PhaseReEncryption,
		PhaseNodeSelection,
		PhaseDAGSubmission,
		PhaseMetadataUpdate,
		PhaseShardEnumeration,
		PhaseDestructionDistribution,
		PhaseGarbageCollection,
		PhaseDestructionConfirmation,
		PhaseTokenCleanup,
	}

	for _, phase := range phases {
		assert.NotEmpty(t, phase)
	}
}
