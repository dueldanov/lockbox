package b2b

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/iotaledger/hive.go/app/configuration"
	appLogger "github.com/iotaledger/hive.go/app/logger"
	"github.com/iotaledger/hive.go/logger"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/dueldanov/lockbox/v2/internal/b2b/api"
	"github.com/dueldanov/lockbox/v2/internal/interfaces"
	"github.com/dueldanov/lockbox/v2/internal/payment"
)

// testAPIKey is the API key for the test partner (32 bytes)
const testAPIKey = "12345678901234567890123456789012"

// testPartner is a registered test partner.
// APIKeyHash is the SHA-256 hash of testAPIKey (produced by hashAPIKey).
var testPartner = &Partner{
	ID:              "test-partner-1",
	APIKeyHash:      hashAPIKey(testAPIKey),
	Tier:            interfaces.TierStandard,
	SharePercentage: 70.0,
	Active:          true,
	CreatedAt:       time.Now(),
}

func init() {
	// Initialize global logger once
	cfg := configuration.New()
	_ = appLogger.InitGlobalLogger(cfg)
}

// setupTestB2BServer creates a B2B server for testing.
// Uses nil lockbox service - only tests authentication and validation.
func setupTestB2BServer(t *testing.T) *B2BServer {
	t.Helper()

	// Create payment processor
	paymentProcessor := payment.NewPaymentProcessor(nil)

	// Create B2B server without lockbox service
	log := logger.NewLogger("b2b-test")
	server := NewB2BServer(log, nil, nil, paymentProcessor, nil)

	// Register test partner
	err := server.RegisterPartner(testPartner)
	require.NoError(t, err)

	return server
}

// =============================================================================
// Partner Registration Tests
// =============================================================================

func TestRegisterPartner_Success(t *testing.T) {
	log := logger.NewLogger("b2b-test")
	server := NewB2BServer(log, nil, nil, nil, nil)

	partner := &Partner{
		ID:              "new-partner",
		APIKeyHash:      []byte("new-api-key-hash"),
		Tier:            interfaces.TierPremium,
		SharePercentage: 75.0,
		Active:          true,
	}

	err := server.RegisterPartner(partner)
	require.NoError(t, err)
}

func TestRegisterPartner_Duplicate(t *testing.T) {
	log := logger.NewLogger("b2b-test")
	server := NewB2BServer(log, nil, nil, nil, nil)

	partner := &Partner{
		ID:              "dup-partner",
		APIKeyHash:      []byte("api-key"),
		Tier:            interfaces.TierBasic,
		SharePercentage: 70.0,
		Active:          true,
	}

	err := server.RegisterPartner(partner)
	require.NoError(t, err)

	// Try to register again
	err = server.RegisterPartner(partner)
	require.Error(t, err)
	require.Contains(t, err.Error(), "already registered")
}

// =============================================================================
// Authentication Tests
// =============================================================================

func TestAuthentication_Success(t *testing.T) {
	server := setupTestB2BServer(t)

	partner, err := server.authenticatePartner(testPartner.ID, testAPIKey)
	require.NoError(t, err)
	require.NotNil(t, partner)
	require.Equal(t, testPartner.ID, partner.ID)
}

func TestAuthentication_InactivePartner(t *testing.T) {
	log := logger.NewLogger("b2b-test")
	server := NewB2BServer(log, nil, nil, nil, nil)

	inactivePartner := &Partner{
		ID:              "inactive-partner",
		APIKeyHash:      []byte("test-key"),
		Tier:            interfaces.TierBasic,
		SharePercentage: 70.0,
		Active:          false, // Inactive
	}

	err := server.RegisterPartner(inactivePartner)
	require.NoError(t, err)

	// Try to authenticate
	_, err = server.authenticatePartner("inactive-partner", "test-key")
	require.Error(t, err)
	require.Contains(t, err.Error(), "inactive")
}

func TestAuthentication_UnknownPartner(t *testing.T) {
	server := setupTestB2BServer(t)

	_, err := server.authenticatePartner("unknown-partner", "some-key")
	require.Error(t, err)
	require.Contains(t, err.Error(), "not found")
}

func TestAuthentication_WrongAPIKey(t *testing.T) {
	server := setupTestB2BServer(t)

	_, err := server.authenticatePartner(testPartner.ID, "wrong-api-key")
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid API key")
}

func TestAuthentication_EmptyPartnerID(t *testing.T) {
	server := setupTestB2BServer(t)

	_, err := server.authenticatePartner("", "api-key")
	require.Error(t, err)
	require.Contains(t, err.Error(), "partner_id is required")
}

func TestAuthentication_EmptyAPIKey(t *testing.T) {
	server := setupTestB2BServer(t)

	_, err := server.authenticatePartner("partner-id", "")
	require.Error(t, err)
	require.Contains(t, err.Error(), "api_key is required")
}

// =============================================================================
// StoreKey Validation Tests (without full service)
// =============================================================================

func TestStoreKey_MissingPrivateKey(t *testing.T) {
	server := setupTestB2BServer(t)
	ctx := context.Background()

	req := &api.StoreKeyRequest{
		PartnerId:           testPartner.ID,
		ApiKey:              testAPIKey,
		PrivateKey:          nil, // Missing
		OwnerAddress:        hex.EncodeToString(make([]byte, 32)),
		LockDurationSeconds: 3600,
	}

	_, err := server.StoreKey(ctx, req)
	require.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, codes.InvalidArgument, st.Code())
	require.Contains(t, st.Message(), "private_key is required")
}

func TestStoreKey_MissingOwnerAddress(t *testing.T) {
	server := setupTestB2BServer(t)
	ctx := context.Background()

	req := &api.StoreKeyRequest{
		PartnerId:           testPartner.ID,
		ApiKey:              testAPIKey,
		PrivateKey:          make([]byte, 32),
		OwnerAddress:        "", // Missing
		LockDurationSeconds: 3600,
	}

	_, err := server.StoreKey(ctx, req)
	require.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, codes.InvalidArgument, st.Code())
	require.Contains(t, st.Message(), "owner_address is required")
}

func TestStoreKey_InvalidLockDuration(t *testing.T) {
	server := setupTestB2BServer(t)
	ctx := context.Background()

	req := &api.StoreKeyRequest{
		PartnerId:           testPartner.ID,
		ApiKey:              testAPIKey,
		PrivateKey:          make([]byte, 32),
		OwnerAddress:        hex.EncodeToString(make([]byte, 32)),
		LockDurationSeconds: 0, // Invalid
	}

	_, err := server.StoreKey(ctx, req)
	require.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, codes.InvalidArgument, st.Code())
	require.Contains(t, st.Message(), "lock_duration")
}

func TestStoreKey_InvalidOwnerAddressFormat(t *testing.T) {
	server := setupTestB2BServer(t)
	ctx := context.Background()

	req := &api.StoreKeyRequest{
		PartnerId:           testPartner.ID,
		ApiKey:              testAPIKey,
		PrivateKey:          make([]byte, 32),
		OwnerAddress:        "not-an-address",
		LockDurationSeconds: 3600,
	}

	_, err := server.StoreKey(ctx, req)
	require.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, codes.InvalidArgument, st.Code())
	require.Contains(t, st.Message(), "invalid owner_address")
}

func TestStoreKey_InvalidMultiSigAddress(t *testing.T) {
	server := setupTestB2BServer(t)
	ctx := context.Background()

	req := &api.StoreKeyRequest{
		PartnerId:           testPartner.ID,
		ApiKey:              testAPIKey,
		PrivateKey:          make([]byte, 32),
		OwnerAddress:        hex.EncodeToString(make([]byte, 32)),
		LockDurationSeconds: 3600,
		MultiSigAddresses:   []string{"bad-multisig"},
	}

	_, err := server.StoreKey(ctx, req)
	require.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, codes.InvalidArgument, st.Code())
	require.Contains(t, st.Message(), "invalid multi_sig_address")
}

func TestStoreKey_ServiceUnavailable(t *testing.T) {
	server := setupTestB2BServer(t)
	ctx := context.Background()

	req := &api.StoreKeyRequest{
		PartnerId:           testPartner.ID,
		ApiKey:              testAPIKey,
		PrivateKey:          make([]byte, 32),
		OwnerAddress:        hex.EncodeToString(make([]byte, 32)),
		LockDurationSeconds: 3600,
	}

	_, err := server.StoreKey(ctx, req)
	require.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, codes.Unavailable, st.Code())
	require.Contains(t, st.Message(), "lockbox service not initialized")
}

func TestStoreKey_InvalidPartner(t *testing.T) {
	server := setupTestB2BServer(t)
	ctx := context.Background()

	req := &api.StoreKeyRequest{
		PartnerId:           "unknown-partner",
		ApiKey:              "test-api-key",
		PrivateKey:          make([]byte, 32),
		OwnerAddress:        hex.EncodeToString(make([]byte, 32)),
		LockDurationSeconds: 3600,
	}

	_, err := server.StoreKey(ctx, req)
	require.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, codes.Unauthenticated, st.Code())
}

func TestStoreKey_InvalidAPIKey(t *testing.T) {
	server := setupTestB2BServer(t)
	ctx := context.Background()

	req := &api.StoreKeyRequest{
		PartnerId:           testPartner.ID,
		ApiKey:              "wrong-api-key",
		PrivateKey:          make([]byte, 32),
		OwnerAddress:        hex.EncodeToString(make([]byte, 32)),
		LockDurationSeconds: 3600,
	}

	_, err := server.StoreKey(ctx, req)
	require.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, codes.Unauthenticated, st.Code())
}

// =============================================================================
// RetrieveKey Validation Tests
// =============================================================================

func TestRetrieveKey_MissingBundleId(t *testing.T) {
	server := setupTestB2BServer(t)
	ctx := context.Background()

	req := &api.RetrieveKeyRequest{
		PartnerId:    testPartner.ID,
		ApiKey:       testAPIKey,
		BundleId:     "", // Missing
		AccessToken:  "some-access-token",
		PaymentToken: "some-payment-token",
		Nonce:        generateTestNonce(),
	}

	_, err := server.RetrieveKey(ctx, req)
	require.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, codes.InvalidArgument, st.Code())
	require.Contains(t, st.Message(), "bundle_id is required")
}

func TestRetrieveKey_MissingAccessToken(t *testing.T) {
	server := setupTestB2BServer(t)
	ctx := context.Background()

	req := &api.RetrieveKeyRequest{
		PartnerId:    testPartner.ID,
		ApiKey:       testAPIKey,
		BundleId:     "some-bundle-id",
		AccessToken:  "", // Missing
		PaymentToken: "some-payment-token",
		Nonce:        generateTestNonce(),
	}

	_, err := server.RetrieveKey(ctx, req)
	require.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, codes.InvalidArgument, st.Code())
	require.Contains(t, st.Message(), "access_token is required")
}

func TestRetrieveKey_MissingPaymentToken(t *testing.T) {
	server := setupTestB2BServer(t)
	ctx := context.Background()

	req := &api.RetrieveKeyRequest{
		PartnerId:    testPartner.ID,
		ApiKey:       testAPIKey,
		BundleId:     "some-bundle-id",
		AccessToken:  "some-access-token",
		PaymentToken: "", // Missing
		Nonce:        generateTestNonce(),
	}

	_, err := server.RetrieveKey(ctx, req)
	require.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, codes.InvalidArgument, st.Code())
	require.Contains(t, st.Message(), "payment_token is required")
}

func TestRetrieveKey_MissingNonce(t *testing.T) {
	server := setupTestB2BServer(t)
	ctx := context.Background()

	req := &api.RetrieveKeyRequest{
		PartnerId:    testPartner.ID,
		ApiKey:       testAPIKey,
		BundleId:     "some-bundle-id",
		AccessToken:  "some-access-token",
		PaymentToken: "some-payment-token",
		Nonce:        "", // Missing
	}

	_, err := server.RetrieveKey(ctx, req)
	require.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, codes.InvalidArgument, st.Code())
	require.Contains(t, st.Message(), "nonce is required")
}

func TestRetrieveKey_InvalidPartner(t *testing.T) {
	server := setupTestB2BServer(t)
	ctx := context.Background()

	req := &api.RetrieveKeyRequest{
		PartnerId:    "unknown-partner",
		ApiKey:       "test-api-key",
		BundleId:     "some-bundle-id",
		AccessToken:  "some-access-token",
		PaymentToken: "some-payment-token",
		Nonce:        generateTestNonce(),
	}

	_, err := server.RetrieveKey(ctx, req)
	require.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, codes.Unauthenticated, st.Code())
}

func TestRetrieveKey_BundlePartnerMismatch(t *testing.T) {
	server := setupTestB2BServer(t)
	ctx := context.Background()

	server.bundlePartnersMu.Lock()
	server.bundlePartners["bundle-mismatch"] = "other-partner"
	server.bundlePartnersMu.Unlock()

	req := &api.RetrieveKeyRequest{
		PartnerId:    testPartner.ID,
		ApiKey:       testAPIKey,
		BundleId:     "bundle-mismatch",
		AccessToken:  "some-access-token",
		PaymentToken: "some-payment-token",
		Nonce:        generateTestNonce(),
	}

	_, err := server.RetrieveKey(ctx, req)
	require.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, codes.PermissionDenied, st.Code())
	require.Contains(t, st.Message(), "bundle does not belong")
}

func TestRetrieveKey_ServiceUnavailable(t *testing.T) {
	server := setupTestB2BServer(t)
	ctx := context.Background()

	req := &api.RetrieveKeyRequest{
		PartnerId:    testPartner.ID,
		ApiKey:       testAPIKey,
		BundleId:     "bundle-1",
		AccessToken:  "some-access-token",
		PaymentToken: "some-payment-token",
		Nonce:        generateTestNonce(),
	}

	_, err := server.RetrieveKey(ctx, req)
	require.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, codes.Unavailable, st.Code())
	require.Contains(t, st.Message(), "lockbox service not initialized")
}

// =============================================================================
// GetRevenueShare Tests
// =============================================================================

func TestGetRevenueShare_Success(t *testing.T) {
	server := setupTestB2BServer(t)
	ctx := context.Background()

	req := &api.GetRevenueShareRequest{
		PartnerId: testPartner.ID,
		ApiKey:    testAPIKey,
	}

	resp, err := server.GetRevenueShare(ctx, req)
	require.NoError(t, err)
	require.Equal(t, testPartner.ID, resp.PartnerId)
	require.Equal(t, testPartner.SharePercentage, resp.SharePercentage)
}

func TestGetRevenueShare_UnknownPartner(t *testing.T) {
	server := setupTestB2BServer(t)
	ctx := context.Background()

	req := &api.GetRevenueShareRequest{
		PartnerId: "unknown-partner",
		ApiKey:    "test-api-key",
	}

	_, err := server.GetRevenueShare(ctx, req)
	require.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, codes.Unauthenticated, st.Code())
}

// =============================================================================
// GetPartnerStats Tests
// =============================================================================

func TestGetPartnerStats_Success(t *testing.T) {
	server := setupTestB2BServer(t)
	ctx := context.Background()

	req := &api.GetPartnerStatsRequest{
		PartnerId: testPartner.ID,
		ApiKey:    testAPIKey,
	}

	resp, err := server.GetPartnerStats(ctx, req)
	require.NoError(t, err)
	require.Equal(t, testPartner.ID, resp.PartnerId)
}

func TestGetPartnerStats_UnknownPartner(t *testing.T) {
	server := setupTestB2BServer(t)
	ctx := context.Background()

	req := &api.GetPartnerStatsRequest{
		PartnerId: "unknown-partner",
		ApiKey:    "test-api-key",
	}

	_, err := server.GetPartnerStats(ctx, req)
	require.Error(t, err)

	st, ok := status.FromError(err)
	require.True(t, ok)
	require.Equal(t, codes.Unauthenticated, st.Code())
}

// =============================================================================
// Script/Vault/Account/Transaction Tests
// =============================================================================

func TestCompileValidateExecuteScript(t *testing.T) {
	server := setupTestB2BServer(t)
	ctx := b2bAuthContext(context.Background())
	script := "1;"

	validateResp, err := server.ValidateScript(ctx, &api.ValidateScriptRequest{
		Source: script,
	})
	require.NoError(t, err)
	require.True(t, validateResp.Valid)

	compileResp, err := server.CompileScript(ctx, &api.CompileScriptRequest{
		Source: script,
	})
	require.NoError(t, err)
	require.NotEmpty(t, compileResp.ScriptId)
	require.NotEmpty(t, compileResp.Bytecode)

	execResp, err := server.ExecuteScript(ctx, &api.ExecuteScriptRequest{
		ScriptId: compileResp.ScriptId,
	})
	require.NoError(t, err)
	require.True(t, execResp.Success)
}

func TestVaultKeyLifecycle(t *testing.T) {
	server := setupTestB2BServer(t)
	ctx := b2bAuthContext(context.Background())

	createResp, err := server.CreateVault(ctx, &api.CreateVaultRequest{
		Name: "test-vault",
	})
	require.NoError(t, err)
	require.NotEmpty(t, createResp.VaultId)

	keyResp, err := server.GenerateKey(ctx, &api.GenerateKeyRequest{
		VaultId: createResp.VaultId,
		KeyType: "ed25519",
		KeyName: "primary",
	})
	require.NoError(t, err)
	require.NotEmpty(t, keyResp.KeyId)
	require.NotEmpty(t, keyResp.PublicKey)

	infoResp, err := server.GetVaultInfo(ctx, &api.GetVaultInfoRequest{
		VaultId: createResp.VaultId,
	})
	require.NoError(t, err)
	require.Len(t, infoResp.Keys, 1)

	rotateResp, err := server.RotateKeys(ctx, &api.RotateKeysRequest{
		VaultId: createResp.VaultId,
		KeyIds:  []string{keyResp.KeyId},
	})
	require.NoError(t, err)
	require.True(t, rotateResp.Success)
	require.Len(t, rotateResp.NewKeyIds, 1)
}

func TestAccountUsageAndTransactions(t *testing.T) {
	server := setupTestB2BServer(t)
	ctx := b2bAuthContext(context.Background())

	accountResp, err := server.GetAccountInfo(ctx, &api.GetAccountInfoRequest{})
	require.NoError(t, err)
	require.NotEmpty(t, accountResp.AccountId)

	upgradeResp, err := server.UpgradeTier(ctx, &api.UpgradeTierRequest{
		NewTier: "Premium",
	})
	require.NoError(t, err)
	require.True(t, upgradeResp.Success)

	usageResp, err := server.GetUsageStats(ctx, &api.GetUsageStatsRequest{})
	require.NoError(t, err)
	require.NotNil(t, usageResp)

	submitResp, err := server.SubmitTransaction(ctx, &api.SubmitTransactionRequest{
		TransactionData: []byte("hello"),
	})
	require.NoError(t, err)
	require.NotEmpty(t, submitResp.TransactionId)

	statusResp, err := server.GetTransactionStatus(ctx, &api.GetTransactionStatusRequest{
		TransactionId: submitResp.TransactionId,
	})
	require.NoError(t, err)
	require.Equal(t, submitResp.TransactionId, statusResp.TransactionId)
}

// =============================================================================
// Helper Functions
// =============================================================================

func generateTestNonce() string {
	timestamp := time.Now().Unix()
	randomBytes := make([]byte, 8)
	rand.Read(randomBytes)
	return fmt.Sprintf("%d_%x", timestamp, randomBytes)
}

func b2bAuthContext(ctx context.Context) context.Context {
	md := metadata.New(map[string]string{
		"partner-id": testPartner.ID,
		"api-key":    testAPIKey,
	})
	return metadata.NewIncomingContext(ctx, md)
}
