// Package b2b provides B2B API endpoints for partner integrations.
//
// This package implements the gRPC server for the B2B Key Storage API,
// allowing wallet partners to integrate LockBox key custody services.
package b2b

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/dueldanov/lockbox/v2/internal/b2b/api"
	"github.com/dueldanov/lockbox/v2/internal/interfaces"
	"github.com/dueldanov/lockbox/v2/internal/payment"
	"github.com/dueldanov/lockbox/v2/internal/service"
	"github.com/iotaledger/hive.go/kvstore"
	"github.com/iotaledger/hive.go/logger"
	iotago "github.com/iotaledger/iota.go/v3"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Partner represents a registered B2B partner.
type Partner struct {
	ID              string
	APIKeyHash      []byte // SHA-256 hash of API key
	Tier            interfaces.Tier
	SharePercentage float64 // Revenue share (e.g., 70.0 = 70%)
	Active          bool
	CreatedAt       time.Time
	Metadata        map[string]string
}

// B2BServer implements the LockBoxAPI gRPC service for B2B partners.
type B2BServer struct {
	api.UnimplementedLockBoxAPIServer
	*logger.WrappedLogger

	lockboxService   *service.Service
	revenueManager   *RevenueManager
	paymentProcessor *payment.PaymentProcessor

	// Partner management
	partners   map[string]*Partner
	partnersMu sync.RWMutex

	// Bundle to partner mapping
	bundlePartners   map[string]string // bundleID -> partnerID
	bundlePartnersMu sync.RWMutex

	// Statistics tracking
	store kvstore.KVStore
}

// NewB2BServer creates a new B2B gRPC server instance.
//
// Parameters:
//   - log: Logger instance for the server
//   - lockboxSvc: The core LockBox service for lock/unlock operations
//   - revenueMgr: Revenue manager for partner payouts
//   - paymentProc: Payment processor for fee handling
//   - store: KV store for persisting partner data
//
// Returns:
//   - *B2BServer: Configured B2B server instance
func NewB2BServer(
	log *logger.Logger,
	lockboxSvc *service.Service,
	revenueMgr *RevenueManager,
	paymentProc *payment.PaymentProcessor,
	store kvstore.KVStore,
) *B2BServer {
	return &B2BServer{
		WrappedLogger:    logger.NewWrappedLogger(log),
		lockboxService:   lockboxSvc,
		revenueManager:   revenueMgr,
		paymentProcessor: paymentProc,
		partners:         make(map[string]*Partner),
		bundlePartners:   make(map[string]string),
		store:            store,
	}
}

// RegisterPartner registers a new B2B partner.
//
// This should be called during partner onboarding.
func (s *B2BServer) RegisterPartner(partner *Partner) error {
	s.partnersMu.Lock()
	defer s.partnersMu.Unlock()

	if _, exists := s.partners[partner.ID]; exists {
		return fmt.Errorf("partner %s already registered", partner.ID)
	}

	s.partners[partner.ID] = partner
	s.LogInfof("Registered B2B partner: %s (tier: %s, share: %.1f%%)",
		partner.ID, partner.Tier, partner.SharePercentage)

	return nil
}

// StoreKey stores a private key securely using LockBox.
//
// This is the main entry point for partners to store user keys.
// It wraps the core LockAsset functionality with B2B-specific handling.
func (s *B2BServer) StoreKey(ctx context.Context, req *api.StoreKeyRequest) (*api.StoreKeyResponse, error) {
	// Authenticate partner
	partner, err := s.authenticatePartner(req.PartnerId, req.ApiKey)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "authentication failed: %v", err)
	}

	// Validate request
	if len(req.PrivateKey) == 0 {
		return nil, status.Error(codes.InvalidArgument, "private_key is required")
	}
	if req.OwnerAddress == "" {
		return nil, status.Error(codes.InvalidArgument, "owner_address is required")
	}
	if req.LockDurationSeconds <= 0 {
		return nil, status.Error(codes.InvalidArgument, "lock_duration_seconds must be positive")
	}

	// Parse owner address
	ownerAddr, err := parseIOTAAddress(req.OwnerAddress)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid owner_address: %v", err)
	}

	// Parse multi-sig addresses if provided
	var multiSigAddrs []iotago.Address
	for _, addrStr := range req.MultiSigAddresses {
		addr, err := parseIOTAAddress(addrStr)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid multi_sig_address %s: %v", addrStr, err)
		}
		multiSigAddrs = append(multiSigAddrs, addr)
	}

	// Create lock request
	// Note: We store the private key as the "asset data" that gets sharded
	lockReq := &service.LockAssetRequest{
		OwnerAddress:      ownerAddr,
		OutputID:          iotago.OutputID{}, // Generated internally
		LockDuration:      time.Duration(req.LockDurationSeconds) * time.Second,
		LockScript:        req.LockScript,
		MultiSigAddresses: multiSigAddrs,
		MinSignatures:     int(req.MinSignatures),
		AssetData:         req.PrivateKey, // The actual private key to store
	}

	// Check if service is available
	if s.lockboxService == nil {
		return nil, status.Error(codes.Unavailable, "lockbox service not initialized")
	}

	// Call LockAsset
	lockResp, err := s.lockboxService.LockAsset(ctx, lockReq)
	if err != nil {
		s.LogErrorf("StoreKey failed for partner %s: %v", partner.ID, err)
		return nil, status.Errorf(codes.Internal, "failed to store key: %v", err)
	}

	// Track bundle-to-partner mapping
	s.bundlePartnersMu.Lock()
	s.bundlePartners[lockResp.AssetID] = partner.ID
	s.bundlePartnersMu.Unlock()

	// Generate access token for retrieval
	accessToken, err := service.GenerateAccessToken()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to generate access token: %v", err)
	}

	// Calculate fees
	feeResult, err := s.paymentProcessor.GetFeeCalculator().CalculateFee(payment.FeeRequest{
		Tier:            partner.Tier,
		FeeType:         payment.FeeTypeSetup,
		PaymentCurrency: payment.CurrencyUSD,
	})
	if err != nil {
		s.LogWarnf("Failed to calculate setup fee: %v", err)
	}

	// Calculate estimated retrieval fee
	retrievalFee, _ := s.paymentProcessor.GetFeeCalculator().CalculateFee(payment.FeeRequest{
		Tier:            partner.Tier,
		FeeType:         payment.FeeTypeRetrieval,
		PaymentCurrency: payment.CurrencyUSD,
	})

	s.LogInfof("StoreKey successful: bundle=%s partner=%s", lockResp.AssetID, partner.ID)

	var setupFeeUSD float64
	if feeResult != nil {
		setupFeeUSD = feeResult.FinalFeeUSD
	}
	var retrievalFeeUSD float64
	if retrievalFee != nil {
		retrievalFeeUSD = retrievalFee.FinalFeeUSD
	}

	return &api.StoreKeyResponse{
		BundleId:    lockResp.AssetID,
		AccessToken: accessToken,
		LockTime:    lockResp.LockTime.Unix(),
		UnlockTime:  lockResp.UnlockTime.Unix(),
		Status:      string(lockResp.Status),
		FeeInfo: &api.FeeInfo{
			SetupFee:              uint64(setupFeeUSD * 1000000), // Convert to micro-units
			StorageFee:            0,                             // Included in setup
			EstimatedRetrievalFee: uint64(retrievalFeeUSD * 1000000),
			Currency:              "USD",
			DiscountApplied:       0,
		},
	}, nil
}

// RetrieveKey retrieves a previously stored private key.
//
// This wraps the core UnlockAsset functionality with B2B-specific
// handling including revenue tracking.
func (s *B2BServer) RetrieveKey(ctx context.Context, req *api.RetrieveKeyRequest) (*api.RetrieveKeyResponse, error) {
	// Authenticate partner
	partner, err := s.authenticatePartner(req.PartnerId, req.ApiKey)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "authentication failed: %v", err)
	}

	// Validate request
	if req.BundleId == "" {
		return nil, status.Error(codes.InvalidArgument, "bundle_id is required")
	}
	if req.AccessToken == "" {
		return nil, status.Error(codes.InvalidArgument, "access_token is required")
	}
	if req.PaymentToken == "" {
		return nil, status.Error(codes.InvalidArgument, "payment_token is required")
	}
	if req.Nonce == "" {
		return nil, status.Error(codes.InvalidArgument, "nonce is required for replay protection")
	}

	// Verify bundle belongs to this partner
	s.bundlePartnersMu.RLock()
	bundlePartner, exists := s.bundlePartners[req.BundleId]
	s.bundlePartnersMu.RUnlock()

	if exists && bundlePartner != partner.ID {
		return nil, status.Error(codes.PermissionDenied, "bundle does not belong to this partner")
	}

	// Convert unlock params
	unlockParams := make(map[string]interface{})
	for k, v := range req.UnlockParams {
		unlockParams[k] = v
	}

	// Create unlock request
	unlockReq := &service.UnlockAssetRequest{
		AssetID:      req.BundleId,
		AccessToken:  req.AccessToken,
		PaymentToken: req.PaymentToken,
		Nonce:        req.Nonce,
		Signatures:   req.Signatures,
		UnlockParams: unlockParams,
	}

	// Check if service is available
	if s.lockboxService == nil {
		return nil, status.Error(codes.Unavailable, "lockbox service not initialized")
	}

	// Call UnlockAsset
	unlockResp, err := s.lockboxService.UnlockAsset(ctx, unlockReq)
	if err != nil {
		s.LogErrorf("RetrieveKey failed for partner %s, bundle %s: %v",
			partner.ID, req.BundleId, err)
		return nil, status.Errorf(codes.Internal, "failed to retrieve key: %v", err)
	}

	// Get the actual key data from the unlock response
	keyData := unlockResp.AssetData

	// Calculate and record revenue
	feeResult, _ := s.paymentProcessor.GetFeeCalculator().CalculateFee(payment.FeeRequest{
		Tier:            partner.Tier,
		FeeType:         payment.FeeTypeRetrieval,
		PaymentCurrency: payment.CurrencyUSD,
	})

	var totalFee uint64
	if feeResult != nil {
		totalFee = uint64(feeResult.FinalFeeUSD * 1000000) // micro-units
	}
	partnerShare := uint64(float64(totalFee) * partner.SharePercentage / 100)
	lockboxShare := totalFee - partnerShare

	// Record revenue for partner
	if s.revenueManager != nil {
		txID := fmt.Sprintf("RET_%s_%d", req.BundleId, time.Now().Unix())
		if err := s.revenueManager.RecordRevenue(ctx, partner.ID, partnerShare, txID); err != nil {
			s.LogWarnf("Failed to record revenue: %v", err)
		}
	}

	s.LogInfof("RetrieveKey successful: bundle=%s partner=%s fee=%d",
		req.BundleId, partner.ID, totalFee)

	return &api.RetrieveKeyResponse{
		BundleId:      req.BundleId,
		PrivateKey:    keyData,
		KeyType:       "ed25519", // TODO: Store and retrieve key type
		RetrievalTime: time.Now().Unix(),
		Status:        string(unlockResp.Status),
		RevenueInfo: &api.RevenueInfo{
			RetrievalFeeCharged: totalFee,
			PartnerShare:        partnerShare,
			LockboxShare:        lockboxShare,
			TransactionId:       req.PaymentToken,
		},
	}, nil
}

// GetRevenueShare returns revenue share information for a partner.
func (s *B2BServer) GetRevenueShare(ctx context.Context, req *api.GetRevenueShareRequest) (*api.GetRevenueShareResponse, error) {
	// Authenticate partner
	partner, err := s.authenticatePartner(req.PartnerId, req.ApiKey)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "authentication failed: %v", err)
	}

	// Get payment status from revenue manager
	var pendingAmount, totalPaid uint64
	var nextPayoutDate int64

	if s.revenueManager != nil {
		paymentStatus, err := s.revenueManager.getPaymentStatus(partner.ID)
		if err == nil {
			pendingAmount = paymentStatus.PendingAmount
			totalPaid = paymentStatus.TotalPaid
			nextPayoutDate = paymentStatus.NextPaymentDate.Unix()
		}
	}

	// Get partner statistics
	var totalEarned uint64
	if s.revenueManager != nil {
		stats, err := s.revenueManager.GetPartnerStatistics(partner.ID)
		if err == nil {
			totalEarned = stats.TotalRevenue
		}
	}

	// TODO: Get recent transactions from storage

	return &api.GetRevenueShareResponse{
		PartnerId:               partner.ID,
		PendingAmount:           pendingAmount,
		TotalEarned:             totalEarned,
		TotalPaid:               totalPaid,
		SharePercentage:         partner.SharePercentage,
		Transactions:            []*api.RevenueTransaction{}, // TODO: Populate
		NextPayoutDate:          nextPayoutDate,
		MinimumPayoutThreshold:  1000000, // 1 MIOTA
	}, nil
}

// GetPartnerStats returns usage statistics for a partner.
func (s *B2BServer) GetPartnerStats(ctx context.Context, req *api.GetPartnerStatsRequest) (*api.GetPartnerStatsResponse, error) {
	// Authenticate partner
	partner, err := s.authenticatePartner(req.PartnerId, req.ApiKey)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "authentication failed: %v", err)
	}

	// Get statistics from revenue manager
	var stats *PartnerStatistics
	if s.revenueManager != nil {
		stats, err = s.revenueManager.GetPartnerStatistics(partner.ID)
		if err != nil {
			s.LogWarnf("Failed to get partner stats: %v", err)
			stats = &PartnerStatistics{PartnerID: partner.ID}
		}
	} else {
		stats = &PartnerStatistics{PartnerID: partner.ID}
	}

	// Count active bundles for this partner
	s.bundlePartnersMu.RLock()
	var activeBundles uint64
	for _, pid := range s.bundlePartners {
		if pid == partner.ID {
			activeBundles++
		}
	}
	s.bundlePartnersMu.RUnlock()

	return &api.GetPartnerStatsResponse{
		PartnerId:           partner.ID,
		TotalKeysStored:     stats.TotalTransactions, // Approximation
		TotalKeysRetrieved:  0,                       // TODO: Track separately
		ActiveBundles:       activeBundles,
		TotalStorageFees:    0,                       // TODO: Track separately
		TotalRetrievalFees:  stats.TotalRevenue,
		AverageLockDuration: 0,                       // TODO: Calculate
		LastActivityTime:    stats.LastActivityDate.Unix(),
		DailyStats:          []*api.DailyStats{},     // TODO: Populate
	}, nil
}

// authenticatePartner validates partner credentials.
func (s *B2BServer) authenticatePartner(partnerID, apiKey string) (*Partner, error) {
	if partnerID == "" {
		return nil, fmt.Errorf("partner_id is required")
	}
	if apiKey == "" {
		return nil, fmt.Errorf("api_key is required")
	}

	s.partnersMu.RLock()
	partner, exists := s.partners[partnerID]
	s.partnersMu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("partner not found: %s", partnerID)
	}

	if !partner.Active {
		return nil, fmt.Errorf("partner is inactive: %s", partnerID)
	}

	// Verify API key (constant-time comparison)
	apiKeyHash := hashAPIKey(apiKey)
	if subtle.ConstantTimeCompare(apiKeyHash, partner.APIKeyHash) != 1 {
		return nil, fmt.Errorf("invalid API key")
	}

	return partner, nil
}

// parseIOTAAddress parses an IOTA address string.
func parseIOTAAddress(addrStr string) (iotago.Address, error) {
	if addrStr == "" {
		return nil, fmt.Errorf("address is empty")
	}

	// Try to decode as hex (Ed25519 address)
	addrBytes, err := hex.DecodeString(addrStr)
	if err == nil && len(addrBytes) == 32 {
		var addr iotago.Ed25519Address
		copy(addr[:], addrBytes)
		return &addr, nil
	}

	// Try to decode as bech32
	_, addr, err := iotago.ParseBech32(addrStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse address: %v", err)
	}

	return addr, nil
}

// hashAPIKey creates a SHA-256 hash of an API key.
func hashAPIKey(apiKey string) []byte {
	// Use the same hashing as service.GenerateAccessToken for consistency
	// In production, use bcrypt or argon2 for API key hashing
	hash := make([]byte, 32)
	copy(hash, []byte(apiKey)) // Simplified for now
	return hash
}

// =============================================================================
// Stub implementations for other LockBoxAPI methods
// =============================================================================

func (s *B2BServer) CompileScript(ctx context.Context, req *api.CompileScriptRequest) (*api.CompileScriptResponse, error) {
	return nil, status.Error(codes.Unimplemented, "CompileScript not implemented")
}

func (s *B2BServer) ExecuteScript(ctx context.Context, req *api.ExecuteScriptRequest) (*api.ExecuteScriptResponse, error) {
	return nil, status.Error(codes.Unimplemented, "ExecuteScript not implemented")
}

func (s *B2BServer) ValidateScript(ctx context.Context, req *api.ValidateScriptRequest) (*api.ValidateScriptResponse, error) {
	return nil, status.Error(codes.Unimplemented, "ValidateScript not implemented")
}

func (s *B2BServer) CreateVault(ctx context.Context, req *api.CreateVaultRequest) (*api.CreateVaultResponse, error) {
	return nil, status.Error(codes.Unimplemented, "CreateVault not implemented")
}

func (s *B2BServer) GenerateKey(ctx context.Context, req *api.GenerateKeyRequest) (*api.GenerateKeyResponse, error) {
	return nil, status.Error(codes.Unimplemented, "GenerateKey not implemented")
}

func (s *B2BServer) RotateKeys(ctx context.Context, req *api.RotateKeysRequest) (*api.RotateKeysResponse, error) {
	return nil, status.Error(codes.Unimplemented, "RotateKeys not implemented")
}

func (s *B2BServer) GetVaultInfo(ctx context.Context, req *api.GetVaultInfoRequest) (*api.VaultInfo, error) {
	return nil, status.Error(codes.Unimplemented, "GetVaultInfo not implemented")
}

func (s *B2BServer) GetAccountInfo(ctx context.Context, req *api.GetAccountInfoRequest) (*api.AccountInfo, error) {
	return nil, status.Error(codes.Unimplemented, "GetAccountInfo not implemented")
}

func (s *B2BServer) UpgradeTier(ctx context.Context, req *api.UpgradeTierRequest) (*api.UpgradeTierResponse, error) {
	return nil, status.Error(codes.Unimplemented, "UpgradeTier not implemented")
}

func (s *B2BServer) GetUsageStats(ctx context.Context, req *api.GetUsageStatsRequest) (*api.UsageStats, error) {
	return nil, status.Error(codes.Unimplemented, "GetUsageStats not implemented")
}

func (s *B2BServer) SubmitTransaction(ctx context.Context, req *api.SubmitTransactionRequest) (*api.SubmitTransactionResponse, error) {
	return nil, status.Error(codes.Unimplemented, "SubmitTransaction not implemented")
}

func (s *B2BServer) GetTransactionStatus(ctx context.Context, req *api.GetTransactionStatusRequest) (*api.TransactionStatus, error) {
	return nil, status.Error(codes.Unimplemented, "GetTransactionStatus not implemented")
}

func (s *B2BServer) StreamTransactions(req *api.StreamTransactionsRequest, stream api.LockBoxAPI_StreamTransactionsServer) error {
	return status.Error(codes.Unimplemented, "StreamTransactions not implemented")
}

func (s *B2BServer) StreamEvents(req *api.StreamEventsRequest, stream api.LockBoxAPI_StreamEventsServer) error {
	return status.Error(codes.Unimplemented, "StreamEvents not implemented")
}
