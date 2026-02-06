// Package b2b provides B2B API endpoints for partner integrations.
//
// This package implements the gRPC server for the B2B Key Storage API,
// allowing wallet partners to integrate LockBox key custody services.
package b2b

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/iotaledger/hive.go/kvstore"
	"github.com/iotaledger/hive.go/logger"
	iotago "github.com/iotaledger/iota.go/v3"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/dueldanov/lockbox/v2/internal/b2b/api"
	"github.com/dueldanov/lockbox/v2/internal/interfaces"
	"github.com/dueldanov/lockbox/v2/internal/lockscript"
	"github.com/dueldanov/lockbox/v2/internal/payment"
	"github.com/dueldanov/lockbox/v2/internal/service"
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

	scriptEngine *lockscript.Engine
	scriptsMu    sync.RWMutex
	scripts      map[string]*lockscript.CompiledScript

	vaultsMu sync.RWMutex
	vaults   map[string]*vaultRecord

	accountsMu sync.RWMutex
	accounts   map[string]*accountRecord

	transactionsMu sync.RWMutex
	transactions   map[string]*transactionRecord

	// Partner management
	partners   map[string]*Partner
	partnersMu sync.RWMutex

	// Bundle to partner mapping
	bundlePartners   map[string]string // bundleID -> partnerID
	bundlePartnersMu sync.RWMutex

	// Statistics tracking
	store kvstore.KVStore
}

type vaultRecord struct {
	ID           string
	Name         string
	Owner        string
	CreatedAt    time.Time
	LastRotation time.Time
	Metadata     map[string]string
	Keys         map[string]*vaultKey
}

type vaultKey struct {
	ID        string
	KeyType   string
	KeyName   string
	PublicKey string
	CreatedAt time.Time
	ExpiresAt time.Time
}

type accountRecord struct {
	ID           string
	Tier         interfaces.Tier
	CreatedAt    time.Time
	LastActivity time.Time
	Usage        *usageStats
}

type usageStats struct {
	TransactionsHour  int32
	StorageUsed       int64
	ContractsDeployed int32
	LastReset         time.Time
}

type transactionRecord struct {
	Status    *api.TransactionStatus
	Data      []byte
	Timestamp time.Time
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
	if paymentProc == nil {
		paymentProc = payment.NewPaymentProcessor(nil)
	}

	tierCaps := service.GetCapabilities(service.TierStandard)
	memoryLimit := tierCaps.ScriptComplexity * 65536
	if memoryLimit <= 0 {
		memoryLimit = 65536
	}

	return &B2BServer{
		WrappedLogger:    logger.NewWrappedLogger(log),
		lockboxService:   lockboxSvc,
		revenueManager:   revenueMgr,
		paymentProcessor: paymentProc,
		scriptEngine:     lockscript.NewEngine(nil, memoryLimit, 5*time.Second),
		scripts:          make(map[string]*lockscript.CompiledScript),
		vaults:           make(map[string]*vaultRecord),
		accounts:         make(map[string]*accountRecord),
		transactions:     make(map[string]*transactionRecord),
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
		KeyType:       "ed25519", // All keys are Ed25519 (IOTA-compatible)
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

	// Transaction history requires persistent B2B storage (not yet implemented)

	return &api.GetRevenueShareResponse{
		PartnerId:              partner.ID,
		PendingAmount:          pendingAmount,
		TotalEarned:            totalEarned,
		TotalPaid:              totalPaid,
		SharePercentage:        partner.SharePercentage,
		Transactions:           []*api.RevenueTransaction{},
		NextPayoutDate:         nextPayoutDate,
		MinimumPayoutThreshold: 1000000, // 1 MIOTA
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

	// Detailed per-metric tracking requires persistent B2B storage (not yet implemented).
	// TotalKeysStored is approximated from TotalTransactions; other granular stats are zero-valued.
	return &api.GetPartnerStatsResponse{
		PartnerId:           partner.ID,
		TotalKeysStored:     stats.TotalTransactions,
		TotalKeysRetrieved:  0,
		ActiveBundles:       activeBundles,
		TotalStorageFees:    0,
		TotalRetrievalFees:  stats.TotalRevenue,
		AverageLockDuration: 0,
		LastActivityTime:    stats.LastActivityDate.Unix(),
		DailyStats:          []*api.DailyStats{},
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

func (s *B2BServer) partnerFromContext(ctx context.Context) (*Partner, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "missing metadata")
	}

	partnerID := firstMetadataValue(md, "partner-id", "partner_id")
	apiKey := firstMetadataValue(md, "api-key", "api_key")
	if partnerID == "" || apiKey == "" {
		return nil, status.Error(codes.Unauthenticated, "missing partner credentials")
	}

	partner, err := s.authenticatePartner(partnerID, apiKey)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "authentication failed: %v", err)
	}

	return partner, nil
}

func firstMetadataValue(md metadata.MD, keys ...string) string {
	for _, key := range keys {
		values := md.Get(key)
		if len(values) > 0 && values[0] != "" {
			return values[0]
		}
	}
	return ""
}

func (s *B2BServer) ensureAccount(partner *Partner) *accountRecord {
	s.accountsMu.Lock()
	defer s.accountsMu.Unlock()

	account, exists := s.accounts[partner.ID]
	if exists {
		return account
	}

	account = &accountRecord{
		ID:           partner.ID,
		Tier:         partner.Tier,
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
		Usage: &usageStats{
			LastReset: time.Now(),
		},
	}
	s.accounts[partner.ID] = account

	return account
}

func (s *B2BServer) recordUsage(partner *Partner, usageType string, amount int64) {
	account := s.ensureAccount(partner)

	s.accountsMu.Lock()
	defer s.accountsMu.Unlock()

	if time.Since(account.Usage.LastReset) > time.Hour {
		account.Usage.TransactionsHour = 0
		account.Usage.LastReset = time.Now()
	}

	switch usageType {
	case "transaction":
		account.Usage.TransactionsHour++
	case "storage":
		account.Usage.StorageUsed += amount
	case "contract":
		account.Usage.ContractsDeployed++
	}

	account.LastActivity = time.Now()
}

func tierLabel(tier interfaces.Tier) string {
	switch tier {
	case interfaces.TierBasic:
		return "Basic"
	case interfaces.TierStandard:
		return "Standard"
	case interfaces.TierPremium:
		return "Premium"
	case interfaces.TierElite:
		return "Elite"
	default:
		return "Unknown"
	}
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
	h := sha256.Sum256([]byte(apiKey))
	return h[:]
}

// =============================================================================
// Stub implementations for other LockBoxAPI methods
// =============================================================================

func (s *B2BServer) CompileScript(ctx context.Context, req *api.CompileScriptRequest) (*api.CompileScriptResponse, error) {
	partner, err := s.partnerFromContext(ctx)
	if err != nil {
		return nil, err
	}

	if strings.TrimSpace(req.Source) == "" {
		return nil, status.Error(codes.InvalidArgument, "source is required")
	}

	caps := service.GetCapabilities(service.Tier(partner.Tier))
	maxSize := caps.ScriptComplexity * 65536
	if maxSize <= 0 {
		maxSize = 65536
	}
	if len(req.Source) > maxSize {
		return nil, status.Errorf(codes.InvalidArgument, "script size exceeds maximum of %d bytes", maxSize)
	}

	compiled, err := s.scriptEngine.CompileScript(ctx, req.Source)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "compilation failed: %v", err)
	}

	scriptID := fmt.Sprintf("script_%s_%d", partner.ID, time.Now().UnixNano())
	s.scriptsMu.Lock()
	s.scripts[scriptID] = compiled
	s.scriptsMu.Unlock()

	s.recordUsage(partner, "contract", 1)

	return &api.CompileScriptResponse{
		ScriptId: scriptID,
		Bytecode: compiled.Bytecode,
		Warnings: []string{},
	}, nil
}

func (s *B2BServer) ExecuteScript(ctx context.Context, req *api.ExecuteScriptRequest) (*api.ExecuteScriptResponse, error) {
	partner, err := s.partnerFromContext(ctx)
	if err != nil {
		return nil, err
	}

	if strings.TrimSpace(req.ScriptId) == "" {
		return nil, status.Error(codes.InvalidArgument, "script_id is required")
	}

	s.scriptsMu.RLock()
	script, exists := s.scripts[req.ScriptId]
	s.scriptsMu.RUnlock()
	if !exists {
		return nil, status.Error(codes.NotFound, "script not found")
	}

	env := lockscript.NewEnvironment()
	for k, v := range req.Environment {
		env.Variables[k] = v
	}

	result, err := s.scriptEngine.ExecuteScript(ctx, script, env)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "execution failed: %v", err)
	}

	s.recordUsage(partner, "transaction", 1)

	var output string
	if result != nil && result.Value != nil {
		output = fmt.Sprintf("%v", result.Value)
	}

	var gasUsed uint64
	var logs []string
	if result != nil {
		gasUsed = result.GasUsed
		logs = result.Logs
	}

	return &api.ExecuteScriptResponse{
		Success: result != nil && result.Success,
		Output:  output,
		GasUsed: gasUsed,
		Logs:    logs,
	}, nil
}

func (s *B2BServer) ValidateScript(ctx context.Context, req *api.ValidateScriptRequest) (*api.ValidateScriptResponse, error) {
	partner, err := s.partnerFromContext(ctx)
	if err != nil {
		return nil, err
	}

	if strings.TrimSpace(req.Source) == "" {
		return &api.ValidateScriptResponse{
			Valid:  false,
			Errors: []string{"source is required"},
		}, nil
	}

	caps := service.GetCapabilities(service.Tier(partner.Tier))
	maxSize := caps.ScriptComplexity * 65536
	if maxSize <= 0 {
		maxSize = 65536
	}
	if len(req.Source) > maxSize {
		return &api.ValidateScriptResponse{
			Valid:  false,
			Errors: []string{fmt.Sprintf("script size exceeds maximum of %d bytes", maxSize)},
		}, nil
	}

	_, err = s.scriptEngine.CompileScript(ctx, req.Source)
	if err != nil {
		return &api.ValidateScriptResponse{
			Valid:  false,
			Errors: []string{err.Error()},
		}, nil
	}

	s.recordUsage(partner, "contract", 1)

	return &api.ValidateScriptResponse{
		Valid:  true,
		Errors: []string{},
	}, nil
}

func (s *B2BServer) CreateVault(ctx context.Context, req *api.CreateVaultRequest) (*api.CreateVaultResponse, error) {
	partner, err := s.partnerFromContext(ctx)
	if err != nil {
		return nil, err
	}

	if strings.TrimSpace(req.Name) == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}

	vaultID := fmt.Sprintf("vault_%s_%d", partner.ID, time.Now().UnixNano())
	record := &vaultRecord{
		ID:        vaultID,
		Name:      req.Name,
		Owner:     partner.ID,
		CreatedAt: time.Now(),
		Metadata:  req.Metadata,
		Keys:      make(map[string]*vaultKey),
	}

	s.vaultsMu.Lock()
	s.vaults[vaultID] = record
	s.vaultsMu.Unlock()

	s.recordUsage(partner, "storage", 0)

	return &api.CreateVaultResponse{
		VaultId: vaultID,
	}, nil
}

func (s *B2BServer) GenerateKey(ctx context.Context, req *api.GenerateKeyRequest) (*api.GenerateKeyResponse, error) {
	partner, err := s.partnerFromContext(ctx)
	if err != nil {
		return nil, err
	}

	if strings.TrimSpace(req.VaultId) == "" {
		return nil, status.Error(codes.InvalidArgument, "vault_id is required")
	}

	keyType := strings.ToLower(strings.TrimSpace(req.KeyType))
	if keyType == "" {
		keyType = "ed25519"
	}
	if keyType != "ed25519" {
		return nil, status.Errorf(codes.InvalidArgument, "unsupported key_type: %s", keyType)
	}

	s.vaultsMu.Lock()
	vault, exists := s.vaults[req.VaultId]
	if !exists {
		s.vaultsMu.Unlock()
		return nil, status.Error(codes.NotFound, "vault not found")
	}

	pubKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		s.vaultsMu.Unlock()
		return nil, status.Errorf(codes.Internal, "failed to generate key: %v", err)
	}

	keyID := fmt.Sprintf("key_%s_%d", partner.ID, time.Now().UnixNano())
	keyName := strings.TrimSpace(req.KeyName)
	if keyName == "" {
		keyName = keyID
	}

	vault.Keys[keyID] = &vaultKey{
		ID:        keyID,
		KeyType:   keyType,
		KeyName:   keyName,
		PublicKey: hex.EncodeToString(pubKey),
		CreatedAt: time.Now(),
	}
	s.vaultsMu.Unlock()

	s.recordUsage(partner, "storage", 0)

	return &api.GenerateKeyResponse{
		KeyId:     keyID,
		PublicKey: hex.EncodeToString(pubKey),
	}, nil
}

func (s *B2BServer) RotateKeys(ctx context.Context, req *api.RotateKeysRequest) (*api.RotateKeysResponse, error) {
	partner, err := s.partnerFromContext(ctx)
	if err != nil {
		return nil, err
	}

	if strings.TrimSpace(req.VaultId) == "" {
		return nil, status.Error(codes.InvalidArgument, "vault_id is required")
	}
	if len(req.KeyIds) == 0 {
		return nil, status.Error(codes.InvalidArgument, "key_ids is required")
	}

	s.vaultsMu.Lock()
	vault, exists := s.vaults[req.VaultId]
	if !exists {
		s.vaultsMu.Unlock()
		return nil, status.Error(codes.NotFound, "vault not found")
	}

	newKeyIDs := make(map[string]string)
	for _, keyID := range req.KeyIds {
		key, ok := vault.Keys[keyID]
		if !ok {
			s.vaultsMu.Unlock()
			return nil, status.Errorf(codes.NotFound, "key not found: %s", keyID)
		}

		if strings.ToLower(key.KeyType) != "ed25519" {
			s.vaultsMu.Unlock()
			return nil, status.Errorf(codes.InvalidArgument, "unsupported key_type: %s", key.KeyType)
		}

		pubKey, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			s.vaultsMu.Unlock()
			return nil, status.Errorf(codes.Internal, "failed to generate key: %v", err)
		}

		newKeyID := fmt.Sprintf("key_%s_%d", partner.ID, time.Now().UnixNano())
		newKeyIDs[keyID] = newKeyID
		delete(vault.Keys, keyID)
		vault.Keys[newKeyID] = &vaultKey{
			ID:        newKeyID,
			KeyType:   key.KeyType,
			KeyName:   key.KeyName,
			PublicKey: hex.EncodeToString(pubKey),
			CreatedAt: time.Now(),
		}
	}
	vault.LastRotation = time.Now()
	s.vaultsMu.Unlock()

	s.recordUsage(partner, "transaction", int64(len(req.KeyIds)))

	return &api.RotateKeysResponse{
		Success:   true,
		NewKeyIds: newKeyIDs,
	}, nil
}

func (s *B2BServer) GetVaultInfo(ctx context.Context, req *api.GetVaultInfoRequest) (*api.VaultInfo, error) {
	_, err := s.partnerFromContext(ctx)
	if err != nil {
		return nil, err
	}

	if strings.TrimSpace(req.VaultId) == "" {
		return nil, status.Error(codes.InvalidArgument, "vault_id is required")
	}

	s.vaultsMu.RLock()
	vault, exists := s.vaults[req.VaultId]
	s.vaultsMu.RUnlock()
	if !exists {
		return nil, status.Error(codes.NotFound, "vault not found")
	}

	keys := make([]*api.KeyInfo, 0, len(vault.Keys))
	for _, key := range vault.Keys {
		keys = append(keys, &api.KeyInfo{
			KeyId:     key.ID,
			KeyType:   key.KeyType,
			KeyName:   key.KeyName,
			CreatedAt: key.CreatedAt.Unix(),
			ExpiresAt: key.ExpiresAt.Unix(),
		})
	}
	sort.Slice(keys, func(i, j int) bool {
		return keys[i].KeyId < keys[j].KeyId
	})

	return &api.VaultInfo{
		VaultId:      vault.ID,
		Owner:        vault.Owner,
		CreatedAt:    vault.CreatedAt.Unix(),
		LastRotation: vault.LastRotation.Unix(),
		Keys:         keys,
		Metadata:     vault.Metadata,
	}, nil
}

func (s *B2BServer) GetAccountInfo(ctx context.Context, req *api.GetAccountInfoRequest) (*api.AccountInfo, error) {
	partner, err := s.partnerFromContext(ctx)
	if err != nil {
		return nil, err
	}

	if req.AccountId != "" && req.AccountId != partner.ID {
		return nil, status.Error(codes.PermissionDenied, "account access denied")
	}

	account := s.ensureAccount(partner)

	usage := &api.UsageStats{
		TransactionsHour:  account.Usage.TransactionsHour,
		StorageUsed:       account.Usage.StorageUsed,
		ContractsDeployed: account.Usage.ContractsDeployed,
		LastReset:         account.Usage.LastReset.Unix(),
	}

	return &api.AccountInfo{
		AccountId:    account.ID,
		Tier:         tierLabel(account.Tier),
		CreatedAt:    account.CreatedAt.Unix(),
		LastActivity: account.LastActivity.Unix(),
		Usage:        usage,
		Metadata:     map[string]string{},
	}, nil
}

func (s *B2BServer) UpgradeTier(ctx context.Context, req *api.UpgradeTierRequest) (*api.UpgradeTierResponse, error) {
	partner, err := s.partnerFromContext(ctx)
	if err != nil {
		return nil, err
	}

	if req.AccountId != "" && req.AccountId != partner.ID {
		return nil, status.Error(codes.PermissionDenied, "account access denied")
	}

	if strings.TrimSpace(req.NewTier) == "" {
		return nil, status.Error(codes.InvalidArgument, "new_tier is required")
	}

	newTier, err := interfaces.TierFromString(strings.ToLower(req.NewTier))
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid tier: %v", err)
	}

	s.partnersMu.Lock()
	partner.Tier = newTier
	s.partnersMu.Unlock()

	account := s.ensureAccount(partner)
	s.accountsMu.Lock()
	account.Tier = newTier
	s.accountsMu.Unlock()

	return &api.UpgradeTierResponse{
		Success: true,
		Message: fmt.Sprintf("upgraded to %s", tierLabel(newTier)),
	}, nil
}

func (s *B2BServer) GetUsageStats(ctx context.Context, req *api.GetUsageStatsRequest) (*api.UsageStats, error) {
	partner, err := s.partnerFromContext(ctx)
	if err != nil {
		return nil, err
	}

	if req.AccountId != "" && req.AccountId != partner.ID {
		return nil, status.Error(codes.PermissionDenied, "account access denied")
	}

	account := s.ensureAccount(partner)

	return &api.UsageStats{
		TransactionsHour:  account.Usage.TransactionsHour,
		StorageUsed:       account.Usage.StorageUsed,
		ContractsDeployed: account.Usage.ContractsDeployed,
		LastReset:         account.Usage.LastReset.Unix(),
	}, nil
}

func (s *B2BServer) SubmitTransaction(ctx context.Context, req *api.SubmitTransactionRequest) (*api.SubmitTransactionResponse, error) {
	partner, err := s.partnerFromContext(ctx)
	if err != nil {
		return nil, err
	}

	if len(req.TransactionData) == 0 {
		return nil, status.Error(codes.InvalidArgument, "transaction_data is required")
	}

	txID := fmt.Sprintf("tx_%s_%d", partner.ID, time.Now().UnixNano())
	statusText := "submitted"

	record := &transactionRecord{
		Status: &api.TransactionStatus{
			TransactionId: txID,
			Status:        statusText,
			Timestamp:     time.Now().Unix(),
		},
		Data:      req.TransactionData,
		Timestamp: time.Now(),
	}

	s.transactionsMu.Lock()
	s.transactions[txID] = record
	s.transactionsMu.Unlock()

	s.recordUsage(partner, "transaction", 1)

	return &api.SubmitTransactionResponse{
		TransactionId: txID,
		Status:        statusText,
	}, nil
}

func (s *B2BServer) GetTransactionStatus(ctx context.Context, req *api.GetTransactionStatusRequest) (*api.TransactionStatus, error) {
	_, err := s.partnerFromContext(ctx)
	if err != nil {
		return nil, err
	}

	if strings.TrimSpace(req.TransactionId) == "" {
		return nil, status.Error(codes.InvalidArgument, "transaction_id is required")
	}

	s.transactionsMu.RLock()
	record, exists := s.transactions[req.TransactionId]
	s.transactionsMu.RUnlock()
	if !exists {
		return nil, status.Error(codes.NotFound, "transaction not found")
	}

	return record.Status, nil
}

func (s *B2BServer) StreamTransactions(req *api.StreamTransactionsRequest, stream api.LockBoxAPI_StreamTransactionsServer) error {
	partner, err := s.partnerFromContext(stream.Context())
	if err != nil {
		return err
	}

	startTime := time.Unix(req.StartTime, 0)

	s.transactionsMu.RLock()
	records := make([]*transactionRecord, 0, len(s.transactions))
	for _, record := range s.transactions {
		records = append(records, record)
	}
	s.transactionsMu.RUnlock()

	sort.Slice(records, func(i, j int) bool {
		return records[i].Timestamp.Before(records[j].Timestamp)
	})

	for _, record := range records {
		if !record.Timestamp.After(startTime) {
			continue
		}
		tx := &api.Transaction{
			TransactionId: record.Status.TransactionId,
			Data:          record.Data,
			Timestamp:     record.Timestamp.Unix(),
			Sender:        partner.ID,
			Receiver:      "",
			Metadata:      map[string]string{},
		}
		if err := stream.Send(tx); err != nil {
			return err
		}
	}

	return nil
}

func (s *B2BServer) StreamEvents(req *api.StreamEventsRequest, stream api.LockBoxAPI_StreamEventsServer) error {
	partner, err := s.partnerFromContext(stream.Context())
	if err != nil {
		return err
	}

	if len(req.EventTypes) == 0 {
		return nil
	}

	for _, eventType := range req.EventTypes {
		if strings.EqualFold(eventType, "stream_start") {
			ev := &api.Event{
				EventId:   fmt.Sprintf("evt_%s_%d", partner.ID, time.Now().UnixNano()),
				EventType: "stream_start",
				Timestamp: time.Now().Unix(),
				Data: map[string]string{
					"partner_id": partner.ID,
				},
			}
			return stream.Send(ev)
		}
	}

	return nil
}
