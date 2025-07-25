package lockbox

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/iotaledger/hive.go/kvstore"
	"github.com/iotaledger/hive.go/logger"
	"github.com/iotaledger/lockbox/v2/lockbox/consensus"
	"github.com/iotaledger/lockbox/v2/lockbox/lockscript"
	"github.com/iotaledger/lockbox/v2/lockbox/tiering"
	"github.com/iotaledger/lockbox/v2/lockbox/vault"
	"github.com/iotaledger/lockbox/v2/pkg/model/storage"
	"github.com/iotaledger/lockbox/v2/pkg/model/syncmanager"
	"github.com/iotaledger/lockbox/v2/pkg/model/utxo"
	"github.com/iotaledger/lockbox/v2/pkg/protocol"
	iotago "github.com/iotaledger/iota.go/v3"
)

// Service provides the main LockBox functionality
type Service struct {
	*logger.WrappedLogger
	
	storage         *storage.Storage
	utxoManager     *utxo.Manager
	syncManager     *syncmanager.SyncManager
	protocolManager *protocol.Manager
	storageManager  *StorageManager
	scriptEngine    *lockscript.Engine
	vaultManager    *vault.Manager
	tierManager     *tiering.Manager
	consensusManager *consensus.Manager
	
	config          *ServiceConfig
	lockedAssets    map[string]*LockedAsset
	assetsLock      sync.RWMutex
	
	// Shutdown handling
	shutdownCtx     context.Context
	shutdownCancel  context.CancelFunc
}

// NewService creates a new LockBox service
func NewService(
	log *logger.Logger,
	storage *storage.Storage,
	utxoManager *utxo.Manager,
	syncManager *syncmanager.SyncManager,
	protocolManager *protocol.Manager,
	config *ServiceConfig,
) (*Service, error) {
	ctx, cancel := context.WithCancel(context.Background())
	
	// Create storage manager
	storageManager, err := NewStorageManager(storage.KVStore())
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create storage manager: %w", err)
	}
	
	// Create script engine
	scriptEngine := lockscript.NewEngine(log, config.MaxScriptSize, config.MaxExecutionTime)
	
	// Create vault manager
	vaultManager := vault.NewManager(log, 24*time.Hour, true) // 24h rotation, backups enabled
	
	// Create tier manager
	tierManager := tiering.NewManager(log)
	
	// Create consensus manager
	consensusManager := consensus.NewManager(log, storage, protocolManager)
	
	s := &Service{
		WrappedLogger:    logger.NewWrappedLogger(log),
		storage:          storage,
		utxoManager:      utxoManager,
		syncManager:      syncManager,
		protocolManager:  protocolManager,
		storageManager:   storageManager,
		scriptEngine:     scriptEngine,
		vaultManager:     vaultManager,
		tierManager:      tierManager,
		consensusManager: consensusManager,
		config:           config,
		lockedAssets:     make(map[string]*LockedAsset),
		shutdownCtx:      ctx,
		shutdownCancel:   cancel,
	}
	
	// Load existing locked assets
	if err := s.loadLockedAssets(); err != nil {
		cancel()
		return nil, fmt.Errorf("failed to load locked assets: %w", err)
	}
	
	return s, nil
}

// InitializeCompiler initializes the LockScript compiler
func (s *Service) InitializeCompiler() error {
	return s.scriptEngine.CompileScript(s.shutdownCtx, "")
}

// LockAsset locks an asset according to the specified conditions
func (s *Service) LockAsset(ctx context.Context, req *LockAssetRequest) (*LockAssetResponse, error) {
	// Validate request
	if err := s.validateLockRequest(req); err != nil {
		return nil, fmt.Errorf("invalid lock request: %w", err)
	}
	
	// Check if output exists and is unspent
	output, err := s.utxoManager.ReadOutputByOutputID(req.OutputID)
	if err != nil {
		if errors.Is(err, kvstore.ErrKeyNotFound) {
			return nil, fmt.Errorf("output not found: %s", req.OutputID.ToHex())
		}
		return nil, fmt.Errorf("failed to read output: %w", err)
	}
	
	// Verify ownership
	if !s.verifyOwnership(output, req.OwnerAddress) {
		return nil, errors.New("caller does not own the output")
	}
	
	// Compile and validate lock script
	compiledScript, err := s.scriptEngine.CompileScript(ctx, req.LockScript)
	if err != nil {
		return nil, fmt.Errorf("failed to compile lock script: %w", err)
	}
	
	// Create locked asset
	assetID := s.generateAssetID()
	now := time.Now()
	unlockTime := now.Add(req.LockDuration)
	
	asset := &LockedAsset{
		ID:                assetID,
		OwnerAddress:      req.OwnerAddress,
		OutputID:          req.OutputID,
		Amount:            output.Deposit(),
		LockTime:          now,
		UnlockTime:        unlockTime,
		LockScript:        req.LockScript,
		MultiSigAddresses: req.MultiSigAddresses,
		MinSignatures:     req.MinSignatures,
		Status:            AssetStatusLocked,
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	
	// Store in memory and persistent storage
	s.assetsLock.Lock()
	s.lockedAssets[assetID] = asset
	s.assetsLock.Unlock()
	
	if err := s.storageManager.StoreLockedAsset(asset); err != nil {
		s.assetsLock.Lock()
		delete(s.lockedAssets, assetID)
		s.assetsLock.Unlock()
		return nil, fmt.Errorf("failed to store locked asset: %w", err)
	}
	
	// Log the lock event
	s.LogInfof("Asset locked: ID=%s, Amount=%d, UnlockTime=%s", assetID, asset.Amount, unlockTime)
	
	return &LockAssetResponse{
		AssetID:    assetID,
		LockTime:   now,
		UnlockTime: unlockTime,
		Status:     AssetStatusLocked,
	}, nil
}

// UnlockAsset unlocks a previously locked asset
func (s *Service) UnlockAsset(ctx context.Context, req *UnlockAssetRequest) (*UnlockAssetResponse, error) {
	s.assetsLock.RLock()
	asset, exists := s.lockedAssets[req.AssetID]
	s.assetsLock.RUnlock()
	
	if !exists {
		return nil, fmt.Errorf("asset not found: %s", req.AssetID)
	}
	
	// Check if asset can be unlocked
	now := time.Now()
	if now.Before(asset.UnlockTime) && !s.config.EnableEmergencyUnlock {
		return nil, fmt.Errorf("asset cannot be unlocked until %s", asset.UnlockTime)
	}
	
	// Verify unlock conditions
	if err := s.verifyUnlockConditions(ctx, asset, req); err != nil {
		return nil, fmt.Errorf("unlock conditions not met: %w", err)
	}
	
	// Update asset status
	asset.Status = AssetStatusUnlocked
	asset.UpdatedAt = now
	
	// Update storage
	if err := s.storageManager.StoreLockedAsset(asset); err != nil {
		return nil, fmt.Errorf("failed to update asset: %w", err)
	}
	
	// Log the unlock event
	s.LogInfof("Asset unlocked: ID=%s", req.AssetID)
	
	return &UnlockAssetResponse{
		AssetID:    req.AssetID,
		OutputID:   asset.OutputID,
		UnlockTime: now,
		Status:     AssetStatusUnlocked,
	}, nil
}

// ProcessMilestone processes a new milestone for any required actions
func (s *Service) ProcessMilestone(msIndex iotago.MilestoneIndex) error {
	// Check for expired locks
	s.processExpiredLocks()
	
	// Process pending unlocks
	if err := s.ProcessPendingUnlocks(); err != nil {
		return fmt.Errorf("failed to process pending unlocks: %w", err)
	}
	
	return nil
}

// ProcessPendingUnlocks processes assets that are ready to be unlocked
func (s *Service) ProcessPendingUnlocks() error {
	s.assetsLock.RLock()
	assets := make([]*LockedAsset, 0)
	for _, asset := range s.lockedAssets {
		if asset.Status == AssetStatusLocked && time.Now().After(asset.UnlockTime) {
			assets = append(assets, asset)
		}
	}
	s.assetsLock.RUnlock()
	
	for _, asset := range assets {
		asset.Status = AssetStatusExpired
		asset.UpdatedAt = time.Now()
		
		if err := s.storageManager.StoreLockedAsset(asset); err != nil {
			s.LogWarnf("Failed to update expired asset %s: %s", asset.ID, err)
		}
	}
	
	return nil
}

// Helper methods

func (s *Service) validateLockRequest(req *LockAssetRequest) error {
	if req.LockDuration < s.config.MinLockPeriod {
		return fmt.Errorf("lock duration too short: minimum %s", s.config.MinLockPeriod)
	}
	
	if req.LockDuration > s.config.MaxLockPeriod {
		return fmt.Errorf("lock duration too long: maximum %s", s.config.MaxLockPeriod)
	}
	
	if len(req.LockScript) > s.config.MaxScriptSize {
		return fmt.Errorf("lock script too large: maximum %d bytes", s.config.MaxScriptSize)
	}
	
	if s.config.MultiSigRequired && len(req.MultiSigAddresses) < s.config.MinMultiSigSigners {
		return fmt.Errorf("insufficient multi-sig signers: minimum %d", s.config.MinMultiSigSigners)
	}
	
	return nil
}

func (s *Service) verifyOwnership(output *utxo.Output, address iotago.Address) bool {
	// Check if the output belongs to the specified address
	switch o := output.Output().(type) {
	case *iotago.BasicOutput:
		return o.UnlockConditionSet().Address().Address.Equal(address)
	case *iotago.AliasOutput:
		return o.UnlockConditionSet().GovernorAddress().Address.Equal(address)
	case *iotago.NFTOutput:
		return o.UnlockConditionSet().Address().Address.Equal(address)
	default:
		return false
	}
}

func (s *Service) verifyUnlockConditions(ctx context.Context, asset *LockedAsset, req *UnlockAssetRequest) error {
	// Compile the lock script
	compiledScript, err := s.scriptEngine.CompileScript(ctx, asset.LockScript)
	if err != nil {
		return fmt.Errorf("failed to compile lock script: %w", err)
	}
	
	// Create execution environment
	env := &lockscript.Environment{
		Variables: make(map[string]interface{}),
		Sender:    asset.OwnerAddress.String(),
		Timestamp: time.Now(),
	}
	
	// Add unlock parameters to environment
	for k, v := range req.UnlockParams {
		env.Variables[k] = v
	}
	
	// Add signatures if multi-sig is required
	if len(asset.MultiSigAddresses) > 0 {
		if len(req.Signatures) < asset.MinSignatures {
			return fmt.Errorf("insufficient signatures: required %d, got %d", asset.MinSignatures, len(req.Signatures))
		}
		// TODO: Verify signatures
	}
	
	// Execute the script
	result, err := s.scriptEngine.ExecuteScript(ctx, compiledScript, env)
	if err != nil {
		return fmt.Errorf("script execution failed: %w", err)
	}
	
	if !result.Success {
		return errors.New("unlock conditions not satisfied")
	}
	
	return nil
}

func (s *Service) generateAssetID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *Service) loadLockedAssets() error {
	assets, err := s.storageManager.ListLockedAssets()
	if err != nil {
		return err
	}
	
	s.assetsLock.Lock()
	defer s.assetsLock.Unlock()
	
	for _, asset := range assets {
		s.lockedAssets[asset.ID] = asset
	}
	
	s.LogInfof("Loaded %d locked assets", len(assets))
	return nil
}

func (s *Service) processExpiredLocks() {
	s.assetsLock.RLock()
	expiredAssets := make([]*LockedAsset, 0)
	now := time.Now()
	
	for _, asset := range s.lockedAssets {
		if asset.Status == AssetStatusLocked && now.After(asset.UnlockTime) {
			expiredAssets = append(expiredAssets, asset)
		}
	}
	s.assetsLock.RUnlock()
	
	for _, asset := range expiredAssets {
		s.LogInfof("Asset %s has expired", asset.ID)
		asset.Status = AssetStatusExpired
		asset.UpdatedAt = now
		
		if err := s.storageManager.StoreLockedAsset(asset); err != nil {
			s.LogWarnf("Failed to update expired asset %s: %s", asset.ID, err)
		}
	}
}

// Shutdown gracefully shuts down the service
func (s *Service) Shutdown() {
	s.shutdownCancel()
	s.LogInfo("LockBox service shutdown complete")
}