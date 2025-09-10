package lockbox

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/iotaledger/hive.go/kvstore"
	"github.com/iotaledger/hive.go/logger"
	"github.com/iotaledger/hive.go/runtime/event"
	"github.com/iotaledger/hornet/v2/pkg/lockbox/lockscript"
	"github.com/iotaledger/hornet/v2/pkg/lockbox/vault"
	"github.com/iotaledger/hornet/v2/pkg/lockbox/verification"
	"github.com/iotaledger/hornet/v2/pkg/model/storage"
	"github.com/iotaledger/hornet/v2/pkg/model/syncmanager"
	"github.com/iotaledger/hornet/v2/pkg/model/utxo"
	"github.com/iotaledger/hornet/v2/pkg/protocol"
	iotago "github.com/iotaledger/iota.go/v3"
)

type Events struct {
	AssetLocked   *event.Event1[*LockedAsset]
	AssetUnlocked *event.Event1[*LockedAsset]
	ScriptCompiled *event.Event1[string]
	VaultCreated  *event.Event1[string]
}

type Service struct {
	*logger.WrappedLogger
	storage         *storage.Storage
	utxoManager     *utxo.Manager
	syncManager     *syncmanager.SyncManager
	protocolManager *protocol.Manager
	config          *ServiceConfig
	
	storageManager   *StorageManager
	scriptEngine     *lockscript.Engine
	vaultManager     *vault.Manager
	
	// Verification components
	verifier      *verification.Verifier
	nodeSelector  *verification.NodeSelector
	tokenManager  *verification.TokenManager
	retryManager  *verification.RetryManager
	
	// State tracking
	pendingUnlocks sync.Map
	processedTxs   sync.Map
	
	Events *Events
	
	shutdownOnce sync.Once
	isShutdown   bool
	shutdownChan chan struct{}
}

func NewService(
	log *logger.Logger,
	storage *storage.Storage,
	utxoManager *utxo.Manager,
	syncManager *syncmanager.SyncManager,
	protocolManager *protocol.Manager,
	config *ServiceConfig,
) (*Service, error) {
	// Initialize storage manager
	lockboxStore, err := storage.Store.WithRealm([]byte{0xFF})
	if err != nil {
		return nil, fmt.Errorf("failed to create lockbox store: %w", err)
	}
	
	storageManager, err := NewStorageManager(lockboxStore)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage manager: %w", err)
	}
	
	// Initialize script engine with proper limits
	scriptEngine := lockscript.NewEngine(
		log,
		config.MaxScriptSize,
		config.MaxExecutionTime,
	)
	
	// Initialize vault manager
	vaultManager := vault.NewManager(
		log,
		24*time.Hour, // rotation interval
		true,         // backup enabled
	)
	
	s := &Service{
		WrappedLogger:   logger.NewWrappedLogger(log),
		storage:         storage,
		utxoManager:     utxoManager,
		syncManager:     syncManager,
		protocolManager: protocolManager,
		config:          config,
		storageManager:  storageManager,
		scriptEngine:    scriptEngine,
		vaultManager:    vaultManager,
		Events: &Events{
			AssetLocked:    event.New1[*LockedAsset](),
			AssetUnlocked:  event.New1[*LockedAsset](),
			ScriptCompiled: event.New1[string](),
			VaultCreated:   event.New1[string](),
		},
		shutdownChan: make(chan struct{}),
	}
	
	// Load existing scripts into cache
	if err := s.loadScripts(); err != nil {
		return nil, fmt.Errorf("failed to load scripts: %w", err)
	}
	
	// Load pending unlocks
	if err := s.loadPendingUnlocks(); err != nil {
		return nil, fmt.Errorf("failed to load pending unlocks: %w", err)
	}
	
	return s, nil
}

func (s *Service) InitializeVerification() error {
	// Initialize node selector
	s.nodeSelector = verification.NewNodeSelector(s.WrappedLogger.Logger)
	for _, location := range s.config.NodeLocations {
		node := &verification.VerificationNode{
			ID:         fmt.Sprintf("node-%s-%d", location, time.Now().Unix()),
			Region:     location,
			Capacity:   100,
			Latency:    50 * time.Millisecond,
			Reputation: 0.95,
			Available:  true,
		}
		if err := s.nodeSelector.RegisterNode(node); err != nil {
			return fmt.Errorf("failed to register verification node: %w", err)
		}
	}
	
	// Initialize token manager
	rotationPeriod := 24 * time.Hour
	if s.config.Tier == TierElite {
		rotationPeriod = 1 * time.Hour
	}
	s.tokenManager = verification.NewTokenManager(s.WrappedLogger.Logger, rotationPeriod, 7*24*time.Hour)
	go s.tokenManager.Start(context.Background())
	
	// Initialize retry manager
	retryConfig := verification.DefaultRetryConfig()
	if s.config.Tier == TierElite {
		retryConfig.MaxAttempts = 10
		retryConfig.InitialBackoff = 50 * time.Millisecond
	}
	s.retryManager = verification.NewRetryManager(s.WrappedLogger.Logger, retryConfig)
	
	// Initialize verifier
	s.verifier = verification.NewVerifier(
		s.WrappedLogger.Logger,
		s.nodeSelector,
		s.tokenManager,
		s.storageManager,
	)
	
	s.LogInfo("Verification system initialized successfully")
	return nil
}

func (s *Service) InitializeCompiler() error {
	// Register built-in functions
	s.scriptEngine.RegisterBuiltinFunctions()
	
	s.LogInfo("LockScript compiler initialized successfully")
	return nil
}

func (s *Service) LockAsset(ctx context.Context, req *LockAssetRequest) (*LockAssetResponse, error) {
	// Validate request
	if err := s.validateLockRequest(req); err != nil {
		return nil, err
	}
	
	// Check if output exists and is unspent
	output, err := s.utxoManager.ReadOutputByOutputID(req.OutputID)
	if err != nil {
		return nil, fmt.Errorf("failed to read output: %w", err)
	}
	
	// Verify ownership
	if !s.verifyOwnership(output, req.OwnerAddress) {
		return nil, fmt.Errorf("address does not own the output")
	}
	
	// Compile lock script if provided
	var compiledScript *lockscript.CompiledScript
	if req.LockScript != "" {
		compiledScript, err = s.scriptEngine.CompileScript(ctx, req.LockScript)
		if err != nil {
			return nil, fmt.Errorf("failed to compile lock script: %w", err)
		}
	}
	
	// Generate asset ID
	assetID := s.generateAssetID()
	
	// Create locked asset
	now := time.Now()
	asset := &LockedAsset{
		ID:                assetID,
		OwnerAddress:      req.OwnerAddress,
		OutputID:          req.OutputID,
		Amount:            output.Deposit(),
		LockTime:          now,
		UnlockTime:        now.Add(req.LockDuration),
		LockScript:        req.LockScript,
		MultiSigAddresses: req.MultiSigAddresses,
		MinSignatures:     req.MinSignatures,
		Status:            AssetStatusLocked,
		CreatedAt:         now,
		UpdatedAt:         now,
		EmergencyUnlock:   s.config.EnableEmergencyUnlock,
	}
	
	// Store the asset
	if err := s.storageManager.StoreLockedAsset(asset); err != nil {
		return nil, fmt.Errorf("failed to store locked asset: %w", err)
	}
	
	// Emit event
	s.Events.AssetLocked.Trigger(asset)
	
	return &LockAssetResponse{
		AssetID:    assetID,
		LockTime:   asset.LockTime,
		UnlockTime: asset.UnlockTime,
		Status:     string(asset.Status),
	}, nil
}

func (s *Service) UnlockAsset(ctx context.Context, req *UnlockAssetRequest) (*UnlockAssetResponse, error) {
	// Get the locked asset
	asset, err := s.storageManager.GetLockedAsset(req.AssetID)
	if err != nil {
		return nil, fmt.Errorf("asset not found: %w", err)
	}
	
	// Check if unlockable
	now := time.Now()
	if now.Before(asset.UnlockTime) && !asset.EmergencyUnlock {
		return nil, fmt.Errorf("asset cannot be unlocked yet")
	}
	
	// Verify unlock conditions
	if err := s.verifyUnlockConditions(ctx, asset, req); err != nil {
		return nil, fmt.Errorf("unlock conditions not met: %w", err)
	}
	
	// Update asset status
	asset.Status = AssetStatusUnlocking
	asset.UpdatedAt = now
	
	if err := s.storageManager.StoreLockedAsset(asset); err != nil {
		return nil, fmt.Errorf("failed to update asset status: %w", err)
	}
	
	// Add to pending unlocks
	s.pendingUnlocks.Store(asset.ID, asset)
	
	// Emit event
	s.Events.AssetUnlocked.Trigger(asset)
	
	return &UnlockAssetResponse{
		AssetID:    asset.ID,
		OutputID:   asset.OutputID,
		UnlockTime: now,
		Status:     string(asset.Status),
	}, nil
}

func (s *Service) ProcessMilestone(ctx context.Context, msIndex iotago.MilestoneIndex) error {
	// Process any pending unlocks that can be finalized
	var toProcess []*LockedAsset
	
	s.pendingUnlocks.Range(func(key, value interface{}) bool {
		asset := value.(*LockedAsset)
		toProcess = append(toProcess, asset)
		return true
	})
	
	for _, asset := range toProcess {
		if err := s.finalizeUnlock(ctx, asset, msIndex); err != nil {
			s.LogWarnf("failed to finalize unlock for asset %s: %s", asset.ID, err)
		}
	}
	
	return nil
}

func (s *Service) ProcessPendingUnlocks(ctx context.Context) error {
	// Get all pending unlocks from storage
	unlocks, err := s.storageManager.GetPendingUnlocks()
	if err != nil {
		return err
	}
	
	now := time.Now()
	for assetID, unlockTime := range unlocks {
		if now.Unix() >= unlockTime {
			asset, err := s.storageManager.GetLockedAsset(assetID)
			if err != nil {
				s.LogWarnf("failed to get asset %s: %s", assetID, err)
				continue
			}
			
			if err := s.finalizeUnlock(ctx, asset, 0); err != nil {
				s.LogWarnf("failed to finalize unlock for asset %s: %s", assetID, err)
			}
		}
	}
	
	return nil
}

func (s *Service) MonitorVerificationHealth(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.LogDebug("Checking verification node health...")
			// Implement health check logic
		}
	}
}

func (s *Service) OptimizeNodeSelection() {
	s.LogDebug("Optimizing node selection based on performance metrics")
	// Implement optimization logic
}

// Helper methods

func (s *Service) validateLockRequest(req *LockAssetRequest) error {
	if req.OwnerAddress == nil {
		return fmt.Errorf("owner address is required")
	}
	
	if req.LockDuration < s.config.MinLockPeriod {
		return fmt.Errorf("lock duration must be at least %s", s.config.MinLockPeriod)
	}
	
	if req.LockDuration > s.config.MaxLockPeriod {
		return fmt.Errorf("lock duration cannot exceed %s", s.config.MaxLockPeriod)
	}
	
	if len(req.LockScript) > s.config.MaxScriptSize {
		return fmt.Errorf("lock script exceeds maximum size")
	}
	
	if len(req.MultiSigAddresses) > 0 && req.MinSignatures <= 0 {
		return fmt.Errorf("minimum signatures must be specified for multi-sig")
	}
	
	return nil
}

func (s *Service) verifyOwnership(output *utxo.Output, address iotago.Address) bool {
	// Implement ownership verification logic
	switch out := output.Output().(type) {
	case *iotago.BasicOutput:
		return out.UnlockConditionSet().Address().Address.Equal(address)
	default:
		return false
	}
}

func (s *Service) verifyUnlockConditions(ctx context.Context, asset *LockedAsset, req *UnlockAssetRequest) error {
	// Verify multi-sig if required
	if len(asset.MultiSigAddresses) > 0 {
		if len(req.Signatures) < asset.MinSignatures {
			return fmt.Errorf("insufficient signatures")
		}
		// Implement signature verification
	}
	
	// Execute lock script if present
	if asset.LockScript != "" {
		compiled, err := s.scriptEngine.CompileScript(ctx, asset.LockScript)
		if err != nil {
			return fmt.Errorf("failed to compile lock script: %w", err)
		}
		
		env := &lockscript.Environment{
			Variables: req.UnlockParams,
			Sender:    asset.OwnerAddress.String(),
			Timestamp: time.Now(),
		}
		
		result, err := s.scriptEngine.ExecuteScript(ctx, compiled, env)
		if err != nil {
			return fmt.Errorf("failed to execute lock script: %w", err)
		}
		
		if !result.Success {
			return fmt.Errorf("lock script execution failed")
		}
	}
	
	return nil
}

func (s *Service) finalizeUnlock(ctx context.Context, asset *LockedAsset, msIndex iotago.MilestoneIndex) error {
	// Update asset status
	asset.Status = AssetStatusUnlocked
	asset.UpdatedAt = time.Now()
	
	// Store updated asset
	if err := s.storageManager.StoreLockedAsset(asset); err != nil {
		return err
	}
	
	// Remove from pending unlocks
	s.pendingUnlocks.Delete(asset.ID)
	
	s.LogInfof("Asset %s unlocked successfully", asset.ID)
	return nil
}

func (s *Service) generateAssetID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *Service) loadScripts() error {
	scripts, err := s.storageManager.LoadScripts()
	if err != nil {
		return err
	}
	
	for _, script := range scripts {
		if err := s.scriptEngine.LoadScript(script); err != nil {
			s.LogWarnf("failed to load script: %s", err)
		}
	}
	
	s.LogInfof("Loaded %d scripts", len(scripts))
	return nil
}

func (s *Service) loadPendingUnlocks() error {
	unlocks, err := s.storageManager.GetPendingUnlocks()
	if err != nil {
		return err
	}
	
	for assetID := range unlocks {
		asset, err := s.storageManager.GetLockedAsset(assetID)
		if err != nil {
			s.LogWarnf("failed to load asset %s: %s", assetID, err)
			continue
		}
		s.pendingUnlocks.Store(assetID, asset)
	}
	
	s.LogInfof("Loaded %d pending unlocks", len(unlocks))
	return nil
}

func (s *Service) Shutdown() {
	s.shutdownOnce.Do(func() {
		s.isShutdown = true
		close(s.shutdownChan)
		
		// Stop token manager
		if s.tokenManager != nil {
			s.tokenManager.Stop()
		}
		
		s.LogInfo("LockBox service shutdown complete")
	})
}