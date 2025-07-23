package lockbox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/iotaledger/hornet/v2/pkg/model/storage"
	"github.com/iotaledger/hornet/v2/pkg/model/syncmanager"
	"github.com/iotaledger/hornet/v2/pkg/model/utxo"
	"github.com/iotaledger/hornet/v2/pkg/protocol"
	iotago "github.com/iotaledger/iota.go/v3"
)

// Tier represents the LockBox service tier
type Tier int

const (
	TierBasic Tier = iota
	TierStandard
	TierPremium
	TierElite
)

// ServiceConfig holds the configuration for the LockBox service
type ServiceConfig struct {
	Tier                 Tier
	MinLockPeriod       time.Duration
	MaxLockPeriod       time.Duration
	MinHoldingsUSD      float64
	GeographicRedundancy int
	NodeLocations       []string
	MaxScriptSize       int
	MaxExecutionTime    time.Duration
	EnableEmergencyUnlock bool
	EmergencyDelayDays   int
	MultiSigRequired    bool
	MinMultiSigSigners  int
}

// Service implements the LockBox service
type Service struct {
	storage         *storage.Storage
	utxoManager     *utxo.Manager
	syncManager     *syncmanager.SyncManager
	protocolManager *protocol.Manager
	config          *ServiceConfig

	compiler *LockScriptCompiler

	mu               sync.RWMutex
	lockedAssets     map[string]*LockedAsset
	pendingUnlocks   map[string]*PendingUnlock
	emergencyUnlocks map[string]*EmergencyUnlock
}

// LockedAsset represents an asset locked in the LockBox
type LockedAsset struct {
	ID               string
	OutputID         iotago.OutputID
	Amount           uint64
	LockTime         time.Time
	UnlockTime       time.Time
	Owner            iotago.Address
	LockScript       *CompiledScript
	MultiSigRequired bool
	Signers          []iotago.Address
	Metadata         map[string]string
}

// PendingUnlock represents a pending unlock request
type PendingUnlock struct {
	AssetID      string
	RequestTime  time.Time
	UnlockScript []byte
	Signatures   [][]byte
	Status       string
}

// EmergencyUnlock represents an emergency unlock request
type EmergencyUnlock struct {
	AssetID     string
	RequestTime time.Time
	UnlockTime  time.Time
	Reason      string
	Approved    bool
}

// NewService creates a new LockBox service
func NewService(storage *storage.Storage, utxoManager *utxo.Manager, syncManager *syncmanager.SyncManager, protocolManager *protocol.Manager, config *ServiceConfig) (*Service, error) {
	s := &Service{
		storage:          storage,
		utxoManager:      utxoManager,
		syncManager:      syncManager,
		protocolManager:  protocolManager,
		config:           config,
		lockedAssets:     make(map[string]*LockedAsset),
		pendingUnlocks:   make(map[string]*PendingUnlock),
		emergencyUnlocks: make(map[string]*EmergencyUnlock),
	}

	// Initialize the LockScript compiler
	compiler, err := NewLockScriptCompiler(config.MaxScriptSize, config.MaxExecutionTime)
	if err != nil {
		return nil, err
	}
	s.compiler = compiler

	// Load existing locked assets from storage
	if err := s.loadLockedAssets(); err != nil {
		return nil, err
	}

	return s, nil
}

// InitializeCompiler initializes the LockScript compiler
func (s *Service) InitializeCompiler() error {
	return s.compiler.Initialize()
}

// LockAsset locks an asset with the specified conditions
func (s *Service) LockAsset(ctx context.Context, req *LockAssetRequest) (*LockAssetResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Validate tier permissions
	if err := s.validateTierPermissions(req); err != nil {
		return nil, err
	}

	// Compile and validate lock script
	compiled, err := s.compiler.Compile(req.LockScript)
	if err != nil {
		return nil, fmt.Errorf("failed to compile lock script: %w", err)
	}

	// Generate asset ID
	assetID := s.generateAssetID(req.OutputID, req.LockTime)

	// Create locked asset
	asset := &LockedAsset{
		ID:               assetID,
		OutputID:         req.OutputID,
		Amount:           req.Amount,
		LockTime:         req.LockTime,
		UnlockTime:       req.UnlockTime,
		Owner:            req.Owner,
		LockScript:       compiled,
		MultiSigRequired: req.MultiSigRequired,
		Signers:          req.Signers,
		Metadata:         req.Metadata,
	}

	// Store locked asset
	if err := s.storeLockedAsset(asset); err != nil {
		return nil, err
	}

	s.lockedAssets[assetID] = asset

	return &LockAssetResponse{
		AssetID:    assetID,
		LockTime:   asset.LockTime,
		UnlockTime: asset.UnlockTime,
		Status:     "locked",
	}, nil
}

// UnlockAsset unlocks an asset if conditions are met
func (s *Service) UnlockAsset(ctx context.Context, req *UnlockAssetRequest) (*UnlockAssetResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	asset, exists := s.lockedAssets[req.AssetID]
	if !exists {
		return nil, errors.New("asset not found")
	}

	// Check if unlock time has passed
	if time.Now().Before(asset.UnlockTime) {
		return nil, errors.New("unlock time not reached")
	}

	// Execute unlock script
	env := NewScriptEnvironment(asset, req.UnlockData)
	result, err := s.compiler.Execute(asset.LockScript, env)
	if err != nil {
		return nil, fmt.Errorf("unlock script execution failed: %w", err)
	}

	if !result.Success {
		return nil, errors.New("unlock conditions not met")
	}

	// Verify multi-sig if required
	if asset.MultiSigRequired {
		if err := s.verifyMultiSig(asset, req.Signatures); err != nil {
			return nil, err
		}
	}

	// Process unlock
	if err := s.processUnlock(asset); err != nil {
		return nil, err
	}

	delete(s.lockedAssets, req.AssetID)

	return &UnlockAssetResponse{
		AssetID:    req.AssetID,
		OutputID:   asset.OutputID,
		UnlockTime: time.Now(),
		Status:     "unlocked",
	}, nil
}

// ProcessMilestone processes a confirmed milestone
func (s *Service) ProcessMilestone(msIndex iotago.MilestoneIndex) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check for assets that should be automatically unlocked
	for id, asset := range s.lockedAssets {
		if time.Now().After(asset.UnlockTime) {
			// Check if auto-unlock is enabled in script
			env := NewScriptEnvironment(asset, nil)
			env.Set("auto_unlock", true)
			
			result, err := s.compiler.Execute(asset.LockScript, env)
			if err == nil && result.Success {
				if err := s.processUnlock(asset); err == nil {
					delete(s.lockedAssets, id)
				}
			}
		}
	}

	return nil
}

// ProcessPendingUnlocks processes pending unlock requests
func (s *Service) ProcessPendingUnlocks() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for id, pending := range s.pendingUnlocks {
		asset, exists := s.lockedAssets[pending.AssetID]
		if !exists {
			delete(s.pendingUnlocks, id)
			continue
		}

		// Re-check unlock conditions
		env := NewScriptEnvironment(asset, nil)
		result, err := s.compiler.Execute(asset.LockScript, env)
		if err == nil && result.Success {
			if err := s.processUnlock(asset); err == nil {
				delete(s.lockedAssets, pending.AssetID)
				delete(s.pendingUnlocks, id)
			}
		}
	}

	return nil
}

// Helper methods

func (s *Service) validateTierPermissions(req *LockAssetRequest) error {
	switch s.config.Tier {
	case TierBasic:
		if req.LockDuration > 30*24*time.Hour {
			return errors.New("basic tier limited to 30 day locks")
		}
	case TierStandard:
		if req.LockDuration > 365*24*time.Hour {
			return errors.New("standard tier limited to 1 year locks")
		}
	case TierPremium:
		// Premium has higher limits
	case TierElite:
		// Elite has no limits
	}
	return nil
}

func (s *Service) generateAssetID(outputID iotago.OutputID, lockTime time.Time) string {
	h := sha256.New()
	h.Write(outputID[:])
	h.Write([]byte(lockTime.Format(time.RFC3339)))
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func (s *Service) storeLockedAsset(asset *LockedAsset) error {
	// Store in database
	// Implementation depends on storage backend
	return nil
}

func (s *Service) loadLockedAssets() error {
	// Load from database
	// Implementation depends on storage backend
	return nil
}

func (s *Service) processUnlock(asset *LockedAsset) error {
	// Process the unlock transaction
	// Implementation depends on UTXO manager
	return nil
}

func (s *Service) verifyMultiSig(asset *LockedAsset, signatures [][]byte) error {
	if len(signatures) < s.config.MinMultiSigSigners {
		return errors.New("insufficient signatures")
	}
	// Verify each signature
	// Implementation depends on crypto library
	return nil
}

// Request/Response types

type LockAssetRequest struct {
	OutputID         iotago.OutputID
	Amount           uint64
	LockTime         time.Time
	UnlockTime       time.Time
	LockDuration     time.Duration
	Owner            iotago.Address
	LockScript       []byte
	MultiSigRequired bool
	Signers          []iotago.Address
	Metadata         map[string]string
}

type LockAssetResponse struct {
	AssetID    string
	LockTime   time.Time
	UnlockTime time.Time
	Status     string
}

type UnlockAssetRequest struct {
	AssetID    string
	UnlockData map[string]interface{}
	Signatures [][]byte
}

type UnlockAssetResponse struct {
	AssetID    string
	OutputID   iotago.OutputID
	UnlockTime time.Time
	Status     string
}