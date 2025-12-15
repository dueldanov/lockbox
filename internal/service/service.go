package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dueldanov/lockbox/v2/internal/crypto"
	"github.com/dueldanov/lockbox/v2/internal/verification"
	"github.com/dueldanov/lockbox/v2/pkg/model/storage"
	"github.com/dueldanov/lockbox/v2/pkg/model/syncmanager"
	"github.com/dueldanov/lockbox/v2/pkg/model/utxo"
	"github.com/dueldanov/lockbox/v2/pkg/protocol"
	"github.com/iotaledger/hive.go/logger"
	iotago "github.com/iotaledger/iota.go/v3"
)

var (
	ErrAssetNotFound      = errors.New("asset not found")
	ErrAssetAlreadyLocked = errors.New("asset already locked")
	ErrUnauthorized       = errors.New("unauthorized")
	ErrInvalidUnlockTime  = errors.New("invalid unlock time")
)

type Service struct {
	*logger.WrappedLogger

	storage          *storage.Storage
	utxoManager      *utxo.Manager
	syncManager      *syncmanager.SyncManager
	protocolManager  *protocol.Manager
	config           *ServiceConfig
	storageManager   *StorageManager

	// Cryptography components
	shardEncryptor   *crypto.ShardEncryptor
	zkpManager       *crypto.ZKPManager

	// Verification components
	verifier         *verification.Verifier
	nodeSelector     *verification.NodeSelector
	tokenManager     *verification.TokenManager
	retryManager     *verification.RetryManager

	// Caches and state
	lockedAssets     map[string]*LockedAsset
	pendingUnlocks   map[string]time.Time
	mu               sync.RWMutex
	scriptCompiler   interface{} // Will be initialized in InitializeCompiler
}

func NewService(
	log *logger.Logger,
	storage *storage.Storage,
	utxoManager *utxo.Manager,
	syncManager *syncmanager.SyncManager,
	protocolManager *protocol.Manager,
	config *ServiceConfig,
) (*Service, error) {
	storageManager, err := NewStorageManager(storage.UTXOStore())
	if err != nil {
		return nil, err
	}

	// Load or generate persistent master key
	keyDir := filepath.Join(config.DataDir, "keys")
	keyStore, err := crypto.NewKeyStore(keyDir)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize key store: %w", err)
	}

	masterKey, err := keyStore.LoadOrGenerate()
	if err != nil {
		return nil, fmt.Errorf("failed to load master key: %w", err)
	}
	defer crypto.ClearBytes(masterKey) // Clear from memory after use

	// Initialize cryptography components
	shardEncryptor, err := crypto.NewShardEncryptor(masterKey, 4096) // 4KB shards
	if err != nil {
		crypto.ClearBytes(masterKey)
		return nil, fmt.Errorf("failed to initialize shard encryptor: %w", err)
	}

	zkpManager := crypto.NewZKPManager()

	return &Service{
		WrappedLogger:   logger.NewWrappedLogger(log),
		storage:         storage,
		utxoManager:     utxoManager,
		syncManager:     syncManager,
		protocolManager: protocolManager,
		config:          config,
		storageManager:  storageManager,
		shardEncryptor:  shardEncryptor,
		zkpManager:      zkpManager,
		lockedAssets:    make(map[string]*LockedAsset),
		pendingUnlocks:  make(map[string]time.Time),
	}, nil
}

func (s *Service) LockAsset(ctx context.Context, req *LockAssetRequest) (*LockAssetResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Validate request
	if req.LockDuration < s.config.MinLockPeriod || req.LockDuration > s.config.MaxLockPeriod {
		return nil, ErrInvalidUnlockTime
	}

	// Generate asset ID
	assetID := s.generateAssetID()
	lockTime := time.Now()
	unlockTime := lockTime.Add(req.LockDuration)

	// Create ownership proof
	ownerSecret := make([]byte, 32)
	if _, err := rand.Read(ownerSecret); err != nil {
		return nil, fmt.Errorf("failed to generate owner secret: %w", err)
	}

	ownershipProof, err := s.zkpManager.GenerateOwnershipProof([]byte(assetID), ownerSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ownership proof: %w", err)
	}

	// Encrypt asset data
	assetData, err := s.serializeAssetData(req)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize asset data: %w", err)
	}

	shards, err := s.shardEncryptor.EncryptData(assetData)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt asset data: %w", err)
	}

	// Store encrypted shards
	for _, shard := range shards {
		if err := s.storeEncryptedShard(assetID, shard); err != nil {
			return nil, fmt.Errorf("failed to store encrypted shard: %w", err)
		}
	}

	// Create locked asset
	asset := &LockedAsset{
		ID:                assetID,
		OwnerAddress:      req.OwnerAddress,
		OutputID:          req.OutputID,
		LockTime:          lockTime,
		UnlockTime:        unlockTime,
		LockScript:        req.LockScript,
		MultiSigAddresses: req.MultiSigAddresses,
		MinSignatures:     req.MinSignatures,
		Status:            AssetStatusLocked,
		CreatedAt:         lockTime,
		UpdatedAt:         lockTime,
	}

	// Store asset
	if err := s.storageManager.StoreLockedAsset(asset); err != nil {
		return nil, err
	}

	// Store ownership proof
	if err := s.storeOwnershipProof(assetID, ownershipProof); err != nil {
		return nil, fmt.Errorf("failed to store ownership proof: %w", err)
	}

	s.lockedAssets[assetID] = asset

	return &LockAssetResponse{
		AssetID:    assetID,
		LockTime:   lockTime,
		UnlockTime: unlockTime,
		Status:     AssetStatusLocked,
	}, nil
}

func (s *Service) UnlockAsset(ctx context.Context, req *UnlockAssetRequest) (*UnlockAssetResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Get asset
	asset, err := s.storageManager.GetLockedAsset(req.AssetID)
	if err != nil {
		return nil, ErrAssetNotFound
	}

	// Verify unlock time
	if time.Now().Before(asset.UnlockTime) {
		// Generate unlock proof for early unlock
		unlockProof, err := s.zkpManager.GenerateUnlockProof(
			[]byte(req.AssetID),
			[]byte(asset.ID),
			[]byte("early_unlock"),
			asset.UnlockTime.Unix(),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to generate unlock proof: %w", err)
		}

		// Verify unlock proof
		if err := s.zkpManager.VerifyUnlockProof(unlockProof); err != nil {
			return nil, ErrUnauthorized
		}
	}

	// Verify ownership proof if provided
	if ownershipProof, err := s.getOwnershipProof(req.AssetID); err == nil {
		if err := s.zkpManager.VerifyOwnershipProof(ownershipProof); err != nil {
			return nil, ErrUnauthorized
		}
	}

	// Retrieve and decrypt shards
	shards, err := s.retrieveEncryptedShards(req.AssetID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve encrypted shards: %w", err)
	}

	assetData, err := s.shardEncryptor.DecryptShards(shards)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt asset data: %w", err)
	}

	// Clear decrypted data after 1 minute
	timedClear := crypto.NewTimedClear()
	timedClear.Schedule(req.AssetID, assetData, 1*time.Minute)

	// Update asset status
	asset.Status = AssetStatusUnlocked
	asset.UpdatedAt = time.Now()

	if err := s.storageManager.StoreLockedAsset(asset); err != nil {
		return nil, err
	}

	// Clean up encrypted shards
	if err := s.cleanupEncryptedShards(req.AssetID); err != nil {
		// Log error but don't fail the unlock
		fmt.Printf("failed to cleanup encrypted shards: %v\n", err)
	}

	return &UnlockAssetResponse{
		AssetID:    asset.ID,
		OutputID:   asset.OutputID,
		UnlockTime: time.Now(),
		Status:     AssetStatusUnlocked,
	}, nil
}

func (s *Service) ProcessMilestone(msIndex iotago.MilestoneIndex) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Check pending unlocks
	now := time.Now()
	for assetID, unlockTime := range s.pendingUnlocks {
		if now.After(unlockTime) {
			asset, err := s.storageManager.GetLockedAsset(assetID)
			if err != nil {
				continue
			}

			asset.Status = AssetStatusUnlocked
			asset.UpdatedAt = now

			if err := s.storageManager.StoreLockedAsset(asset); err != nil {
				continue
			}

			delete(s.pendingUnlocks, assetID)
		}
	}

	return nil
}

func (s *Service) ProcessPendingUnlocks() error {
	assets, err := s.storageManager.ListLockedAssets()
	if err != nil {
		return err
	}

	now := time.Now()
	for _, asset := range assets {
		if asset.Status == AssetStatusLocked && now.After(asset.UnlockTime) {
			s.mu.Lock()
			s.pendingUnlocks[asset.ID] = asset.UnlockTime
			s.mu.Unlock()
		}
	}

	return nil
}

func (s *Service) InitializeCompiler() error {
	// This will be implemented with the LockScript compiler
	return nil
}

// Helper methods

func (s *Service) generateAssetID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *Service) serializeAssetData(req *LockAssetRequest) ([]byte, error) {
	// Simple serialization - in production use protobuf or similar
	data := fmt.Sprintf("%s|%s|%s|%d",
		req.OwnerAddress.String(),
		hex.EncodeToString(req.OutputID[:]),
		req.LockScript,
		req.MinSignatures,
	)
	return []byte(data), nil
}

func (s *Service) storeEncryptedShard(assetID string, shard *crypto.CharacterShard) error {
	key := fmt.Sprintf("shard_%s_%d", assetID, shard.Index)
	value, err := s.serializeShard(shard)
	if err != nil {
		return err
	}
	return s.storage.UTXOStore().Set([]byte(key), value)
}

func (s *Service) retrieveEncryptedShards(assetID string) ([]*crypto.CharacterShard, error) {
	// This is simplified - in production, track shard count
	var shards []*crypto.CharacterShard
	for i := uint32(0); i < 100; i++ { // Max 100 shards
		key := fmt.Sprintf("shard_%s_%d", assetID, i)
		value, err := s.storage.UTXOStore().Get([]byte(key))
		if err != nil {
			break // No more shards
		}
		
		shard, err := s.deserializeShard(value)
		if err != nil {
			return nil, err
		}
		shards = append(shards, shard)
		
		if len(shards) > 0 && uint32(len(shards)) == shards[0].Total {
			break // Got all shards
		}
	}
	
	return shards, nil
}

func (s *Service) cleanupEncryptedShards(assetID string) error {
	// Clean up all shards for this asset
	for i := uint32(0); i < 100; i++ {
		key := fmt.Sprintf("shard_%s_%d", assetID, i)
		if err := s.storage.UTXOStore().Delete([]byte(key)); err != nil {
			// Key might not exist, ignore error
			continue
		}
	}
	return nil
}

func (s *Service) serializeShard(shard *crypto.CharacterShard) ([]byte, error) {
	// Simple serialization - in production use protobuf
	data := fmt.Sprintf("%d|%d|%d|%d|%s|%s|%s",
		shard.ID,
		shard.Index,
		shard.Total,
		shard.Timestamp,
		hex.EncodeToString(shard.Data),
		hex.EncodeToString(shard.Nonce),
		hex.EncodeToString(shard.Checksum),
	)
	return []byte(data), nil
}

func (s *Service) deserializeShard(data []byte) (*crypto.CharacterShard, error) {
	// Parse pipe-delimited format: ID|Index|Total|Timestamp|DataHex|NonceHex|ChecksumHex
	parts := strings.Split(string(data), "|")
	if len(parts) != 7 {
		return nil, fmt.Errorf("invalid shard format: expected 7 fields, got %d", len(parts))
	}

	// Parse numeric fields
	id, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid shard ID: %w", err)
	}

	index, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid shard Index: %w", err)
	}

	total, err := strconv.ParseUint(parts[2], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid shard Total: %w", err)
	}

	timestamp, err := strconv.ParseInt(parts[3], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid shard Timestamp: %w", err)
	}

	// Decode hex fields
	shardData, err := hex.DecodeString(parts[4])
	if err != nil {
		return nil, fmt.Errorf("invalid shard Data hex: %w", err)
	}

	nonce, err := hex.DecodeString(parts[5])
	if err != nil {
		return nil, fmt.Errorf("invalid shard Nonce hex: %w", err)
	}

	checksum, err := hex.DecodeString(parts[6])
	if err != nil {
		return nil, fmt.Errorf("invalid shard Checksum hex: %w", err)
	}

	return &crypto.CharacterShard{
		ID:        uint32(id),
		Index:     uint32(index),
		Total:     uint32(total),
		Data:      shardData,
		Nonce:     nonce,
		Timestamp: timestamp,
		Checksum:  checksum,
	}, nil
}

func (s *Service) storeOwnershipProof(assetID string, proof *crypto.OwnershipProof) error {
	key := fmt.Sprintf("proof_%s", assetID)
	value := fmt.Sprintf("%s|%s|%d",
		hex.EncodeToString(proof.AssetCommitment),
		hex.EncodeToString(proof.OwnerAddress),
		proof.Timestamp,
	)
	return s.storage.UTXOStore().Set([]byte(key), []byte(value))
}

func (s *Service) getOwnershipProof(assetID string) (*crypto.OwnershipProof, error) {
	key := fmt.Sprintf("proof_%s", assetID)
	data, err := s.storage.UTXOStore().Get([]byte(key))
	if err != nil {
		return nil, err
	}

	// Parse pipe-delimited format: AssetCommitmentHex|OwnerAddressHex|Timestamp
	parts := strings.Split(string(data), "|")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid proof format: expected 3 fields, got %d", len(parts))
	}

	// Decode hex fields
	assetCommitment, err := hex.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid AssetCommitment hex: %w", err)
	}

	ownerAddress, err := hex.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid OwnerAddress hex: %w", err)
	}

	// Parse timestamp
	timestamp, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid Timestamp: %w", err)
	}

	return &crypto.OwnershipProof{
		AssetCommitment: assetCommitment,
		OwnerAddress:    ownerAddress,
		Timestamp:       timestamp,
		// Note: Proof field is not serialized in storeOwnershipProof()
	}, nil
}

// GetAssetStatus retrieves the current status of an asset
// Automatically updates status to Expired if unlock time has passed
func (s *Service) GetAssetStatus(assetID string) (*LockedAsset, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	asset, err := s.storageManager.GetLockedAsset(assetID)
	if err != nil {
		return nil, err
	}

	// Auto-update status to Expired if unlock time has passed
	if asset.Status == AssetStatusLocked && time.Now().After(asset.UnlockTime) {
		asset.Status = AssetStatusExpired
		asset.UpdatedAt = time.Now()
		if err := s.storageManager.StoreLockedAsset(asset); err != nil {
			return nil, fmt.Errorf("failed to update expired status: %w", err)
		}
	}

	return asset, nil
}

// ListAssets returns all assets matching the given filters
// If owner is nil, returns assets for all owners
// If statusFilter is empty, returns assets with any status
func (s *Service) ListAssets(owner iotago.Address, statusFilter AssetStatus) ([]*LockedAsset, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	allAssets, err := s.storageManager.ListLockedAssets()
	if err != nil {
		return nil, err
	}

	var filtered []*LockedAsset
	for _, asset := range allAssets {
		// Filter by owner (if specified)
		if owner != nil && !asset.OwnerAddress.Equal(owner) {
			continue
		}
		// Filter by status (if specified)
		if statusFilter != "" && asset.Status != statusFilter {
			continue
		}
		filtered = append(filtered, asset)
	}

	return filtered, nil
}

// EmergencyUnlock initiates an emergency unlock for an asset
// Requires multi-sig approval if configured, and applies delay from config
func (s *Service) EmergencyUnlock(assetID string, signatures [][]byte, reason string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	asset, err := s.storageManager.GetLockedAsset(assetID)
	if err != nil {
		return err
	}

	// Check if EmergencyUnlock is enabled for this tier
	if !s.config.EnableEmergencyUnlock {
		return fmt.Errorf("emergency unlock not enabled for this tier")
	}

	// Check multi-sig signatures if required
	if len(asset.MultiSigAddresses) > 0 && asset.MinSignatures > 0 {
		if len(signatures) < asset.MinSignatures {
			return fmt.Errorf("insufficient signatures: need %d, got %d",
				asset.MinSignatures, len(signatures))
		}
		// TODO: Verify each signature against MultiSigAddresses
	}

	// Apply delay from config (EmergencyDelayDays)
	delayDuration := time.Duration(s.config.EmergencyDelayDays) * 24 * time.Hour
	asset.UnlockTime = time.Now().Add(delayDuration)
	asset.EmergencyUnlock = true
	asset.Status = AssetStatusEmergency
	asset.UpdatedAt = time.Now()

	return s.storageManager.StoreLockedAsset(asset)
}