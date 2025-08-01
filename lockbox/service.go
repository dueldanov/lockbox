package lockbox

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/iotaledger/hornet/v2/lockbox/crypto"
	"github.com/iotaledger/hornet/v2/pkg/lockbox"
	"github.com/iotaledger/hornet/v2/pkg/model/storage"
	"github.com/iotaledger/hornet/v2/pkg/model/syncmanager"
	"github.com/iotaledger/hornet/v2/pkg/model/utxo"
	"github.com/iotaledger/hornet/v2/pkg/protocol"
	iotago "github.com/iotaledger/iota.go/v3"
)

var (
	ErrAssetNotFound      = errors.New("asset not found")
	ErrAssetAlreadyLocked = errors.New("asset already locked")
	ErrUnauthorized       = errors.New("unauthorized")
	ErrInvalidUnlockTime  = errors.New("invalid unlock time")
)

type Service struct {
	storage          *storage.Storage
	utxoManager      *utxo.Manager
	syncManager      *syncmanager.SyncManager
	protocolManager  *protocol.Manager
	config           *lockbox.ServiceConfig
	storageManager   *lockbox.StorageManager
	
	// Cryptography components
	shardEncryptor   *crypto.ShardEncryptor
	zkpManager       *crypto.ZKPManager
	
	// Caches and state
	lockedAssets     map[string]*lockbox.LockedAsset
	pendingUnlocks   map[string]time.Time
	mu               sync.RWMutex
	scriptCompiler   interface{} // Will be initialized in InitializeCompiler
}

func NewService(
	storage *storage.Storage,
	utxoManager *utxo.Manager,
	syncManager *syncmanager.SyncManager,
	protocolManager *protocol.Manager,
	config *lockbox.ServiceConfig,
) (*Service, error) {
	storageManager, err := lockbox.NewStorageManager(storage.UTXOStore())
	if err != nil {
		return nil, err
	}

	// Generate master key for encryption
	masterKey := make([]byte, 32)
	if _, err := rand.Read(masterKey); err != nil {
		return nil, fmt.Errorf("failed to generate master key: %w", err)
	}

	// Initialize cryptography components
	shardEncryptor, err := crypto.NewShardEncryptor(masterKey, 4096) // 4KB shards
	if err != nil {
		return nil, fmt.Errorf("failed to initialize shard encryptor: %w", err)
	}

	zkpManager := crypto.NewZKPManager()

	return &Service{
		storage:         storage,
		utxoManager:     utxoManager,
		syncManager:     syncManager,
		protocolManager: protocolManager,
		config:          config,
		storageManager:  storageManager,
		shardEncryptor:  shardEncryptor,
		zkpManager:      zkpManager,
		lockedAssets:    make(map[string]*lockbox.LockedAsset),
		pendingUnlocks:  make(map[string]time.Time),
	}, nil
}

func (s *Service) LockAsset(ctx context.Context, req *lockbox.LockAssetRequest) (*lockbox.LockAssetResponse, error) {
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
	asset := &lockbox.LockedAsset{
		ID:                assetID,
		OwnerAddress:      req.OwnerAddress,
		OutputID:          req.OutputID,
		LockTime:          lockTime,
		UnlockTime:        unlockTime,
		LockScript:        req.LockScript,
		MultiSigAddresses: req.MultiSigAddresses,
		MinSignatures:     req.MinSignatures,
		Status:            lockbox.AssetStatusLocked,
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

	return &lockbox.LockAssetResponse{
		AssetID:    assetID,
		LockTime:   lockTime,
		UnlockTime: unlockTime,
		Status:     lockbox.AssetStatusLocked,
	}, nil
}

func (s *Service) UnlockAsset(ctx context.Context, req *lockbox.UnlockAssetRequest) (*lockbox.UnlockAssetResponse, error) {
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
	asset.Status = lockbox.AssetStatusUnlocked
	asset.UpdatedAt = time.Now()

	if err := s.storageManager.StoreLockedAsset(asset); err != nil {
		return nil, err
	}

	// Clean up encrypted shards
	if err := s.cleanupEncryptedShards(req.AssetID); err != nil {
		// Log error but don't fail the unlock
		fmt.Printf("failed to cleanup encrypted shards: %v\n", err)
	}

	return &lockbox.UnlockAssetResponse{
		AssetID:    asset.ID,
		OutputID:   asset.OutputID,
		UnlockTime: time.Now(),
		Status:     lockbox.AssetStatusUnlocked,
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

			asset.Status = lockbox.AssetStatusUnlocked
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
		if asset.Status == lockbox.AssetStatusLocked && now.After(asset.UnlockTime) {
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

func (s *Service) serializeAssetData(req *lockbox.LockAssetRequest) ([]byte, error) {
	// Simple serialization - in production use protobuf or similar
	data := fmt.Sprintf("%s|%s|%s|%d",
		req.OwnerAddress.String(),
		req.OutputID.String(),
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
	// Simple deserialization - in production use protobuf
	// This is a placeholder implementation
	return &crypto.CharacterShard{}, nil
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
	_, err := s.storage.UTXOStore().Get([]byte(key))
	if err != nil {
		return nil, err
	}
	// Deserialize proof - placeholder
	return &crypto.OwnershipProof{}, nil
}