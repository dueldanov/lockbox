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
	"github.com/dueldanov/lockbox/v2/internal/interfaces"
	"github.com/dueldanov/lockbox/v2/internal/lockscript"
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
	zkpProvider      interfaces.ZKPProvider // Optional: if set, used instead of zkpManager (for testing)
	hkdfManager      *crypto.HKDFManager
	decoyGenerator   *crypto.DecoyGenerator
	shardMixer       *crypto.ShardMixer

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

	// Initialize HKDF manager for key derivation
	hkdfManager, err := crypto.NewHKDFManager(masterKey)
	if err != nil {
		crypto.ClearBytes(masterKey)
		return nil, fmt.Errorf("failed to initialize HKDF manager: %w", err)
	}

	// Initialize decoy generator with tier-based config
	tierCaps := GetCapabilities(config.Tier)
	decoyConfig := crypto.DecoyConfig{
		DecoyRatio:         tierCaps.DecoyRatio,
		MetadataDecoyRatio: tierCaps.MetadataDecoyRatio,
	}
	decoyGenerator := crypto.NewDecoyGenerator(hkdfManager, decoyConfig)
	shardMixer := crypto.NewShardMixer()

	zkpManager := crypto.NewZKPManager()

	// Initialize verification components
	nodeSelector := verification.NewNodeSelector(log)
	tokenManager := verification.NewTokenManager(log, 24*time.Hour, 1*time.Hour) // 24h rotation, 1h validity
	retryManager := verification.NewRetryManager(log, nil)                        // use default config

	svc := &Service{
		WrappedLogger:   logger.NewWrappedLogger(log),
		storage:         storage,
		utxoManager:     utxoManager,
		syncManager:     syncManager,
		protocolManager: protocolManager,
		config:          config,
		storageManager:  storageManager,
		shardEncryptor:  shardEncryptor,
		zkpManager:      zkpManager,
		hkdfManager:     hkdfManager,
		decoyGenerator:  decoyGenerator,
		shardMixer:      shardMixer,
		nodeSelector:    nodeSelector,
		tokenManager:    tokenManager,
		retryManager:    retryManager,
		lockedAssets:    make(map[string]*LockedAsset),
		pendingUnlocks:  make(map[string]time.Time),
	}

	// Create verifier with storage manager adapter
	verifier := verification.NewVerifier(log, nodeSelector, tokenManager, &verificationStorageAdapter{svc})
	svc.verifier = verifier

	return svc, nil
}

// verificationStorageAdapter adapts Service to verification.StorageManager interface
type verificationStorageAdapter struct {
	service *Service
}

func (a *verificationStorageAdapter) GetLockedAsset(assetID string) (*LockedAsset, error) {
	return a.service.storageManager.GetLockedAsset(assetID)
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

	// Use zkpProvider if set (for testing), otherwise use zkpManager
	var ownershipProof *interfaces.OwnershipProof
	var zkpErr error
	if s.zkpProvider != nil {
		ownershipProof, zkpErr = s.zkpProvider.GenerateOwnershipProof([]byte(assetID), ownerSecret)
		if zkpErr != nil {
			return nil, fmt.Errorf("failed to generate ownership proof: %w", zkpErr)
		}
	} else {
		cryptoProof, err := s.zkpManager.GenerateOwnershipProof([]byte(assetID), ownerSecret)
		if err != nil {
			return nil, fmt.Errorf("failed to generate ownership proof: %w", err)
		}
		ownershipProof = &interfaces.OwnershipProof{
			AssetCommitment: cryptoProof.AssetCommitment,
			OwnerAddress:    cryptoProof.OwnerAddress,
			Timestamp:       cryptoProof.Timestamp,
		}
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

	// Generate decoy shards based on tier configuration
	// DecoyGenerator was initialized with tier config in NewService
	decoys, err := s.decoyGenerator.GenerateDecoyShards(len(shards), 4096) // 4KB shards
	if err != nil {
		return nil, fmt.Errorf("failed to generate decoy shards: %w", err)
	}

	// Mix real and decoy shards for storage
	mixedShards, indexMap, err := s.shardMixer.MixShards(shards, decoys)
	if err != nil {
		return nil, fmt.Errorf("failed to mix shards: %w", err)
	}

	// Store mixed shards (real + decoys) with sequential indices
	for i, shard := range mixedShards {
		if err := s.storeEncryptedMixedShardAtIndex(assetID, uint32(i), shard); err != nil {
			return nil, fmt.Errorf("failed to store encrypted shard: %w", err)
		}
	}

	// Create locked asset with shard index map for decoy extraction
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
		ShardIndexMap:     indexMap,
		ShardCount:        len(shards),
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

	// Get asset - try in-memory cache first (handles interface type serialization issues)
	asset, ok := s.lockedAssets[req.AssetID]
	if !ok {
		// Fall back to storage manager
		var err error
		asset, err = s.storageManager.GetLockedAsset(req.AssetID)
		if err != nil {
			return nil, ErrAssetNotFound
		}
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
		// Use zkpProvider if set (for testing), otherwise use zkpManager
		if s.zkpProvider != nil {
			// Convert to interfaces.OwnershipProof for mock
			interfaceProof := &interfaces.OwnershipProof{
				AssetCommitment: ownershipProof.AssetCommitment,
				OwnerAddress:    ownershipProof.OwnerAddress,
				Timestamp:       ownershipProof.Timestamp,
			}
			if err := s.zkpProvider.VerifyOwnershipProof(interfaceProof); err != nil {
				return nil, ErrUnauthorized
			}
		} else if err := s.zkpManager.VerifyOwnershipProof(ownershipProof); err != nil {
			return nil, ErrUnauthorized
		}
	}

	// Execute LockScript conditions if present
	if asset.LockScript != "" && s.scriptCompiler != nil {
		engine, ok := s.scriptCompiler.(*lockscript.Engine)
		if !ok {
			return nil, fmt.Errorf("script compiler not properly initialized")
		}

		// Compile script
		compiled, err := engine.CompileScript(ctx, asset.LockScript)
		if err != nil {
			return nil, fmt.Errorf("failed to compile lock script: %w", err)
		}

		// Create execution environment with unlock parameters
		env := lockscript.NewEnvironment()
		env.Variables["unlock_time"] = asset.UnlockTime.Unix()
		env.Variables["lock_time"] = asset.LockTime.Unix()
		env.Variables["asset_id"] = asset.ID
		env.Variables["now"] = time.Now().Unix()

		// Add request parameters (signatures, custom params)
		if req.UnlockParams != nil {
			for k, v := range req.UnlockParams {
				env.Variables[k] = v
			}
		}
		if len(req.Signatures) > 0 {
			env.Variables["signatures"] = req.Signatures
		}

		// Execute script - must return true to allow unlock
		result, err := engine.ExecuteScript(ctx, compiled, env)
		if err != nil {
			return nil, fmt.Errorf("lock script execution failed: %w", err)
		}

		// Check result - script must return true/truthy value
		if !isTruthy(result) {
			return nil, fmt.Errorf("lock script conditions not met")
		}
	}

	// Verify multi-sig signatures if configured (and not already handled by LockScript)
	if len(asset.MultiSigAddresses) > 0 && asset.MinSignatures > 0 {
		if len(req.Signatures) < asset.MinSignatures {
			return nil, fmt.Errorf("insufficient signatures: need %d, got %d",
				asset.MinSignatures, len(req.Signatures))
		}

		validSigs, err := s.verifyMultiSigSignatures(req.AssetID, req.Signatures, asset.MultiSigAddresses)
		if err != nil {
			return nil, fmt.Errorf("multi-sig verification failed: %w", err)
		}
		if validSigs < asset.MinSignatures {
			return nil, fmt.Errorf("insufficient valid signatures: need %d, got %d",
				asset.MinSignatures, validSigs)
		}
	}

	// Retrieve all mixed shards (real + decoys)
	mixedShards, err := s.retrieveEncryptedMixedShards(req.AssetID)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve encrypted shards: %w", err)
	}

	// Extract only real shards using the index map
	realShards, err := s.shardMixer.ExtractRealShards(mixedShards, asset.ShardIndexMap)
	if err != nil {
		return nil, fmt.Errorf("failed to extract real shards: %w", err)
	}

	assetData, err := s.shardEncryptor.DecryptShards(realShards)
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
	// Initialize LockScript engine with tier-based limits
	tierCaps := GetCapabilities(s.config.Tier)

	// Memory limit based on script complexity tier
	memoryLimit := tierCaps.ScriptComplexity * 65536 // 64KB per complexity level

	engine := lockscript.NewEngine(nil, memoryLimit, 5*time.Second)
	engine.RegisterBuiltinFunctions()

	s.scriptCompiler = engine
	s.LogInfo("LockScript compiler initialized with complexity level %d", tierCaps.ScriptComplexity)

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

// storeEncryptedMixedShardAtIndex stores a mixed shard at a specific index position
func (s *Service) storeEncryptedMixedShardAtIndex(assetID string, index uint32, shard *crypto.MixedShard) error {
	key := fmt.Sprintf("mixedshard_%s_%d", assetID, index)
	value, err := s.serializeMixedShard(shard)
	if err != nil {
		return err
	}
	// Use storageManager if available (for tests), otherwise use storage
	if s.storageManager != nil {
		return s.storageManager.StoreShard(key, value)
	}
	return s.storage.UTXOStore().Set([]byte(key), value)
}

// storeEncryptedMixedShard stores a mixed shard (real or decoy) - uses shard.Index as key
func (s *Service) storeEncryptedMixedShard(assetID string, shard *crypto.MixedShard) error {
	key := fmt.Sprintf("mixedshard_%s_%d", assetID, shard.Index)
	value, err := s.serializeMixedShard(shard)
	if err != nil {
		return err
	}
	// Use storageManager if available (for tests), otherwise use storage
	if s.storageManager != nil {
		return s.storageManager.StoreShard(key, value)
	}
	return s.storage.UTXOStore().Set([]byte(key), value)
}

// serializeMixedShard serializes a mixed shard for storage
// Format: id|index|total|data(hex)|nonce(hex)|timestamp|checksum(hex)|shardType|originalIndex
func (s *Service) serializeMixedShard(shard *crypto.MixedShard) ([]byte, error) {
	return []byte(fmt.Sprintf("%d|%d|%d|%s|%s|%d|%s|%d|%d",
		shard.ID,
		shard.Index,
		shard.Total,
		hex.EncodeToString(shard.Data),
		hex.EncodeToString(shard.Nonce),
		shard.Timestamp,
		hex.EncodeToString(shard.Checksum),
		shard.ShardType,
		shard.OriginalIndex,
	)), nil
}

// retrieveMixedShards retrieves mixed shards for an asset
func (s *Service) retrieveMixedShards(assetID string, totalCount int) ([]*crypto.MixedShard, error) {
	var shards []*crypto.MixedShard
	for i := 0; i < totalCount; i++ {
		key := fmt.Sprintf("mixedshard_%s_%d", assetID, i)
		value, err := s.storage.UTXOStore().Get([]byte(key))
		if err != nil {
			break // No more shards
		}

		shard, err := s.deserializeMixedShard(value)
		if err != nil {
			return nil, err
		}
		shards = append(shards, shard)
	}
	return shards, nil
}

// deserializeMixedShard deserializes a mixed shard from storage
func (s *Service) deserializeMixedShard(data []byte) (*crypto.MixedShard, error) {
	parts := strings.Split(string(data), "|")
	if len(parts) != 9 {
		return nil, fmt.Errorf("invalid mixed shard format: expected 9 parts, got %d", len(parts))
	}

	id, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid ID: %w", err)
	}

	index, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid index: %w", err)
	}

	total, err := strconv.ParseUint(parts[2], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid total: %w", err)
	}

	shardData, err := hex.DecodeString(parts[3])
	if err != nil {
		return nil, fmt.Errorf("invalid data hex: %w", err)
	}

	nonce, err := hex.DecodeString(parts[4])
	if err != nil {
		return nil, fmt.Errorf("invalid nonce hex: %w", err)
	}

	timestamp, err := strconv.ParseInt(parts[5], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid timestamp: %w", err)
	}

	checksum, err := hex.DecodeString(parts[6])
	if err != nil {
		return nil, fmt.Errorf("invalid checksum hex: %w", err)
	}

	shardType, err := strconv.ParseInt(parts[7], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid shard type: %w", err)
	}

	originalIndex, err := strconv.ParseUint(parts[8], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid original index: %w", err)
	}

	return &crypto.MixedShard{
		CharacterShard: crypto.CharacterShard{
			ID:        uint32(id),
			Index:     uint32(index),
			Total:     uint32(total),
			Data:      shardData,
			Nonce:     nonce,
			Timestamp: timestamp,
			Checksum:  checksum,
		},
		ShardType:     crypto.DecoyType(shardType),
		OriginalIndex: uint32(originalIndex),
	}, nil
}

func (s *Service) retrieveEncryptedMixedShards(assetID string) ([]*crypto.MixedShard, error) {
	// This is simplified - in production, track shard count
	var shards []*crypto.MixedShard
	for i := uint32(0); i < 100; i++ { // Max 100 shards
		key := fmt.Sprintf("mixedshard_%s_%d", assetID, i) // Match storeEncryptedMixedShard format
		var value []byte
		var err error
		// Use storageManager if available (for tests), otherwise use storage
		if s.storageManager != nil {
			value, err = s.storageManager.GetShard(key)
		} else {
			value, err = s.storage.UTXOStore().Get([]byte(key))
		}
		if err != nil {
			break // No more shards
		}

		// Deserialize as mixed shard (9 fields)
		mixedShard, err := s.deserializeMixedShard(value)
		if err != nil {
			return nil, err
		}
		shards = append(shards, mixedShard)
	}

	return shards, nil
}

func (s *Service) cleanupEncryptedShards(assetID string) error {
	// Clean up all shards for this asset
	for i := uint32(0); i < 100; i++ {
		key := fmt.Sprintf("mixedshard_%s_%d", assetID, i) // Match storage format
		// Use storageManager if available (for tests), otherwise use storage
		if s.storageManager != nil {
			// storageManager doesn't have Delete for shards yet, skip in tests
			continue
		}
		if err := s.storage.UTXOStore().Delete([]byte(key)); err != nil {
			// Key might not exist, ignore error
			continue
		}
	}
	return nil
}

// isTruthy checks if a script result is truthy
func isTruthy(result interface{}) bool {
	if result == nil {
		return false
	}
	switch v := result.(type) {
	case bool:
		return v
	case int:
		return v != 0
	case int64:
		return v != 0
	case float64:
		return v != 0
	case string:
		return v != "" && v != "false" && v != "0"
	default:
		return true // Non-nil, non-zero is truthy
	}
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

func (s *Service) storeOwnershipProof(assetID string, proof *interfaces.OwnershipProof) error {
	key := fmt.Sprintf("proof_%s", assetID)
	value := fmt.Sprintf("%s|%s|%d",
		hex.EncodeToString(proof.AssetCommitment),
		hex.EncodeToString(proof.OwnerAddress),
		proof.Timestamp,
	)
	// Use storageManager if available (for tests), otherwise use storage
	if s.storageManager != nil {
		return s.storageManager.StoreOwnershipProof(key, []byte(value))
	}
	return s.storage.UTXOStore().Set([]byte(key), []byte(value))
}

func (s *Service) getOwnershipProof(assetID string) (*crypto.OwnershipProof, error) {
	key := fmt.Sprintf("proof_%s", assetID)
	var data []byte
	var err error
	// Use storageManager if available (for tests), otherwise use storage
	if s.storageManager != nil {
		data, err = s.storageManager.GetOwnershipProof(key)
	} else {
		data, err = s.storage.UTXOStore().Get([]byte(key))
	}
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

		// Verify each signature against MultiSigAddresses
		// Each signature is 96 bytes: pubKey (32) + signature (64)
		validSigs, err := s.verifyMultiSigSignatures(assetID, signatures, asset.MultiSigAddresses)
		if err != nil {
			return fmt.Errorf("multi-sig verification failed: %w", err)
		}
		if validSigs < asset.MinSignatures {
			return fmt.Errorf("insufficient valid signatures: need %d, got %d",
				asset.MinSignatures, validSigs)
		}
	}

	// Apply delay from config (EmergencyDelayDays)
	delayDuration := time.Duration(s.config.EmergencyDelayDays) * 24 * time.Hour
	asset.UnlockTime = time.Now().Add(delayDuration)
	asset.EmergencyUnlock = true
	asset.Status = AssetStatusEmergency
	asset.UpdatedAt = time.Now()

	return s.storageManager.StoreLockedAsset(asset)
}

// CreateMultiSig creates a new multi-signature configuration
// Returns the multi-sig ID and aggregated address
func (s *Service) CreateMultiSig(ctx context.Context, addresses []iotago.Address, minSignatures int) (*MultiSigConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Validate inputs
	if len(addresses) < 2 {
		return nil, fmt.Errorf("multi-sig requires at least 2 addresses")
	}

	if minSignatures <= 0 || minSignatures > len(addresses) {
		return nil, fmt.Errorf("invalid minSignatures: must be between 1 and %d", len(addresses))
	}

	// Check tier limits
	if s.config.MinMultiSigSigners > 0 && minSignatures < s.config.MinMultiSigSigners {
		return nil, fmt.Errorf("tier requires minimum %d signers", s.config.MinMultiSigSigners)
	}

	// Generate unique multi-sig ID
	multiSigID := s.generateMultiSigID()

	// Create multi-sig config
	config := &MultiSigConfig{
		ID:            multiSigID,
		Addresses:     addresses,
		MinSignatures: minSignatures,
		CreatedAt:     time.Now(),
	}

	// Store the configuration
	if err := s.storageManager.StoreMultiSigConfig(config); err != nil {
		return nil, fmt.Errorf("failed to store multi-sig config: %w", err)
	}

	s.LogInfof("Created multi-sig config %s with %d-of-%d addresses", multiSigID, minSignatures, len(addresses))

	return config, nil
}

// generateMultiSigID generates a unique identifier for multi-sig configuration
func (s *Service) generateMultiSigID() string {
	id := make([]byte, 8)
	rand.Read(id)
	return "msig-" + hex.EncodeToString(id)
}

// ============================================================================
// AssetService interface implementation (for verification package)
// ============================================================================

// GetAssetStatusString implements interfaces.AssetService
// Returns the status as a string for verification purposes
func (s *Service) GetAssetStatusString(ctx context.Context, assetID string) (string, error) {
	asset, err := s.GetAssetStatus(assetID)
	if err != nil {
		return "", err
	}
	return string(asset.Status), nil
}

// ValidateAssetOwnership implements interfaces.AssetService
// Checks if the given address owns the specified asset
func (s *Service) ValidateAssetOwnership(ctx context.Context, assetID string, address iotago.Address) (bool, error) {
	asset, err := s.GetAssetStatus(assetID)
	if err != nil {
		return false, err
	}
	return asset.OwnerAddress.Equal(address), nil
}

// GetAssetLockTime implements interfaces.AssetService
// Returns the Unix timestamp when the asset was locked
func (s *Service) GetAssetLockTime(ctx context.Context, assetID string) (int64, error) {
	asset, err := s.GetAssetStatus(assetID)
	if err != nil {
		return 0, err
	}
	return asset.LockTime.Unix(), nil
}

// VerifyAsset performs verification of an asset using the verification subsystem
func (s *Service) VerifyAsset(ctx context.Context, assetID string, requester iotago.Address) (*verification.VerificationResult, error) {
	if s.verifier == nil {
		return nil, fmt.Errorf("verification subsystem not initialized")
	}

	// Generate nonce for verification request
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Get asset to determine tier
	asset, err := s.GetAssetStatus(assetID)
	if err != nil {
		return nil, err
	}

	// Create verification request
	req := &verification.VerificationRequest{
		AssetID:   assetID,
		Tier:      s.config.Tier,
		Requester: requester,
		Nonce:     nonce,
	}

	// Verify asset ownership first
	if !asset.OwnerAddress.Equal(requester) {
		return nil, ErrUnauthorized
	}

	return s.verifier.VerifyAsset(ctx, req)
}

// verifyMultiSigSignatures verifies multi-signature signatures against registered addresses
// Each signature must be 96 bytes: pubKey (32 bytes) + signature (64 bytes)
// The pubKey is hashed to derive the address, which must match one of the registered addresses
// Returns the count of valid signatures
func (s *Service) verifyMultiSigSignatures(assetID string, signatures [][]byte, addresses []iotago.Address) (int, error) {
	validCount := 0
	usedAddresses := make(map[string]bool)

	for i, sigData := range signatures {
		// Each signature must be 96 bytes: pubKey (32) + signature (64)
		if len(sigData) != 96 {
			s.LogWarnf("Multi-sig signature %d has invalid length: expected 96 bytes, got %d", i, len(sigData))
			continue
		}

		pubKeyBytes := sigData[:32]
		signatureBytes := sigData[32:]

		// Derive address from public key
		derivedAddr := iotago.Ed25519AddressFromPubKey(pubKeyBytes)

		// Check if this address is in the registered multi-sig addresses
		var matchedAddr iotago.Address
		for _, addr := range addresses {
			if derivedAddr.Equal(addr) {
				matchedAddr = addr
				break
			}
		}

		if matchedAddr == nil {
			s.LogWarnf("Multi-sig signature %d: derived address not in registered addresses", i)
			continue
		}

		// Check if this address was already used
		addrKey := hex.EncodeToString(derivedAddr[:])
		if usedAddresses[addrKey] {
			s.LogWarnf("Multi-sig signature %d: address already used", i)
			continue
		}

		// Verify the signature using Ed25519
		pubKeyHex := hex.EncodeToString(pubKeyBytes)
		sigHex := hex.EncodeToString(signatureBytes)

		valid, err := lockscript.VerifyEd25519Signature(pubKeyHex, assetID, sigHex)
		if err != nil {
			s.LogWarnf("Multi-sig signature %d verification error: %v", i, err)
			continue
		}

		if !valid {
			s.LogWarnf("Multi-sig signature %d: invalid signature", i)
			continue
		}

		// Mark address as used and increment valid count
		usedAddresses[addrKey] = true
		validCount++
		s.LogInfof("Multi-sig signature %d verified successfully from address %s", i, addrKey[:16]+"...")
	}

	return validCount, nil
}