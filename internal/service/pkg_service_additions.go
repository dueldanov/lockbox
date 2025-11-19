package service

import (
	"context"
	"fmt"
	"time"

	"github.com/dueldanov/lockbox/v2/internal/verification"
	iotago "github.com/iotaledger/iota.go/v3"
)

// Additional service methods for verification and retrieval

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
	
	// Initialize token manager with tier-based rotation
	rotationPeriod := 24 * time.Hour
	if s.config.Tier == TierElite {
		rotationPeriod = 1 * time.Hour
	}
	s.tokenManager = verification.NewTokenManager(s.WrappedLogger.Logger, rotationPeriod, 7*24*time.Hour)
	go s.tokenManager.Start(context.Background())
	
	// Initialize retry manager with tier-based configuration
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

func (s *Service) VerifyAssetRetrieval(ctx context.Context, assetID string, requester iotago.Address) (*verification.VerificationResult, error) {
	req := &verification.VerificationRequest{
		AssetID:   assetID,
		Tier:      s.config.Tier,
		Requester: requester,
		Nonce:     generateNonce(),
	}
	
	result, err := s.retryManager.RetryVerification(ctx, s.verifier, req)
	if err != nil {
		return nil, fmt.Errorf("verification failed: %w", err)
	}
	
	// Log performance metrics
	if result.LatencyMs > 2000 {
		s.LogWarnf("Verification latency exceeded target: %dms", result.LatencyMs)
	}
	
	// Store verification result for audit
	if err := s.storageManager.StoreVerificationResult(assetID, &VerificationResult{
		AssetID:   assetID,
		Valid:     result.Valid,
		Timestamp: result.Timestamp,
		NodeID:    result.NodeID,
		Signature: result.Signature,
	}); err != nil {
		s.LogWarnf("Failed to store verification result: %s", err)
	}
	
	return result, nil
}

func (s *Service) RetrieveAsset(ctx context.Context, assetID string, requester iotago.Address) (*UnlockAssetResponse, error) {
	// Perform verification first
	verifyResult, err := s.VerifyAssetRetrieval(ctx, assetID, requester)
	if err != nil {
		return nil, fmt.Errorf("verification failed: %w", err)
	}
	
	if !verifyResult.Valid {
		return nil, fmt.Errorf("verification invalid")
	}
	
	// Get the asset
	asset, err := s.storageManager.GetLockedAsset(assetID)
	if err != nil {
		return nil, fmt.Errorf("failed to get asset: %w", err)
	}
	
	// Check if asset can be retrieved
	now := time.Now()
	if now.Before(asset.UnlockTime) && !asset.EmergencyUnlock {
		return nil, fmt.Errorf("asset cannot be unlocked yet")
	}
	
	// Update asset status
	asset.Status = AssetStatusUnlocking
	asset.UpdatedAt = now
	
	if err := s.storageManager.StoreLockedAsset(asset); err != nil {
		return nil, fmt.Errorf("failed to update asset status: %w", err)
	}
	
	// Add to pending unlocks
	if err := s.storageManager.StorePendingUnlock(assetID, now.Add(5*time.Minute).Unix()); err != nil {
		s.LogWarnf("Failed to store pending unlock: %s", err)
	}
	
	return &UnlockAssetResponse{
		AssetID:    assetID,
		OutputID:   asset.OutputID,
		UnlockTime: now,
		Status:     string(asset.Status),
	}, nil
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
			s.performHealthCheck()
		}
	}
}

func (s *Service) performHealthCheck() {
	// Check each verification node
	for _, location := range s.config.NodeLocations {
		nodeID := fmt.Sprintf("node-%s", location)
		
		// Simulate health check
		isHealthy := s.checkNodeHealth(nodeID)
		
		if err := s.nodeSelector.UpdateNodeStatus(nodeID, isHealthy); err != nil {
			s.LogWarnf("Failed to update node status for %s: %s", nodeID, err)
		}
	}
}

func (s *Service) checkNodeHealth(nodeID string) bool {
	// Implement actual health check logic
	// For now, return true
	return true
}

func (s *Service) OptimizeNodeSelection() {
	s.LogDebug("Optimizing node selection based on performance metrics")
	
	// Get performance metrics
	nodes := s.nodeSelector.GetActiveNodes()
	
	for _, node := range nodes {
		// Analyze node performance
		if node.Latency > 1000*time.Millisecond {
			s.LogWarnf("Node %s has high latency: %v", node.ID, node.Latency)
		}
		
		if node.Reputation < 0.8 {
			s.LogWarnf("Node %s has low reputation: %.2f", node.ID, node.Reputation)
		}
	}
}

func (s *Service) GetAssetStatus(ctx context.Context, assetID string) (*LockedAsset, error) {
	asset, err := s.storageManager.GetLockedAsset(assetID)
	if err != nil {
		return nil, fmt.Errorf("asset not found: %w", err)
	}
	
	// Check if asset should be automatically unlocked
	now := time.Now()
	if asset.Status == AssetStatusLocked && now.After(asset.UnlockTime) {
		asset.Status = AssetStatusExpired
		asset.UpdatedAt = now
		
		if err := s.storageManager.StoreLockedAsset(asset); err != nil {
			s.LogWarnf("Failed to update expired asset status: %s", err)
		}
	}
	
	return asset, nil
}

func (s *Service) ListAssets(ctx context.Context, owner iotago.Address, status AssetStatus) ([]*LockedAsset, error) {
	assets, err := s.storageManager.ListLockedAssets()
	if err != nil {
		return nil, fmt.Errorf("failed to list assets: %w", err)
	}
	
	// Filter by owner and status
	var filtered []*LockedAsset
	for _, asset := range assets {
		if owner != nil && !asset.OwnerAddress.Equal(owner) {
			continue
		}
		
		if status != "" && asset.Status != status {
			continue
		}
		
		filtered = append(filtered, asset)
	}
	
	return filtered, nil
}

func (s *Service) CreateMultiSig(ctx context.Context, addresses []iotago.Address, minSignatures int) (*MultiSigConfig, error) {
	if len(addresses) < minSignatures {
		return nil, fmt.Errorf("minimum signatures cannot exceed number of addresses")
	}
	
	config := &MultiSigConfig{
		ID:            s.generateAssetID(),
		Addresses:     addresses,
		MinSignatures: minSignatures,
		CreatedAt:     time.Now(),
	}
	
	if err := s.storageManager.StoreMultiSigConfig(config); err != nil {
		return nil, fmt.Errorf("failed to store multi-sig config: %w", err)
	}
	
	return config, nil
}

func (s *Service) EmergencyUnlock(ctx context.Context, assetID string, reason string, signatures [][]byte) (*UnlockAssetResponse, error) {
	if !s.config.EnableEmergencyUnlock {
		return nil, fmt.Errorf("emergency unlock is not enabled")
	}
	
	asset, err := s.storageManager.GetLockedAsset(assetID)
	if err != nil {
		return nil, fmt.Errorf("asset not found: %w", err)
	}
	
	// Verify emergency signatures (implement actual verification)
	if len(signatures) < 3 { // Example: require 3 admin signatures
		return nil, fmt.Errorf("insufficient emergency signatures")
	}
	
	// Check emergency delay
	emergencyDelay := time.Duration(s.config.EmergencyDelayDays) * 24 * time.Hour
	if time.Since(asset.LockTime) < emergencyDelay {
		return nil, fmt.Errorf("emergency unlock delay not met")
	}
	
	// Log emergency unlock
	s.LogWarnf("Emergency unlock initiated for asset %s: %s", assetID, reason)
	
	// Update asset status
	now := time.Now()
	asset.Status = AssetStatusEmergency
	asset.UpdatedAt = now
	asset.EmergencyUnlock = true
	
	if err := s.storageManager.StoreLockedAsset(asset); err != nil {
		return nil, fmt.Errorf("failed to update asset: %w", err)
	}
	
	return &UnlockAssetResponse{
		AssetID:    assetID,
		OutputID:   asset.OutputID,
		UnlockTime: now,
		Status:     string(asset.Status),
	}, nil
}

func generateNonce() []byte {
	nonce := make([]byte, 32)
	rand.Read(nonce)
	return nonce
}