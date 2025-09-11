package lockbox

import (
	"context"
	"fmt"
	"time"

	"github.com/iotaledger/hornet/v2/pkg/daemon"
	"github.com/iotaledger/lockbox/v2/lockbox/verification"
	iotago "github.com/iotaledger/iota.go/v3"
)

type ServiceAdditions struct {
	verifier         *verification.Verifier
	nodeSelector     *verification.NodeSelector
	tokenManager     *verification.TokenManager
	retryManager     *verification.RetryManager
}

func (s *Service) InitializeVerification() error {
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
			s.LogErrorf("Failed to register verification node: %v", err)
			return fmt.Errorf("failed to register verification node: %w", err)
		}
	}

	rotationPeriod := 24 * time.Hour
	if s.config.Tier == TierElite {
		rotationPeriod = 1 * time.Hour
	}
	s.tokenManager = verification.NewTokenManager(s.WrappedLogger.Logger, rotationPeriod, 7*24*time.Hour)
	go s.tokenManager.Start(context.Background())

	// Check if token initialization was successful
	if s.tokenManager.GetCurrentToken() == nil {
		s.LogError("Token manager failed to initialize with a valid token")
		return fmt.Errorf("token manager initialization failed")
	}

	retryConfig := verification.DefaultRetryConfig()
	if s.config.Tier == TierElite {
		retryConfig.MaxAttempts = 10
		retryConfig.InitialBackoff = 50 * time.Millisecond
	}
	s.retryManager = verification.NewRetryManager(s.WrappedLogger.Logger, retryConfig)

	s.verifier = verification.NewVerifier(s.WrappedLogger.Logger, s.nodeSelector, s.tokenManager, s.storageManager)
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
	if result.LatencyMs > 2000 {
		s.LogWarnf("Verification latency exceeded target: %dms", result.LatencyMs)
	}
	return result, nil
}

func (s *Service) RetrieveAsset(ctx context.Context, assetID string, requester iotago.Address) (*UnlockAssetResponse, error) {
	verifyResult, err := s.VerifyAssetRetrieval(ctx, assetID, requester)
	if err != nil {
		return nil, fmt.Errorf("verification failed: %w", err)
	}
	if !verifyResult.Valid {
		return nil, fmt.Errorf("verification invalid")
	}

	asset, err := s.storageManager.GetLockedAsset(assetID)
	if err != nil {
		return nil, fmt.Errorf("failed to get asset: %w", err)
	}

	now := time.Now()
	if now.Before(asset.UnlockTime) && !asset.EmergencyUnlock {
		return nil, fmt.Errorf("asset cannot be unlocked yet")
	}

	asset.Status = AssetStatusUnlocking
	asset.UpdatedAt = now
	if err := s.storageManager.StoreLockedAsset(asset); err != nil {
		return nil, fmt.Errorf("failed to update asset status: %w", err)
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
			// Perform actual health checks on nodes
			for _, node := range s.nodeSelector.GetAllNodes() {
				// Simulate a health check (replace with real network ping or status check)
				if time.Since(node.LastUsed) > 5*time.Minute {
					s.nodeSelector.UpdateNodeStatus(node.ID, false)
					s.LogWarnf("Node %s marked unavailable due to inactivity", node.ID)
				}
			}
		}
	}
}

func generateNonce() []byte {
	nonce := make([]byte, 32)
	rand.Read(nonce)
	return nonce
}

func (s *Service) OptimizeNodeSelection() {
	s.LogDebug("Optimizing node selection based on performance metrics")
	// Placeholder for node selection optimization logic
	// Could involve re-ranking nodes based on recent metrics
}