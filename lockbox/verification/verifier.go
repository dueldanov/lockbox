package verification

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/iotaledger/hive.go/logger"
	"github.com/iotaledger/lockbox/v2/lockbox"
	"github.com/iotaledger/lockbox/v2/lockbox/crypto"
	iotago "github.com/iotaledger/iota.go/v3"
)

// Verifier handles the verification of locked assets
type Verifier struct {
	*logger.WrappedLogger
	
	nodeSelector *NodeSelector
	tokenManager *TokenManager
	storage      *lockbox.StorageManager
}

// VerificationRequest represents a request to verify an asset
type VerificationRequest struct {
	AssetID   string
	Tier      lockbox.Tier
	Requester iotago.Address
	Nonce     []byte
}

// VerificationResult represents the result of a verification
type VerificationResult struct {
	AssetID      string
	Valid        bool
	Signatures   [][]byte
	VerifiedBy   []string
	Timestamp    time.Time
	LatencyMs    int64
}

// NewVerifier creates a new verifier
func NewVerifier(log *logger.Logger, nodeSelector *NodeSelector, tokenManager *TokenManager, storage *lockbox.StorageManager) *Verifier {
	return &Verifier{
		WrappedLogger: logger.NewWrappedLogger(log),
		nodeSelector:  nodeSelector,
		tokenManager:  tokenManager,
		storage:       storage,
	}
}

// VerifyAsset performs verification based on tier requirements
func (v *Verifier) VerifyAsset(ctx context.Context, req *VerificationRequest) (*VerificationResult, error) {
	startTime := time.Now()
	
	// Get asset from storage
	asset, err := v.storage.GetLockedAsset(req.AssetID)
	if err != nil {
		return nil, fmt.Errorf("failed to get asset: %w", err)
	}
	
	// Check if requester is authorized
	if !v.isAuthorized(asset, req.Requester) {
		return nil, fmt.Errorf("requester not authorized")
	}
	
	// Select verification nodes based on tier
	nodes, err := v.nodeSelector.SelectNodes(ctx, req.Tier, asset.NodeLocations)
	if err != nil {
		return nil, fmt.Errorf("failed to select verification nodes: %w", err)
	}
	
	// Perform verification based on tier
	var result *VerificationResult
	switch req.Tier {
	case lockbox.TierBasic, lockbox.TierStandard, lockbox.TierPremium:
		result, err = v.performTripleVerification(ctx, asset, nodes, req)
	case lockbox.TierElite:
		result, err = v.performDualVerification(ctx, asset, nodes, req)
	default:
		return nil, fmt.Errorf("unsupported tier: %v", req.Tier)
	}
	
	if err != nil {
		return nil, err
	}
	
	// Record latency
	result.LatencyMs = time.Since(startTime).Milliseconds()
	
	// Update node metrics
	for i, nodeID := range result.VerifiedBy {
		success := result.Valid && len(result.Signatures[i]) > 0
		v.nodeSelector.UpdateNodeMetrics(nodeID, time.Since(startTime), success)
	}
	
	v.LogInfof("Asset %s verification completed in %dms, valid: %v", req.AssetID, result.LatencyMs, result.Valid)
	
	return result, nil
}

// performTripleVerification performs verification with three nodes
func (v *Verifier) performTripleVerification(ctx context.Context, asset *lockbox.LockedAsset, nodes []*VerificationNode, req *VerificationRequest) (*VerificationResult, error) {
	if len(nodes) < 3 {
		return nil, fmt.Errorf("insufficient nodes for triple verification: %d", len(nodes))
	}
	
	// Create verification tasks
	type verifyResult struct {
		nodeID    string
		valid     bool
		signature []byte
		err       error
	}
	
	results := make(chan verifyResult, 3)
	var wg sync.WaitGroup
	
	// Launch parallel verification
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(node *VerificationNode) {
			defer wg.Done()
			
			valid, signature, err := v.verifyWithNode(ctx, node, asset, req)
			results <- verifyResult{
				nodeID:    node.ID,
				valid:     valid,
				signature: signature,
				err:       err,
			}
		}(nodes[i])
	}
	
	// Wait for all verifications to complete
	go func() {
		wg.Wait()
		close(results)
	}()
	
	// Collect results
	validCount := 0
	signatures := make([][]byte, 0, 3)
	verifiedBy := make([]string, 0, 3)
	
	for result := range results {
		if result.err != nil {
			v.LogWarnf("Verification failed on node %s: %v", result.nodeID, result.err)
			continue
		}
		
		if result.valid {
			validCount++
			signatures = append(signatures, result.signature)
			verifiedBy = append(verifiedBy, result.nodeID)
		}
	}
	
	// Require at least 2 out of 3 nodes to agree
	valid := validCount >= 2
	
	return &VerificationResult{
		AssetID:    req.AssetID,
		Valid:      valid,
		Signatures: signatures,
		VerifiedBy: verifiedBy,
		Timestamp:  time.Now(),
	}, nil
}

// performDualVerification performs shard-level verification for Elite tier
func (v *Verifier) performDualVerification(ctx context.Context, asset *lockbox.LockedAsset, nodes []*VerificationNode, req *VerificationRequest) (*VerificationResult, error) {
	if len(nodes) < 2 {
		return nil, fmt.Errorf("insufficient nodes for dual verification: %d", len(nodes))
	}
	
	// For Elite tier, we verify at shard level
	shardID := v.calculateShardID(asset.ID)
	
	// Verify with both nodes
	results := make([]verifyResult, 2)
	var wg sync.WaitGroup
	
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int, node *VerificationNode) {
			defer wg.Done()
			
			valid, signature, err := v.verifyShardWithNode(ctx, node, shardID, asset, req)
			results[idx] = verifyResult{
				nodeID:    node.ID,
				valid:     valid,
				signature: signature,
				err:       err,
			}
		}(i, nodes[i])
	}
	
	wg.Wait()
	
	// Both nodes must agree for Elite tier
	valid := true
	signatures := make([][]byte, 0, 2)
	verifiedBy := make([]string, 0, 2)
	
	for _, result := range results {
		if result.err != nil {
			return nil, fmt.Errorf("shard verification failed on node %s: %w", result.nodeID, result.err)
		}
		
		if !result.valid {
			valid = false
		}
		
		signatures = append(signatures, result.signature)
		verifiedBy = append(verifiedBy, result.nodeID)
	}
	
	return &VerificationResult{
		AssetID:    req.AssetID,
		Valid:      valid,
		Signatures: signatures,
		VerifiedBy: verifiedBy,
		Timestamp:  time.Now(),
	}, nil
}

// verifyWithNode performs verification with a single node
func (v *Verifier) verifyWithNode(ctx context.Context, node *VerificationNode, asset *lockbox.LockedAsset, req *VerificationRequest) (bool, []byte, error) {
	// Get current verification token
	token, err := v.tokenManager.GetCurrentToken(node.ID)
	if err != nil {
		return false, nil, fmt.Errorf("failed to get verification token: %w", err)
	}
	
	// Create verification payload
	payload := v.createVerificationPayload(asset, req, token)
	
	// TODO: Send verification request to node via secure channel
	// For now, simulate verification
	valid := v.simulateVerification(asset, payload)
	
	// Generate signature if valid
	var signature []byte
	if valid {
		signature = v.generateSignature(payload, node.ID)
	}
	
	return valid, signature, nil
}

// verifyShardWithNode performs shard-level verification for Elite tier
func (v *Verifier) verifyShardWithNode(ctx context.Context, node *VerificationNode, shardID string, asset *lockbox.LockedAsset, req *VerificationRequest) (bool, []byte, error) {
	// Get shard-specific token
	token, err := v.tokenManager.GetShardToken(node.ID, shardID)
	if err != nil {
		return false, nil, fmt.Errorf("failed to get shard token: %w", err)
	}
	
	// Create shard verification payload
	payload := v.createShardVerificationPayload(shardID, asset, req, token)
	
	// TODO: Implement actual shard verification protocol
	valid := v.simulateShardVerification(shardID, asset, payload)
	
	// Generate shard signature
	var signature []byte
	if valid {
		signature = v.generateShardSignature(payload, node.ID, shardID)
	}
	
	return valid, signature, nil
}

// isAuthorized checks if the requester is authorized to access the asset
func (v *Verifier) isAuthorized(asset *lockbox.LockedAsset, requester iotago.Address) bool {
	// Check if requester is the owner
	if asset.OwnerAddress.Equal(requester) {
		return true
	}
	
	// Check if requester is in multi-sig addresses
	for _, addr := range asset.MultiSigAddresses {
		if addr.Equal(requester) {
			return true
		}
	}
	
	return false
}

// calculateShardID calculates the shard ID for an asset
func (v *Verifier) calculateShardID(assetID string) string {
	hash := sha256.Sum256([]byte(assetID))
	return hex.EncodeToString(hash[:8])
}

// createVerificationPayload creates the payload for verification
func (v *Verifier) createVerificationPayload(asset *lockbox.LockedAsset, req *VerificationRequest, token *VerificationToken) []byte {
	// Combine all relevant data
	data := append([]byte(asset.ID), req.Nonce...)
	data = append(data, token.Value...)
	data = append(data, []byte(fmt.Sprintf("%d", time.Now().Unix()))...)
	
	return data
}

// createShardVerificationPayload creates the payload for shard verification
func (v *Verifier) createShardVerificationPayload(shardID string, asset *lockbox.LockedAsset, req *VerificationRequest, token *VerificationToken) []byte {
	// Include shard ID in payload
	data := append([]byte(shardID), []byte(asset.ID)...)
	data = append(data, req.Nonce...)
	data = append(data, token.Value...)
	data = append(data, []byte(fmt.Sprintf("%d", time.Now().Unix()))...)
	
	return data
}

// simulateVerification simulates the verification process (to be replaced with actual implementation)
func (v *Verifier) simulateVerification(asset *lockbox.LockedAsset, payload []byte) bool {
	// TODO: Implement actual verification logic
	// For now, simulate success based on asset status
	return asset.Status == lockbox.AssetStatusLocked
}

// simulateShardVerification simulates shard verification (to be replaced with actual implementation)
func (v *Verifier) simulateShardVerification(shardID string, asset *lockbox.LockedAsset, payload []byte) bool {
	// TODO: Implement actual shard verification logic
	return asset.Status == lockbox.AssetStatusLocked
}

// generateSignature generates a signature for the verification
func (v *Verifier) generateSignature(payload []byte, nodeID string) []byte {
	// TODO: Implement actual signature generation with node's private key
	hash := sha256.Sum256(append(payload, []byte(nodeID)...))
	return hash[:]
}

// generateShardSignature generates a signature for shard verification
func (v *Verifier) generateShardSignature(payload []byte, nodeID, shardID string) []byte {
	// TODO: Implement actual shard signature generation
	data := append(payload, []byte(nodeID)...)
	data = append(data, []byte(shardID)...)
	hash := sha256.Sum256(data)
	return hash[:]
}

// Result type for channel communication
type verifyResult struct {
	nodeID    string
	valid     bool
	signature []byte
	err       error
}