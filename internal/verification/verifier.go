package verification

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"sync"
	"time"

	lockbox "github.com/dueldanov/lockbox/v2/internal/interfaces"
	"github.com/iotaledger/hive.go/logger"
	iotago "github.com/iotaledger/iota.go/v3"
)

type Verifier struct {
	*logger.WrappedLogger
	
	nodeSelector   *NodeSelector
	tokenManager   *TokenManager
	storageManager StorageManager
	cache          *VerificationCache
	metrics        *Metrics
	
	verificationTimeout time.Duration
	maxConcurrent       int
	semaphore          chan struct{}
}

type StorageManager interface {
	GetLockedAsset(assetID string) (*lockbox.LockedAsset, error)
}

type VerificationRequest struct {
	AssetID   string
	Tier      lockbox.Tier
	Requester iotago.Address
	Nonce     []byte
}

type VerificationResult struct {
	Valid      bool
	AssetID    string
	NodeID     string
	Timestamp  time.Time
	Signature  []byte
	LatencyMs  int64
}

func NewVerifier(
	log *logger.Logger,
	nodeSelector *NodeSelector,
	tokenManager *TokenManager,
	storageManager StorageManager,
) *Verifier {
	return &Verifier{
		WrappedLogger:       logger.NewWrappedLogger(log),
		nodeSelector:        nodeSelector,
		tokenManager:        tokenManager,
		storageManager:      storageManager,
		cache:               NewVerificationCache(5*time.Minute, 10000),
		verificationTimeout: 10 * time.Second,
		maxConcurrent:       100,
		semaphore:          make(chan struct{}, 100),
	}
}

func (v *Verifier) VerifyAsset(ctx context.Context, req *VerificationRequest) (*VerificationResult, error) {
	// Check cache first
	if cached, found := v.cache.Get(req.AssetID); found {
		v.metrics.RecordCacheHit()
		return cached, nil
	}
	v.metrics.RecordCacheMiss()
	
	// Acquire semaphore
	select {
	case v.semaphore <- struct{}{}:
		defer func() { <-v.semaphore }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	
	// Start verification
	start := time.Now()
	
	// Select verification nodes
	nodes, err := v.nodeSelector.SelectNodes(ctx, req.Tier, []string{})
	if err != nil {
		return nil, fmt.Errorf("failed to select nodes: %w", err)
	}
	
	// Create verification context with timeout
	verifyCtx, cancel := context.WithTimeout(ctx, v.verificationTimeout)
	defer cancel()
	
	// Perform verification on multiple nodes
	results := make(chan *VerificationResult, len(nodes))
	var wg sync.WaitGroup
	
	for _, node := range nodes {
		wg.Add(1)
		go func(n *VerificationNode) {
			defer wg.Done()
			result := v.verifyWithNode(verifyCtx, n, req)
			select {
			case results <- result:
			case <-verifyCtx.Done():
			}
		}(node)
	}
	
	// Wait for all verifications to complete
	go func() {
		wg.Wait()
		close(results)
	}()
	
	// Collect results
	var validResults []*VerificationResult
	for result := range results {
		if result != nil && result.Valid {
			validResults = append(validResults, result)
		}
	}
	
	// Check consensus
	consensusThreshold := len(nodes) / 2 + 1
	if len(validResults) < consensusThreshold {
		return nil, fmt.Errorf("verification consensus not reached: %d/%d", len(validResults), consensusThreshold)
	}
	
	// Select best result
	bestResult := validResults[0]
	for _, result := range validResults {
		if result.LatencyMs < bestResult.LatencyMs {
			bestResult = result
		}
	}
	
	// Update metrics
	duration := time.Since(start)
	v.metrics.RecordVerification(duration, true)
	
	// Cache result
	v.cache.Put(req.AssetID, bestResult)
	
	// Update node metrics
	for _, node := range nodes {
		for _, result := range validResults {
			if result.NodeID == node.ID {
				v.nodeSelector.UpdateNodeMetrics(node.ID, time.Duration(result.LatencyMs)*time.Millisecond, true)
			}
		}
	}
	
	return bestResult, nil
}

func (v *Verifier) verifyWithNode(ctx context.Context, node *VerificationNode, req *VerificationRequest) *VerificationResult {
	start := time.Now()
	
	// Get verification token
	token := v.tokenManager.GetCurrentToken()
	
	// Create verification payload
	payload := v.createVerificationPayload(req, token, node.ID)
	
	// Sign payload
	signature := v.signPayload(payload, token)
	
	// Simulate verification (in production, this would call the node's API)
	// For now, we'll implement a local verification
	
	// Verify the asset exists
	asset, err := v.storageManager.GetLockedAsset(req.AssetID)
	if err != nil {
		v.LogWarnf("Asset not found: %s", req.AssetID)
		return &VerificationResult{
			Valid:     false,
			AssetID:   req.AssetID,
			NodeID:    node.ID,
			Timestamp: time.Now(),
			LatencyMs: time.Since(start).Milliseconds(),
		}
	}
	
	// Verify ownership
	if !asset.OwnerAddress.Equal(req.Requester) {
		v.LogWarnf("Ownership verification failed for asset: %s", req.AssetID)
		return &VerificationResult{
			Valid:     false,
			AssetID:   req.AssetID,
			NodeID:    node.ID,
			Timestamp: time.Now(),
			LatencyMs: time.Since(start).Milliseconds(),
		}
	}
	
	// Additional verifications based on tier
	if req.Tier >= lockbox.TierPremium {
		// Perform additional security checks
		if !v.performAdvancedVerification(asset, req) {
			return &VerificationResult{
				Valid:     false,
				AssetID:   req.AssetID,
				NodeID:    node.ID,
				Timestamp: time.Now(),
				LatencyMs: time.Since(start).Milliseconds(),
			}
		}
	}
	
	return &VerificationResult{
		Valid:      true,
		AssetID:    req.AssetID,
		NodeID:     node.ID,
		Timestamp:  time.Now(),
		Signature:  signature,
		LatencyMs:  time.Since(start).Milliseconds(),
	}
}

func (v *Verifier) createVerificationPayload(req *VerificationRequest, token *VerificationToken, nodeID string) []byte {
	h := sha256.New()
	h.Write([]byte(req.AssetID))
	h.Write([]byte(req.Requester.String()))
	h.Write(req.Nonce)
	h.Write([]byte(token.ID))
	h.Write([]byte(nodeID))
	h.Write([]byte(fmt.Sprintf("%d", time.Now().Unix())))
	return h.Sum(nil)
}

func (v *Verifier) signPayload(payload []byte, token *VerificationToken) []byte {
	mac := hmac.New(sha256.New, token.Secret)
	mac.Write(payload)
	return mac.Sum(nil)
}

func (v *Verifier) performAdvancedVerification(asset *lockbox.LockedAsset, req *VerificationRequest) bool {
	// Check asset status
	if asset.Status != lockbox.AssetStatusLocked {
		return false
	}
	
	// Check emergency unlock status
	if asset.EmergencyUnlock && req.Tier < lockbox.TierElite {
		return false
	}
	
	// Verify multi-sig requirements
	if len(asset.MultiSigAddresses) > 0 && asset.MinSignatures > 0 {
		// Additional multi-sig verification logic
	}
	
	return true
}

// VerifySignature verifies an Ed25519 signature.
// publicKey must be 32 bytes, signature must be 64 bytes.
func (v *Verifier) VerifySignature(data []byte, signature []byte, publicKey []byte) bool {
	// Validate key and signature sizes
	if len(publicKey) != ed25519.PublicKeySize {
		return false
	}
	if len(signature) != ed25519.SignatureSize {
		return false
	}
	// Verify Ed25519 signature
	return ed25519.Verify(publicKey, data, signature)
}