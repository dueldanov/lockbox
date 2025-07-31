package verification

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/iotaledger/hive.go/logger"
	"github.com/iotaledger/hive.go/runtime/event"
)

// TokenManager manages verification tokens with automatic rotation
type TokenManager struct {
	*logger.WrappedLogger
	
	tokens          map[string]*VerificationToken
	shardTokens     map[string]map[string]*VerificationToken // nodeID -> shardID -> token
	rotationPeriod  time.Duration
	tokenLifetime   time.Duration
	mu              sync.RWMutex
	
	Events *TokenEvents
}

// TokenEvents contains token-related events
type TokenEvents struct {
	TokenRotated *event.Event2[string, string] // nodeID, tokenID
	TokenExpired *event.Event2[string, string] // nodeID, tokenID
}

// VerificationToken represents a token used for verification
type VerificationToken struct {
	ID         string
	NodeID     string
	ShardID    string // Empty for node tokens, populated for shard tokens
	Value      []byte
	CreatedAt  time.Time
	ExpiresAt  time.Time
	RotateAt   time.Time
	Generation int
}

// NewTokenManager creates a new token manager
func NewTokenManager(log *logger.Logger, rotationPeriod, tokenLifetime time.Duration) *TokenManager {
	tm := &TokenManager{
		WrappedLogger:  logger.NewWrappedLogger(log),
		tokens:         make(map[string]*VerificationToken),
		shardTokens:    make(map[string]map[string]*VerificationToken),
		rotationPeriod: rotationPeriod,
		tokenLifetime:  tokenLifetime,
		Events: &TokenEvents{
			TokenRotated: event.New2[string, string](),
			TokenExpired: event.New2[string, string](),
		},
	}
	
	return tm
}

// Start begins the automatic token rotation
func (tm *TokenManager) Start(ctx context.Context) {
	ticker := time.NewTicker(tm.rotationPeriod / 10) // Check more frequently than rotation period
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			tm.checkAndRotateTokens()
		}
	}
}

// GenerateTokenForNode generates a new token for a verification node
func (tm *TokenManager) GenerateTokenForNode(nodeID string) (*VerificationToken, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	
	// Check if we need to rotate existing token
	if existing, ok := tm.tokens[nodeID]; ok && time.Now().Before(existing.RotateAt) {
		return existing, nil
	}
	
	token, err := tm.generateToken(nodeID, "")
	if err != nil {
		return nil, err
	}
	
	tm.tokens[nodeID] = token
	tm.LogInfof("Generated new token for node %s (ID: %s)", nodeID, token.ID)
	
	return token, nil
}

// GenerateShardToken generates a token for shard-level verification
func (tm *TokenManager) GenerateShardToken(nodeID, shardID string) (*VerificationToken, error) {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	
	if _, ok := tm.shardTokens[nodeID]; !ok {
		tm.shardTokens[nodeID] = make(map[string]*VerificationToken)
	}
	
	// Check existing shard token
	if existing, ok := tm.shardTokens[nodeID][shardID]; ok && time.Now().Before(existing.RotateAt) {
		return existing, nil
	}
	
	token, err := tm.generateToken(nodeID, shardID)
	if err != nil {
		return nil, err
	}
	
	tm.shardTokens[nodeID][shardID] = token
	tm.LogInfof("Generated new shard token for node %s, shard %s (ID: %s)", nodeID, shardID, token.ID)
	
	return token, nil
}

// GetCurrentToken gets the current valid token for a node
func (tm *TokenManager) GetCurrentToken(nodeID string) (*VerificationToken, error) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	
	token, ok := tm.tokens[nodeID]
	if !ok {
		return nil, fmt.Errorf("no token found for node %s", nodeID)
	}
	
	if time.Now().After(token.ExpiresAt) {
		return nil, fmt.Errorf("token for node %s has expired", nodeID)
	}
	
	return token, nil
}

// GetShardToken gets the current shard token
func (tm *TokenManager) GetShardToken(nodeID, shardID string) (*VerificationToken, error) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	
	nodeTokens, ok := tm.shardTokens[nodeID]
	if !ok {
		return nil, fmt.Errorf("no tokens found for node %s", nodeID)
	}
	
	token, ok := nodeTokens[shardID]
	if !ok {
		return nil, fmt.Errorf("no token found for node %s, shard %s", nodeID, shardID)
	}
	
	if time.Now().After(token.ExpiresAt) {
		return nil, fmt.Errorf("shard token for node %s, shard %s has expired", nodeID, shardID)
	}
	
	return token, nil
}

// generateToken creates a new verification token
func (tm *TokenManager) generateToken(nodeID, shardID string) (*VerificationToken, error) {
	// Generate secure random token
	tokenValue := make([]byte, 32)
	if _, err := rand.Read(tokenValue); err != nil {
		return nil, fmt.Errorf("failed to generate token: %w", err)
	}
	
	now := time.Now()
	token := &VerificationToken{
		ID:         hex.EncodeToString(tokenValue[:8]),
		NodeID:     nodeID,
		ShardID:    shardID,
		Value:      tokenValue,
		CreatedAt:  now,
		ExpiresAt:  now.Add(tm.tokenLifetime),
		RotateAt:   now.Add(tm.rotationPeriod),
		Generation: tm.getNextGeneration(nodeID, shardID),
	}
	
	return token, nil
}

// getNextGeneration gets the next generation number for a token
func (tm *TokenManager) getNextGeneration(nodeID, shardID string) int {
	if shardID == "" {
		if existing, ok := tm.tokens[nodeID]; ok {
			return existing.Generation + 1
		}
	} else {
		if nodeTokens, ok := tm.shardTokens[nodeID]; ok {
			if existing, ok := nodeTokens[shardID]; ok {
				return existing.Generation + 1
			}
		}
	}
	return 1
}

// checkAndRotateTokens checks all tokens and rotates them if necessary
func (tm *TokenManager) checkAndRotateTokens() {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	
	now := time.Now()
	
	// Check node tokens
	for nodeID, token := range tm.tokens {
		if now.After(token.ExpiresAt) {
			tm.Events.TokenExpired.Trigger(nodeID, token.ID)
			delete(tm.tokens, nodeID)
			tm.LogWarnf("Token for node %s expired and removed", nodeID)
		} else if now.After(token.RotateAt) {
			// Rotate token
			newToken, err := tm.generateToken(nodeID, "")
			if err != nil {
				tm.LogErrorf("Failed to rotate token for node %s: %v", nodeID, err)
				continue
			}
			
			tm.tokens[nodeID] = newToken
			tm.Events.TokenRotated.Trigger(nodeID, newToken.ID)
			tm.LogInfof("Rotated token for node %s (new ID: %s)", nodeID, newToken.ID)
		}
	}
	
	// Check shard tokens
	for nodeID, shardTokens := range tm.shardTokens {
		for shardID, token := range shardTokens {
			if now.After(token.ExpiresAt) {
				tm.Events.TokenExpired.Trigger(nodeID, token.ID)
				delete(shardTokens, shardID)
				tm.LogWarnf("Shard token for node %s, shard %s expired and removed", nodeID, shardID)
			} else if now.After(token.RotateAt) {
				// Rotate shard token
				newToken, err := tm.generateToken(nodeID, shardID)
				if err != nil {
					tm.LogErrorf("Failed to rotate shard token for node %s, shard %s: %v", nodeID, shardID, err)
					continue
				}
				
				shardTokens[shardID] = newToken
				tm.Events.TokenRotated.Trigger(nodeID, newToken.ID)
				tm.LogInfof("Rotated shard token for node %s, shard %s (new ID: %s)", nodeID, shardID, newToken.ID)
			}
		}
		
		// Clean up empty shard token maps
		if len(shardTokens) == 0 {
			delete(tm.shardTokens, nodeID)
		}
	}
}

// RevokeToken immediately revokes a token
func (tm *TokenManager) RevokeToken(nodeID string) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	
	if token, ok := tm.tokens[nodeID]; ok {
		delete(tm.tokens, nodeID)
		tm.LogInfof("Revoked token for node %s (ID: %s)", nodeID, token.ID)
		return nil
	}
	
	return fmt.Errorf("no token found for node %s", nodeID)
}

// RevokeShardToken immediately revokes a shard token
func (tm *TokenManager) RevokeShardToken(nodeID, shardID string) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	
	if nodeTokens, ok := tm.shardTokens[nodeID]; ok {
		if token, ok := nodeTokens[shardID]; ok {
			delete(nodeTokens, shardID)
			tm.LogInfof("Revoked shard token for node %s, shard %s (ID: %s)", nodeID, shardID, token.ID)
			return nil
		}
	}
	
	return fmt.Errorf("no shard token found for node %s, shard %s", nodeID, shardID)
}