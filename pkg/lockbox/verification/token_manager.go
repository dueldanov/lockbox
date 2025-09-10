package verification

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	"github.com/iotaledger/hive.go/logger"
)

type TokenManager struct {
	*logger.WrappedLogger
	
	currentToken  *VerificationToken
	previousToken *VerificationToken
	mu            sync.RWMutex
	
	rotationPeriod time.Duration
	tokenValidity  time.Duration
	
	rotationTimer *time.Timer
	stopChan      chan struct{}
}

type VerificationToken struct {
	ID        string
	Secret    []byte
	IssuedAt  time.Time
	ExpiresAt time.Time
}

func NewTokenManager(log *logger.Logger, rotationPeriod, tokenValidity time.Duration) *TokenManager {
	return &TokenManager{
		WrappedLogger:  logger.NewWrappedLogger(log),
		rotationPeriod: rotationPeriod,
		tokenValidity:  tokenValidity,
		stopChan:       make(chan struct{}),
	}
}

func (tm *TokenManager) Start(ctx context.Context) {
	// Generate initial token
	if err := tm.rotateToken(); err != nil {
		tm.LogErrorf("Failed to generate initial token: %v", err)
		return
	}
	
	// Start rotation timer
	tm.scheduleNextRotation()
	
	// Wait for shutdown
	<-ctx.Done()
	tm.Stop()
}

func (tm *TokenManager) Stop() {
	close(tm.stopChan)
	
	if tm.rotationTimer != nil {
		tm.rotationTimer.Stop()
	}
	
	tm.LogInfo("Token manager stopped")
}

func (tm *TokenManager) GetCurrentToken() *VerificationToken {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	
	return tm.currentToken
}

func (tm *TokenManager) GetPreviousToken() *VerificationToken {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	
	return tm.previousToken
}

func (tm *TokenManager) ValidateToken(tokenID string) bool {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	
	// Check current token
	if tm.currentToken != nil && tm.currentToken.ID == tokenID {
		return time.Now().Before(tm.currentToken.ExpiresAt)
	}
	
	// Check previous token (for grace period)
	if tm.previousToken != nil && tm.previousToken.ID == tokenID {
		return time.Now().Before(tm.previousToken.ExpiresAt)
	}
	
	return false
}

func (tm *TokenManager) rotateToken() error {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	
	// Move current to previous
	if tm.currentToken != nil {
		tm.previousToken = tm.currentToken
	}
	
	// Generate new token
	token, err := tm.generateToken()
	if err != nil {
		return fmt.Errorf("failed to generate token: %w", err)
	}
	
	tm.currentToken = token
	tm.LogInfof("Rotated verification token: %s", token.ID)
	
	// Emit event if needed
	// tm.Events.TokenRotated.Trigger(token.ID)
	
	return nil
}

func (tm *TokenManager) generateToken() (*VerificationToken, error) {
	// Generate random secret
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	
	// Generate token ID
	h := sha256.New()
	h.Write(secret)
	h.Write([]byte(fmt.Sprintf("%d", time.Now().Unix())))
	tokenID := hex.EncodeToString(h.Sum(nil)[:16])
	
	now := time.Now()
	return &VerificationToken{
		ID:        tokenID,
		Secret:    secret,
		IssuedAt:  now,
		ExpiresAt: now.Add(tm.tokenValidity),
	}, nil
}

func (tm *TokenManager) scheduleNextRotation() {
	tm.rotationTimer = time.AfterFunc(tm.rotationPeriod, func() {
		select {
		case <-tm.stopChan:
			return
		default:
			if err := tm.rotateToken(); err != nil {
				tm.LogErrorf("Token rotation failed: %v", err)
			}
			tm.scheduleNextRotation()
		}
	})
}

func (tm *TokenManager) GetRotationStats() map[string]interface{} {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	
	stats := map[string]interface{}{
		"rotation_period": tm.rotationPeriod.String(),
		"token_validity":  tm.tokenValidity.String(),
	}
	
	if tm.currentToken != nil {
		stats["current_token_id"] = tm.currentToken.ID
		stats["current_token_expires_in"] = time.Until(tm.currentToken.ExpiresAt).String()
	}
	
	if tm.previousToken != nil {
		stats["previous_token_id"] = tm.previousToken.ID
		stats["previous_token_expires_in"] = time.Until(tm.previousToken.ExpiresAt).String()
	}
	
	return stats
}