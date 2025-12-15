package verification

import (
	"errors"
	"sync"
	"time"
)

var (
	ErrRateLimited = errors.New("rate limit exceeded")
)

// RateLimiter implements a token bucket rate limiter per user ID.
// Default: 5 requests per minute per user as per LockBox requirements.
type RateLimiter struct {
	mu            sync.RWMutex
	buckets       map[string]*tokenBucket
	maxTokens     int           // Maximum tokens per bucket
	refillRate    time.Duration // Time to add one token
	cleanupTicker *time.Ticker
	stopChan      chan struct{}
}

type tokenBucket struct {
	tokens     int
	lastRefill time.Time
}

// RateLimiterConfig holds configuration for the rate limiter
type RateLimiterConfig struct {
	MaxRequests   int           // Maximum requests per window (default: 5)
	WindowSize    time.Duration // Time window (default: 1 minute)
	CleanupPeriod time.Duration // How often to clean up old buckets (default: 5 minutes)
}

// DefaultRateLimiterConfig returns the default configuration per LockBox requirements
func DefaultRateLimiterConfig() *RateLimiterConfig {
	return &RateLimiterConfig{
		MaxRequests:   5,
		WindowSize:    time.Minute,
		CleanupPeriod: 5 * time.Minute,
	}
}

// NewRateLimiter creates a new rate limiter with the given configuration
func NewRateLimiter(config *RateLimiterConfig) *RateLimiter {
	if config == nil {
		config = DefaultRateLimiterConfig()
	}

	rl := &RateLimiter{
		buckets:    make(map[string]*tokenBucket),
		maxTokens:  config.MaxRequests,
		refillRate: config.WindowSize / time.Duration(config.MaxRequests),
		stopChan:   make(chan struct{}),
	}

	// Start cleanup goroutine
	rl.cleanupTicker = time.NewTicker(config.CleanupPeriod)
	go rl.cleanupLoop()

	return rl
}

// Allow checks if a request from the given user ID should be allowed.
// Returns nil if allowed, ErrRateLimited if rate limit exceeded.
func (rl *RateLimiter) Allow(userID string) error {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	bucket, exists := rl.buckets[userID]
	if !exists {
		// New user, create bucket with full tokens
		rl.buckets[userID] = &tokenBucket{
			tokens:     rl.maxTokens - 1, // Use one token for this request
			lastRefill: time.Now(),
		}
		return nil
	}

	// Refill tokens based on time passed
	rl.refillTokens(bucket)

	// Check if we have tokens available
	if bucket.tokens <= 0 {
		return ErrRateLimited
	}

	// Consume a token
	bucket.tokens--
	return nil
}

// refillTokens adds tokens based on time elapsed since last refill
func (rl *RateLimiter) refillTokens(bucket *tokenBucket) {
	now := time.Now()
	elapsed := now.Sub(bucket.lastRefill)
	tokensToAdd := int(elapsed / rl.refillRate)

	if tokensToAdd > 0 {
		bucket.tokens += tokensToAdd
		if bucket.tokens > rl.maxTokens {
			bucket.tokens = rl.maxTokens
		}
		bucket.lastRefill = now
	}
}

// GetRemaining returns the number of remaining requests for a user
func (rl *RateLimiter) GetRemaining(userID string) int {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	bucket, exists := rl.buckets[userID]
	if !exists {
		return rl.maxTokens
	}

	// Calculate with refill (read-only, don't modify)
	now := time.Now()
	elapsed := now.Sub(bucket.lastRefill)
	tokensToAdd := int(elapsed / rl.refillRate)
	tokens := bucket.tokens + tokensToAdd
	if tokens > rl.maxTokens {
		tokens = rl.maxTokens
	}

	return tokens
}

// GetRetryAfter returns the duration until the next request is allowed
func (rl *RateLimiter) GetRetryAfter(userID string) time.Duration {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	bucket, exists := rl.buckets[userID]
	if !exists {
		return 0
	}

	if bucket.tokens > 0 {
		return 0
	}

	// Calculate time until next token
	now := time.Now()
	elapsed := now.Sub(bucket.lastRefill)
	timeToNextToken := rl.refillRate - (elapsed % rl.refillRate)

	return timeToNextToken
}

// Reset clears the rate limit for a specific user
func (rl *RateLimiter) Reset(userID string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	delete(rl.buckets, userID)
}

// cleanupLoop periodically removes old/inactive buckets
func (rl *RateLimiter) cleanupLoop() {
	for {
		select {
		case <-rl.cleanupTicker.C:
			rl.cleanup()
		case <-rl.stopChan:
			return
		}
	}
}

// cleanup removes buckets that have been inactive and fully refilled
func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	inactiveThreshold := time.Duration(rl.maxTokens) * rl.refillRate * 2

	for userID, bucket := range rl.buckets {
		if now.Sub(bucket.lastRefill) > inactiveThreshold {
			delete(rl.buckets, userID)
		}
	}
}

// Stop stops the rate limiter cleanup goroutine
func (rl *RateLimiter) Stop() {
	close(rl.stopChan)
	rl.cleanupTicker.Stop()
}

// Stats returns current statistics about the rate limiter
type RateLimiterStats struct {
	ActiveUsers int
	MaxTokens   int
	RefillRate  time.Duration
}

// GetStats returns current rate limiter statistics
func (rl *RateLimiter) GetStats() RateLimiterStats {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	return RateLimiterStats{
		ActiveUsers: len(rl.buckets),
		MaxTokens:   rl.maxTokens,
		RefillRate:  rl.refillRate,
	}
}
