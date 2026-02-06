package middleware

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/dueldanov/lockbox/v2/internal/errors"
	"github.com/dueldanov/lockbox/v2/internal/performance"
	"github.com/dueldanov/lockbox/v2/internal/service"
	"github.com/dueldanov/lockbox/v2/internal/tiering"
)

// Service defines the interface for service operations that can be wrapped by middleware
type Service interface {
	LockAsset(ctx context.Context, req *service.LockAssetRequest) (*service.LockAssetResponse, error)
	UnlockAsset(ctx context.Context, req *service.UnlockAssetRequest) (*service.UnlockAssetResponse, error)
	GetAssetStatus(assetID string) (*service.LockedAsset, error)
}

// RateLimitMiddleware provides rate limiting
type RateLimitMiddleware struct {
	next         Service
	limiter      *performance.ResourceLimiter
	tierManager  *tiering.Manager
	limiters     map[string]*UserRateLimiter
	limiterMutex sync.RWMutex
}

// UserRateLimiter tracks per-user rate limits
type UserRateLimiter struct {
	userID       string
	tier         service.Tier
	requests     []time.Time
	mu           sync.Mutex
	lastCleanup  time.Time
}

// NewRateLimitMiddleware creates rate limit middleware
func NewRateLimitMiddleware(next Service, limiter *performance.ResourceLimiter, tierManager *tiering.Manager) *RateLimitMiddleware {
	return &RateLimitMiddleware{
		next:        next,
		limiter:     limiter,
		tierManager: tierManager,
		limiters:    make(map[string]*UserRateLimiter),
	}
}

// getUserID extracts user ID from context
func getUserID(ctx context.Context) string {
	// Implementation would extract from JWT or session
	if userID, ok := ctx.Value("userID").(string); ok {
		return userID
	}
	return "anonymous"
}

// getUserTier gets user's tier from context or falls back to Basic.
// The tier is expected to be set in context by the auth interceptor (e.g., from mTLS client cert metadata).
func (r *RateLimitMiddleware) getUserTier(ctx context.Context, userID string) service.Tier {
	if tier, ok := ctx.Value("userTier").(service.Tier); ok {
		return tier
	}
	return service.TierBasic
}

// checkRateLimit checks if request is within rate limits
func (r *RateLimitMiddleware) checkRateLimit(ctx context.Context, operation string) error {
	userID := getUserID(ctx)
	tier := r.getUserTier(ctx, userID)
	
	// Get or create user limiter
	r.limiterMutex.Lock()
	userLimiter, exists := r.limiters[userID]
	if !exists {
		userLimiter = &UserRateLimiter{
			userID:      userID,
			tier:        tier,
			requests:    make([]time.Time, 0, 1000),
			lastCleanup: time.Now(),
		}
		r.limiters[userID] = userLimiter
	}
	r.limiterMutex.Unlock()
	
	// Check tier-based rate limit
	allowed := r.limiter.Allow(tier.String(), 1)
	if !allowed {
		return errors.ErrTierLimitExceeded(tier.String(), "rate limit")
	}
	
	// Check per-user rate limit
	userLimiter.mu.Lock()
	defer userLimiter.mu.Unlock()
	
	now := time.Now()
	
	// Cleanup old requests
	if now.Sub(userLimiter.lastCleanup) > time.Minute {
		cutoff := now.Add(-time.Hour)
		validRequests := make([]time.Time, 0, len(userLimiter.requests))
		for _, t := range userLimiter.requests {
			if t.After(cutoff) {
				validRequests = append(validRequests, t)
			}
		}
		userLimiter.requests = validRequests
		userLimiter.lastCleanup = now
	}
	
	// Check hourly limit based on tier
	hourlyLimit := getHourlyLimit(tier)
	hourAgo := now.Add(-time.Hour)
	hourlyCount := 0
	for _, t := range userLimiter.requests {
		if t.After(hourAgo) {
			hourlyCount++
		}
	}
	
	if hourlyCount >= hourlyLimit {
		return errors.ErrResourceExhausted(fmt.Sprintf("hourly limit of %d requests exceeded", hourlyLimit))
	}
	
	// Add current request
	userLimiter.requests = append(userLimiter.requests, now)
	
	return nil
}

// getHourlyLimit returns hourly request limit for tier
func getHourlyLimit(tier service.Tier) int {
	switch tier {
	case service.TierBasic:
		return 1000
	case service.TierStandard:
		return 10000
	case service.TierPremium:
		return 100000
	case service.TierElite:
		return -1 // unlimited
	default:
		return 1000
	}
}

// LockAsset implements rate-limited lock asset
func (r *RateLimitMiddleware) LockAsset(ctx context.Context, req *service.LockAssetRequest) (*service.LockAssetResponse, error) {
	if err := r.checkRateLimit(ctx, "lock_asset"); err != nil {
		return nil, err
	}

	return r.next.LockAsset(ctx, req)
}

// UnlockAsset implements rate-limited unlock asset
func (r *RateLimitMiddleware) UnlockAsset(ctx context.Context, req *service.UnlockAssetRequest) (*service.UnlockAssetResponse, error) {
	if err := r.checkRateLimit(ctx, "unlock_asset"); err != nil {
		return nil, err
	}

	return r.next.UnlockAsset(ctx, req)
}

// GetAssetStatus implements rate-limited get asset status
func (r *RateLimitMiddleware) GetAssetStatus(assetID string) (*service.LockedAsset, error) {
	ctx := context.Background()
	if err := r.checkRateLimit(ctx, "get_asset_status"); err != nil {
		return nil, err
	}

	return r.next.GetAssetStatus(assetID)
}

// Cleanup cleans up old rate limit data
func (r *RateLimitMiddleware) Cleanup(olderThan time.Duration) {
	r.limiterMutex.Lock()
	defer r.limiterMutex.Unlock()
	
	cutoff := time.Now().Add(-olderThan)
	for userID, limiter := range r.limiters {
		limiter.mu.Lock()
		
		// Check if user has any recent activity
		hasRecent := false
		for _, t := range limiter.requests {
			if t.After(cutoff) {
				hasRecent = true
				break
			}
		}
		
		limiter.mu.Unlock()
		
		// Remove inactive users
		if !hasRecent {
			delete(r.limiters, userID)
		}
	}
}