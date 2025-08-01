package verification

import (
	"sync"
	"time"
)

// VerificationCache caches verification results to improve latency
type VerificationCache struct {
	cache     map[string]*CachedVerification
	mu        sync.RWMutex
	ttl       time.Duration
	maxSize   int
}

// CachedVerification represents a cached verification result
type CachedVerification struct {
	Result    *VerificationResult
	CachedAt  time.Time
	ExpiresAt time.Time
	HitCount  int
}

// NewVerificationCache creates a new verification cache
func NewVerificationCache(ttl time.Duration, maxSize int) *VerificationCache {
	vc := &VerificationCache{
		cache:   make(map[string]*CachedVerification),
		ttl:     ttl,
		maxSize: maxSize,
	}
	
	// Start cleanup routine
	go vc.cleanupRoutine()
	
	return vc
}

// Get retrieves a cached verification result
func (vc *VerificationCache) Get(assetID string) (*VerificationResult, bool) {
	vc.mu.RLock()
	defer vc.mu.RUnlock()
	
	cached, ok := vc.cache[assetID]
	if !ok {
		return nil, false
	}
	
	// Check if expired
	if time.Now().After(cached.ExpiresAt) {
		return nil, false
	}
	
	// Update hit count
	cached.HitCount++
	
	return cached.Result, true
}

// Put stores a verification result in cache
func (vc *VerificationCache) Put(assetID string, result *VerificationResult) {
	vc.mu.Lock()
	defer vc.mu.Unlock()
	
	// Check size limit
	if len(vc.cache) >= vc.maxSize {
		vc.evictOldest()
	}
	
	now := time.Now()
	vc.cache[assetID] = &CachedVerification{
		Result:    result,
		CachedAt:  now,
		ExpiresAt: now.Add(vc.ttl),
		HitCount:  0,
	}
}

// evictOldest removes the oldest cache entry
func (vc *VerificationCache) evictOldest() {
	var oldestID string
	var oldestTime time.Time
	
	for id, cached := range vc.cache {
		if oldestID == "" || cached.CachedAt.Before(oldestTime) {
			oldestID = id
			oldestTime = cached.CachedAt
		}
	}
	
	if oldestID != "" {
		delete(vc.cache, oldestID)
	}
}

// cleanupRoutine periodically removes expired entries
func (vc *VerificationCache) cleanupRoutine() {
	ticker := time.NewTicker(vc.ttl / 2)
	defer ticker.Stop()
	
	for range ticker.C {
		vc.mu.Lock()
		now := time.Now()
		
		for id, cached := range vc.cache {
			if now.After(cached.ExpiresAt) {
				delete(vc.cache, id)
			}
		}
		
		vc.mu.Unlock()
	}
}

// Stats returns cache statistics
func (vc *VerificationCache) Stats() (entries int, hits int, size int) {
	vc.mu.RLock()
	defer vc.mu.RUnlock()
	
	entries = len(vc.cache)
	for _, cached := range vc.cache {
		hits += cached.HitCount
	}
	
	// Approximate memory size
	size = entries * (32 + 200) // Rough estimate
	
	return
}