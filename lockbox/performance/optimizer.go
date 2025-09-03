package performance

import (
	"context"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/iotaledger/hive.go/logger"
)

// PerformanceOptimizer manages system performance optimizations
type PerformanceOptimizer struct {
	*logger.WrappedLogger
	
	// Connection pooling
	connectionPools map[string]*ConnectionPool
	poolMutex      sync.RWMutex
	
	// Caching
	cacheManager   *CacheManager
	
	// Batch processing
	batchProcessor *BatchProcessor
	
	// Resource management
	resourceLimiter *ResourceLimiter
	
	// Metrics
	metrics *PerformanceMetrics
}

// NewPerformanceOptimizer creates a new performance optimizer
func NewPerformanceOptimizer(log *logger.Logger) *PerformanceOptimizer {
	return &PerformanceOptimizer{
		WrappedLogger:   logger.NewWrappedLogger(log),
		connectionPools: make(map[string]*ConnectionPool),
		cacheManager:    NewCacheManager(),
		batchProcessor:  NewBatchProcessor(),
		resourceLimiter: NewResourceLimiter(),
		metrics:         NewPerformanceMetrics(),
	}
}

// ConnectionPool manages a pool of connections
type ConnectionPool struct {
	name        string
	maxSize     int
	minSize     int
	idleTimeout time.Duration
	
	connections chan *Connection
	factory     ConnectionFactory
	
	activeCount int32
	mu          sync.Mutex
}

// Connection represents a pooled connection
type Connection struct {
	ID         string
	Resource   interface{}
	CreatedAt  time.Time
	LastUsedAt time.Time
}

// ConnectionFactory creates new connections
type ConnectionFactory func() (*Connection, error)

// NewConnectionPool creates a new connection pool
func NewConnectionPool(name string, minSize, maxSize int, idleTimeout time.Duration, factory ConnectionFactory) *ConnectionPool {
	pool := &ConnectionPool{
		name:        name,
		maxSize:     maxSize,
		minSize:     minSize,
		idleTimeout: idleTimeout,
		connections: make(chan *Connection, maxSize),
		factory:     factory,
	}
	
	// Initialize minimum connections
	for i := 0; i < minSize; i++ {
		conn, err := factory()
		if err == nil {
			pool.connections <- conn
			atomic.AddInt32(&pool.activeCount, 1)
		}
	}
	
	return pool
}

// Get retrieves a connection from the pool
func (p *ConnectionPool) Get(ctx context.Context) (*Connection, error) {
	select {
	case conn := <-p.connections:
		conn.LastUsedAt = time.Now()
		return conn, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
		// Create new connection if under limit
		if atomic.LoadInt32(&p.activeCount) < int32(p.maxSize) {
			conn, err := p.factory()
			if err != nil {
				return nil, err
			}
			atomic.AddInt32(&p.activeCount, 1)
			return conn, nil
		}
		
		// Wait for available connection
		select {
		case conn := <-p.connections:
			conn.LastUsedAt = time.Now()
			return conn, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// Put returns a connection to the pool
func (p *ConnectionPool) Put(conn *Connection) {
	if conn == nil {
		return
	}
	
	select {
	case p.connections <- conn:
		// Connection returned to pool
	default:
		// Pool is full, close connection
		atomic.AddInt32(&p.activeCount, -1)
	}
}

// CacheManager manages various caches
type CacheManager struct {
	caches map[string]*Cache
	mu     sync.RWMutex
}

// Cache represents a generic cache
type Cache struct {
	name     string
	maxSize  int
	ttl      time.Duration
	items    map[string]*CacheItem
	mu       sync.RWMutex
	hits     uint64
	misses   uint64
}

// CacheItem represents a cached item
type CacheItem struct {
	Value      interface{}
	ExpiresAt  time.Time
	AccessCount uint64
}

// NewCacheManager creates a new cache manager
func NewCacheManager() *CacheManager {
	cm := &CacheManager{
		caches: make(map[string]*Cache),
	}
	
	// Initialize default caches
	cm.CreateCache("assets", 10000, 5*time.Minute)
	cm.CreateCache("scripts", 1000, time.Hour)
	cm.CreateCache("verification", 5000, 10*time.Minute)
	
	return cm
}

// CreateCache creates a new cache
func (cm *CacheManager) CreateCache(name string, maxSize int, ttl time.Duration) *Cache {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	
	cache := &Cache{
		name:    name,
		maxSize: maxSize,
		ttl:     ttl,
		items:   make(map[string]*CacheItem),
	}
	
	cm.caches[name] = cache
	
	// Start cleanup routine
	go cache.cleanupRoutine()
	
	return cache
}

// Get retrieves a value from cache
func (c *Cache) Get(key string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	item, exists := c.items[key]
	if !exists {
		atomic.AddUint64(&c.misses, 1)
		return nil, false
	}
	
	if time.Now().After(item.ExpiresAt) {
		atomic.AddUint64(&c.misses, 1)
		return nil, false
	}
	
	atomic.AddUint64(&c.hits, 1)
	atomic.AddUint64(&item.AccessCount, 1)
	return item.Value, true
}

// Set stores a value in cache
func (c *Cache) Set(key string, value interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	// Evict if at capacity
	if len(c.items) >= c.maxSize {
		c.evictLRU()
	}
	
	c.items[key] = &CacheItem{
		Value:     value,
		ExpiresAt: time.Now().Add(c.ttl),
	}
}

// evictLRU evicts the least recently used item
func (c *Cache) evictLRU() {
	var lruKey string
	var lruCount uint64 = ^uint64(0)
	
	for key, item := range c.items {
		if item.AccessCount < lruCount {
			lruKey = key
			lruCount = item.AccessCount
		}
	}
	
	if lruKey != "" {
		delete(c.items, lruKey)
	}
}

// cleanupRoutine periodically removes expired items
func (c *Cache) cleanupRoutine() {
	ticker := time.NewTicker(c.ttl / 2)
	defer ticker.Stop()
	
	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for key, item := range c.items {
			if now.After(item.ExpiresAt) {
				delete(c.items, key)
			}
		}
		c.mu.Unlock()
	}
}

// BatchProcessor handles batch processing of operations
type BatchProcessor struct {
	batches    map[string]*Batch
	processors map[string]BatchProcessorFunc
	mu         sync.RWMutex
}

// Batch represents a batch of items
type Batch struct {
	name      string
	items     []interface{}
	maxSize   int
	maxWait   time.Duration
	processor BatchProcessorFunc
	mu        sync.Mutex
	timer     *time.Timer
}

// BatchProcessorFunc processes a batch of items
type BatchProcessorFunc func(items []interface{}) error

// NewBatchProcessor creates a new batch processor
func NewBatchProcessor() *BatchProcessor {
	return &BatchProcessor{
		batches:    make(map[string]*Batch),
		processors: make(map[string]BatchProcessorFunc),
	}
}

// RegisterProcessor registers a batch processor
func (bp *BatchProcessor) RegisterProcessor(name string, maxSize int, maxWait time.Duration, processor BatchProcessorFunc) {
	bp.mu.Lock()
	defer bp.mu.Unlock()
	
	batch := &Batch{
		name:      name,
		maxSize:   maxSize,
		maxWait:   maxWait,
		processor: processor,
		items:     make([]interface{}, 0, maxSize),
	}
	
	bp.batches[name] = batch
	bp.processors[name] = processor
}

// Add adds an item to a batch
func (bp *BatchProcessor) Add(batchName string, item interface{}) error {
	bp.mu.RLock()
	batch, exists := bp.batches[batchName]
	bp.mu.RUnlock()
	
	if !exists {
		return fmt.Errorf("batch %s not found", batchName)
	}
	
	batch.mu.Lock()
	defer batch.mu.Unlock()
	
	batch.items = append(batch.items, item)
	
	// Start timer if this is the first item
	if len(batch.items) == 1 {
		batch.timer = time.AfterFunc(batch.maxWait, func() {
			bp.processBatch(batchName)
		})
	}
	
	// Process if batch is full
	if len(batch.items) >= batch.maxSize {
		if batch.timer != nil {
			batch.timer.Stop()
		}
		go bp.processBatch(batchName)
	}
	
	return nil
}

// processBatch processes a batch
func (bp *BatchProcessor) processBatch(batchName string) {
	bp.mu.RLock()
	batch, exists := bp.batches[batchName]
	bp.mu.RUnlock()
	
	if !exists {
		return
	}
	
	batch.mu.Lock()
	items := batch.items
	batch.items = make([]interface{}, 0, batch.maxSize)
	batch.timer = nil
	batch.mu.Unlock()
	
	if len(items) > 0 {
		_ = batch.processor(items)
	}
}

// ResourceLimiter manages resource limits
type ResourceLimiter struct {
	limiters map[string]*RateLimiter
	mu       sync.RWMutex
}

// RateLimiter implements token bucket algorithm
type RateLimiter struct {
	name       string
	capacity   int64
	refillRate int64
	tokens     int64
	lastRefill time.Time
	mu         sync.Mutex
}

// NewResourceLimiter creates a new resource limiter
func NewResourceLimiter() *ResourceLimiter {
	rl := &ResourceLimiter{
		limiters: make(map[string]*RateLimiter),
	}
	
	// Initialize tier-based rate limiters
	rl.CreateLimiter("basic", 1000, 1000)      // 1000 TPS
	rl.CreateLimiter("standard", 10000, 10000) // 10K TPS
	rl.CreateLimiter("premium", 100000, 100000) // 100K TPS
	rl.CreateLimiter("elite", 500000, 500000)   // 500K TPS
	
	return rl
}

// CreateLimiter creates a new rate limiter
func (rl *ResourceLimiter) CreateLimiter(name string, capacity, refillRate int64) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	
	rl.limiters[name] = &RateLimiter{
		name:       name,
		capacity:   capacity,
		refillRate: refillRate,
		tokens:     capacity,
		lastRefill: time.Now(),
	}
}

// Allow checks if an operation is allowed
func (rl *ResourceLimiter) Allow(limiterName string, tokens int64) bool {
	rl.mu.RLock()
	limiter, exists := rl.limiters[limiterName]
	rl.mu.RUnlock()
	
	if !exists {
		return false
	}
	
	return limiter.Allow(tokens)
}

// Allow checks if tokens are available
func (l *RateLimiter) Allow(requested int64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	
	// Refill tokens
	now := time.Now()
	elapsed := now.Sub(l.lastRefill)
	tokensToAdd := int64(elapsed.Seconds() * float64(l.refillRate))
	
	l.tokens = min(l.tokens+tokensToAdd, l.capacity)
	l.lastRefill = now
	
	// Check if enough tokens
	if l.tokens >= requested {
		l.tokens -= requested
		return true
	}
	
	return false
}

// PerformanceMetrics tracks performance metrics
type PerformanceMetrics struct {
	TransactionCount  uint64
	TransactionTime   uint64
	CacheHits        uint64
	CacheMisses      uint64
	BatchesProcessed uint64
	RateLimitHits    uint64
}

// NewPerformanceMetrics creates new performance metrics
func NewPerformanceMetrics() *PerformanceMetrics {
	return &PerformanceMetrics{}
}

// min returns the minimum of two int64 values
func min(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}