package lockscript

import (
	"sync"
	"time"
)

type ScriptCache struct {
	cache map[string]*cacheEntry
	mu    sync.RWMutex
	ttl   time.Duration
}

type cacheEntry struct {
	script    *CompiledScript
	timestamp time.Time
}

func NewScriptCache() *ScriptCache {
	return &ScriptCache{
		cache: make(map[string]*cacheEntry),
		ttl:   time.Hour,
	}
}

func (c *ScriptCache) Get(source string) *CompiledScript {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	entry, ok := c.cache[source]
	if !ok {
		return nil
	}
	
	if time.Since(entry.timestamp) > c.ttl {
		return nil
	}
	
	return entry.script
}

func (c *ScriptCache) Put(source string, script *CompiledScript) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	c.cache[source] = &cacheEntry{
		script:    script,
		timestamp: time.Now(),
	}
	
	// Simple eviction: remove old entries
	if len(c.cache) > 1000 {
		c.evictOld()
	}
}

func (c *ScriptCache) evictOld() {
	cutoff := time.Now().Add(-c.ttl)
	
	for key, entry := range c.cache {
		if entry.timestamp.Before(cutoff) {
			delete(c.cache, key)
		}
	}
}