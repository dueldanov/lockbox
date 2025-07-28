package crypto

import (
	"crypto/rand"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// SecureMemoryPool manages secure memory buffers
type SecureMemoryPool struct {
	mu       sync.Mutex
	buffers  chan *SecureBuffer
	size     int
	bufSize  int
	clearTicker *time.Ticker
	stopChan chan struct{}
}

// SecureBuffer represents a secure memory buffer
type SecureBuffer struct {
	data     []byte
	locked   bool
	lastUsed time.Time
}

// NewSecureMemoryPool creates a new secure memory pool
func NewSecureMemoryPool(size int) *SecureMemoryPool {
	pool := &SecureMemoryPool{
		buffers:  make(chan *SecureBuffer, size),
		size:     size,
		bufSize:  4096, // 4KB default buffer size
		clearTicker: time.NewTicker(1 * time.Second),
		stopChan: make(chan struct{}),
	}

	// Pre-allocate buffers
	for i := 0; i < size; i++ {
		buf := &SecureBuffer{
			data: make([]byte, pool.bufSize),
		}
		// Lock memory page
		if err := lockMemory(buf.data); err == nil {
			buf.locked = true
		}
		pool.buffers <- buf
	}

	// Start cleaner goroutine
	go pool.cleaner()

	return pool
}

// Get retrieves a secure buffer from the pool
func (p *SecureMemoryPool) Get() *SecureBuffer {
	select {
	case buf := <-p.buffers:
		buf.lastUsed = time.Now()
		return buf
	default:
		// Pool exhausted, create new buffer
		buf := &SecureBuffer{
			data:     make([]byte, p.bufSize),
			lastUsed: time.Now(),
		}
		if err := lockMemory(buf.data); err == nil {
			buf.locked = true
		}
		return buf
	}
}

// Put returns a secure buffer to the pool
func (p *SecureMemoryPool) Put(buf *SecureBuffer) {
	// Clear buffer before returning to pool
	clearBytes(buf.data)
	
	select {
	case p.buffers <- buf:
		// Buffer returned to pool
	default:
		// Pool full, release buffer
		if buf.locked {
			unlockMemory(buf.data)
		}
	}
}

// Clear clears all buffers in the pool
func (p *SecureMemoryPool) Clear() {
	p.mu.Lock()
	defer p.mu.Unlock()

	close(p.stopChan)
	
	// Clear all buffers
	for {
		select {
		case buf := <-p.buffers:
			clearBytes(buf.data)
			if buf.locked {
				unlockMemory(buf.data)
			}
		default:
			return
		}
	}
}

// cleaner periodically clears unused buffers
func (p *SecureMemoryPool) cleaner() {
	for {
		select {
		case <-p.clearTicker.C:
			p.cleanUnusedBuffers()
		case <-p.stopChan:
			p.clearTicker.Stop()
			return
		}
	}
}

// cleanUnusedBuffers clears buffers that haven't been used recently
func (p *SecureMemoryPool) cleanUnusedBuffers() {
	threshold := time.Now().Add(-5 * time.Minute)
	
	// Check and clear old buffers
	buffers := make([]*SecureBuffer, 0)
	
	// Drain channel
	for {
		select {
		case buf := <-p.buffers:
			if buf.lastUsed.Before(threshold) {
				clearBytes(buf.data)
			}
			buffers = append(buffers, buf)
		default:
			goto done
		}
	}
	
done:
	// Put buffers back
	for _, buf := range buffers {
		select {
		case p.buffers <- buf:
		default:
			if buf.locked {
				unlockMemory(buf.data)
			}
		}
	}
}

// clearBytes securely clears a byte slice
func clearBytes(b []byte) {
	if len(b) == 0 {
		return
	}
	
	// First pass: overwrite with random data
	rand.Read(b)
	
	// Second pass: overwrite with zeros
	for i := range b {
		b[i] = 0
	}
	
	// Third pass: overwrite with ones
	for i := range b {
		b[i] = 0xFF
	}
	
	// Final pass: overwrite with zeros
	for i := range b {
		b[i] = 0
	}
	
	// Force memory barrier
	runtime.KeepAlive(b)
}

// Platform-specific memory locking functions

// lockMemory locks a memory page (platform-specific implementation)
func lockMemory(b []byte) error {
	// This is a simplified version - production code would need proper platform checks
	if len(b) == 0 {
		return nil
	}
	
	// Get page-aligned address
	ptr := uintptr(unsafe.Pointer(&b[0]))
	pageSize := uintptr(syscall.Getpagesize())
	start := ptr &^ (pageSize - 1)
	length := ((ptr + uintptr(len(b)) - start) + pageSize - 1) &^ (pageSize - 1)
	
	// Try to lock memory (Unix-specific)
	_, _, errno := syscall.Syscall(syscall.SYS_MLOCK, start, length, 0)
	if errno != 0 {
		return errno
	}
	
	return nil
}

// unlockMemory unlocks a memory page
func unlockMemory(b []byte) error {
	if len(b) == 0 {
		return nil
	}
	
	// Get page-aligned address
	ptr := uintptr(unsafe.Pointer(&b[0]))
	pageSize := uintptr(syscall.Getpagesize())
	start := ptr &^ (pageSize - 1)
	length := ((ptr + uintptr(len(b)) - start) + pageSize - 1) &^ (pageSize - 1)
	
	// Try to unlock memory (Unix-specific)
	_, _, errno := syscall.Syscall(syscall.SYS_MUNLOCK, start, length, 0)
	if errno != 0 {
		return errno
	}
	
	return nil
}

// TimedClear clears data after a specified duration
type TimedClear struct {
	mu      sync.Mutex
	timers  map[string]*time.Timer
}

// NewTimedClear creates a new timed clear manager
func NewTimedClear() *TimedClear {
	return &TimedClear{
		timers: make(map[string]*time.Timer),
	}
}

// Schedule schedules data to be cleared after duration
func (tc *TimedClear) Schedule(id string, data []byte, duration time.Duration) {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	// Cancel existing timer if any
	if timer, exists := tc.timers[id]; exists {
		timer.Stop()
	}

	// Create new timer
	timer := time.AfterFunc(duration, func() {
		clearBytes(data)
		tc.mu.Lock()
		delete(tc.timers, id)
		tc.mu.Unlock()
	})

	tc.timers[id] = timer
}

// Cancel cancels a scheduled clear
func (tc *TimedClear) Cancel(id string) {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	if timer, exists := tc.timers[id]; exists {
		timer.Stop()
		delete(tc.timers, id)
	}
}

// ClearAll clears all scheduled timers
func (tc *TimedClear) ClearAll() {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	for id, timer := range tc.timers {
		timer.Stop()
		delete(tc.timers, id)
	}
}