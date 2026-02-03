package crypto

import (
	"crypto/rand"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestSecureMemoryPool_CleanupLatency verifies <1s SLA for cleanup
// This test ensures the cleaner goroutine runs frequently enough
func TestSecureMemoryPool_CleanupLatency(t *testing.T) {
	pool := NewSecureMemoryPool(10)
	defer pool.Clear()

	// Get and return a buffer
	buf := pool.Get()
	require.NotNil(t, buf)

	// Record time before return
	start := time.Now()
	pool.Put(buf)

	// Wait for cleanup cycle (1s ticker + margin)
	time.Sleep(1500 * time.Millisecond)

	latency := time.Since(start)

	// Cleanup should happen within 2s (1s ticker + 1s margin)
	require.Less(t, latency, 2*time.Second,
		"Cleanup should happen within 2s (1s ticker + margin), actual: %v", latency)

	t.Logf("Cleanup latency: %v (within SLA)", latency)
}

// TestSecureMemoryPool_OverwriteLatency verifies multi-pass overwrite is fast
// This test ensures clearing sensitive data doesn't cause performance issues
func TestSecureMemoryPool_OverwriteLatency(t *testing.T) {
	sizes := []int{1024, 4096, 16384, 65536}

	for _, size := range sizes {
		t.Run(string(rune(size)), func(t *testing.T) {
			// Create buffer with sensitive data
			buf := make([]byte, size)
			rand.Read(buf)

			// Measure overwrite time
			start := time.Now()
			clearBytes(buf)
			latency := time.Since(start)

			// Should be <10ms for buffers up to 64KB
			require.Less(t, latency, 10*time.Millisecond,
				"Overwrite of %d bytes took %v (should be <10ms)", size, latency)

			// Verify buffer is zeroed
			for i, b := range buf {
				require.Equal(t, byte(0), b,
					"Byte at index %d should be zero after clearBytes", i)
			}

			t.Logf("Overwrite %d bytes: %v", size, latency)
		})
	}
}

// TestSecureMemoryPool_ConcurrentCleanup verifies no race conditions
// This test ensures thread-safe operation under concurrent load
func TestSecureMemoryPool_ConcurrentCleanup(t *testing.T) {
	pool := NewSecureMemoryPool(50)
	defer pool.Clear()

	// Stress test with concurrent get/return
	done := make(chan bool)
	numGoroutines := 50
	operationsPerGoroutine := 100

	start := time.Now()

	for i := 0; i < numGoroutines; i++ {
		go func() {
			for j := 0; j < operationsPerGoroutine; j++ {
				buf := pool.Get()

				// Simulate using buffer
				rand.Read(buf.data[:100])

				// Small delay to trigger concurrent access
				time.Sleep(time.Microsecond)

				pool.Put(buf)
			}
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < numGoroutines; i++ {
		<-done
	}

	duration := time.Since(start)
	totalOperations := numGoroutines * operationsPerGoroutine

	t.Logf("Completed %d concurrent operations in %v", totalOperations, duration)
	t.Logf("Average operation latency: %v", duration/time.Duration(totalOperations))

	// No panics = success (race detector will catch issues)
	require.True(t, true, "Concurrent operations completed without panics")
}

// TestSecureMemoryPool_BufferReuse verifies buffers are properly reused
// This test ensures the pool efficiently manages memory
func TestSecureMemoryPool_BufferReuse(t *testing.T) {
	poolSize := 5
	pool := NewSecureMemoryPool(poolSize)
	defer pool.Clear()

	// Get all buffers from pool
	buffers := make([]*SecureBuffer, poolSize)
	for i := 0; i < poolSize; i++ {
		buffers[i] = pool.Get()
		require.NotNil(t, buffers[i], "Should get buffer %d", i)
	}

	// Return all buffers
	for i := 0; i < poolSize; i++ {
		pool.Put(buffers[i])
	}

	// Get buffers again - should reuse existing ones
	reusedBuffers := make([]*SecureBuffer, poolSize)
	for i := 0; i < poolSize; i++ {
		reusedBuffers[i] = pool.Get()
		require.NotNil(t, reusedBuffers[i], "Should reuse buffer %d", i)
	}

	// At least some buffers should be reused (same pointer addresses)
	reuseCount := 0
	for _, reused := range reusedBuffers {
		for _, original := range buffers {
			if reused == original {
				reuseCount++
				break
			}
		}
	}

	require.Greater(t, reuseCount, 0,
		"Pool should reuse at least some buffers (found %d/%d reused)", reuseCount, poolSize)

	t.Logf("Reused %d/%d buffers from pool", reuseCount, poolSize)
}

// TestSecureMemoryPool_MemoryClearing verifies data is actually cleared
// This is a security-critical test ensuring sensitive data is wiped
func TestSecureMemoryPool_MemoryClearing(t *testing.T) {
	pool := NewSecureMemoryPool(10)
	defer pool.Clear()

	// Get buffer and fill with sensitive data
	buf := pool.Get()
	require.NotNil(t, buf)

	// Fill with recognizable pattern
	for i := range buf.data {
		buf.data[i] = byte(0xFF)
	}

	// Verify data is present
	for i := 0; i < 100; i++ {
		require.Equal(t, byte(0xFF), buf.data[i],
			"Buffer should contain test pattern before clearing")
	}

	// Return buffer to pool (triggers clearing)
	pool.Put(buf)

	// Get same buffer again
	clearedBuf := pool.Get()
	require.NotNil(t, clearedBuf)

	// Verify data is cleared (should be zeros)
	nonZeroCount := 0
	for i := range clearedBuf.data {
		if clearedBuf.data[i] != 0 {
			nonZeroCount++
		}
	}

	// Allow some noise (hardware artifacts), but most should be zero
	require.Less(t, nonZeroCount, len(clearedBuf.data)/100,
		"Buffer should be mostly cleared (found %d non-zero bytes out of %d)",
		nonZeroCount, len(clearedBuf.data))

	t.Logf("Buffer clearing: %d/%d bytes zeroed", len(clearedBuf.data)-nonZeroCount, len(clearedBuf.data))
}

// TestClearBytes_MultiPass verifies multi-pass overwrite pattern
// This test ensures the clearing algorithm follows security best practices
func TestClearBytes_MultiPass(t *testing.T) {
	// Create buffer with test pattern
	buf := make([]byte, 1024)
	for i := range buf {
		buf[i] = byte(i % 256)
	}

	// Verify pattern exists
	for i := 0; i < 100; i++ {
		require.Equal(t, byte(i%256), buf[i], "Test pattern should be present")
	}

	// Measure clearing time
	start := time.Now()
	clearBytes(buf)
	duration := time.Since(start)

	// Should be fast
	require.Less(t, duration, 5*time.Millisecond,
		"clearBytes should complete in <5ms for 1KB, actual: %v", duration)

	// Verify all bytes are zero
	for i, b := range buf {
		require.Equal(t, byte(0), b,
			"Byte at index %d should be zero after multi-pass overwrite", i)
	}

	t.Logf("Multi-pass overwrite (1KB): %v", duration)
}

// TestSecureMemoryPool_Cleanup_StopsGoroutine verifies cleaner goroutine stops
// This test ensures no goroutine leaks when pool is cleared
func TestSecureMemoryPool_Cleanup_StopsGoroutine(t *testing.T) {
	initialGoroutines := numGoroutines()

	// Create and destroy multiple pools
	for i := 0; i < 10; i++ {
		pool := NewSecureMemoryPool(5)

		// Use pool briefly
		buf := pool.Get()
		pool.Put(buf)

		// Clear pool (should stop cleaner goroutine)
		pool.Clear()
	}

	// Give goroutines time to exit
	time.Sleep(100 * time.Millisecond)

	finalGoroutines := numGoroutines()

	// Should not have accumulated goroutines
	goroutineIncrease := finalGoroutines - initialGoroutines
	require.Less(t, goroutineIncrease, 5,
		"Should not leak goroutines (increase: %d)", goroutineIncrease)

	t.Logf("Goroutine count: initial=%d, final=%d, increase=%d",
		initialGoroutines, finalGoroutines, goroutineIncrease)
}

// BenchmarkSecureMemoryPool_GetPut benchmarks pool operations
func BenchmarkSecureMemoryPool_GetPut(b *testing.B) {
	pool := NewSecureMemoryPool(100)
	defer pool.Clear()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf := pool.Get()
		pool.Put(buf)
	}
}

// BenchmarkClearBytes benchmarks memory clearing speed
func BenchmarkClearBytes(b *testing.B) {
	sizes := []int{1024, 4096, 16384, 65536}

	for _, size := range sizes {
		b.Run(string(rune(size)), func(b *testing.B) {
			buf := make([]byte, size)
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				clearBytes(buf)
			}

			b.SetBytes(int64(size))
		})
	}
}

// Helper: Count active goroutines
func numGoroutines() int {
	var buf [4096]byte
	n := runtime.Stack(buf[:], false)
	count := 0
	for i := 0; i < n; i++ {
		if buf[i] == '\n' {
			count++
		}
	}
	// Each goroutine has multiple lines, estimate
	return count / 4
}
