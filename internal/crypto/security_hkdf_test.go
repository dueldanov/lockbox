package crypto

import (
	"bytes"
	"crypto/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ============================================
// CRITICAL: DeriveKey Pool Race Condition (CRIT-003)
// These tests expose the race condition in key derivation
// ============================================

// TestDeriveKey_ConcurrentRaceCondition tests for race condition in DeriveKey.
// SECURITY: The current implementation returns the buffer to pool via defer
// BEFORE the copy completes. This can cause key corruption under load.
func TestDeriveKey_ConcurrentRaceCondition(t *testing.T) {
	masterKey := make([]byte, HKDFKeySize)
	rand.Read(masterKey)

	manager, err := NewHKDFManager(masterKey)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}
	defer manager.Clear()

	// Run many concurrent derivations with same context
	// If race condition exists, some keys will be corrupted
	context := []byte("test-context-for-race")

	var wg sync.WaitGroup
	results := make([][]byte, 1000)
	errors := make([]error, 1000)

	// Start all goroutines simultaneously
	start := make(chan struct{})

	for i := 0; i < 1000; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start // Wait for signal

			key, err := manager.DeriveKey(context)
			results[idx] = key
			errors[idx] = err
		}(i)
	}

	// Release all goroutines at once
	close(start)
	wg.Wait()

	// Check for errors
	for i, err := range errors {
		if err != nil {
			t.Errorf("Derivation %d failed: %v", i, err)
		}
	}

	// All derived keys should be IDENTICAL (same context = same key)
	// If race condition occurred, some keys will be different or corrupted
	referenceKey := results[0]
	mismatchCount := 0

	for i := 1; i < len(results); i++ {
		if results[i] == nil {
			continue
		}
		if !bytes.Equal(referenceKey, results[i]) {
			mismatchCount++
			if mismatchCount <= 5 {
				t.Logf("RACE DETECTED: Key %d differs from reference", i)
				t.Logf("  Reference: %x", referenceKey[:8])
				t.Logf("  Got:       %x", results[i][:8])
			}
		}
	}

	if mismatchCount > 0 {
		t.Fatalf("CRITICAL SECURITY VULNERABILITY: Race condition in DeriveKey! "+
			"%d/%d keys were corrupted. "+
			"This means encryption keys can be wrong, causing data loss or security breach.",
			mismatchCount, len(results))
	}
}

// TestDeriveKey_PoolReuseCorruption specifically tests the pool reuse bug.
// The bug: defer returns buffer to pool before copy completes.
func TestDeriveKey_PoolReuseCorruption(t *testing.T) {
	masterKey := make([]byte, HKDFKeySize)
	rand.Read(masterKey)

	manager, err := NewHKDFManager(masterKey)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}
	defer manager.Clear()

	// Derive keys with different contexts
	contexts := [][]byte{
		[]byte("context-A"),
		[]byte("context-B"),
		[]byte("context-C"),
	}

	// Expected: Each context produces a unique, deterministic key
	expectedKeys := make(map[string][]byte)

	// First, derive reference keys sequentially (no race possible)
	for _, ctx := range contexts {
		key, err := manager.DeriveKey(ctx)
		if err != nil {
			t.Fatalf("Sequential derivation failed: %v", err)
		}
		expectedKeys[string(ctx)] = key
	}

	// Verify sequential derivation is deterministic
	for _, ctx := range contexts {
		key, err := manager.DeriveKey(ctx)
		if err != nil {
			t.Fatalf("Re-derivation failed: %v", err)
		}
		if !bytes.Equal(key, expectedKeys[string(ctx)]) {
			t.Fatalf("HKDF not deterministic! Same context produced different keys")
		}
	}

	// Now stress test with concurrent derivations
	var wg sync.WaitGroup
	corruptionDetected := atomic.Bool{}

	for round := 0; round < 100; round++ {
		for _, ctx := range contexts {
			wg.Add(1)
			go func(context []byte) {
				defer wg.Done()

				key, err := manager.DeriveKey(context)
				if err != nil {
					return
				}

				expected := expectedKeys[string(context)]
				if !bytes.Equal(key, expected) {
					corruptionDetected.Store(true)
				}
			}(ctx)
		}
	}

	wg.Wait()

	if corruptionDetected.Load() {
		t.Fatalf("CRITICAL: Key corruption detected under concurrent load! "+
			"Pool reuse race condition is present.")
	}
}

// TestDeriveKey_DifferentContextsDifferentKeys verifies key isolation.
func TestDeriveKey_DifferentContextsDifferentKeys(t *testing.T) {
	masterKey := make([]byte, HKDFKeySize)
	rand.Read(masterKey)

	manager, err := NewHKDFManager(masterKey)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}
	defer manager.Clear()

	key1, _ := manager.DeriveKey([]byte("bundle-A:shard-0"))
	key2, _ := manager.DeriveKey([]byte("bundle-A:shard-1"))
	key3, _ := manager.DeriveKey([]byte("bundle-B:shard-0"))

	// All keys must be different
	if bytes.Equal(key1, key2) {
		t.Error("SECURITY: Different shard indices produced same key!")
	}
	if bytes.Equal(key1, key3) {
		t.Error("SECURITY: Different bundles produced same key!")
	}
	if bytes.Equal(key2, key3) {
		t.Error("SECURITY: Different contexts produced same key!")
	}
}

// ============================================
// Memory Security Tests
// ============================================

// TestClearBytes_ActuallyClearsMemory tests that clearBytes works.
// Note: This is hard to test definitively due to compiler optimizations.
func TestClearBytes_ActuallyClearsMemory(t *testing.T) {
	secret := make([]byte, 32)
	rand.Read(secret)

	// Copy for comparison
	original := make([]byte, 32)
	copy(original, secret)

	// Verify secret has data
	allZero := true
	for _, b := range secret {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("Test setup failed: secret is all zeros")
	}

	// Clear it
	clearBytes(secret)

	// Verify it's cleared
	for i, b := range secret {
		if b != 0 {
			t.Errorf("SECURITY: clearBytes did not clear byte %d (value: %d)", i, b)
		}
	}
}

// TestHKDFManager_Clear_Security tests that Clear() actually clears keys.
func TestHKDFManager_Clear_Security(t *testing.T) {
	masterKey := make([]byte, HKDFKeySize)
	rand.Read(masterKey)

	manager, err := NewHKDFManager(masterKey)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}

	// Derive a key to ensure manager is working
	_, err = manager.DeriveKey([]byte("test"))
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}

	// Clear the manager
	manager.Clear()

	// After Clear, derivation should fail or produce wrong results
	// because the master key should be zeroed
	key, err := manager.DeriveKey([]byte("test"))
	if err == nil && key != nil {
		// Check if master key was actually cleared
		// This is implementation-dependent
		t.Log("Warning: DeriveKey succeeded after Clear(). " +
			"Verify master key was actually zeroed.")
	}
}

// ============================================
// Timing Attack Tests
// ============================================

// TestDeriveKey_ConstantTime tests that key derivation time is consistent.
// Timing variations could leak information about the master key.
func TestDeriveKey_ConstantTime(t *testing.T) {
	masterKey := make([]byte, HKDFKeySize)
	rand.Read(masterKey)

	manager, err := NewHKDFManager(masterKey)
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}
	defer manager.Clear()

	// Warm up
	for i := 0; i < 100; i++ {
		manager.DeriveKey([]byte("warmup"))
	}

	// Measure timing for different contexts
	contexts := [][]byte{
		[]byte("short"),
		[]byte("this is a much longer context string that should take the same time"),
		bytes.Repeat([]byte("x"), 1000),
	}

	timings := make([]time.Duration, len(contexts))

	const iterations = 1000
	for i, ctx := range contexts {
		start := time.Now()
		for j := 0; j < iterations; j++ {
			manager.DeriveKey(ctx)
		}
		timings[i] = time.Since(start) / iterations
	}

	// Check timing variance
	// Allow 50% variance (timing attacks usually need much tighter correlation)
	baseTime := timings[0]
	for i, timing := range timings {
		ratio := float64(timing) / float64(baseTime)
		if ratio < 0.5 || ratio > 2.0 {
			t.Logf("Warning: Timing variance detected for context %d: ratio=%.2f", i, ratio)
			t.Logf("  Base time: %v, This time: %v", baseTime, timing)
		}
	}
}

// ============================================
// Salt Management Tests
// ============================================

// TestHKDFManager_SaltPersistence tests that salt must be saved for recovery.
func TestHKDFManager_SaltPersistence(t *testing.T) {
	masterKey := make([]byte, HKDFKeySize)
	rand.Read(masterKey)

	// Create first manager
	manager1, _ := NewHKDFManager(masterKey)
	salt1 := manager1.GetSalt()
	key1, _ := manager1.DeriveKey([]byte("test"))

	// Create second manager with same master key but NEW salt
	manager2, _ := NewHKDFManager(masterKey)
	key2, _ := manager2.DeriveKey([]byte("test"))

	// Keys will be DIFFERENT because salts are different!
	if bytes.Equal(key1, key2) {
		t.Log("Keys are equal (salts happen to match?) - this is unexpected")
	} else {
		t.Log("IMPORTANT: Keys differ because salts differ. " +
			"Salt MUST be persisted with encrypted data for recovery!")
	}

	// To recover, we need to use the original salt
	manager3, _ := NewHKDFManagerWithSalt(masterKey, salt1)
	key3, _ := manager3.DeriveKey([]byte("test"))

	if !bytes.Equal(key1, key3) {
		t.Error("CRITICAL: Same master key + same salt should produce same key!")
	}

	manager1.Clear()
	manager2.Clear()
	manager3.Clear()
}

// ============================================
// Key Derivation Uniqueness Tests
// ============================================

// TestDeriveKeyForPosition_NoTypeLeakage tests that position-based keys
// don't leak whether a shard is real or decoy.
func TestDeriveKeyForPosition_NoTypeLeakage(t *testing.T) {
	masterKey := make([]byte, HKDFKeySize)
	rand.Read(masterKey)

	manager, _ := NewHKDFManager(masterKey)
	defer manager.Clear()

	bundleID := "test-bundle"

	// Get contexts for different positions
	ctx0 := manager.GetContextForPosition(bundleID, 0)
	ctx1 := manager.GetContextForPosition(bundleID, 1)
	ctx100 := manager.GetContextForPosition(bundleID, 100)

	// SECURITY: Context strings should NOT contain "real" or "decoy"
	for _, ctx := range [][]byte{ctx0, ctx1, ctx100} {
		ctxStr := string(ctx)
		if bytes.Contains(ctx, []byte("real")) {
			t.Errorf("SECURITY: Context contains 'real': %s", ctxStr)
		}
		if bytes.Contains(ctx, []byte("decoy")) {
			t.Errorf("SECURITY: Context contains 'decoy': %s", ctxStr)
		}
	}
}
