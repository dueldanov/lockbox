package lockscript

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"math"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

// ============================================
// CRITICAL: VM Integer Overflow Tests (CRIT-002)
// These tests MUST FAIL until overflow checks are added
// ============================================

// TestVM_IntegerOverflow_Add tests that OpAdd detects overflow.
// SECURITY: Without overflow checks, attackers can cause wraparound
// to bypass time-based conditions.
func TestVM_IntegerOverflow_Add(t *testing.T) {
	vm := NewVirtualMachine()
	ctx := context.Background()
	env := &Environment{Variables: make(map[string]interface{})}

	// Test: MaxInt64 + 1 should error, not wrap to MinInt64
	// Bytecode: PUSH MaxInt64, PUSH 1, ADD
	maxInt64 := int64(math.MaxInt64)

	bytecode := make([]byte, 0)

	// PUSH MaxInt64
	bytecode = append(bytecode, byte(OpPush))
	for i := 7; i >= 0; i-- {
		bytecode = append(bytecode, byte(maxInt64>>(i*8)))
	}

	// PUSH 1
	bytecode = append(bytecode, byte(OpPush))
	for i := 7; i >= 0; i-- {
		bytecode = append(bytecode, byte(1>>(i*8)))
	}

	// ADD
	bytecode = append(bytecode, byte(OpAdd))

	// Execute - this SHOULD return an error for overflow
	result, err := vm.Execute(ctx, bytecode, env)

	// SECURITY: If no error, the VM is vulnerable to overflow attacks!
	// The result would wrap around to a negative number.
	if err == nil {
		// Check if overflow occurred (result wrapped to negative)
		if resultVal, ok := result.Value.(int64); ok {
			if resultVal < 0 {
				t.Fatalf("SECURITY VULNERABILITY: Integer overflow not detected! "+
					"MaxInt64 + 1 = %d (wrapped to negative). "+
					"Attacker can bypass time-locks!", resultVal)
			}
		}
	}

	// If we reach here with no error and positive result, something is wrong
	require.Error(t, err, "SECURITY: OpAdd MUST return error on overflow")
}

// TestVM_IntegerOverflow_Mul tests that OpMul detects overflow.
// SECURITY: Multiplication overflow is even more dangerous as it can
// produce arbitrary results including zero or negative numbers.
func TestVM_IntegerOverflow_Mul(t *testing.T) {
	vm := NewVirtualMachine()
	ctx := context.Background()
	env := &Environment{Variables: make(map[string]interface{})}

	// Test: Large number * 2 should overflow
	largeNum := int64(math.MaxInt64 / 2)

	bytecode := make([]byte, 0)

	// PUSH large number
	bytecode = append(bytecode, byte(OpPush))
	for i := 7; i >= 0; i-- {
		bytecode = append(bytecode, byte(largeNum>>(i*8)))
	}

	// PUSH 3 (will definitely overflow)
	bytecode = append(bytecode, byte(OpPush))
	for i := 7; i >= 0; i-- {
		bytecode = append(bytecode, byte(3>>(i*8)))
	}

	// MUL
	bytecode = append(bytecode, byte(OpMul))

	result, err := vm.Execute(ctx, bytecode, env)

	if err == nil {
		if resultVal, ok := result.Value.(int64); ok {
			// Check if result is wrong (overflow occurred silently)
			expected := largeNum * 3 // This will overflow
			if resultVal != expected || resultVal < largeNum {
				t.Fatalf("SECURITY VULNERABILITY: Integer overflow in multiplication! "+
					"%d * 3 = %d (should be ~%d or error). "+
					"Attacker can manipulate arithmetic results!", largeNum, resultVal, expected)
			}
		}
	}

	require.Error(t, err, "SECURITY: OpMul MUST return error on overflow")
}

// TestVM_TimeLockBypass_ViaOverflow demonstrates how overflow can bypass time-locks.
// This is a CRITICAL security test.
func TestVM_TimeLockBypass_ViaOverflow(t *testing.T) {
	vm := NewVirtualMachine()
	ctx := context.Background()

	// Scenario: Asset locked until year 2033
	unlockTime := int64(2000000000) // Unix timestamp ~2033

	env := &Environment{
		Variables: map[string]interface{}{
			"var_0": unlockTime,
		},
	}

	// Malicious script trying to bypass:
	// Instead of checking: current_time >= unlock_time
	// Attacker tries: (unlock_time * HUGE) > 0
	// If overflow wraps to negative, comparison may fail
	// If overflow wraps to positive, comparison succeeds incorrectly

	bytecode := make([]byte, 0)

	// LOAD unlock_time (var_0)
	bytecode = append(bytecode, byte(OpLoad), 0)

	// PUSH huge multiplier
	hugeMultiplier := int64(math.MaxInt64)
	bytecode = append(bytecode, byte(OpPush))
	for i := 7; i >= 0; i-- {
		bytecode = append(bytecode, byte(hugeMultiplier>>(i*8)))
	}

	// MUL - this will overflow
	bytecode = append(bytecode, byte(OpMul))

	// PUSH 0
	bytecode = append(bytecode, byte(OpPush))
	for i := 0; i < 8; i++ {
		bytecode = append(bytecode, 0)
	}

	// GT (check if result > 0)
	bytecode = append(bytecode, byte(OpGt))

	result, err := vm.Execute(ctx, bytecode, env)

	// If no error and result is true, time-lock was bypassed!
	if err == nil && result != nil {
		if success, ok := result.Value.(bool); ok && success {
			t.Fatalf("CRITICAL SECURITY VULNERABILITY: Time-lock bypassed via integer overflow! "+
				"Attacker can unlock assets before unlock_time by exploiting arithmetic overflow.")
		}
	}

	// The secure behavior is to either:
	// 1. Return an error on overflow
	// 2. Return false (fail-safe)
	if err == nil {
		t.Logf("Warning: No error on overflow, but result was false (fail-safe)")
	}
}

// ============================================
// MEDIUM: Stack Underflow Tests (MED-008)
// ============================================

// TestVM_StackUnderflow_ReturnsError tests that stack underflow returns error.
// SECURITY: Returning nil on underflow can lead to unexpected behavior
// where nil is converted to 0 or false, potentially bypassing checks.
func TestVM_StackUnderflow_ReturnsError(t *testing.T) {
	vm := NewVirtualMachine()
	ctx := context.Background()
	env := &Environment{Variables: make(map[string]interface{})}

	// Try to ADD with empty stack
	bytecode := []byte{byte(OpAdd)}

	_, err := vm.Execute(ctx, bytecode, env)

	// SECURITY: Stack underflow MUST return an error, not nil values
	require.Error(t, err, "SECURITY: Stack underflow MUST return error, not nil")
}

// TestVM_StackUnderflow_NilToZero verifies that popInt returns an error on empty stack (FIXED).
// Previously this tested for a panic; now popInt returns (int64, error) for crash resilience.
func TestVM_StackUnderflow_NilToZero(t *testing.T) {
	vm := NewVirtualMachine()

	// SECURITY FIX: popInt must return error on empty stack, not 0
	_, err := vm.popInt()
	require.Error(t, err, "SECURITY: popInt must return error on empty stack")
	require.Contains(t, err.Error(), "SECURITY ERROR",
		"Error message must indicate security violation")

	t.Logf("SECURITY FIX VERIFIED: popInt correctly returns error on empty stack: %v", err)
}

// ============================================
// HIGH: Multi-Sig with Real Crypto Tests (HIGH-008)
// These tests verify that require_sigs actually verifies signatures
// ============================================

// TestRequireSigs_RejectsEmptySignatures tests that empty signatures are rejected.
func TestRequireSigs_RejectsEmptySignatures(t *testing.T) {
	// Generate real keypairs
	pub1, _, _ := ed25519.GenerateKey(rand.Reader)
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)

	pubKeys := []interface{}{
		hex.EncodeToString(pub1),
		hex.EncodeToString(pub2),
	}

	message := "test-asset-id"

	// Empty signatures
	signatures := []interface{}{"", ""}

	result, err := funcRequireSigs([]interface{}{
		pubKeys,
		message,
		signatures,
		int64(2), // require 2 signatures
	})

	require.NoError(t, err)
	require.False(t, result.(bool), "SECURITY: Empty signatures MUST be rejected")
}

// TestRequireSigs_RejectsFakeSignatures tests that fake signatures are rejected.
// CRITICAL: This is the most important multi-sig security test.
func TestRequireSigs_RejectsFakeSignatures(t *testing.T) {
	// Generate real keypairs
	pub1, priv1, _ := ed25519.GenerateKey(rand.Reader)
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)

	pubKeys := []interface{}{
		hex.EncodeToString(pub1),
		hex.EncodeToString(pub2),
	}

	message := "test-asset-id"

	// One real signature, one FAKE
	realSig := ed25519.Sign(priv1, []byte(message))
	fakeSig := make([]byte, 64) // All zeros - fake signature
	rand.Read(fakeSig)          // Random bytes - still fake

	signatures := []interface{}{
		hex.EncodeToString(realSig),
		hex.EncodeToString(fakeSig), // FAKE!
	}

	result, err := funcRequireSigs([]interface{}{
		pubKeys,
		message,
		signatures,
		int64(2), // require 2 signatures
	})

	require.NoError(t, err)
	require.False(t, result.(bool),
		"CRITICAL SECURITY: Fake signature MUST be rejected! "+
			"If this passes, multi-sig is broken and attacker can forge signatures.")
}

// TestRequireSigs_RejectsWrongKeySignature tests signature from wrong key is rejected.
func TestRequireSigs_RejectsWrongKeySignature(t *testing.T) {
	// Generate 3 keypairs
	pub1, _, _ := ed25519.GenerateKey(rand.Reader)
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	_, priv3, _ := ed25519.GenerateKey(rand.Reader) // Attacker's key

	pubKeys := []interface{}{
		hex.EncodeToString(pub1),
		hex.EncodeToString(pub2),
	}

	message := "test-asset-id"

	// Sign with attacker's key (priv3), not pub1 or pub2
	wrongKeySig1 := ed25519.Sign(priv3, []byte(message))
	wrongKeySig2 := ed25519.Sign(priv3, []byte(message))

	signatures := []interface{}{
		hex.EncodeToString(wrongKeySig1),
		hex.EncodeToString(wrongKeySig2),
	}

	result, err := funcRequireSigs([]interface{}{
		pubKeys,
		message,
		signatures,
		int64(2),
	})

	require.NoError(t, err)
	require.False(t, result.(bool),
		"SECURITY: Signatures from wrong keys MUST be rejected!")
}

// TestRequireSigs_RejectsReplayAttack tests that signatures for wrong message are rejected.
func TestRequireSigs_RejectsReplayAttack(t *testing.T) {
	// Generate keypairs
	pub1, priv1, _ := ed25519.GenerateKey(rand.Reader)
	pub2, priv2, _ := ed25519.GenerateKey(rand.Reader)

	pubKeys := []interface{}{
		hex.EncodeToString(pub1),
		hex.EncodeToString(pub2),
	}

	// Sign for asset A
	originalMessage := "asset-A"
	sig1 := ed25519.Sign(priv1, []byte(originalMessage))
	sig2 := ed25519.Sign(priv2, []byte(originalMessage))

	// Try to use signatures for asset B (replay attack)
	attackMessage := "asset-B"

	signatures := []interface{}{
		hex.EncodeToString(sig1),
		hex.EncodeToString(sig2),
	}

	result, err := funcRequireSigs([]interface{}{
		pubKeys,
		attackMessage, // Different message!
		signatures,
		int64(2),
	})

	require.NoError(t, err)
	require.False(t, result.(bool),
		"SECURITY: Replay attack MUST be rejected! "+
			"Signatures for asset-A cannot unlock asset-B.")
}

// TestRequireSigs_ValidSignaturesPass ensures valid signatures work.
func TestRequireSigs_ValidSignaturesPass(t *testing.T) {
	// Generate keypairs
	pub1, priv1, _ := ed25519.GenerateKey(rand.Reader)
	pub2, priv2, _ := ed25519.GenerateKey(rand.Reader)

	pubKeys := []interface{}{
		hex.EncodeToString(pub1),
		hex.EncodeToString(pub2),
	}

	message := "test-asset-id"

	// Both valid signatures
	sig1 := ed25519.Sign(priv1, []byte(message))
	sig2 := ed25519.Sign(priv2, []byte(message))

	signatures := []interface{}{
		hex.EncodeToString(sig1),
		hex.EncodeToString(sig2),
	}

	result, err := funcRequireSigs([]interface{}{
		pubKeys,
		message,
		signatures,
		int64(2),
	})

	require.NoError(t, err)
	require.True(t, result.(bool),
		"Valid signatures should be accepted")
}

// TestRequireSigs_ThresholdEnforced tests that threshold is actually enforced.
func TestRequireSigs_ThresholdEnforced(t *testing.T) {
	// Generate 3 keypairs for 2-of-3 multisig
	pub1, priv1, _ := ed25519.GenerateKey(rand.Reader)
	pub2, _, _ := ed25519.GenerateKey(rand.Reader) // No signature from this
	pub3, _, _ := ed25519.GenerateKey(rand.Reader) // No signature from this

	pubKeys := []interface{}{
		hex.EncodeToString(pub1),
		hex.EncodeToString(pub2),
		hex.EncodeToString(pub3),
	}

	message := "test-asset-id"

	// Only 1 valid signature, need 2
	sig1 := ed25519.Sign(priv1, []byte(message))

	signatures := []interface{}{
		hex.EncodeToString(sig1),
		"", // Missing
		"", // Missing
	}

	result, err := funcRequireSigs([]interface{}{
		pubKeys,
		message,
		signatures,
		int64(2), // Require 2
	})

	require.NoError(t, err)
	require.False(t, result.(bool),
		"SECURITY: 1-of-3 should NOT pass when 2-of-3 required!")
}

// ============================================
// HIGH: Concurrent Access Tests
// ============================================

// TestVM_ConcurrentExecution tests VM is safe under concurrent use.
func TestVM_ConcurrentExecution(t *testing.T) {
	var wg sync.WaitGroup
	errors := make(chan error, 100)
	successCount := atomic.Int32{}

	// Simple bytecode: PUSH 1, PUSH 2, ADD
	bytecode := []byte{
		byte(OpPush), 0, 0, 0, 0, 0, 0, 0, 1, // PUSH 1
		byte(OpPush), 0, 0, 0, 0, 0, 0, 0, 2, // PUSH 2
		byte(OpAdd), // ADD
	}

	// Run 100 concurrent executions
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			vm := NewVirtualMachine() // Each goroutine gets its own VM
			ctx := context.Background()
			env := &Environment{Variables: make(map[string]interface{})}

			result, err := vm.Execute(ctx, bytecode, env)
			if err != nil {
				errors <- err
				return
			}

			// Verify result is correct
			if val, ok := result.Value.(int64); ok {
				if val == 3 {
					successCount.Add(1)
				} else {
					errors <- &vmError{msg: "wrong result"}
				}
			}
		}()
	}

	wg.Wait()
	close(errors)

	// Collect errors
	var errs []error
	for err := range errors {
		errs = append(errs, err)
	}

	require.Empty(t, errs, "Concurrent VM execution should not produce errors")
	require.Equal(t, int32(100), successCount.Load(),
		"All concurrent executions should succeed with correct result")
}

type vmError struct {
	msg string
}

func (e *vmError) Error() string {
	return e.msg
}
