package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"
)

// =============================================================================
// AEAD Authentication Tests
// =============================================================================
//
// SECURITY: These tests verify that AEAD (Authenticated Encryption with
// Associated Data) properly rejects tampered ciphertext.
//
// Per SHARD_INDISTINGUISHABILITY_PLAN.md:
// - Trial decryption relies on AEAD auth failure to identify wrong keys
// - If wrong key "succeeds" = false positive = security break
// - All tampering must result in authentication failure

// TestAEADAuthenticationFailure verifies AEAD rejects tampered ciphertext.
func TestAEADAuthenticationFailure(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}

	encryptor, err := NewAEADEncryptor(key)
	if err != nil {
		t.Fatalf("failed to create encryptor: %v", err)
	}

	plaintext := []byte("secret message for AEAD authentication test")
	ciphertext, err := encryptor.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	// Test 1: Valid decryption works
	decrypted, err := encryptor.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("valid decryption failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Error("decrypted data doesn't match plaintext")
	}

	// Test 2: Various tampering methods must fail
	testCases := []struct {
		name   string
		modify func([]byte) []byte
	}{
		{
			"flip first byte",
			func(c []byte) []byte {
				r := make([]byte, len(c))
				copy(r, c)
				r[0] ^= 0xFF
				return r
			},
		},
		{
			"flip last byte",
			func(c []byte) []byte {
				r := make([]byte, len(c))
				copy(r, c)
				r[len(r)-1] ^= 0xFF
				return r
			},
		},
		{
			"flip middle byte",
			func(c []byte) []byte {
				r := make([]byte, len(c))
				copy(r, c)
				r[len(r)/2] ^= 0xFF
				return r
			},
		},
		{
			"truncate one byte",
			func(c []byte) []byte {
				return c[:len(c)-1]
			},
		},
		{
			"truncate half",
			func(c []byte) []byte {
				return c[:len(c)/2]
			},
		},
		{
			"extend with zero",
			func(c []byte) []byte {
				return append(c, 0x00)
			},
		},
		{
			"extend with random",
			func(c []byte) []byte {
				extra := make([]byte, 16)
				rand.Read(extra)
				return append(c, extra...)
			},
		},
		{
			"all zeros same length",
			func(c []byte) []byte {
				return make([]byte, len(c))
			},
		},
		{
			"random data same length",
			func(c []byte) []byte {
				r := make([]byte, len(c))
				rand.Read(r)
				return r
			},
		},
		{
			"swap first and last byte",
			func(c []byte) []byte {
				r := make([]byte, len(c))
				copy(r, c)
				r[0], r[len(r)-1] = r[len(r)-1], r[0]
				return r
			},
		},
		{
			"bit flip in auth tag area",
			func(c []byte) []byte {
				r := make([]byte, len(c))
				copy(r, c)
				// Auth tag is last 16 bytes in ChaCha20-Poly1305
				if len(r) >= 16 {
					r[len(r)-8] ^= 0x01 // Single bit flip
				}
				return r
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tampered := tc.modify(ciphertext)
			_, err := encryptor.Decrypt(tampered)
			if err == nil {
				t.Errorf("SECURITY: tampered ciphertext (%s) was accepted", tc.name)
			}
		})
	}
}

// TestAEADWrongKeyRejection verifies wrong key is rejected.
//
// CRITICAL: This is the foundation of trial decryption security.
func TestAEADWrongKeyRejection(t *testing.T) {
	correctKey := make([]byte, 32)
	wrongKey := make([]byte, 32)
	for i := range correctKey {
		correctKey[i] = byte(i)
		wrongKey[i] = byte(255 - i)
	}

	// Encrypt with correct key
	encryptorCorrect, _ := NewAEADEncryptor(correctKey)
	plaintext := []byte("secret data encrypted with correct key")
	ciphertext, _ := encryptorCorrect.Encrypt(plaintext)

	// Try decrypt with wrong key
	encryptorWrong, _ := NewAEADEncryptor(wrongKey)
	_, err := encryptorWrong.Decrypt(ciphertext)
	if err == nil {
		t.Error("SECURITY: wrong key must not decrypt ciphertext")
	}
}

// TestAEADConstantTime verifies absence of timing side-channel.
//
// NOTE: This is a probabilistic test and may be flaky.
// It checks that rejection time doesn't vary based on where tampering occurs.
func TestAEADConstantTime(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping timing test in short mode")
	}

	key := make([]byte, 32)
	rand.Read(key)

	encryptor, _ := NewAEADEncryptor(key)

	plaintext := []byte("secret message for constant-time verification test")
	ciphertext, _ := encryptor.Encrypt(plaintext)

	// Create tampered versions
	tampered1 := make([]byte, len(ciphertext))
	copy(tampered1, ciphertext)
	tampered1[0] ^= 0xFF // First byte wrong

	tampered2 := make([]byte, len(ciphertext))
	copy(tampered2, ciphertext)
	tampered2[len(tampered2)-1] ^= 0xFF // Last byte wrong (in auth tag)

	// Measure timing
	const iterations = 2000

	measure := func(ct []byte) time.Duration {
		start := time.Now()
		for i := 0; i < iterations; i++ {
			encryptor.Decrypt(ct) // Ignore error, we expect failure
		}
		return time.Since(start)
	}

	time1 := measure(tampered1)
	time2 := measure(tampered2)

	// Calculate ratio
	var ratio float64
	if time2 > 0 {
		ratio = float64(time1) / float64(time2)
	}

	t.Logf("Timing: first-byte tamper=%v, last-byte tamper=%v, ratio=%.3f",
		time1, time2, ratio)

	// Ratio should be close to 1.0 (within 40%) to avoid flakiness.
	if ratio < 0.6 || ratio > 1.4 {
		t.Errorf("SECURITY: timing difference too large (ratio=%.3f) - possible side-channel", ratio)
	}
}

// TestAEADNonceUniqueness verifies nonce generation is unique.
func TestAEADNonceUniqueness(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	encryptor, _ := NewAEADEncryptor(key)

	plaintext := []byte("same plaintext encrypted multiple times")

	// Encrypt same plaintext multiple times
	const count = 1000
	ciphertexts := make([][]byte, count)

	for i := 0; i < count; i++ {
		ct, err := encryptor.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("encryption %d failed: %v", i, err)
		}
		ciphertexts[i] = ct
	}

	// Verify all ciphertexts are different (due to unique nonces)
	seen := make(map[string]bool)
	for i, ct := range ciphertexts {
		ctStr := string(ct)
		if seen[ctStr] {
			t.Errorf("ciphertext collision at index %d", i)
		}
		seen[ctStr] = true
	}
}

// TestAEADEmptyPlaintext verifies empty plaintext encryption works.
func TestAEADEmptyPlaintext(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	encryptor, _ := NewAEADEncryptor(key)

	// Empty plaintext
	plaintext := []byte{}
	ciphertext, err := encryptor.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encryption of empty plaintext failed: %v", err)
	}

	// Ciphertext should have at least nonce + auth tag
	minSize := 24 + 16 // XChaCha20 nonce + Poly1305 tag
	if len(ciphertext) < minSize {
		t.Errorf("ciphertext too short for empty plaintext: got %d, expected >= %d",
			len(ciphertext), minSize)
	}

	// Decryption should work
	decrypted, err := encryptor.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("decryption of empty plaintext failed: %v", err)
	}

	if len(decrypted) != 0 {
		t.Errorf("decrypted empty plaintext should be empty, got %d bytes", len(decrypted))
	}
}

// TestAEADLargePlaintext verifies large data encryption works.
func TestAEADLargePlaintext(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping large plaintext test in short mode")
	}

	key := make([]byte, 32)
	rand.Read(key)

	encryptor, _ := NewAEADEncryptor(key)

	// 1MB plaintext
	plaintext := make([]byte, 1024*1024)
	rand.Read(plaintext)

	ciphertext, err := encryptor.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("encryption of large plaintext failed: %v", err)
	}

	decrypted, err := encryptor.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("decryption of large plaintext failed: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Error("large plaintext decryption mismatch")
	}
}

// TestAEADKeyValidation verifies key size validation.
func TestAEADKeyValidation(t *testing.T) {
	testCases := []struct {
		name      string
		keySize   int
		expectErr bool
	}{
		{"valid 32-byte key", 32, false},
		{"too short 16-byte key", 16, true},
		{"too short 24-byte key", 24, true},
		{"too long 64-byte key", 64, true},
		{"empty key", 0, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			key := make([]byte, tc.keySize)
			_, err := NewAEADEncryptor(key)

			if tc.expectErr && err == nil {
				t.Error("expected error for invalid key size")
			}
			if !tc.expectErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

// TestAEADWithAssociatedData verifies additional authenticated data.
func TestAEADWithAssociatedData(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	encryptor, _ := NewAEADEncryptor(key)

	plaintext := []byte("secret message")
	aad := []byte("additional authenticated data - not encrypted but authenticated")

	// Encrypt with AAD
	ciphertext, err := encryptor.EncryptWithAAD(plaintext, aad)
	if err != nil {
		t.Fatalf("encryption with AAD failed: %v", err)
	}

	// Decrypt with correct AAD
	decrypted, err := encryptor.DecryptWithAAD(ciphertext, aad)
	if err != nil {
		t.Fatalf("decryption with correct AAD failed: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Error("decrypted data mismatch")
	}

	// Decrypt with wrong AAD must fail
	wrongAAD := []byte("wrong additional data")
	_, err = encryptor.DecryptWithAAD(ciphertext, wrongAAD)
	if err == nil {
		t.Error("SECURITY: decryption with wrong AAD should fail")
	}

	// Decrypt with no AAD must fail
	_, err = encryptor.DecryptWithAAD(ciphertext, nil)
	if err == nil {
		t.Error("SECURITY: decryption with missing AAD should fail")
	}
}

// TestAEADCiphertextIntegrity verifies ciphertext format.
func TestAEADCiphertextIntegrity(t *testing.T) {
	key := make([]byte, 32)
	rand.Read(key)

	encryptor, _ := NewAEADEncryptor(key)

	plaintext := []byte("test message")
	ciphertext, _ := encryptor.Encrypt(plaintext)

	// XChaCha20-Poly1305 format: nonce (24) + ciphertext + tag (16)
	expectedMinSize := 24 + len(plaintext) + 16
	if len(ciphertext) < expectedMinSize {
		t.Errorf("ciphertext too short: got %d, expected >= %d",
			len(ciphertext), expectedMinSize)
	}
}

// =============================================================================
// Required new type/methods
// =============================================================================
//
// type AEADEncryptor struct { ... }
//
// func NewAEADEncryptor(key []byte) (*AEADEncryptor, error)
// func (e *AEADEncryptor) Encrypt(plaintext []byte) ([]byte, error)
// func (e *AEADEncryptor) Decrypt(ciphertext []byte) ([]byte, error)
// func (e *AEADEncryptor) EncryptWithAAD(plaintext, aad []byte) ([]byte, error)
// func (e *AEADEncryptor) DecryptWithAAD(ciphertext, aad []byte) ([]byte, error)
