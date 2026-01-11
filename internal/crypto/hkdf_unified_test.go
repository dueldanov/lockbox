package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// Unified key derivation must be deterministic for the same inputs and
// distinct across bundle/position pairs.
func TestDeriveKeyForPositionDeterministic(t *testing.T) {
	masterKey := make([]byte, HKDFKeySize)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}

	salt := make([]byte, HKDFSaltSize)
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("failed to generate salt: %v", err)
	}

	hkdf, err := NewHKDFManagerWithSalt(masterKey, salt)
	if err != nil {
		t.Fatalf("failed to create HKDF manager: %v", err)
	}
	defer hkdf.Clear()

	key0, err := hkdf.DeriveKeyForPosition("bundle-1", 0)
	if err != nil {
		t.Fatalf("derive pos0: %v", err)
	}
	key1, err := hkdf.DeriveKeyForPosition("bundle-1", 1)
	if err != nil {
		t.Fatalf("derive pos1: %v", err)
	}
	if bytes.Equal(key0, key1) {
		t.Fatal("keys for different positions must differ")
	}

	keyOtherBundle, err := hkdf.DeriveKeyForPosition("bundle-2", 0)
	if err != nil {
		t.Fatalf("derive other bundle: %v", err)
	}
	if bytes.Equal(key0, keyOtherBundle) {
		t.Fatal("keys for different bundles must differ")
	}

	key0Again, err := hkdf.DeriveKeyForPosition("bundle-1", 0)
	if err != nil {
		t.Fatalf("derive pos0 again: %v", err)
	}
	if !bytes.Equal(key0, key0Again) {
		t.Fatal("same inputs must produce deterministic key")
	}
	if len(key0) != HKDFKeySize {
		t.Fatalf("key length = %d, want %d", len(key0), HKDFKeySize)
	}
}

// Salt must be persisted to recover keys after restart.
func TestSaltPersistenceRoundTrip(t *testing.T) {
	masterKey := make([]byte, HKDFKeySize)
	for i := range masterKey {
		masterKey[i] = byte(0xAA ^ i)
	}

	hkdf1, err := NewHKDFManager(masterKey)
	if err != nil {
		t.Fatalf("create hkdf1: %v", err)
	}
	key1, err := hkdf1.DeriveKeyForPosition("bundle", 5)
	if err != nil {
		t.Fatalf("derive with hkdf1: %v", err)
	}
	salt := hkdf1.GetSalt()
	hkdf1.Clear()

	hkdf2, err := NewHKDFManagerWithSalt(masterKey, salt)
	if err != nil {
		t.Fatalf("create hkdf2: %v", err)
	}
	defer hkdf2.Clear()
	key2, err := hkdf2.DeriveKeyForPosition("bundle", 5)
	if err != nil {
		t.Fatalf("derive with hkdf2: %v", err)
	}

	if !bytes.Equal(key1, key2) {
		t.Fatal("keys must match after salt round-trip")
	}
}

// Context used for derivation must not leak shard type information.
func TestContextDoesNotLeakType(t *testing.T) {
	hkdf := &HKDFManager{}
	ctx := hkdf.GetContextForPosition("bundle-xyz", 42)
	ctxStr := string(ctx)

	forbidden := []string{"real", "Real", "decoy", "Decoy", "char", "Char"}
	for _, f := range forbidden {
		if bytes.Contains(ctx, []byte(f)) {
			t.Fatalf("context leaks type marker %q: %s", f, ctxStr)
		}
	}
	if !bytes.HasPrefix(ctx, []byte("LockBox:shard:")) {
		t.Fatalf("context prefix mismatch: %s", ctxStr)
	}
	if !bytes.Contains(ctx, []byte(":42")) {
		t.Fatalf("context must include position: %s", ctxStr)
	}
}

// Concurrent derivation should not race or fail.
func TestConcurrentKeyDerivation(t *testing.T) {
	masterKey := make([]byte, HKDFKeySize)
	if _, err := rand.Read(masterKey); err != nil {
		t.Fatalf("master key: %v", err)
	}

	hkdf, err := NewHKDFManager(masterKey)
	if err != nil {
		t.Fatalf("create hkdf: %v", err)
	}
	defer hkdf.Clear()

	const goroutines = 16
	const iterations = 50
	errCh := make(chan error, goroutines)

	for g := 0; g < goroutines; g++ {
		go func(base uint32) {
			for i := 0; i < iterations; i++ {
				if _, err := hkdf.DeriveKeyForPosition("bundle", base+uint32(i)); err != nil {
					errCh <- err
					return
				}
			}
			errCh <- nil
		}(uint32(g * iterations))
	}

	for i := 0; i < goroutines; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("concurrent derivation error: %v", err)
		}
	}
}
