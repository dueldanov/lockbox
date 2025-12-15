package crypto

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"testing"
)

func TestNewHKDFManager_MasterKeyCopy(t *testing.T) {
	// Generate a unique master key
	masterKey := make([]byte, HKDFKeySize)
	if _, err := io.ReadFull(rand.Reader, masterKey); err != nil {
		t.Fatalf("failed to generate master key: %v", err)
	}

	// Create manager
	manager, err := NewHKDFManager(masterKey)
	if err != nil {
		t.Fatalf("NewHKDFManager failed: %v", err)
	}
	defer manager.Clear()

	// Verify master key was copied (not all zeros)
	allZeros := true
	for _, b := range manager.masterKey {
		if b != 0 {
			allZeros = false
			break
		}
	}

	if allZeros {
		t.Error("Master key was not copied - all zeros detected")
	}

	// Verify key is actually the same
	if !bytes.Equal(manager.masterKey, masterKey) {
		t.Error("Master key was not copied correctly")
	}
}

func TestNewHKDFManager_InvalidKeySize(t *testing.T) {
	tests := []struct {
		name    string
		keySize int
	}{
		{"too short", 16},
		{"too long", 64},
		{"empty", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := make([]byte, tt.keySize)
			_, err := NewHKDFManager(key)
			if !errors.Is(err, ErrInvalidKeySize) {
				t.Errorf("expected ErrInvalidKeySize, got %v", err)
			}
		})
	}
}

func TestDeriveKey_ProducesUniqueKeys(t *testing.T) {
	masterKey := make([]byte, HKDFKeySize)
	if _, err := io.ReadFull(rand.Reader, masterKey); err != nil {
		t.Fatalf("failed to generate master key: %v", err)
	}

	manager, err := NewHKDFManager(masterKey)
	if err != nil {
		t.Fatalf("NewHKDFManager failed: %v", err)
	}
	defer manager.Clear()

	// Derive keys with different contexts
	key1, err := manager.DeriveKey([]byte("context1"))
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}

	key2, err := manager.DeriveKey([]byte("context2"))
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}

	// Keys should be different
	if bytes.Equal(key1, key2) {
		t.Error("Derived keys should be unique for different contexts")
	}

	// Keys should be deterministic
	key1Again, err := manager.DeriveKey([]byte("context1"))
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}

	if !bytes.Equal(key1, key1Again) {
		t.Error("Key derivation should be deterministic")
	}
}

func TestHKDFManager_Clear(t *testing.T) {
	masterKey := make([]byte, HKDFKeySize)
	if _, err := io.ReadFull(rand.Reader, masterKey); err != nil {
		t.Fatalf("failed to generate master key: %v", err)
	}

	manager, err := NewHKDFManager(masterKey)
	if err != nil {
		t.Fatalf("NewHKDFManager failed: %v", err)
	}

	// Verify key is not zeros before clear
	allZeros := true
	for _, b := range manager.masterKey {
		if b != 0 {
			allZeros = false
			break
		}
	}
	if allZeros {
		t.Error("Key should not be all zeros before Clear")
	}

	// Clear the manager
	manager.Clear()

	// Verify key is zeros after clear
	allZeros = true
	for _, b := range manager.masterKey {
		if b != 0 {
			allZeros = false
			break
		}
	}
	if !allZeros {
		t.Error("Key should be all zeros after Clear")
	}
}
