package crypto

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"testing"
)

func TestKeyStore_LoadOrGenerate_NewKey(t *testing.T) {
	tmpDir := t.TempDir()

	ks, err := NewKeyStore(tmpDir)
	if err != nil {
		t.Fatalf("NewKeyStore failed: %v", err)
	}

	// First call should generate new key
	key1, err := ks.LoadOrGenerate()
	if err != nil {
		t.Fatalf("LoadOrGenerate failed: %v", err)
	}
	defer ClearBytes(key1)

	if len(key1) != HKDFKeySize {
		t.Errorf("expected key size %d, got %d", HKDFKeySize, len(key1))
	}

	// Second call should load the same key
	key2, err := ks.LoadOrGenerate()
	if err != nil {
		t.Fatalf("LoadOrGenerate failed on second call: %v", err)
	}
	defer ClearBytes(key2)

	if !bytes.Equal(key1, key2) {
		t.Error("LoadOrGenerate should return same key on subsequent calls")
	}
}

func TestKeyStore_SaveAndLoad(t *testing.T) {
	tmpDir := t.TempDir()

	ks, err := NewKeyStore(tmpDir)
	if err != nil {
		t.Fatalf("NewKeyStore failed: %v", err)
	}

	// Generate test key
	originalKey := make([]byte, HKDFKeySize)
	if _, err := io.ReadFull(rand.Reader, originalKey); err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	// Save key
	if err := ks.Save(originalKey); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Load key
	loadedKey, err := ks.Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	defer ClearBytes(loadedKey)

	// Verify they match
	if !bytes.Equal(originalKey, loadedKey) {
		t.Error("Loaded key doesn't match saved key")
	}
}

func TestKeyStore_FilePermissions(t *testing.T) {
	tmpDir := t.TempDir()

	ks, err := NewKeyStore(tmpDir)
	if err != nil {
		t.Fatalf("NewKeyStore failed: %v", err)
	}

	// Generate and save key
	key := make([]byte, HKDFKeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	if err := ks.Save(key); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Check file permissions
	info, err := os.Stat(ks.Path())
	if err != nil {
		t.Fatalf("failed to stat key file: %v", err)
	}

	if info.Mode().Perm() != KeyFileMode {
		t.Errorf("expected permissions %o, got %o", KeyFileMode, info.Mode().Perm())
	}
}

func TestKeyStore_Delete(t *testing.T) {
	tmpDir := t.TempDir()

	ks, err := NewKeyStore(tmpDir)
	if err != nil {
		t.Fatalf("NewKeyStore failed: %v", err)
	}

	// Generate and save key
	key, err := ks.LoadOrGenerate()
	if err != nil {
		t.Fatalf("LoadOrGenerate failed: %v", err)
	}
	ClearBytes(key)

	// Verify key exists
	if !ks.Exists() {
		t.Fatal("Key should exist after LoadOrGenerate")
	}

	// Delete key
	if err := ks.Delete(); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Verify key doesn't exist
	if ks.Exists() {
		t.Error("Key should not exist after Delete")
	}

	// Load should fail
	_, err = ks.Load()
	if !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestKeyStore_InvalidKeySize(t *testing.T) {
	tmpDir := t.TempDir()

	ks, err := NewKeyStore(tmpDir)
	if err != nil {
		t.Fatalf("NewKeyStore failed: %v", err)
	}

	// Try to save invalid key
	invalidKey := make([]byte, 16) // Wrong size
	err = ks.Save(invalidKey)
	if !errors.Is(err, ErrInvalidKeySize) {
		t.Errorf("expected ErrInvalidKeySize, got %v", err)
	}
}

func TestKeyStore_KeyAlreadyExists(t *testing.T) {
	tmpDir := t.TempDir()

	ks, err := NewKeyStore(tmpDir)
	if err != nil {
		t.Fatalf("NewKeyStore failed: %v", err)
	}

	// Generate and save key
	key := make([]byte, HKDFKeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}

	if err := ks.Save(key); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Try to save again
	err = ks.Save(key)
	if !errors.Is(err, ErrKeyAlreadyExists) {
		t.Errorf("expected ErrKeyAlreadyExists, got %v", err)
	}
}

func TestKeyStore_LoadNotFound(t *testing.T) {
	tmpDir := t.TempDir()

	ks, err := NewKeyStore(tmpDir)
	if err != nil {
		t.Fatalf("NewKeyStore failed: %v", err)
	}

	// Try to load non-existent key
	_, err = ks.Load()
	if !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestKeyStore_Path(t *testing.T) {
	tmpDir := t.TempDir()

	ks, err := NewKeyStore(tmpDir)
	if err != nil {
		t.Fatalf("NewKeyStore failed: %v", err)
	}

	path := ks.Path()
	if path == "" {
		t.Error("Path should not be empty")
	}

	// Verify path contains the key filename
	if !contains(path, KeyStoreFileName) {
		t.Errorf("Path should contain %s, got %s", KeyStoreFileName, path)
	}
}

func TestKeyStore_Exists(t *testing.T) {
	tmpDir := t.TempDir()

	ks, err := NewKeyStore(tmpDir)
	if err != nil {
		t.Fatalf("NewKeyStore failed: %v", err)
	}

	// Key should not exist initially
	if ks.Exists() {
		t.Error("Key should not exist initially")
	}

	// Generate key
	_, err = ks.LoadOrGenerate()
	if err != nil {
		t.Fatalf("LoadOrGenerate failed: %v", err)
	}

	// Key should exist now
	if !ks.Exists() {
		t.Error("Key should exist after LoadOrGenerate")
	}
}

func TestKeyStore_DirectoryCreation(t *testing.T) {
	tmpDir := t.TempDir()
	nonExistentDir := tmpDir + "/nested/path/that/does/not/exist"

	ks, err := NewKeyStore(nonExistentDir)
	if err != nil {
		t.Fatalf("NewKeyStore should create directory: %v", err)
	}

	// Verify directory was created
	info, err := os.Stat(nonExistentDir)
	if err != nil {
		t.Fatalf("directory should exist: %v", err)
	}

	if !info.IsDir() {
		t.Error("path should be a directory")
	}

	// Verify KeyStore works
	key, err := ks.LoadOrGenerate()
	if err != nil {
		t.Fatalf("LoadOrGenerate failed: %v", err)
	}
	defer ClearBytes(key)

	if len(key) != HKDFKeySize {
		t.Errorf("expected key size %d, got %d", HKDFKeySize, len(key))
	}
}

// Helper function
func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[len(s)-len(substr):] == substr ||
		   len(s) > len(substr) && findSubstring(s, substr)
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
