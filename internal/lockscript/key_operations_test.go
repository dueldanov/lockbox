package lockscript

import (
	"encoding/hex"
	"testing"

	"github.com/dueldanov/lockbox/v2/internal/crypto"
)

func TestStoreKey_Success(t *testing.T) {
	// Reset global manager for clean test
	ResetGlobalKeyManager()

	testCases := []struct {
		name string
		key  string
		tier SecurityTier
	}{
		{"Basic tier", "my-secret-key", TierBasic},
		{"Standard tier", "another-secret", TierStandard},
		{"Premium tier", "premium-secret-key-data", TierPremium},
		{"Elite tier", "elite-super-secret-key", TierElite},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			bundleID, token, err := globalKeyManager.StoreKey([]byte(tc.key), tc.tier)
			if err != nil {
				t.Fatalf("StoreKey failed: %v", err)
			}

			if bundleID == "" {
				t.Error("Expected non-empty bundleID")
			}
			if token == "" {
				t.Error("Expected non-empty token")
			}

			// Verify bundleID is valid hex (16 bytes = 32 hex chars)
			if len(bundleID) != 32 {
				t.Errorf("Expected bundleID length 32, got %d", len(bundleID))
			}

			// Verify token is valid hex (32 bytes = 64 hex chars)
			if len(token) != 64 {
				t.Errorf("Expected token length 64, got %d", len(token))
			}
		})
	}
}

func TestStoreKey_InvalidTier(t *testing.T) {
	ResetGlobalKeyManager()

	_, _, err := globalKeyManager.StoreKey([]byte("test-key"), SecurityTier("InvalidTier"))
	if err != ErrInvalidTier {
		t.Errorf("Expected ErrInvalidTier, got %v", err)
	}
}

func TestGetKey_Success(t *testing.T) {
	ResetGlobalKeyManager()

	originalKey := "my-super-secret-key-12345"

	// Store the key
	bundleID, token, err := globalKeyManager.StoreKey([]byte(originalKey), TierStandard)
	if err != nil {
		t.Fatalf("StoreKey failed: %v", err)
	}

	// Retrieve the key
	retrievedKey, err := globalKeyManager.GetKey(bundleID, token)
	if err != nil {
		t.Fatalf("GetKey failed: %v", err)
	}

	if string(retrievedKey) != originalKey {
		t.Errorf("Retrieved key mismatch: expected %q, got %q", originalKey, string(retrievedKey))
	}
}

func TestGetKey_InvalidBundleID(t *testing.T) {
	ResetGlobalKeyManager()

	_, err := globalKeyManager.GetKey("nonexistent-bundle", "some-token")
	if err != ErrKeyNotFound {
		t.Errorf("Expected ErrKeyNotFound, got %v", err)
	}
}

func TestGetKey_InvalidToken(t *testing.T) {
	ResetGlobalKeyManager()

	bundleID, _, err := globalKeyManager.StoreKey([]byte("test-key"), TierBasic)
	if err != nil {
		t.Fatalf("StoreKey failed: %v", err)
	}

	_, err = globalKeyManager.GetKey(bundleID, "wrong-token")
	if err != ErrInvalidToken {
		t.Errorf("Expected ErrInvalidToken, got %v", err)
	}
}

func TestRotate_Success(t *testing.T) {
	ResetGlobalKeyManager()

	originalKey := "key-to-rotate"

	// Store the key
	oldBundleID, oldToken, err := globalKeyManager.StoreKey([]byte(originalKey), TierStandard)
	if err != nil {
		t.Fatalf("StoreKey failed: %v", err)
	}

	// Rotate the key
	newBundleID, newToken, err := globalKeyManager.RotateKey(oldBundleID, oldToken)
	if err != nil {
		t.Fatalf("RotateKey failed: %v", err)
	}

	// Verify new credentials are different
	if newBundleID == oldBundleID {
		t.Error("Expected different bundleID after rotation")
	}
	if newToken == oldToken {
		t.Error("Expected different token after rotation")
	}

	// Verify can retrieve with new credentials
	retrievedKey, err := globalKeyManager.GetKey(newBundleID, newToken)
	if err != nil {
		t.Fatalf("GetKey with new credentials failed: %v", err)
	}
	if string(retrievedKey) != originalKey {
		t.Errorf("Key content changed after rotation: expected %q, got %q", originalKey, string(retrievedKey))
	}

	// Verify old credentials no longer work
	_, err = globalKeyManager.GetKey(oldBundleID, oldToken)
	if err != ErrKeyNotFound {
		t.Errorf("Expected ErrKeyNotFound for old credentials, got %v", err)
	}
}

func TestRotate_InvalidCredentials(t *testing.T) {
	ResetGlobalKeyManager()

	bundleID, _, err := globalKeyManager.StoreKey([]byte("test"), TierBasic)
	if err != nil {
		t.Fatalf("StoreKey failed: %v", err)
	}

	_, _, err = globalKeyManager.RotateKey(bundleID, "wrong-token")
	if err == nil {
		t.Error("Expected error for invalid token")
	}
}

func TestDeriveKey_DifferentPurposes(t *testing.T) {
	ResetGlobalKeyManager()

	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}

	key1, err := globalKeyManager.DeriveKey(masterKey, "shard-encrypt", 0)
	if err != nil {
		t.Fatalf("DeriveKey for shard-encrypt failed: %v", err)
	}

	key2, err := globalKeyManager.DeriveKey(masterKey, "metadata", 0)
	if err != nil {
		t.Fatalf("DeriveKey for metadata failed: %v", err)
	}

	// Different purposes should produce different keys
	if hex.EncodeToString(key1) == hex.EncodeToString(key2) {
		t.Error("Expected different keys for different purposes")
	}

	// Verify key length (32 bytes)
	if len(key1) != 32 {
		t.Errorf("Expected key length 32, got %d", len(key1))
	}
}

func TestDeriveKey_SamePurposeDifferentIndex(t *testing.T) {
	ResetGlobalKeyManager()

	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}

	key0, err := globalKeyManager.DeriveKey(masterKey, "shard", 0)
	if err != nil {
		t.Fatalf("DeriveKey index 0 failed: %v", err)
	}

	key1, err := globalKeyManager.DeriveKey(masterKey, "shard", 1)
	if err != nil {
		t.Fatalf("DeriveKey index 1 failed: %v", err)
	}

	// Different indices should produce different keys
	if hex.EncodeToString(key0) == hex.EncodeToString(key1) {
		t.Error("Expected different keys for different indices")
	}
}

func TestDeriveKey_DeterministicWithSameSalt(t *testing.T) {
	ResetGlobalKeyManager()

	// Note: Each call to globalKeyManager.DeriveKey creates a new HKDFManager
	// with a new random salt, so the results will be different.
	// This test verifies that when using the crypto.NewHKDFManagerWithSalt
	// with the same master key and salt, the results are deterministic.

	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}

	// Create first manager and get its salt
	manager1, err := crypto.NewHKDFManager(masterKey)
	if err != nil {
		t.Fatalf("Failed to create manager1: %v", err)
	}
	defer manager1.Clear()

	salt := manager1.GetSalt()

	// Derive key from first manager
	context := []byte("test:42")
	key1, err := manager1.DeriveKey(context)
	if err != nil {
		t.Fatalf("First DeriveKey failed: %v", err)
	}

	// Create second manager with same master key and salt
	manager2, err := crypto.NewHKDFManagerWithSalt(masterKey, salt)
	if err != nil {
		t.Fatalf("Failed to create manager2: %v", err)
	}
	defer manager2.Clear()

	// Derive key from second manager
	key2, err := manager2.DeriveKey(context)
	if err != nil {
		t.Fatalf("Second DeriveKey failed: %v", err)
	}

	// Same master key + same salt + same context = same key
	if hex.EncodeToString(key1) != hex.EncodeToString(key2) {
		t.Error("Expected same key for same master key, salt, and context")
	}
}

func TestRegisterUsername_Success(t *testing.T) {
	ResetGlobalKeyManager()

	err := globalKeyManager.RegisterUsername("alice", "addr:alice123")
	if err != nil {
		t.Fatalf("RegisterUsername failed: %v", err)
	}

	// Resolve the username
	addr, err := globalKeyManager.ResolveUsername("alice")
	if err != nil {
		t.Fatalf("ResolveUsername failed: %v", err)
	}

	if addr != "addr:alice123" {
		t.Errorf("Expected addr:alice123, got %s", addr)
	}
}

func TestRegisterUsername_Duplicate(t *testing.T) {
	ResetGlobalKeyManager()

	err := globalKeyManager.RegisterUsername("bob", "addr:bob1")
	if err != nil {
		t.Fatalf("First RegisterUsername failed: %v", err)
	}

	err = globalKeyManager.RegisterUsername("bob", "addr:bob2")
	if err != ErrUsernameExists {
		t.Errorf("Expected ErrUsernameExists, got %v", err)
	}
}

func TestResolveUsername_NotFound(t *testing.T) {
	ResetGlobalKeyManager()

	_, err := globalKeyManager.ResolveUsername("nonexistent")
	if err != ErrUsernameNotFound {
		t.Errorf("Expected ErrUsernameNotFound, got %v", err)
	}
}

func TestDeleteKey_Success(t *testing.T) {
	ResetGlobalKeyManager()

	bundleID, token, err := globalKeyManager.StoreKey([]byte("delete-me"), TierBasic)
	if err != nil {
		t.Fatalf("StoreKey failed: %v", err)
	}

	err = globalKeyManager.DeleteKey(bundleID, token)
	if err != nil {
		t.Fatalf("DeleteKey failed: %v", err)
	}

	// Verify key is gone
	_, err = globalKeyManager.GetKey(bundleID, token)
	if err != ErrKeyNotFound {
		t.Errorf("Expected ErrKeyNotFound after delete, got %v", err)
	}
}

func TestDeleteKey_InvalidToken(t *testing.T) {
	ResetGlobalKeyManager()

	bundleID, _, err := globalKeyManager.StoreKey([]byte("test"), TierBasic)
	if err != nil {
		t.Fatalf("StoreKey failed: %v", err)
	}

	err = globalKeyManager.DeleteKey(bundleID, "wrong-token")
	if err != ErrInvalidToken {
		t.Errorf("Expected ErrInvalidToken, got %v", err)
	}
}

// Builtin function tests

func TestFuncStoreKey(t *testing.T) {
	ResetGlobalKeyManager()

	result, err := funcStoreKey([]interface{}{"my-secret", "Standard"})
	if err != nil {
		t.Fatalf("funcStoreKey failed: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("Expected map result, got %T", result)
	}

	if resultMap["bundleId"] == "" {
		t.Error("Expected non-empty bundleId")
	}
	if resultMap["token"] == "" {
		t.Error("Expected non-empty token")
	}
}

func TestFuncStoreKey_InvalidArgs(t *testing.T) {
	ResetGlobalKeyManager()

	// Wrong number of args
	_, err := funcStoreKey([]interface{}{"only-one-arg"})
	if err == nil {
		t.Error("Expected error for wrong arg count")
	}

	// Invalid types
	_, err = funcStoreKey([]interface{}{123, "Standard"})
	if err == nil {
		t.Error("Expected error for invalid key type")
	}

	_, err = funcStoreKey([]interface{}{"key", 123})
	if err == nil {
		t.Error("Expected error for invalid tier type")
	}
}

func TestFuncGetKey(t *testing.T) {
	ResetGlobalKeyManager()

	// First store a key
	storeResult, err := funcStoreKey([]interface{}{"retrieve-me", "Basic"})
	if err != nil {
		t.Fatalf("funcStoreKey failed: %v", err)
	}

	resultMap := storeResult.(map[string]interface{})
	bundleID := resultMap["bundleId"].(string)
	token := resultMap["token"].(string)

	// Now retrieve it
	result, err := funcGetKey([]interface{}{bundleID, token})
	if err != nil {
		t.Fatalf("funcGetKey failed: %v", err)
	}

	if result != "retrieve-me" {
		t.Errorf("Expected 'retrieve-me', got %q", result)
	}
}

func TestFuncRotate(t *testing.T) {
	ResetGlobalKeyManager()

	// Store a key
	storeResult, err := funcStoreKey([]interface{}{"rotate-me", "Standard"})
	if err != nil {
		t.Fatalf("funcStoreKey failed: %v", err)
	}

	resultMap := storeResult.(map[string]interface{})
	bundleID := resultMap["bundleId"].(string)
	token := resultMap["token"].(string)

	// Rotate it
	rotateResult, err := funcRotate([]interface{}{bundleID, token})
	if err != nil {
		t.Fatalf("funcRotate failed: %v", err)
	}

	newResultMap := rotateResult.(map[string]interface{})
	newBundleID := newResultMap["bundleId"].(string)
	newToken := newResultMap["token"].(string)

	// Verify key content is preserved
	result, err := funcGetKey([]interface{}{newBundleID, newToken})
	if err != nil {
		t.Fatalf("funcGetKey after rotate failed: %v", err)
	}

	if result != "rotate-me" {
		t.Errorf("Expected 'rotate-me', got %q", result)
	}
}

func TestFuncDeriveKey(t *testing.T) {
	ResetGlobalKeyManager()

	result, err := funcDeriveKey([]interface{}{"shard-encrypt", int64(0)})
	if err != nil {
		t.Fatalf("funcDeriveKey failed: %v", err)
	}

	hexKey, ok := result.(string)
	if !ok {
		t.Fatalf("Expected string result, got %T", result)
	}

	// Verify it's valid hex (64 chars for 32 bytes)
	if len(hexKey) != 64 {
		t.Errorf("Expected hex length 64, got %d", len(hexKey))
	}

	// Verify it decodes
	_, err = hex.DecodeString(hexKey)
	if err != nil {
		t.Errorf("Invalid hex string: %v", err)
	}
}

func TestFuncRegisterUsername(t *testing.T) {
	ResetGlobalKeyManager()

	result, err := funcRegisterUsername([]interface{}{"testuser", "addr:test123"})
	if err != nil {
		t.Fatalf("funcRegisterUsername failed: %v", err)
	}

	if result != true {
		t.Errorf("Expected true, got %v", result)
	}
}

func TestFuncResolveUsername(t *testing.T) {
	ResetGlobalKeyManager()

	// Register first
	_, err := funcRegisterUsername([]interface{}{"resolver-test", "addr:resolved"})
	if err != nil {
		t.Fatalf("funcRegisterUsername failed: %v", err)
	}

	// Resolve
	result, err := funcResolveUsername([]interface{}{"resolver-test"})
	if err != nil {
		t.Fatalf("funcResolveUsername failed: %v", err)
	}

	if result != "addr:resolved" {
		t.Errorf("Expected 'addr:resolved', got %q", result)
	}
}

// Test all security tiers preserve key content
func TestAllTiers_KeyPreservation(t *testing.T) {
	tiers := []SecurityTier{TierBasic, TierStandard, TierPremium, TierElite}

	for _, tier := range tiers {
		t.Run(string(tier), func(t *testing.T) {
			ResetGlobalKeyManager()

			originalKey := "test-key-for-" + string(tier)

			bundleID, token, err := globalKeyManager.StoreKey([]byte(originalKey), tier)
			if err != nil {
				t.Fatalf("StoreKey failed for %s: %v", tier, err)
			}

			retrievedKey, err := globalKeyManager.GetKey(bundleID, token)
			if err != nil {
				t.Fatalf("GetKey failed for %s: %v", tier, err)
			}

			if string(retrievedKey) != originalKey {
				t.Errorf("Key mismatch for %s: expected %q, got %q", tier, originalKey, string(retrievedKey))
			}
		})
	}
}

// Test concurrent access
func TestConcurrentAccess(t *testing.T) {
	ResetGlobalKeyManager()

	const numGoroutines = 10
	done := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			key := "concurrent-key-" + string(rune('a'+id))
			bundleID, token, err := globalKeyManager.StoreKey([]byte(key), TierStandard)
			if err != nil {
				t.Errorf("Goroutine %d StoreKey failed: %v", id, err)
				done <- false
				return
			}

			retrieved, err := globalKeyManager.GetKey(bundleID, token)
			if err != nil {
				t.Errorf("Goroutine %d GetKey failed: %v", id, err)
				done <- false
				return
			}

			if string(retrieved) != key {
				t.Errorf("Goroutine %d key mismatch", id)
				done <- false
				return
			}

			done <- true
		}(i)
	}

	for i := 0; i < numGoroutines; i++ {
		<-done
	}
}
