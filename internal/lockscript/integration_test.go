package lockscript

import (
	"testing"
	"time"
)

// Integration tests for key operations pipeline:
// storeKey -> getKey -> rotate -> verify

func TestIntegration_KeyOperations_FullPipeline(t *testing.T) {
	ResetGlobalKeyManager()

	// Test: Store, retrieve, rotate, retrieve again
	originalKey := "my-super-secret-api-key-123"
	tier := TierStandard

	// Step 1: Store the key
	bundleID, token, err := globalKeyManager.StoreKey([]byte(originalKey), tier)
	if err != nil {
		t.Fatalf("StoreKey failed: %v", err)
	}
	t.Logf("Stored key with bundleID=%s", bundleID)

	// Step 2: Retrieve and verify
	retrievedKey, err := globalKeyManager.GetKey(bundleID, token)
	if err != nil {
		t.Fatalf("GetKey failed: %v", err)
	}
	if string(retrievedKey) != originalKey {
		t.Errorf("Key mismatch: expected %q, got %q", originalKey, string(retrievedKey))
	}

	// Step 3: Rotate the key
	newBundleID, newToken, err := globalKeyManager.RotateKey(bundleID, token)
	if err != nil {
		t.Fatalf("RotateKey failed: %v", err)
	}
	t.Logf("Rotated to bundleID=%s", newBundleID)

	// Verify credentials changed
	if newBundleID == bundleID {
		t.Error("BundleID should change after rotation")
	}
	if newToken == token {
		t.Error("Token should change after rotation")
	}

	// Step 4: Verify key content preserved
	finalKey, err := globalKeyManager.GetKey(newBundleID, newToken)
	if err != nil {
		t.Fatalf("GetKey after rotate failed: %v", err)
	}
	if string(finalKey) != originalKey {
		t.Errorf("Key content changed after rotation: expected %q, got %q", originalKey, string(finalKey))
	}

	// Step 5: Verify old credentials no longer work
	_, err = globalKeyManager.GetKey(bundleID, token)
	if err != ErrKeyNotFound {
		t.Errorf("Expected ErrKeyNotFound for old credentials, got %v", err)
	}
}

func TestIntegration_AllTiers_Pipeline(t *testing.T) {
	tiers := []SecurityTier{TierBasic, TierStandard, TierPremium, TierElite}

	for _, tier := range tiers {
		t.Run(string(tier), func(t *testing.T) {
			ResetGlobalKeyManager()

			secret := "secret-for-tier-" + string(tier)

			// Store
			bundleID, token, err := globalKeyManager.StoreKey([]byte(secret), tier)
			if err != nil {
				t.Fatalf("StoreKey failed for %s: %v", tier, err)
			}

			// Retrieve
			retrieved, err := globalKeyManager.GetKey(bundleID, token)
			if err != nil {
				t.Fatalf("GetKey failed for %s: %v", tier, err)
			}

			if string(retrieved) != secret {
				t.Errorf("Key mismatch for %s: expected %q, got %q", tier, secret, string(retrieved))
			}

			// Rotate
			newID, newToken, err := globalKeyManager.RotateKey(bundleID, token)
			if err != nil {
				t.Fatalf("RotateKey failed for %s: %v", tier, err)
			}

			// Verify after rotation
			final, err := globalKeyManager.GetKey(newID, newToken)
			if err != nil {
				t.Fatalf("GetKey after rotate failed for %s: %v", tier, err)
			}

			if string(final) != secret {
				t.Errorf("Key changed after rotation for %s", tier)
			}
		})
	}
}

func TestIntegration_UsernameFlow(t *testing.T) {
	ResetGlobalKeyManager()

	// Register multiple usernames
	users := []struct {
		name    string
		address string
	}{
		{"alice", "iota1qpg4tqh7vj9s7y9zk2smj8t4qgvse9um42l7apdkhw6syp5ju4w3v6ffg6n"},
		{"bob", "iota1qpl3m7wj7yg8rxz8krq9rkg9stvzc78xj3j5p7v4r4k9cpz5e2kuw6rjjn8"},
		{"charlie", "iota1qzvjvjz8y2g7mf5xm5c7uc7t5zv3je76ufje9m5ey8z5x5r8se77c6p4qtz"},
	}

	// Register all
	for _, u := range users {
		err := globalKeyManager.RegisterUsername(u.name, u.address)
		if err != nil {
			t.Fatalf("RegisterUsername failed for %s: %v", u.name, err)
		}
	}

	// Resolve all
	for _, u := range users {
		addr, err := globalKeyManager.ResolveUsername(u.name)
		if err != nil {
			t.Fatalf("ResolveUsername failed for %s: %v", u.name, err)
		}
		if addr != u.address {
			t.Errorf("Address mismatch for %s: expected %s, got %s", u.name, u.address, addr)
		}
	}

	// Try to register duplicate
	err := globalKeyManager.RegisterUsername("alice", "different-address")
	if err != ErrUsernameExists {
		t.Errorf("Expected ErrUsernameExists for duplicate, got %v", err)
	}

	// Resolve non-existent
	_, err = globalKeyManager.ResolveUsername("nonexistent")
	if err != ErrUsernameNotFound {
		t.Errorf("Expected ErrUsernameNotFound, got %v", err)
	}
}

func TestIntegration_Builtins_Time(t *testing.T) {
	// Test now()
	before := time.Now().Unix()
	result, err := funcNow(nil)
	after := time.Now().Unix()

	if err != nil {
		t.Fatalf("funcNow failed: %v", err)
	}

	ts := result.(int64)
	if ts < before || ts > after {
		t.Errorf("now() = %d, expected between %d and %d", ts, before, after)
	}

	// Test after() with past timestamp
	pastTime := time.Now().Add(-1 * time.Hour).Unix()
	result, err = funcAfter([]interface{}{pastTime})
	if err != nil {
		t.Fatalf("funcAfter failed: %v", err)
	}
	if result != true {
		t.Error("after(past) should return true")
	}

	// Test after() with future timestamp
	futureTime := time.Now().Add(1 * time.Hour).Unix()
	result, err = funcAfter([]interface{}{futureTime})
	if err != nil {
		t.Fatalf("funcAfter failed: %v", err)
	}
	if result != false {
		t.Error("after(future) should return false")
	}

	// Test before() with past timestamp
	result, err = funcBefore([]interface{}{pastTime})
	if err != nil {
		t.Fatalf("funcBefore failed: %v", err)
	}
	if result != false {
		t.Error("before(past) should return false")
	}

	// Test before() with future timestamp
	result, err = funcBefore([]interface{}{futureTime})
	if err != nil {
		t.Fatalf("funcBefore failed: %v", err)
	}
	if result != true {
		t.Error("before(future) should return true")
	}
}

func TestIntegration_Builtins_Signature(t *testing.T) {
	// Generate key pair
	pubKeyHex, privKey, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}

	message := "test-message-for-signing"
	signature := SignMessage(privKey, message)

	// Test valid signature
	result, err := funcVerifySig([]interface{}{pubKeyHex, message, signature})
	if err != nil {
		t.Fatalf("funcVerifySig failed: %v", err)
	}
	if result != true {
		t.Error("verify_sig should return true for valid signature")
	}

	// Test wrong message
	result, err = funcVerifySig([]interface{}{pubKeyHex, "wrong-message", signature})
	if err != nil {
		t.Fatalf("funcVerifySig failed: %v", err)
	}
	if result != false {
		t.Error("verify_sig should return false for wrong message")
	}

	// Test wrong public key
	otherPubKey, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	result, err = funcVerifySig([]interface{}{otherPubKey, message, signature})
	if err != nil {
		t.Fatalf("funcVerifySig failed: %v", err)
	}
	if result != false {
		t.Error("verify_sig should return false for wrong public key")
	}
}

func TestIntegration_Builtins_Hash(t *testing.T) {
	result, err := funcSHA256([]interface{}{"hello"})
	if err != nil {
		t.Fatalf("funcSHA256 failed: %v", err)
	}

	expected := "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if result != expected {
		t.Errorf("sha256('hello') = %v, expected %s", result, expected)
	}
}

func TestIntegration_Builtins_Geo(t *testing.T) {
	validRegions := []string{"us-east", "eu-west", "asia-pacific"}
	invalidRegions := []string{"africa", "south-america", "australia"}

	for _, region := range validRegions {
		result, err := funcCheckGeo([]interface{}{region})
		if err != nil {
			t.Fatalf("funcCheckGeo failed for %s: %v", region, err)
		}
		if result != true {
			t.Errorf("check_geo('%s') should return true", region)
		}
	}

	for _, region := range invalidRegions {
		result, err := funcCheckGeo([]interface{}{region})
		if err != nil {
			t.Fatalf("funcCheckGeo failed for %s: %v", region, err)
		}
		if result != false {
			t.Errorf("check_geo('%s') should return false", region)
		}
	}
}

func TestIntegration_Builtins_Math(t *testing.T) {
	// Test min
	result, err := funcMin([]interface{}{int64(10), int64(5), int64(8)})
	if err != nil {
		t.Fatalf("funcMin failed: %v", err)
	}
	if result != int64(5) {
		t.Errorf("min(10, 5, 8) = %v, expected 5", result)
	}

	// Test max
	result, err = funcMax([]interface{}{int64(10), int64(5), int64(8)})
	if err != nil {
		t.Fatalf("funcMax failed: %v", err)
	}
	if result != int64(10) {
		t.Errorf("max(10, 5, 8) = %v, expected 10", result)
	}
}

func TestIntegration_LockScriptBuiltins_StoreGetKey(t *testing.T) {
	ResetGlobalKeyManager()

	// Test storeKey builtin
	storeResult, err := funcStoreKey([]interface{}{"my-secret", "Standard"})
	if err != nil {
		t.Fatalf("funcStoreKey failed: %v", err)
	}

	resultMap := storeResult.(map[string]interface{})
	bundleID := resultMap["bundleId"].(string)
	token := resultMap["token"].(string)

	// Test getKey builtin
	getResult, err := funcGetKey([]interface{}{bundleID, token})
	if err != nil {
		t.Fatalf("funcGetKey failed: %v", err)
	}

	if getResult != "my-secret" {
		t.Errorf("Expected 'my-secret', got %v", getResult)
	}
}

func TestIntegration_LockScriptBuiltins_Rotate(t *testing.T) {
	ResetGlobalKeyManager()

	// Store
	storeResult, _ := funcStoreKey([]interface{}{"rotate-me", "Premium"})
	resultMap := storeResult.(map[string]interface{})
	bundleID := resultMap["bundleId"].(string)
	token := resultMap["token"].(string)

	// Rotate
	rotateResult, err := funcRotate([]interface{}{bundleID, token})
	if err != nil {
		t.Fatalf("funcRotate failed: %v", err)
	}

	newMap := rotateResult.(map[string]interface{})
	newBundleID := newMap["bundleId"].(string)
	newToken := newMap["token"].(string)

	// Verify
	getResult, err := funcGetKey([]interface{}{newBundleID, newToken})
	if err != nil {
		t.Fatalf("funcGetKey after rotate failed: %v", err)
	}

	if getResult != "rotate-me" {
		t.Errorf("Expected 'rotate-me', got %v", getResult)
	}
}

func TestIntegration_LockScriptBuiltins_DeriveKey(t *testing.T) {
	ResetGlobalKeyManager()

	result, err := funcDeriveKey([]interface{}{"shard-encrypt", int64(0)})
	if err != nil {
		t.Fatalf("funcDeriveKey failed: %v", err)
	}

	keyHex, ok := result.(string)
	if !ok {
		t.Fatalf("Expected string, got %T", result)
	}

	// 32 bytes = 64 hex chars
	if len(keyHex) != 64 {
		t.Errorf("Expected 64 hex chars, got %d", len(keyHex))
	}
}

func TestIntegration_LockScriptBuiltins_Username(t *testing.T) {
	ResetGlobalKeyManager()

	// Register
	result, err := funcRegisterUsername([]interface{}{"testuser", "addr:test123"})
	if err != nil {
		t.Fatalf("funcRegisterUsername failed: %v", err)
	}
	if result != true {
		t.Errorf("Expected true, got %v", result)
	}

	// Resolve
	result, err = funcResolveUsername([]interface{}{"testuser"})
	if err != nil {
		t.Fatalf("funcResolveUsername failed: %v", err)
	}
	if result != "addr:test123" {
		t.Errorf("Expected 'addr:test123', got %v", result)
	}
}

func TestIntegration_MultipleKeys(t *testing.T) {
	ResetGlobalKeyManager()

	// Store multiple keys
	keys := []struct {
		name   string
		secret string
		tier   SecurityTier
	}{
		{"key1", "secret-1", TierBasic},
		{"key2", "secret-2", TierStandard},
		{"key3", "secret-3", TierPremium},
		{"key4", "secret-4", TierElite},
	}

	credentials := make(map[string]struct{ bundleID, token string })

	// Store all keys
	for _, k := range keys {
		bundleID, token, err := globalKeyManager.StoreKey([]byte(k.secret), k.tier)
		if err != nil {
			t.Fatalf("StoreKey failed for %s: %v", k.name, err)
		}
		credentials[k.name] = struct{ bundleID, token string }{bundleID, token}
	}

	// Retrieve and verify all keys
	for _, k := range keys {
		cred := credentials[k.name]
		retrieved, err := globalKeyManager.GetKey(cred.bundleID, cred.token)
		if err != nil {
			t.Fatalf("GetKey failed for %s: %v", k.name, err)
		}
		if string(retrieved) != k.secret {
			t.Errorf("Key mismatch for %s: expected %q, got %q", k.name, k.secret, string(retrieved))
		}
	}
}

func TestIntegration_LargeKey(t *testing.T) {
	ResetGlobalKeyManager()

	// Create a large key (10KB)
	largeKey := make([]byte, 10*1024)
	for i := range largeKey {
		largeKey[i] = byte(i % 256)
	}

	bundleID, token, err := globalKeyManager.StoreKey(largeKey, TierElite)
	if err != nil {
		t.Fatalf("StoreKey for large key failed: %v", err)
	}

	retrieved, err := globalKeyManager.GetKey(bundleID, token)
	if err != nil {
		t.Fatalf("GetKey for large key failed: %v", err)
	}

	if len(retrieved) != len(largeKey) {
		t.Errorf("Length mismatch: expected %d, got %d", len(largeKey), len(retrieved))
	}

	for i := range largeKey {
		if retrieved[i] != largeKey[i] {
			t.Errorf("Byte mismatch at position %d", i)
			break
		}
	}
}
