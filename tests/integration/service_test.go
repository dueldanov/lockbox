// Package integration provides integration tests for the LockBox service.
// These tests verify the complete flow of the service including:
// - Crypto operations (HKDF, encryption, decoys)
// - Tier capabilities
// - Rate limiting
// - Error handling
//
// Run with: go test ./tests/integration/... -v
package integration

import (
	"testing"
	"time"

	"github.com/dueldanov/lockbox/v2/internal/crypto"
	"github.com/dueldanov/lockbox/v2/internal/service"
	"github.com/dueldanov/lockbox/v2/internal/verification"
)

// TestCryptoIntegration tests the crypto subsystem
func TestCryptoIntegration(t *testing.T) {
	// Test HKDF key derivation
	t.Run("HKDF_PurposeSpecificKeys", func(t *testing.T) {
		masterKey := make([]byte, crypto.HKDFKeySize)
		for i := range masterKey {
			masterKey[i] = byte(i)
		}

		manager, err := crypto.NewHKDFManager(masterKey)
		if err != nil {
			t.Fatalf("Failed to create HKDF manager: %v", err)
		}

		// Derive keys for different purposes
		realKey0, err := manager.DeriveKeyForRealChar(0)
		if err != nil {
			t.Fatalf("DeriveKeyForRealChar failed: %v", err)
		}

		decoyKey0, err := manager.DeriveKeyForDecoyChar(0)
		if err != nil {
			t.Fatalf("DeriveKeyForDecoyChar failed: %v", err)
		}

		realMetaKey, err := manager.DeriveKeyForRealMeta(0)
		if err != nil {
			t.Fatalf("DeriveKeyForRealMeta failed: %v", err)
		}

		decoyMetaKey, err := manager.DeriveKeyForDecoyMeta(0)
		if err != nil {
			t.Fatalf("DeriveKeyForDecoyMeta failed: %v", err)
		}

		// Verify keys are different
		if string(realKey0) == string(decoyKey0) {
			t.Error("Real and decoy keys should be different")
		}
		if string(realKey0) == string(realMetaKey) {
			t.Error("Real char and real meta keys should be different")
		}
		if string(realMetaKey) == string(decoyMetaKey) {
			t.Error("Real meta and decoy meta keys should be different")
		}

		// Verify key sizes
		if len(realKey0) != crypto.HKDFKeySize {
			t.Errorf("Expected key size %d, got %d", crypto.HKDFKeySize, len(realKey0))
		}

		t.Log("Purpose-specific HKDF keys: OK")
	})

	// Test Shard Encryption
	t.Run("ShardEncryption", func(t *testing.T) {
		masterKey := make([]byte, crypto.HKDFKeySize)
		for i := range masterKey {
			masterKey[i] = byte(i)
		}

		encryptor, err := crypto.NewShardEncryptor(masterKey, 64)
		if err != nil {
			t.Fatalf("Failed to create encryptor: %v", err)
		}

		testData := []byte("Integration test data for encryption verification")
		shards, err := encryptor.EncryptData(testData)
		if err != nil {
			t.Fatalf("EncryptData failed: %v", err)
		}

		if len(shards) == 0 {
			t.Fatal("No shards generated")
		}

		decrypted, err := encryptor.DecryptShards(shards)
		if err != nil {
			t.Fatalf("DecryptShards failed: %v", err)
		}

		if string(decrypted) != string(testData) {
			t.Errorf("Data mismatch: expected %q, got %q", string(testData), string(decrypted))
		}

		t.Logf("Shard encryption/decryption: OK (%d shards)", len(shards))
	})

	// Test Decoy Generation
	t.Run("DecoyGeneration", func(t *testing.T) {
		masterKey := make([]byte, crypto.HKDFKeySize)
		for i := range masterKey {
			masterKey[i] = byte(i)
		}

		hkdfManager, err := crypto.NewHKDFManager(masterKey)
		if err != nil {
			t.Fatalf("Failed to create HKDF manager: %v", err)
		}

		// Test all tier configurations
		tierConfigs := []struct {
			name               string
			decoyRatio         float64
			metadataDecoyRatio float64
			realShards         int
			expectedDecoys     int
		}{
			{"Basic", 0.5, 0, 10, 5},
			{"Standard", 1.0, 0, 10, 10},
			{"Premium", 1.5, 1.0, 10, 15},
			{"Elite", 2.0, 2.0, 10, 20},
		}

		for _, tc := range tierConfigs {
			t.Run(tc.name, func(t *testing.T) {
				config := crypto.DecoyConfig{
					DecoyRatio:         tc.decoyRatio,
					MetadataDecoyRatio: tc.metadataDecoyRatio,
				}

				generator := crypto.NewDecoyGenerator(hkdfManager, config)
				decoys, err := generator.GenerateDecoyShards(tc.realShards, 64)
				if err != nil {
					t.Fatalf("GenerateDecoyShards failed: %v", err)
				}

				if len(decoys) != tc.expectedDecoys {
					t.Errorf("Expected %d decoys, got %d", tc.expectedDecoys, len(decoys))
				}

				// Verify decoy structure
				for i, decoy := range decoys {
					if decoy.ShardType != crypto.ShardTypeDecoy {
						t.Errorf("Decoy %d has wrong type", i)
					}
					if len(decoy.Data) == 0 {
						t.Errorf("Decoy %d has empty data", i)
					}
				}
			})
		}
	})

	// Test Shard Mixing
	t.Run("ShardMixing", func(t *testing.T) {
		masterKey := make([]byte, crypto.HKDFKeySize)
		for i := range masterKey {
			masterKey[i] = byte(i)
		}

		// Create real shards
		encryptor, err := crypto.NewShardEncryptor(masterKey, 64)
		if err != nil {
			t.Fatalf("Failed to create encryptor: %v", err)
		}

		testData := []byte("Data for shard mixing test - verify extraction works")
		realShards, err := encryptor.EncryptData(testData)
		if err != nil {
			t.Fatalf("Failed to encrypt data: %v", err)
		}

		// Create decoys
		hkdfManager, err := crypto.NewHKDFManager(masterKey)
		if err != nil {
			t.Fatalf("Failed to create HKDF manager: %v", err)
		}

		generator := crypto.NewDecoyGenerator(hkdfManager, crypto.DecoyConfig{
			DecoyRatio: 1.0,
		})

		decoyShards, err := generator.GenerateDecoyShards(len(realShards), 64)
		if err != nil {
			t.Fatalf("Failed to generate decoys: %v", err)
		}

		// Mix shards
		mixer := crypto.NewShardMixer()
		mixed, indexMap, err := mixer.MixShards(realShards, decoyShards)
		if err != nil {
			t.Fatalf("Failed to mix shards: %v", err)
		}

		expectedTotal := len(realShards) + len(decoyShards)
		if len(mixed) != expectedTotal {
			t.Errorf("Expected %d mixed shards, got %d", expectedTotal, len(mixed))
		}

		// Extract and verify
		extracted, err := mixer.ExtractRealShards(mixed, indexMap)
		if err != nil {
			t.Fatalf("Failed to extract real shards: %v", err)
		}

		decrypted, err := encryptor.DecryptShards(extracted)
		if err != nil {
			t.Fatalf("Failed to decrypt extracted shards: %v", err)
		}

		if string(decrypted) != string(testData) {
			t.Errorf("Data mismatch after mix/extract")
		}

		t.Logf("Shard mixing: OK (real=%d, decoy=%d, total=%d)",
			len(realShards), len(decoyShards), len(mixed))
	})
}

// TestRateLimiterIntegration tests the rate limiter
func TestRateLimiterIntegration(t *testing.T) {
	config := &verification.RateLimiterConfig{
		MaxRequests:   5,
		WindowSize:    time.Minute,
		CleanupPeriod: 5 * time.Minute,
	}

	rl := verification.NewRateLimiter(config)
	defer rl.Stop()

	userID := "test-user-123"

	// Test basic rate limiting
	t.Run("BasicRateLimit", func(t *testing.T) {
		// Reset for clean test
		rl.Reset(userID)

		// Should allow first 5 requests
		for i := 0; i < 5; i++ {
			if err := rl.Allow(userID); err != nil {
				t.Errorf("Request %d should be allowed: %v", i+1, err)
			}
		}

		// 6th request should be rate limited
		if err := rl.Allow(userID); err == nil {
			t.Error("6th request should be rate limited")
		}

		t.Log("Basic rate limiting: OK")
	})

	// Test remaining count
	t.Run("RemainingCount", func(t *testing.T) {
		newUser := "new-user-456"
		rl.Reset(newUser)

		remaining := rl.GetRemaining(newUser)
		if remaining != 5 {
			t.Errorf("New user should have 5 remaining, got %d", remaining)
		}

		rl.Allow(newUser)
		remaining = rl.GetRemaining(newUser)
		if remaining != 4 {
			t.Errorf("After 1 request should have 4 remaining, got %d", remaining)
		}

		t.Log("Remaining count: OK")
	})

	// Test retry after
	t.Run("RetryAfter", func(t *testing.T) {
		blockedUser := "blocked-user-789"
		rl.Reset(blockedUser)

		// Exhaust rate limit
		for i := 0; i < 6; i++ {
			rl.Allow(blockedUser)
		}

		retryAfter := rl.GetRetryAfter(blockedUser)
		if retryAfter <= 0 {
			t.Error("RetryAfter should be > 0 when rate limited")
		}
		t.Logf("Retry after: %v", retryAfter)
	})

	// Test stats
	t.Run("Stats", func(t *testing.T) {
		stats := rl.GetStats()
		if stats.MaxTokens != 5 {
			t.Errorf("MaxTokens should be 5, got %d", stats.MaxTokens)
		}
		t.Logf("Stats: %+v", stats)
	})
}

// TestTierCapabilities tests tier-specific capabilities
func TestTierCapabilities(t *testing.T) {
	tiers := []service.Tier{
		service.TierBasic,
		service.TierStandard,
		service.TierPremium,
		service.TierElite,
	}

	expectedShardCopies := map[service.Tier]int{
		service.TierBasic:    3,
		service.TierStandard: 5,
		service.TierPremium:  7,
		service.TierElite:    10,
	}

	expectedDecoyRatio := map[service.Tier]float64{
		service.TierBasic:    0.5,
		service.TierStandard: 1.0,
		service.TierPremium:  1.5,
		service.TierElite:    2.0,
	}

	expectedMetaDecoyRatio := map[service.Tier]float64{
		service.TierBasic:    0,
		service.TierStandard: 0,
		service.TierPremium:  1.0,
		service.TierElite:    2.0,
	}

	for _, tier := range tiers {
		t.Run(tier.String(), func(t *testing.T) {
			caps := service.GetCapabilities(tier)

			// Test ShardCopies
			if caps.ShardCopies != expectedShardCopies[tier] {
				t.Errorf("ShardCopies: expected %d, got %d",
					expectedShardCopies[tier], caps.ShardCopies)
			}

			// Test DecoyRatio
			if caps.DecoyRatio != expectedDecoyRatio[tier] {
				t.Errorf("DecoyRatio: expected %f, got %f",
					expectedDecoyRatio[tier], caps.DecoyRatio)
			}

			// Test MetadataDecoyRatio
			if caps.MetadataDecoyRatio != expectedMetaDecoyRatio[tier] {
				t.Errorf("MetadataDecoyRatio: expected %f, got %f",
					expectedMetaDecoyRatio[tier], caps.MetadataDecoyRatio)
			}

			// Test MultiSig support (Standard+)
			if tier >= service.TierStandard && !caps.MultiSigSupported {
				t.Error("MultiSig should be supported for Standard+")
			}
			if tier == service.TierBasic && caps.MultiSigSupported {
				t.Error("MultiSig should NOT be supported for Basic")
			}

			// Test EmergencyUnlock (Standard+)
			if tier >= service.TierStandard && !caps.EmergencyUnlock {
				t.Error("EmergencyUnlock should be supported for Standard+")
			}
			if tier == service.TierBasic && caps.EmergencyUnlock {
				t.Error("EmergencyUnlock should NOT be supported for Basic")
			}

			// Test Geographic Redundancy (minimum 3)
			if caps.GeographicRedundancy < 3 {
				t.Errorf("GeographicRedundancy must be >= 3, got %d", caps.GeographicRedundancy)
			}

			t.Logf("%s: ShardCopies=%d, DecoyRatio=%.1f, MetaDecoy=%.1f, MultiSig=%v, Emergency=%v",
				tier, caps.ShardCopies, caps.DecoyRatio, caps.MetadataDecoyRatio,
				caps.MultiSigSupported, caps.EmergencyUnlock)
		})
	}
}

// BenchmarkHKDFKeyDerivation benchmarks key derivation performance
func BenchmarkHKDFKeyDerivation(b *testing.B) {
	masterKey := make([]byte, crypto.HKDFKeySize)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}

	manager, err := crypto.NewHKDFManager(masterKey)
	if err != nil {
		b.Fatalf("Failed to create HKDF manager: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := manager.DeriveKeyForRealChar(uint32(i))
		if err != nil {
			b.Fatalf("DeriveKeyForRealChar failed: %v", err)
		}
	}
}

// BenchmarkDecoyGeneration benchmarks decoy generation performance
func BenchmarkDecoyGeneration(b *testing.B) {
	masterKey := make([]byte, crypto.HKDFKeySize)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}

	hkdfManager, err := crypto.NewHKDFManager(masterKey)
	if err != nil {
		b.Fatalf("Failed to create HKDF manager: %v", err)
	}

	generator := crypto.NewDecoyGenerator(hkdfManager, crypto.DecoyConfig{
		DecoyRatio: 2.0, // Elite tier
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := generator.GenerateDecoyShards(10, 64)
		if err != nil {
			b.Fatalf("GenerateDecoyShards failed: %v", err)
		}
	}
}

// BenchmarkRateLimiter benchmarks rate limiter performance
func BenchmarkRateLimiter(b *testing.B) {
	rl := verification.NewRateLimiter(nil) // default config
	defer rl.Stop()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		userID := "user-" + string(rune(i%100))
		rl.Allow(userID)
	}
}
