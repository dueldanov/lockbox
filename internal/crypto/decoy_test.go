package crypto

import (
	"testing"
)

func TestDecoyGenerator_GenerateDecoyShards(t *testing.T) {
	// Create master key
	masterKey := make([]byte, HKDFKeySize)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}

	// Create HKDF manager
	hkdfManager, err := NewHKDFManager(masterKey)
	if err != nil {
		t.Fatalf("failed to create HKDF manager: %v", err)
	}

	tests := []struct {
		name           string
		config         DecoyConfig
		realShardCount int
		shardSize      int
		expectedMin    int // minimum expected decoys
		expectedMax    int // maximum expected decoys
	}{
		{
			name: "Basic tier (0.5 ratio)",
			config: DecoyConfig{
				DecoyRatio:         0.5,
				MetadataDecoyRatio: 0,
			},
			realShardCount: 10,
			shardSize:      64,
			expectedMin:    5,
			expectedMax:    5,
		},
		{
			name: "Standard tier (1.0 ratio)",
			config: DecoyConfig{
				DecoyRatio:         1.0,
				MetadataDecoyRatio: 0,
			},
			realShardCount: 10,
			shardSize:      64,
			expectedMin:    10,
			expectedMax:    10,
		},
		{
			name: "Premium tier (1.5 ratio)",
			config: DecoyConfig{
				DecoyRatio:         1.5,
				MetadataDecoyRatio: 1.0,
			},
			realShardCount: 10,
			shardSize:      64,
			expectedMin:    15,
			expectedMax:    15,
		},
		{
			name: "Elite tier (2.0 ratio)",
			config: DecoyConfig{
				DecoyRatio:         2.0,
				MetadataDecoyRatio: 2.0,
			},
			realShardCount: 10,
			shardSize:      64,
			expectedMin:    20,
			expectedMax:    20,
		},
		{
			name: "Zero ratio (no decoys)",
			config: DecoyConfig{
				DecoyRatio:         0,
				MetadataDecoyRatio: 0,
			},
			realShardCount: 10,
			shardSize:      64,
			expectedMin:    0,
			expectedMax:    0,
		},
		{
			name: "Small ratio ensures at least 1",
			config: DecoyConfig{
				DecoyRatio:         0.1,
				MetadataDecoyRatio: 0,
			},
			realShardCount: 5,
			shardSize:      64,
			expectedMin:    1,
			expectedMax:    1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			generator := NewDecoyGenerator(hkdfManager, tt.config)

			decoys, err := generator.GenerateDecoyShards(tt.realShardCount, tt.shardSize)
			if err != nil {
				t.Fatalf("GenerateDecoyShards failed: %v", err)
			}

			if len(decoys) < tt.expectedMin || len(decoys) > tt.expectedMax {
				t.Errorf("expected %d-%d decoys, got %d", tt.expectedMin, tt.expectedMax, len(decoys))
			}

			// Verify each decoy is properly formed
			for i, decoy := range decoys {
				if decoy.ShardType != ShardTypeDecoy {
					t.Errorf("decoy %d has wrong type: %v", i, decoy.ShardType)
				}
				if len(decoy.Data) == 0 {
					t.Errorf("decoy %d has empty data", i)
				}
				if len(decoy.Nonce) != NonceSize {
					t.Errorf("decoy %d has wrong nonce size: %d", i, len(decoy.Nonce))
				}
				if len(decoy.Checksum) == 0 {
					t.Errorf("decoy %d has no checksum", i)
				}
			}
		})
	}
}

func TestDecoyGenerator_GenerateDecoyMetadata(t *testing.T) {
	masterKey := make([]byte, HKDFKeySize)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}

	hkdfManager, err := NewHKDFManager(masterKey)
	if err != nil {
		t.Fatalf("failed to create HKDF manager: %v", err)
	}

	tests := []struct {
		name           string
		config         DecoyConfig
		realMetaCount  int
		metaSize       int
		expectedDecoys int
	}{
		{
			name: "Basic tier (no metadata decoys)",
			config: DecoyConfig{
				DecoyRatio:         0.5,
				MetadataDecoyRatio: 0,
			},
			realMetaCount:  5,
			metaSize:       128,
			expectedDecoys: 0,
		},
		{
			name: "Premium tier (1.0 metadata ratio)",
			config: DecoyConfig{
				DecoyRatio:         1.5,
				MetadataDecoyRatio: 1.0,
			},
			realMetaCount:  5,
			metaSize:       128,
			expectedDecoys: 5,
		},
		{
			name: "Elite tier (2.0 metadata ratio)",
			config: DecoyConfig{
				DecoyRatio:         2.0,
				MetadataDecoyRatio: 2.0,
			},
			realMetaCount:  5,
			metaSize:       128,
			expectedDecoys: 10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			generator := NewDecoyGenerator(hkdfManager, tt.config)

			decoys, err := generator.GenerateDecoyMetadata(tt.realMetaCount, tt.metaSize)
			if err != nil {
				t.Fatalf("GenerateDecoyMetadata failed: %v", err)
			}

			if tt.expectedDecoys == 0 {
				if decoys != nil && len(decoys) > 0 {
					t.Errorf("expected no decoys, got %d", len(decoys))
				}
				return
			}

			if len(decoys) != tt.expectedDecoys {
				t.Errorf("expected %d metadata decoys, got %d", tt.expectedDecoys, len(decoys))
			}
		})
	}
}

func TestShardMixer_MixAndExtract(t *testing.T) {
	masterKey := make([]byte, HKDFKeySize)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}

	// Create real shards
	encryptor, err := NewShardEncryptor(masterKey, 64)
	if err != nil {
		t.Fatalf("failed to create encryptor: %v", err)
	}

	testData := []byte("This is test data for shard mixing verification test")
	realShards, err := encryptor.EncryptData(testData)
	if err != nil {
		t.Fatalf("failed to encrypt data: %v", err)
	}

	// Create decoy shards
	hkdfManager, err := NewHKDFManager(masterKey)
	if err != nil {
		t.Fatalf("failed to create HKDF manager: %v", err)
	}

	generator := NewDecoyGenerator(hkdfManager, DecoyConfig{
		DecoyRatio:         1.0,
		MetadataDecoyRatio: 0,
	})

	decoyShards, err := generator.GenerateDecoyShards(len(realShards), 64)
	if err != nil {
		t.Fatalf("failed to generate decoys: %v", err)
	}

	// Mix shards
	mixer := NewShardMixer()
	mixed, realIndexMap, err := mixer.MixShards(realShards, decoyShards)
	if err != nil {
		t.Fatalf("failed to mix shards: %v", err)
	}

	// Verify total count
	expectedTotal := len(realShards) + len(decoyShards)
	if len(mixed) != expectedTotal {
		t.Errorf("expected %d mixed shards, got %d", expectedTotal, len(mixed))
	}

	// Verify index map size matches real shards
	if len(realIndexMap) != len(realShards) {
		t.Errorf("expected %d entries in index map, got %d", len(realShards), len(realIndexMap))
	}

	// Extract real shards
	extracted, err := mixer.ExtractRealShards(mixed, realIndexMap)
	if err != nil {
		t.Fatalf("failed to extract real shards: %v", err)
	}

	if len(extracted) != len(realShards) {
		t.Errorf("expected %d extracted shards, got %d", len(realShards), len(extracted))
	}

	// Verify extracted shards can be decrypted
	decrypted, err := encryptor.DecryptShards(extracted)
	if err != nil {
		t.Fatalf("failed to decrypt extracted shards: %v", err)
	}

	if string(decrypted) != string(testData) {
		t.Errorf("decrypted data mismatch: expected %q, got %q", string(testData), string(decrypted))
	}
}

func TestDecoyIndistinguishability(t *testing.T) {
	masterKey := make([]byte, HKDFKeySize)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}

	// Create real shard
	encryptor, err := NewShardEncryptor(masterKey, 64)
	if err != nil {
		t.Fatalf("failed to create encryptor: %v", err)
	}

	testData := []byte("Real data for indistinguishability test")
	realShards, err := encryptor.EncryptData(testData)
	if err != nil {
		t.Fatalf("failed to encrypt data: %v", err)
	}

	// Create decoy shards
	hkdfManager, err := NewHKDFManager(masterKey)
	if err != nil {
		t.Fatalf("failed to create HKDF manager: %v", err)
	}

	generator := NewDecoyGenerator(hkdfManager, DecoyConfig{
		DecoyRatio: 1.0,
	})

	decoyShards, err := generator.GenerateDecoyShards(len(realShards), 64)
	if err != nil {
		t.Fatalf("failed to generate decoys: %v", err)
	}

	// Verify structural similarity
	for i, decoy := range decoyShards {
		if i >= len(realShards) {
			break
		}
		real := realShards[i]

		// Nonce sizes should match
		if len(decoy.Nonce) != len(real.Nonce) {
			t.Errorf("nonce size mismatch: decoy=%d, real=%d", len(decoy.Nonce), len(real.Nonce))
		}

		// Checksum sizes should match
		if len(decoy.Checksum) != len(real.Checksum) {
			t.Errorf("checksum size mismatch: decoy=%d, real=%d", len(decoy.Checksum), len(real.Checksum))
		}

		// Data should be non-zero length
		if len(decoy.Data) == 0 {
			t.Error("decoy data is empty")
		}

		// Timestamp should be set
		if decoy.Timestamp == 0 {
			t.Error("decoy timestamp not set")
		}
	}
}

func TestGetDecoyStats(t *testing.T) {
	config := DecoyConfig{
		DecoyRatio:         1.5,
		MetadataDecoyRatio: 1.0,
	}

	mixed := []*MixedShard{
		{ShardType: ShardTypeReal},
		{ShardType: ShardTypeReal},
		{ShardType: ShardTypeReal},
		{ShardType: ShardTypeDecoy},
		{ShardType: ShardTypeDecoy},
		{ShardType: ShardTypeDecoy},
		{ShardType: ShardTypeDecoy},
	}

	stats := GetDecoyStats(mixed, config)

	if stats.RealShardCount != 3 {
		t.Errorf("expected 3 real shards, got %d", stats.RealShardCount)
	}
	if stats.DecoyShardCount != 4 {
		t.Errorf("expected 4 decoy shards, got %d", stats.DecoyShardCount)
	}
	if stats.TotalShards != 7 {
		t.Errorf("expected 7 total shards, got %d", stats.TotalShards)
	}
	if stats.DecoyRatio != 1.5 {
		t.Errorf("expected decoy ratio 1.5, got %f", stats.DecoyRatio)
	}
}
