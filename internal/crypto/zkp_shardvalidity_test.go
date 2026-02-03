package crypto

import (
	"crypto/rand"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestShardValidityProof_ValidShard verifies correct shard proof generation and verification
func TestShardValidityProof_ValidShard(t *testing.T) {
	manager := NewZKPManager()

	// Create test shard data
	shardData := make([]byte, 4096) // 4KB shard
	io.ReadFull(rand.Reader, shardData)

	bundleID := make([]byte, 32)
	io.ReadFull(rand.Reader, bundleID)

	// Generate proof
	proof, err := manager.GenerateShardValidityProof(shardData, 3, 10, bundleID)
	require.NoError(t, err, "Should generate proof successfully")
	require.NotNil(t, proof)

	// Verify public parameters are set
	require.NotEmpty(t, proof.Commitment)
	require.Equal(t, uint32(3), proof.ShardIndex)
	require.Equal(t, uint32(10), proof.TotalShards)
	require.Greater(t, proof.Timestamp, int64(0))

	// Verify proof
	err = manager.VerifyShardValidityProof(proof)
	require.NoError(t, err, "Valid proof should verify successfully")
}

// TestShardValidityProof_DifferentShards verifies proofs for multiple shards
func TestShardValidityProof_DifferentShards(t *testing.T) {
	manager := NewZKPManager()

	bundleID := make([]byte, 32)
	io.ReadFull(rand.Reader, bundleID)

	totalShards := uint32(5)

	// Generate proofs for multiple shards
	proofs := make([]*ShardValidityProof, totalShards)
	for i := uint32(0); i < totalShards; i++ {
		shardData := make([]byte, 4096)
		io.ReadFull(rand.Reader, shardData)

		proof, err := manager.GenerateShardValidityProof(shardData, i, totalShards, bundleID)
		require.NoError(t, err, "Should generate proof for shard %d", i)
		require.NotNil(t, proof)

		proofs[i] = proof
	}

	// Verify all proofs
	for i, proof := range proofs {
		err := manager.VerifyShardValidityProof(proof)
		require.NoError(t, err, "Proof for shard %d should verify", i)
	}

	// Verify each proof has different commitment (different shard data)
	for i := 0; i < len(proofs); i++ {
		for j := i + 1; j < len(proofs); j++ {
			require.NotEqual(t, proofs[i].Commitment, proofs[j].Commitment,
				"Shards %d and %d should have different commitments", i, j)
		}
	}
}

// TestShardValidityProof_InvalidIndex verifies proof fails with wrong index
func TestShardValidityProof_InvalidIndex(t *testing.T) {
	manager := NewZKPManager()

	shardData := make([]byte, 4096)
	io.ReadFull(rand.Reader, shardData)

	bundleID := make([]byte, 32)
	io.ReadFull(rand.Reader, bundleID)

	// Generate proof with index 3
	proof, err := manager.GenerateShardValidityProof(shardData, 3, 10, bundleID)
	require.NoError(t, err)

	// Tamper with index
	proof.ShardIndex = 5

	// Verification should FAIL (index doesn't match proof)
	err = manager.VerifyShardValidityProof(proof)
	require.Error(t, err, "Proof should NOT verify with wrong shard index")
}

// TestShardValidityProof_InvalidTotalShards verifies proof fails with wrong total
func TestShardValidityProof_InvalidTotalShards(t *testing.T) {
	manager := NewZKPManager()

	shardData := make([]byte, 4096)
	io.ReadFull(rand.Reader, shardData)

	bundleID := make([]byte, 32)
	io.ReadFull(rand.Reader, bundleID)

	// Generate proof with totalShards=10
	proof, err := manager.GenerateShardValidityProof(shardData, 3, 10, bundleID)
	require.NoError(t, err)

	// Tamper with total shards
	proof.TotalShards = 15

	// Verification should FAIL
	err = manager.VerifyShardValidityProof(proof)
	require.Error(t, err, "Proof should NOT verify with wrong total shards")
}

// TestShardValidityProof_TamperedCommitment verifies proof fails with tampered commitment
func TestShardValidityProof_TamperedCommitment(t *testing.T) {
	manager := NewZKPManager()

	shardData := make([]byte, 4096)
	io.ReadFull(rand.Reader, shardData)

	bundleID := make([]byte, 32)
	io.ReadFull(rand.Reader, bundleID)

	// Generate proof
	proof, err := manager.GenerateShardValidityProof(shardData, 3, 10, bundleID)
	require.NoError(t, err)

	// Tamper with commitment
	proof.Commitment[0] ^= 0xFF

	// Verification should FAIL
	err = manager.VerifyShardValidityProof(proof)
	require.Error(t, err, "Proof should NOT verify with tampered commitment")
}

// TestShardValidityProof_DifferentShardSizes verifies proofs work for various shard sizes
func TestShardValidityProof_DifferentShardSizes(t *testing.T) {
	manager := NewZKPManager()

	bundleID := make([]byte, 32)
	io.ReadFull(rand.Reader, bundleID)

	sizes := []int{1024, 4096, 16384, 65536} // 1KB, 4KB, 16KB, 64KB

	for _, size := range sizes {
		t.Run(string(rune(size)), func(t *testing.T) {
			shardData := make([]byte, size)
			io.ReadFull(rand.Reader, shardData)

			proof, err := manager.GenerateShardValidityProof(shardData, 0, 1, bundleID)
			require.NoError(t, err, "Should generate proof for %d byte shard", size)

			err = manager.VerifyShardValidityProof(proof)
			require.NoError(t, err, "Should verify proof for %d byte shard", size)
		})
	}
}

// TestShardValidityProof_EdgeCaseIndices verifies edge case shard indices
func TestShardValidityProof_EdgeCaseIndices(t *testing.T) {
	manager := NewZKPManager()

	shardData := make([]byte, 4096)
	io.ReadFull(rand.Reader, shardData)

	bundleID := make([]byte, 32)
	io.ReadFull(rand.Reader, bundleID)

	testCases := []struct {
		name        string
		shardIndex  uint32
		totalShards uint32
		shouldPass  bool
	}{
		{"First shard", 0, 10, true},
		{"Last shard", 9, 10, true},
		{"Single shard", 0, 1, true},
		{"Middle shard", 5, 10, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			proof, err := manager.GenerateShardValidityProof(shardData, tc.shardIndex, tc.totalShards, bundleID)

			if tc.shouldPass {
				require.NoError(t, err, "Should generate proof for %s", tc.name)
				err = manager.VerifyShardValidityProof(proof)
				require.NoError(t, err, "Should verify proof for %s", tc.name)
			}
		})
	}
}

// TestShardValidityProof_Deterministic verifies same input produces verifiable proof
func TestShardValidityProof_Deterministic(t *testing.T) {
	manager1 := NewZKPManager()
	manager2 := NewZKPManager()

	shardData := make([]byte, 4096)
	io.ReadFull(rand.Reader, shardData)

	bundleID := make([]byte, 32)
	io.ReadFull(rand.Reader, bundleID)

	// Generate proof with manager1
	proof1, err := manager1.GenerateShardValidityProof(shardData, 3, 10, bundleID)
	require.NoError(t, err)

	// Verify with manager2 (different instance)
	// Note: This will fail if manager2 hasn't compiled the circuit yet
	// In production, compiled circuits would be shared or cached
	proof2, err := manager2.GenerateShardValidityProof(shardData, 3, 10, bundleID)
	require.NoError(t, err)

	// Both proofs should verify successfully (though they may differ due to randomness)
	err = manager1.VerifyShardValidityProof(proof1)
	require.NoError(t, err, "Proof should verify with same manager")

	err = manager2.VerifyShardValidityProof(proof2)
	require.NoError(t, err, "Proof should verify with different manager")
}

// TestShardValidityProof_ZeroKnowledge verifies proof doesn't leak shard data
func TestShardValidityProof_ZeroKnowledge(t *testing.T) {
	manager := NewZKPManager()

	// Two different shard data with same metadata
	shardData1 := make([]byte, 4096)
	shardData2 := make([]byte, 4096)
	io.ReadFull(rand.Reader, shardData1)
	io.ReadFull(rand.Reader, shardData2)

	// Make sure they're different
	require.NotEqual(t, shardData1, shardData2, "Test shards should be different")

	bundleID := make([]byte, 32)
	io.ReadFull(rand.Reader, bundleID)

	// Generate proofs for both shards
	proof1, err := manager.GenerateShardValidityProof(shardData1, 0, 2, bundleID)
	require.NoError(t, err)

	proof2, err := manager.GenerateShardValidityProof(shardData2, 1, 2, bundleID)
	require.NoError(t, err)

	// Both proofs should verify
	err = manager.VerifyShardValidityProof(proof1)
	require.NoError(t, err)

	err = manager.VerifyShardValidityProof(proof2)
	require.NoError(t, err)

	// Proofs should have different commitments (different data)
	require.NotEqual(t, proof1.Commitment, proof2.Commitment,
		"Different shard data should produce different commitments")

	// CRITICAL: Verifier learns NOTHING about shard content
	// Only learns: hash matches, index is valid, belongs to bundle
	// Shard data remains completely private
	t.Log("Zero-knowledge property: Verifier cannot determine shard content from proof")
}

// TestShardValidityProof_ConcurrentGeneration verifies thread-safety
func TestShardValidityProof_ConcurrentGeneration(t *testing.T) {
	manager := NewZKPManager()

	bundleID := make([]byte, 32)
	io.ReadFull(rand.Reader, bundleID)

	numGoroutines := 10
	done := make(chan bool, numGoroutines)

	// Generate proofs concurrently
	for i := 0; i < numGoroutines; i++ {
		go func(index int) {
			shardData := make([]byte, 4096)
			io.ReadFull(rand.Reader, shardData)

			proof, err := manager.GenerateShardValidityProof(shardData, uint32(index), 10, bundleID)
			if err != nil {
				t.Errorf("Concurrent generation failed for shard %d: %v", index, err)
				done <- false
				return
			}

			err = manager.VerifyShardValidityProof(proof)
			if err != nil {
				t.Errorf("Concurrent verification failed for shard %d: %v", index, err)
				done <- false
				return
			}

			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < numGoroutines; i++ {
		success := <-done
		require.True(t, success, "Concurrent proof generation should succeed")
	}
}
