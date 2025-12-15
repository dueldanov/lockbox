package crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"testing"
)

func TestCalculateCommitment_NotReversible(t *testing.T) {
	assetID := []byte("asset123")
	ownerSecret := []byte("secret456")
	nonce := []byte("nonce789")

	commitment := calculateCommitment(assetID, ownerSecret, nonce)

	// Commitment should be deterministic
	commitment2 := calculateCommitment(assetID, ownerSecret, nonce)
	if commitment.Cmp(commitment2) != 0 {
		t.Error("Commitment should be deterministic")
	}

	// Different inputs should produce different commitments
	commitment3 := calculateCommitment([]byte("different"), ownerSecret, nonce)
	if commitment.Cmp(commitment3) == 0 {
		t.Error("Different inputs should produce different commitments")
	}

	// Commitment should be 256 bits (32 bytes from SHA256)
	if len(commitment.Bytes()) > 32 {
		t.Errorf("Commitment exceeds 256 bits: got %d bytes", len(commitment.Bytes()))
	}
}

func TestCalculateCommitment_NoCollisions(t *testing.T) {
	// Test that length-prefixing prevents ambiguous inputs

	// Case 1: assetID="ab", ownerSecret="cd", nonce="ef"
	c1 := calculateCommitment([]byte("ab"), []byte("cd"), []byte("ef"))

	// Case 2: assetID="abc", ownerSecret="d", nonce="ef"
	c2 := calculateCommitment([]byte("abc"), []byte("d"), []byte("ef"))

	// These should be different (length-prefixing prevents collision)
	if c1.Cmp(c2) == 0 {
		t.Error("Length-prefixing failed to prevent collision")
	}

	// Case 3: assetID="a", ownerSecret="bcd", nonce="ef"
	c3 := calculateCommitment([]byte("a"), []byte("bcd"), []byte("ef"))

	// All three should be different
	if c1.Cmp(c3) == 0 || c2.Cmp(c3) == 0 {
		t.Error("Length-prefixing failed to prevent collision")
	}
}

func TestCalculateAddress_DomainSeparation(t *testing.T) {
	secret := []byte("shared-secret")

	// Calculate using address function
	address := calculateAddress(secret)

	// Calculate what commitment would produce with same input
	// Using empty bytes for ownerSecret and nonce
	commitment := calculateCommitment(secret, []byte{}, []byte{})

	// These should be different due to domain separation
	if address.Cmp(commitment) == 0 {
		t.Error("Domain separation failed - address and commitment collide")
	}
}

func TestCalculateAddress_Deterministic(t *testing.T) {
	secret := []byte("my-secret")

	addr1 := calculateAddress(secret)
	addr2 := calculateAddress(secret)

	if addr1.Cmp(addr2) != 0 {
		t.Error("Address calculation should be deterministic")
	}
}

func TestCalculateAddress_DifferentSecrets(t *testing.T) {
	addr1 := calculateAddress([]byte("secret-1"))
	addr2 := calculateAddress([]byte("secret-2"))

	if addr1.Cmp(addr2) == 0 {
		t.Error("Different secrets should produce different addresses")
	}
}

func TestCalculateUnlockCommitment_Comprehensive(t *testing.T) {
	unlockSecret := make([]byte, 32)
	assetID := make([]byte, 32)
	additionalData := make([]byte, 32)

	rand.Read(unlockSecret)
	rand.Read(assetID)
	rand.Read(additionalData)

	c1 := calculateUnlockCommitment(unlockSecret, assetID, additionalData)

	// Should be deterministic
	c2 := calculateUnlockCommitment(unlockSecret, assetID, additionalData)
	if c1.Cmp(c2) != 0 {
		t.Error("Unlock commitment should be deterministic")
	}

	// Should change with any input change
	c3 := calculateUnlockCommitment(unlockSecret, assetID, []byte("different"))
	if c1.Cmp(c3) == 0 {
		t.Error("Changing additional data should change commitment")
	}

	c4 := calculateUnlockCommitment(unlockSecret, []byte("different"), additionalData)
	if c1.Cmp(c4) == 0 {
		t.Error("Changing assetID should change commitment")
	}

	c5 := calculateUnlockCommitment([]byte("different"), assetID, additionalData)
	if c1.Cmp(c5) == 0 {
		t.Error("Changing unlockSecret should change commitment")
	}
}

func TestHashFunctions_ProduceValidBigInt(t *testing.T) {
	data := []byte("test-data")

	commitment := calculateCommitment(data, data, data)
	address := calculateAddress(data)
	unlock := calculateUnlockCommitment(data, data, data)

	// All should be non-nil positive integers
	if commitment == nil || commitment.Sign() <= 0 {
		t.Error("Commitment should be positive")
	}
	if address == nil || address.Sign() <= 0 {
		t.Error("Address should be positive")
	}
	if unlock == nil || unlock.Sign() <= 0 {
		t.Error("Unlock commitment should be positive")
	}

	// Should fit in 256 bits (32 bytes from SHA256)
	maxVal := new(big.Int).Lsh(big.NewInt(1), 256)
	if commitment.Cmp(maxVal) >= 0 {
		t.Error("Commitment exceeds 256 bits")
	}
	if address.Cmp(maxVal) >= 0 {
		t.Error("Address exceeds 256 bits")
	}
	if unlock.Cmp(maxVal) >= 0 {
		t.Error("Unlock commitment exceeds 256 bits")
	}
}

func TestWriteLengthPrefixed(t *testing.T) {
	h1 := sha256.New()
	h2 := sha256.New()

	data1 := []byte("test")
	data2 := []byte("data")

	// Write data1 + data2 to h1
	writeLengthPrefixed(h1, data1)
	writeLengthPrefixed(h1, data2)
	hash1 := h1.Sum(nil)

	// Write concatenated to h2 (without length prefix)
	h2.Write(append(data1, data2...))
	hash2 := h2.Sum(nil)

	// These should be different (length prefix changes hash)
	if bytes.Equal(hash1, hash2) {
		t.Error("Length prefixing should change the hash")
	}
}

func TestDomainSeparation_AllFunctions(t *testing.T) {
	data := []byte("same-data")

	// All three functions should produce different results for the same input
	// due to domain separation
	commitment := calculateCommitment(data, data, data)
	address := calculateAddress(data)
	unlock := calculateUnlockCommitment(data, data, data)

	if commitment.Cmp(address) == 0 {
		t.Error("Commitment and address should differ (domain separation)")
	}
	if commitment.Cmp(unlock) == 0 {
		t.Error("Commitment and unlock should differ (domain separation)")
	}
	if address.Cmp(unlock) == 0 {
		t.Error("Address and unlock should differ (domain separation)")
	}
}

func TestCalculateCommitment_EmptyInputs(t *testing.T) {
	// Should handle empty inputs gracefully
	c1 := calculateCommitment([]byte{}, []byte{}, []byte{})
	if c1 == nil {
		t.Error("Should handle empty inputs")
	}

	// Different combinations of empty/non-empty should produce different results
	c2 := calculateCommitment([]byte("data"), []byte{}, []byte{})
	if c1.Cmp(c2) == 0 {
		t.Error("Empty and non-empty inputs should produce different results")
	}
}
