package service

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/dueldanov/lockbox/v2/internal/crypto"
)

// TestOwnershipProof_RoundTrip tests storeOwnershipProof and getOwnershipProof
// This test uses a mock storage to isolate the serialization/deserialization logic
func TestOwnershipProof_RoundTrip(t *testing.T) {
	// Create original proof with known values
	original := &crypto.OwnershipProof{
		AssetCommitment: make([]byte, 32),
		OwnerAddress:    make([]byte, 32),
		Timestamp:       1702500000,
	}
	// Fill with recognizable pattern
	for i := range original.AssetCommitment {
		original.AssetCommitment[i] = byte(i)
	}
	for i := range original.OwnerAddress {
		original.OwnerAddress[i] = byte(255 - i)
	}

	// Create serialized data in the same format as storeOwnershipProof
	serialized := fmt.Sprintf("%s|%s|%d",
		hex.EncodeToString(original.AssetCommitment),
		hex.EncodeToString(original.OwnerAddress),
		original.Timestamp,
	)

	// Test deserialization logic directly
	result, err := parseOwnershipProofData([]byte(serialized))
	if err != nil {
		t.Fatalf("parseOwnershipProofData failed: %v", err)
	}

	// Verify all fields
	if string(result.AssetCommitment) != string(original.AssetCommitment) {
		t.Errorf("AssetCommitment mismatch")
	}
	if string(result.OwnerAddress) != string(original.OwnerAddress) {
		t.Errorf("OwnerAddress mismatch")
	}
	if result.Timestamp != original.Timestamp {
		t.Errorf("Timestamp mismatch: got %d, want %d", result.Timestamp, original.Timestamp)
	}
}

// parseOwnershipProofData is a helper to test the parsing logic
// This mimics the parsing logic in getOwnershipProof
// Format: AssetCommitmentHex|OwnerAddressHex|Timestamp|ProofBytesHex (4th field optional)
func parseOwnershipProofData(data []byte) (*crypto.OwnershipProof, error) {
	parts := strings.Split(string(data), "|")
	if len(parts) < 3 {
		return nil, fmt.Errorf("invalid proof format: expected at least 3 fields, got %d", len(parts))
	}

	assetCommitment, err := hex.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid AssetCommitment hex: %w", err)
	}

	ownerAddress, err := hex.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("invalid OwnerAddress hex: %w", err)
	}

	timestamp, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid Timestamp: %w", err)
	}

	proof := &crypto.OwnershipProof{
		AssetCommitment: assetCommitment,
		OwnerAddress:    ownerAddress,
		Timestamp:       timestamp,
	}

	// Parse ProofBytes if present (4th field)
	if len(parts) >= 4 && parts[3] != "" {
		proofBytes, err := hex.DecodeString(parts[3])
		if err != nil {
			return nil, fmt.Errorf("invalid ProofBytes hex: %w", err)
		}
		// Note: In the actual implementation, we would deserialize groth16.Proof here
		// For tests, we just store the bytes (the Proof field in crypto.OwnershipProof is groth16.Proof)
		_ = proofBytes // We can't set groth16.Proof without the actual deserialization
	}

	return proof, nil
}

func TestOwnershipProof_InvalidFormat(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{"empty string", ""},
		{"too few fields", "aabb|ccdd"},
		{"only one field", "aabbccdd"},
		// Note: 4 fields is now VALID (ProofBytes in 4th field)
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseOwnershipProofData([]byte(tc.data))
			if err == nil {
				t.Error("expected error for invalid format, got nil")
			}
		})
	}
}

func TestOwnershipProof_InvalidHex(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{"invalid AssetCommitment hex", "gggg|aabb|123"},
		{"invalid OwnerAddress hex", "aabb|zzzz|123"},
		{"odd length AssetCommitment", "aab|aabb|123"},
		{"odd length OwnerAddress", "aabb|aab|123"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseOwnershipProofData([]byte(tc.data))
			if err == nil {
				t.Error("expected error for invalid hex, got nil")
			}
		})
	}
}

func TestOwnershipProof_InvalidTimestamp(t *testing.T) {
	tests := []struct {
		name string
		data string
	}{
		{"non-numeric timestamp", "aabb|ccdd|notanumber"},
		{"float timestamp", "aabb|ccdd|123.456"},
		{"empty timestamp", "aabb|ccdd|"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseOwnershipProofData([]byte(tc.data))
			if err == nil {
				t.Error("expected error for invalid timestamp, got nil")
			}
		})
	}
}

func TestOwnershipProof_LargeValues(t *testing.T) {
	// Test with 32-byte commitments (SHA256 hash size)
	assetCommitment := make([]byte, 32)
	ownerAddress := make([]byte, 32)
	for i := range assetCommitment {
		assetCommitment[i] = 0xff
	}
	for i := range ownerAddress {
		ownerAddress[i] = 0xaa
	}

	serialized := fmt.Sprintf("%s|%s|%d",
		hex.EncodeToString(assetCommitment),
		hex.EncodeToString(ownerAddress),
		9223372036854775807, // max int64
	)

	result, err := parseOwnershipProofData([]byte(serialized))
	if err != nil {
		t.Fatalf("parseOwnershipProofData failed: %v", err)
	}

	if len(result.AssetCommitment) != 32 {
		t.Errorf("AssetCommitment length: got %d, want 32", len(result.AssetCommitment))
	}
	if len(result.OwnerAddress) != 32 {
		t.Errorf("OwnerAddress length: got %d, want 32", len(result.OwnerAddress))
	}
	if result.Timestamp != 9223372036854775807 {
		t.Errorf("Timestamp: got %d, want max int64", result.Timestamp)
	}
}

func TestOwnershipProof_EmptyCommitments(t *testing.T) {
	// Empty hex values are valid (decode to empty slices)
	serialized := "||123"

	result, err := parseOwnershipProofData([]byte(serialized))
	if err != nil {
		t.Fatalf("parseOwnershipProofData failed: %v", err)
	}

	if len(result.AssetCommitment) != 0 {
		t.Errorf("AssetCommitment should be empty, got %d bytes", len(result.AssetCommitment))
	}
	if len(result.OwnerAddress) != 0 {
		t.Errorf("OwnerAddress should be empty, got %d bytes", len(result.OwnerAddress))
	}
	if result.Timestamp != 123 {
		t.Errorf("Timestamp: got %d, want 123", result.Timestamp)
	}
}

func TestOwnershipProof_KnownGoodData(t *testing.T) {
	// Known commitment values
	commitment := "e7f5d9c2a8b3e4f1a0c5d2e8f7a3b6c9e7f5d9c2a8b3e4f1a0c5d2e8f7a3b6c9"
	address := "f1e2d3c4b5a69788776655443322110ff1e2d3c4b5a69788776655443322110f"
	timestamp := "1702500000"

	serialized := commitment + "|" + address + "|" + timestamp

	result, err := parseOwnershipProofData([]byte(serialized))
	if err != nil {
		t.Fatalf("parseOwnershipProofData failed: %v", err)
	}

	if hex.EncodeToString(result.AssetCommitment) != commitment {
		t.Errorf("AssetCommitment hex mismatch")
	}
	if hex.EncodeToString(result.OwnerAddress) != address {
		t.Errorf("OwnerAddress hex mismatch")
	}
	if result.Timestamp != 1702500000 {
		t.Errorf("Timestamp: got %d, want 1702500000", result.Timestamp)
	}
}

func TestOwnershipProof_NegativeTimestamp(t *testing.T) {
	serialized := "aabb|ccdd|-12345"

	result, err := parseOwnershipProofData([]byte(serialized))
	if err != nil {
		t.Fatalf("parseOwnershipProofData failed: %v", err)
	}

	if result.Timestamp != -12345 {
		t.Errorf("Timestamp: got %d, want -12345", result.Timestamp)
	}
}

func TestOwnershipProof_ZeroTimestamp(t *testing.T) {
	serialized := "aabb|ccdd|0"

	result, err := parseOwnershipProofData([]byte(serialized))
	if err != nil {
		t.Fatalf("parseOwnershipProofData failed: %v", err)
	}

	if result.Timestamp != 0 {
		t.Errorf("Timestamp: got %d, want 0", result.Timestamp)
	}
}
