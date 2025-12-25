package crypto

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

// ============================================
// Checksum Tests (SHA-256 based)
// ============================================

func TestCalculateChecksum_Deterministic(t *testing.T) {
	data := []byte("test data for checksum")

	// Same data should produce same checksum
	checksum1 := calculateChecksum(data)
	checksum2 := calculateChecksum(data)

	require.Equal(t, checksum1, checksum2, "Same data should produce same checksum")
}

func TestCalculateChecksum_DifferentData(t *testing.T) {
	data1 := []byte("data one")
	data2 := []byte("data two")

	checksum1 := calculateChecksum(data1)
	checksum2 := calculateChecksum(data2)

	require.NotEqual(t, checksum1, checksum2, "Different data should produce different checksums")
}

func TestCalculateChecksum_Length(t *testing.T) {
	data := []byte("test data")
	checksum := calculateChecksum(data)

	require.Len(t, checksum, 16, "Checksum should be 16 bytes (128 bits)")
}

func TestVerifyChecksum_Valid(t *testing.T) {
	data := []byte("test data for verification")
	checksum := calculateChecksum(data)

	result := verifyChecksum(data, checksum)
	require.True(t, result, "Valid checksum should verify")
}

func TestVerifyChecksum_TamperedData(t *testing.T) {
	data := []byte("original data")
	checksum := calculateChecksum(data)

	// Tamper with data
	tamperedData := []byte("tampered data")
	result := verifyChecksum(tamperedData, checksum)

	require.False(t, result, "Tampered data should fail verification")
}

func TestVerifyChecksum_TamperedChecksum(t *testing.T) {
	data := []byte("test data")
	checksum := calculateChecksum(data)

	// Tamper with checksum
	tamperedChecksum := make([]byte, len(checksum))
	copy(tamperedChecksum, checksum)
	tamperedChecksum[0] ^= 0xFF // Flip bits

	result := verifyChecksum(data, tamperedChecksum)
	require.False(t, result, "Tampered checksum should fail verification")
}

func TestVerifyChecksum_WrongLength(t *testing.T) {
	data := []byte("test data")
	wrongLengthChecksum := []byte("short")

	result := verifyChecksum(data, wrongLengthChecksum)
	require.False(t, result, "Wrong length checksum should fail")
}

func TestVerifyChecksum_EmptyData(t *testing.T) {
	data := []byte{}
	checksum := calculateChecksum(data)

	result := verifyChecksum(data, checksum)
	require.True(t, result, "Empty data checksum should verify")
}

func TestVerifyChecksum_LargeData(t *testing.T) {
	// Test with 1MB of data
	data := make([]byte, 1024*1024)
	for i := range data {
		data[i] = byte(i % 256)
	}

	checksum := calculateChecksum(data)
	require.Len(t, checksum, 16, "Checksum should still be 16 bytes for large data")

	result := verifyChecksum(data, checksum)
	require.True(t, result, "Large data checksum should verify")
}

func TestCalculateChecksum_NotXOR(t *testing.T) {
	// This test ensures we're not using the old XOR-based checksum
	// XOR checksum would produce identical results for data that differs
	// only by bytes at positions that are 16 bytes apart

	// Create two data slices that would have the same XOR checksum
	// if using the old i%16 XOR algorithm
	data1 := make([]byte, 32)
	data2 := make([]byte, 32)
	copy(data2, data1)
	data2[0] = 0xFF // Change byte at position 0
	data2[16] = 0xFF // XOR would cancel out if using i%16

	checksum1 := calculateChecksum(data1)
	checksum2 := calculateChecksum(data2)

	// With SHA-256, these should be different
	// With old XOR, they might be the same
	require.False(t, bytes.Equal(checksum1, checksum2),
		"Checksum should detect differences that XOR would miss")
}
