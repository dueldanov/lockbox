package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestBinaryHashVerifier_ValidHash verifies correct hash passes
func TestBinaryHashVerifier_ValidHash(t *testing.T) {
	// Create temp file with known content
	tmpfile, err := os.CreateTemp("", "test-binary-*")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())

	content := []byte("test binary content for verification")
	_, err = tmpfile.Write(content)
	require.NoError(t, err)
	tmpfile.Close()

	// Calculate expected hash
	hasher := sha256.New()
	hasher.Write(content)
	expectedHash := hex.EncodeToString(hasher.Sum(nil))

	// Verify with correct hash
	verifier := NewBinaryHashVerifier(map[string]string{
		tmpfile.Name(): expectedHash,
	})

	err = verifier.VerifyBinary(tmpfile.Name())
	require.NoError(t, err, "Verification should succeed with correct hash")
}

// TestBinaryHashVerifier_InvalidHash verifies wrong hash fails
func TestBinaryHashVerifier_InvalidHash(t *testing.T) {
	// Create temp file
	tmpfile, err := os.CreateTemp("", "test-binary-*")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())

	tmpfile.Write([]byte("test content"))
	tmpfile.Close()

	// Use WRONG expected hash
	verifier := NewBinaryHashVerifier(map[string]string{
		tmpfile.Name(): "0000000000000000000000000000000000000000000000000000000000000000",
	})

	err = verifier.VerifyBinary(tmpfile.Name())
	require.Error(t, err, "Verification should FAIL with wrong hash")
	require.Contains(t, err.Error(), "hash mismatch")
}

// TestBinaryHashVerifier_FileNotFound verifies missing file fails
func TestBinaryHashVerifier_FileNotFound(t *testing.T) {
	verifier := NewBinaryHashVerifier(map[string]string{
		"/nonexistent/binary": "abcd1234",
	})

	err := verifier.VerifyBinary("/nonexistent/binary")
	require.Error(t, err, "Verification should fail for missing file")
	require.Contains(t, err.Error(), "failed to open binary")
}

// TestBinaryHashVerifier_NoExpectedHash verifies unregistered file fails
func TestBinaryHashVerifier_NoExpectedHash(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "test-binary-*")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())

	tmpfile.Write([]byte("content"))
	tmpfile.Close()

	// Verifier without expected hash for this file
	verifier := NewBinaryHashVerifier(map[string]string{})

	err = verifier.VerifyBinary(tmpfile.Name())
	require.Error(t, err, "Verification should fail when no expected hash")
	require.Contains(t, err.Error(), "no expected hash")
}

// TestBinaryHashVerifier_VerifyAllBinaries verifies multiple binaries
func TestBinaryHashVerifier_VerifyAllBinaries(t *testing.T) {
	// Create two temp files
	tmpfile1, err := os.CreateTemp("", "test-binary-1-*")
	require.NoError(t, err)
	defer os.Remove(tmpfile1.Name())

	tmpfile2, err := os.CreateTemp("", "test-binary-2-*")
	require.NoError(t, err)
	defer os.Remove(tmpfile2.Name())

	// Write content and calculate hashes
	content1 := []byte("binary 1 content")
	content2 := []byte("binary 2 content")

	tmpfile1.Write(content1)
	tmpfile1.Close()
	tmpfile2.Write(content2)
	tmpfile2.Close()

	hash1 := sha256.Sum256(content1)
	hash2 := sha256.Sum256(content2)

	// Verify both binaries
	verifier := NewBinaryHashVerifier(map[string]string{
		tmpfile1.Name(): hex.EncodeToString(hash1[:]),
		tmpfile2.Name(): hex.EncodeToString(hash2[:]),
	})

	err = verifier.VerifyAllBinaries()
	require.NoError(t, err, "All binaries should verify successfully")
}

// TestBinaryHashVerifier_VerifyAllBinaries_OneFails verifies failure propagates
func TestBinaryHashVerifier_VerifyAllBinaries_OneFails(t *testing.T) {
	tmpfile1, err := os.CreateTemp("", "test-binary-1-*")
	require.NoError(t, err)
	defer os.Remove(tmpfile1.Name())

	tmpfile2, err := os.CreateTemp("", "test-binary-2-*")
	require.NoError(t, err)
	defer os.Remove(tmpfile2.Name())

	content1 := []byte("binary 1")
	content2 := []byte("binary 2")

	tmpfile1.Write(content1)
	tmpfile1.Close()
	tmpfile2.Write(content2)
	tmpfile2.Close()

	hash1 := sha256.Sum256(content1)

	// Verifier with one correct hash and one wrong hash
	verifier := NewBinaryHashVerifier(map[string]string{
		tmpfile1.Name(): hex.EncodeToString(hash1[:]),                                      // Correct
		tmpfile2.Name(): "0000000000000000000000000000000000000000000000000000000000000000", // Wrong
	})

	err = verifier.VerifyAllBinaries()
	require.Error(t, err, "VerifyAllBinaries should fail if any binary fails")
	require.Contains(t, err.Error(), "hash mismatch")
}

// TestBinaryHashVerifier_EmptyFile verifies empty file handling
func TestBinaryHashVerifier_EmptyFile(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "test-empty-*")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())
	tmpfile.Close()

	// Hash of empty file
	emptyHash := sha256.Sum256([]byte{})
	expectedHash := hex.EncodeToString(emptyHash[:])

	verifier := NewBinaryHashVerifier(map[string]string{
		tmpfile.Name(): expectedHash,
	})

	err = verifier.VerifyBinary(tmpfile.Name())
	require.NoError(t, err, "Should verify empty file correctly")
}

// TestBinaryHashVerifier_LargeFile verifies large file handling
func TestBinaryHashVerifier_LargeFile(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "test-large-*")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())

	// Create 1MB file
	largeContent := make([]byte, 1024*1024)
	for i := range largeContent {
		largeContent[i] = byte(i % 256)
	}

	_, err = tmpfile.Write(largeContent)
	require.NoError(t, err)
	tmpfile.Close()

	// Calculate hash
	hash := sha256.Sum256(largeContent)
	expectedHash := hex.EncodeToString(hash[:])

	verifier := NewBinaryHashVerifier(map[string]string{
		tmpfile.Name(): expectedHash,
	})

	err = verifier.VerifyBinary(tmpfile.Name())
	require.NoError(t, err, "Should verify large file correctly")
}

// TestCalculateBinaryHash verifies hash calculation helper
func TestCalculateBinaryHash(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "test-calc-*")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())

	content := []byte("test content for hash calculation")
	tmpfile.Write(content)
	tmpfile.Close()

	// Calculate using helper
	actualHash, err := CalculateBinaryHash(tmpfile.Name())
	require.NoError(t, err)

	// Calculate expected
	expected := sha256.Sum256(content)
	expectedHash := hex.EncodeToString(expected[:])

	require.Equal(t, expectedHash, actualHash, "Calculated hash should match expected")
}

// TestBinaryHashVerifier_AddExpectedHash verifies dynamic hash addition
func TestBinaryHashVerifier_AddExpectedHash(t *testing.T) {
	verifier := NewBinaryHashVerifier(map[string]string{})

	tmpfile, err := os.CreateTemp("", "test-add-*")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())

	content := []byte("dynamic content")
	tmpfile.Write(content)
	tmpfile.Close()

	hash := sha256.Sum256(content)
	hashStr := hex.EncodeToString(hash[:])

	// Add hash dynamically
	verifier.AddExpectedHash(tmpfile.Name(), hashStr)

	// Should now verify successfully
	err = verifier.VerifyBinary(tmpfile.Name())
	require.NoError(t, err, "Should verify after adding expected hash")
}

// TestBinaryHashVerifier_RemoveExpectedHash verifies hash removal
func TestBinaryHashVerifier_RemoveExpectedHash(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "test-remove-*")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())

	content := []byte("content to remove")
	tmpfile.Write(content)
	tmpfile.Close()

	hash := sha256.Sum256(content)
	hashStr := hex.EncodeToString(hash[:])

	verifier := NewBinaryHashVerifier(map[string]string{
		tmpfile.Name(): hashStr,
	})

	// Should verify initially
	err = verifier.VerifyBinary(tmpfile.Name())
	require.NoError(t, err)

	// Remove hash
	verifier.RemoveExpectedHash(tmpfile.Name())

	// Should fail after removal
	err = verifier.VerifyBinary(tmpfile.Name())
	require.Error(t, err)
	require.Contains(t, err.Error(), "no expected hash")
}

// TestBinaryHashVerifier_GetExpectedHash verifies hash retrieval
func TestBinaryHashVerifier_GetExpectedHash(t *testing.T) {
	expectedHash := "abcd1234567890"
	filePath := "/path/to/binary"

	verifier := NewBinaryHashVerifier(map[string]string{
		filePath: expectedHash,
	})

	hash, ok := verifier.GetExpectedHash(filePath)
	require.True(t, ok, "Should find expected hash")
	require.Equal(t, expectedHash, hash)

	// Try non-existent path
	_, ok = verifier.GetExpectedHash("/nonexistent")
	require.False(t, ok, "Should not find hash for non-existent path")
}

// TestBinaryHashVerifier_ListBinaries verifies binary listing
func TestBinaryHashVerifier_ListBinaries(t *testing.T) {
	paths := []string{"/bin/binary1", "/bin/binary2", "/bin/binary3"}
	hashes := map[string]string{
		paths[0]: "hash1",
		paths[1]: "hash2",
		paths[2]: "hash3",
	}

	verifier := NewBinaryHashVerifier(hashes)

	binaries := verifier.ListBinaries()
	require.Len(t, binaries, 3, "Should list all registered binaries")

	// Check all paths are present (order doesn't matter)
	for _, path := range paths {
		require.Contains(t, binaries, path)
	}
}

// TestBinaryHashVerifier_CaseInsensitiveHash verifies hash comparison is case-insensitive
func TestBinaryHashVerifier_CaseInsensitiveHash(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "test-case-*")
	require.NoError(t, err)
	defer os.Remove(tmpfile.Name())

	content := []byte("case test")
	tmpfile.Write(content)
	tmpfile.Close()

	hash := sha256.Sum256(content)
	lowerHash := hex.EncodeToString(hash[:]) // lowercase

	// Use uppercase expected hash
	upperHash := ""
	for _, c := range lowerHash {
		if c >= 'a' && c <= 'f' {
			upperHash += string(c - 'a' + 'A')
		} else {
			upperHash += string(c)
		}
	}

	verifier := NewBinaryHashVerifier(map[string]string{
		tmpfile.Name(): upperHash, // UPPERCASE
	})

	// Should verify successfully (case-insensitive)
	err = verifier.VerifyBinary(tmpfile.Name())
	require.NoError(t, err, "Hash comparison should be case-insensitive")
}

// TestBinaryHashVerifier_VerifyAllBinaries_Empty verifies empty verifier
func TestBinaryHashVerifier_VerifyAllBinaries_Empty(t *testing.T) {
	verifier := NewBinaryHashVerifier(map[string]string{})

	// Should succeed without error (no binaries to verify)
	err := verifier.VerifyAllBinaries()
	require.NoError(t, err, "Empty verifier should succeed")
}

// TestBinaryHashVerifier_RealBinary verifies verification works on actual binary
func TestBinaryHashVerifier_RealBinary(t *testing.T) {
	// Get path to test binary (this test executable)
	testBinary, err := os.Executable()
	require.NoError(t, err)

	// Calculate actual hash
	actualHash, err := CalculateBinaryHash(testBinary)
	require.NoError(t, err)
	require.NotEmpty(t, actualHash)

	t.Logf("Test binary: %s", filepath.Base(testBinary))
	t.Logf("SHA-256: %s", actualHash)

	// Verify with calculated hash
	verifier := NewBinaryHashVerifier(map[string]string{
		testBinary: actualHash,
	})

	err = verifier.VerifyBinary(testBinary)
	require.NoError(t, err, "Should verify test binary successfully")
}
