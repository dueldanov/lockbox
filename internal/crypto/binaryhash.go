package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// BinaryHashVerifier verifies software integrity using SHA-256 hashes
type BinaryHashVerifier struct {
	expectedHashes map[string]string // filename → expected SHA256 hash
}

// NewBinaryHashVerifier creates a verifier with expected hashes
//
// Example:
//   verifier := NewBinaryHashVerifier(map[string]string{
//       "/usr/local/bin/lockbox": "a1b2c3d4...",
//   })
func NewBinaryHashVerifier(expectedHashes map[string]string) *BinaryHashVerifier {
	return &BinaryHashVerifier{
		expectedHashes: expectedHashes,
	}
}

// VerifyBinary checks if binary matches expected hash
//
// Parameters:
//   - filePath: absolute path to binary file
//
// Returns:
//   - error if hash mismatch or file cannot be read
//
// Security: Uses SHA-256 for integrity verification.
// Does NOT verify signatures (that requires separate PKI infrastructure).
func (v *BinaryHashVerifier) VerifyBinary(filePath string) error {
	// Calculate actual hash
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open binary %s: %w", filePath, err)
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return fmt.Errorf("failed to hash binary %s: %w", filePath, err)
	}

	actualHash := hex.EncodeToString(hasher.Sum(nil))

	// Get expected hash
	expectedHash, ok := v.expectedHashes[filePath]
	if !ok {
		return fmt.Errorf("no expected hash for binary: %s", filePath)
	}

	// Compare (case-insensitive)
	if !equalHashes(actualHash, expectedHash) {
		return fmt.Errorf("binary hash mismatch for %s:\n  expected: %s\n  actual:   %s",
			filepath.Base(filePath), expectedHash, actualHash)
	}

	return nil
}

// VerifyAllBinaries verifies all registered binaries
//
// Returns:
//   - error if any binary fails verification
//
// Example:
//   if err := verifier.VerifyAllBinaries(); err != nil {
//       log.Fatal("Binary integrity check failed", err)
//   }
func (v *BinaryHashVerifier) VerifyAllBinaries() error {
	if len(v.expectedHashes) == 0 {
		// No binaries registered - skip verification
		return nil
	}

	for filePath := range v.expectedHashes {
		if err := v.VerifyBinary(filePath); err != nil {
			return err
		}
	}

	return nil
}

// CalculateBinaryHash calculates SHA-256 hash of a binary file
//
// This is a helper function for generating expected hashes during build.
//
// Example:
//   hash, err := CalculateBinaryHash("/usr/local/bin/lockbox")
//   fmt.Printf("Hash: %s\n", hash)
func CalculateBinaryHash(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to open file %s: %w", filePath, err)
	}
	defer file.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", fmt.Errorf("failed to hash file %s: %w", filePath, err)
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// AddExpectedHash adds or updates an expected hash
//
// Useful for dynamic hash registration.
func (v *BinaryHashVerifier) AddExpectedHash(filePath string, expectedHash string) {
	v.expectedHashes[filePath] = expectedHash
}

// RemoveExpectedHash removes an expected hash
//
// Useful for testing or dynamic configuration.
func (v *BinaryHashVerifier) RemoveExpectedHash(filePath string) {
	delete(v.expectedHashes, filePath)
}

// GetExpectedHash retrieves the expected hash for a binary
//
// Returns:
//   - hash string and true if hash exists
//   - empty string and false if not found
func (v *BinaryHashVerifier) GetExpectedHash(filePath string) (string, bool) {
	hash, ok := v.expectedHashes[filePath]
	return hash, ok
}

// ListBinaries returns all registered binary paths
func (v *BinaryHashVerifier) ListBinaries() []string {
	binaries := make([]string, 0, len(v.expectedHashes))
	for path := range v.expectedHashes {
		binaries = append(binaries, path)
	}
	return binaries
}

// equalHashes compares two hex-encoded hashes (case-insensitive)
func equalHashes(hash1, hash2 string) bool {
	if len(hash1) != len(hash2) {
		return false
	}

	// Case-insensitive comparison
	for i := 0; i < len(hash1); i++ {
		c1 := hash1[i]
		c2 := hash2[i]

		// Normalize to lowercase
		if c1 >= 'A' && c1 <= 'F' {
			c1 = c1 - 'A' + 'a'
		}
		if c2 >= 'A' && c2 <= 'F' {
			c2 = c2 - 'A' + 'a'
		}

		if c1 != c2 {
			return false
		}
	}

	return true
}
