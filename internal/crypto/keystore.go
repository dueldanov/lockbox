package crypto

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

var (
	ErrKeyNotFound      = errors.New("key not found")
	ErrKeyAlreadyExists = errors.New("key already exists")
	ErrInvalidKeyFile   = errors.New("invalid key file")
)

const (
	KeyStoreFileName = "master.key"
	KeyFileMode      = 0600 // Read/write for owner only
	KeyDirMode       = 0700 // Read/write/execute for owner only
)

// KeyStore manages persistent storage of cryptographic keys
type KeyStore struct {
	keyPath string
}

// NewKeyStore creates a new key store at the specified directory
func NewKeyStore(keyDir string) (*KeyStore, error) {
	// Create directory if it doesn't exist
	if err := os.MkdirAll(keyDir, KeyDirMode); err != nil {
		return nil, fmt.Errorf("failed to create key directory: %w", err)
	}

	// Verify directory permissions
	info, err := os.Stat(keyDir)
	if err != nil {
		return nil, fmt.Errorf("failed to stat key directory: %w", err)
	}

	if !info.IsDir() {
		return nil, fmt.Errorf("key path is not a directory: %s", keyDir)
	}

	// On Unix systems, check permissions
	if info.Mode().Perm()&0077 != 0 {
		// Directory is accessible by group or others - fix it
		if err := os.Chmod(keyDir, KeyDirMode); err != nil {
			return nil, fmt.Errorf("failed to fix directory permissions: %w", err)
		}
	}

	return &KeyStore{
		keyPath: filepath.Join(keyDir, KeyStoreFileName),
	}, nil
}

// LoadOrGenerate loads an existing key or generates a new one
func (ks *KeyStore) LoadOrGenerate() ([]byte, error) {
	// Try to load existing key
	key, err := ks.Load()
	if err == nil {
		return key, nil
	}

	if !errors.Is(err, ErrKeyNotFound) {
		return nil, fmt.Errorf("failed to load key: %w", err)
	}

	// Key doesn't exist, generate new one
	key = make([]byte, HKDFKeySize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	// Save the new key
	if err := ks.Save(key); err != nil {
		clearBytes(key)
		return nil, fmt.Errorf("failed to save key: %w", err)
	}

	return key, nil
}

// Load loads the master key from disk
func (ks *KeyStore) Load() ([]byte, error) {
	// Check if file exists
	if _, err := os.Stat(ks.keyPath); os.IsNotExist(err) {
		return nil, ErrKeyNotFound
	}

	// Read file
	data, err := os.ReadFile(ks.keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read key file: %w", err)
	}

	// Verify file permissions
	info, err := os.Stat(ks.keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat key file: %w", err)
	}

	if info.Mode().Perm() != KeyFileMode {
		return nil, fmt.Errorf("%w: invalid permissions %o", ErrInvalidKeyFile, info.Mode().Perm())
	}

	// Decode hex
	key := make([]byte, hex.DecodedLen(len(data)))
	n, err := hex.Decode(key, data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode key: %w", err)
	}

	key = key[:n]

	// Validate key size
	if len(key) != HKDFKeySize {
		clearBytes(key)
		return nil, fmt.Errorf("%w: expected %d bytes, got %d", ErrInvalidKeyFile, HKDFKeySize, len(key))
	}

	return key, nil
}

// Save saves the master key to disk
func (ks *KeyStore) Save(key []byte) error {
	if len(key) != HKDFKeySize {
		return fmt.Errorf("%w: expected %d bytes, got %d", ErrInvalidKeySize, HKDFKeySize, len(key))
	}

	// Check if file already exists
	if _, err := os.Stat(ks.keyPath); err == nil {
		return ErrKeyAlreadyExists
	}

	// Encode to hex
	encoded := make([]byte, hex.EncodedLen(len(key)))
	hex.Encode(encoded, key)

	// Write to temporary file first
	tmpPath := ks.keyPath + ".tmp"
	if err := os.WriteFile(tmpPath, encoded, KeyFileMode); err != nil {
		return fmt.Errorf("failed to write temporary key file: %w", err)
	}

	// Atomic rename
	if err := os.Rename(tmpPath, ks.keyPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("failed to rename key file: %w", err)
	}

	return nil
}

// Delete removes the master key from disk
func (ks *KeyStore) Delete() error {
	if _, err := os.Stat(ks.keyPath); os.IsNotExist(err) {
		return ErrKeyNotFound
	}

	// Overwrite file with random data before deletion (basic secure delete)
	info, err := os.Stat(ks.keyPath)
	if err != nil {
		return fmt.Errorf("failed to stat key file: %w", err)
	}

	randomData := make([]byte, info.Size())
	if _, err := io.ReadFull(rand.Reader, randomData); err != nil {
		return fmt.Errorf("failed to generate random data: %w", err)
	}

	if err := os.WriteFile(ks.keyPath, randomData, KeyFileMode); err != nil {
		return fmt.Errorf("failed to overwrite key file: %w", err)
	}

	// Delete the file
	if err := os.Remove(ks.keyPath); err != nil {
		return fmt.Errorf("failed to delete key file: %w", err)
	}

	return nil
}

// Exists checks if a key file exists
func (ks *KeyStore) Exists() bool {
	_, err := os.Stat(ks.keyPath)
	return err == nil
}

// Path returns the key file path (for logging/debugging)
func (ks *KeyStore) Path() string {
	return ks.keyPath
}
