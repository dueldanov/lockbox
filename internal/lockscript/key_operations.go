package lockscript

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/dueldanov/lockbox/v2/internal/crypto"
)

// Security tier configuration for key operations
type SecurityTier string

const (
	TierBasic    SecurityTier = "Basic"
	TierStandard SecurityTier = "Standard"
	TierPremium  SecurityTier = "Premium"
	TierElite    SecurityTier = "Elite"
)

// Errors for key operations
var (
	ErrInvalidTier       = errors.New("invalid security tier")
	ErrKeyNotFound       = errors.New("key not found")
	ErrInvalidBundleID   = errors.New("invalid bundle ID")
	ErrInvalidToken      = errors.New("invalid access token")
	ErrKeyRotationFailed = errors.New("key rotation failed")
	ErrKeyStoreFailed    = errors.New("key store failed")
	ErrKeyRetrieveFailed = errors.New("key retrieve failed")
	ErrUsernameExists    = errors.New("username already registered")
	ErrUsernameNotFound  = errors.New("username not found")
)

// TierConfig holds decoy configuration for each tier
var TierConfig = map[SecurityTier]crypto.DecoyConfig{
	TierBasic: {
		DecoyRatio:         0.5,
		MetadataDecoyRatio: 0,
	},
	TierStandard: {
		DecoyRatio:         1.0,
		MetadataDecoyRatio: 0,
	},
	TierPremium: {
		DecoyRatio:         1.5,
		MetadataDecoyRatio: 1.0,
	},
	TierElite: {
		DecoyRatio:         2.0,
		MetadataDecoyRatio: 2.0,
	},
}

// KeyBundle represents a stored key bundle with encrypted data
type KeyBundle struct {
	ID            string
	MasterKey     []byte // Master key for HKDF derivation
	Salt          []byte // HKDF salt for key derivation
	EncryptedData []byte // Encrypted key data (nonce prepended)
	DecoyCount    int    // Number of decoy shards generated
	Tier          SecurityTier
	Token         string // Access token for retrieval
}

// KeyOperationsManager manages key storage and retrieval operations
type KeyOperationsManager struct {
	mu        sync.RWMutex
	bundles   map[string]*KeyBundle
	usernames map[string]string // username -> address mapping
}

// NewKeyOperationsManager creates a new key operations manager
func NewKeyOperationsManager() *KeyOperationsManager {
	return &KeyOperationsManager{
		bundles:   make(map[string]*KeyBundle),
		usernames: make(map[string]string),
	}
}

// Global manager instance for LockScript functions
var globalKeyManager = NewKeyOperationsManager()

// StoreKey encrypts and stores a key with the specified security tier
// Returns bundleID and access token
func (m *KeyOperationsManager) StoreKey(key []byte, tier SecurityTier) (bundleID string, token string, err error) {
	config, ok := TierConfig[tier]
	if !ok {
		return "", "", ErrInvalidTier
	}

	// Generate master key for HKDF
	masterKey := make([]byte, crypto.HKDFKeySize)
	if _, err := io.ReadFull(rand.Reader, masterKey); err != nil {
		return "", "", fmt.Errorf("%w: failed to generate master key: %v", ErrKeyStoreFailed, err)
	}

	// Create HKDF encryptor
	encryptor, err := crypto.NewHKDFEncryptor(masterKey)
	if err != nil {
		crypto.ClearBytes(masterKey)
		return "", "", fmt.Errorf("%w: failed to create encryptor: %v", ErrKeyStoreFailed, err)
	}
	defer encryptor.Clear()

	// Generate bundle ID and token
	bundleIDBytes := make([]byte, 16)
	tokenBytes := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, bundleIDBytes); err != nil {
		crypto.ClearBytes(masterKey)
		return "", "", fmt.Errorf("%w: failed to generate bundle ID: %v", ErrKeyStoreFailed, err)
	}
	if _, err := io.ReadFull(rand.Reader, tokenBytes); err != nil {
		crypto.ClearBytes(masterKey)
		return "", "", fmt.Errorf("%w: failed to generate token: %v", ErrKeyStoreFailed, err)
	}

	bundleID = hex.EncodeToString(bundleIDBytes)
	token = hex.EncodeToString(tokenBytes)

	// Encrypt the key with bundle-specific context
	context := []byte("LockBox:key:" + bundleID)
	encryptedData, err := encryptor.EncryptWithContext(key, context)
	if err != nil {
		crypto.ClearBytes(masterKey)
		return "", "", fmt.Errorf("%w: failed to encrypt key: %v", ErrKeyStoreFailed, err)
	}

	// Save the salt for later decryption
	salt := encryptor.GetSalt()

	// Calculate decoy count based on tier ratio
	decoyCount := int(config.DecoyRatio * float64(len(key)/4096+1))
	if decoyCount == 0 && config.DecoyRatio > 0 {
		decoyCount = 1
	}

	// Store the bundle
	bundle := &KeyBundle{
		ID:            bundleID,
		MasterKey:     masterKey, // Transfer ownership
		Salt:          salt,      // Save salt for decryption
		EncryptedData: encryptedData,
		DecoyCount:    decoyCount,
		Tier:          tier,
		Token:         token,
	}

	m.mu.Lock()
	m.bundles[bundleID] = bundle
	m.mu.Unlock()

	return bundleID, token, nil
}

// GetKey retrieves and decrypts a key using the bundle ID and token
func (m *KeyOperationsManager) GetKey(bundleID, token string) ([]byte, error) {
	m.mu.RLock()
	bundle, exists := m.bundles[bundleID]
	m.mu.RUnlock()

	if !exists {
		return nil, ErrKeyNotFound
	}

	if bundle.Token != token {
		return nil, ErrInvalidToken
	}

	// Create HKDF encryptor with the stored master key and salt
	encryptor, err := crypto.NewHKDFEncryptorWithSalt(bundle.MasterKey, bundle.Salt)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create encryptor: %v", ErrKeyRetrieveFailed, err)
	}
	defer encryptor.Clear()

	// Decrypt with the same context
	context := []byte("LockBox:key:" + bundleID)
	key, err := encryptor.DecryptWithContext(bundle.EncryptedData, context)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to decrypt key: %v", ErrKeyRetrieveFailed, err)
	}

	return key, nil
}

// RotateKey rotates a key by re-encrypting with a new master key
// Returns new bundleID and token
func (m *KeyOperationsManager) RotateKey(bundleID, token string) (newBundleID string, newToken string, err error) {
	// Get the original key
	originalKey, err := m.GetKey(bundleID, token)
	if err != nil {
		return "", "", fmt.Errorf("%w: failed to retrieve original key: %v", ErrKeyRotationFailed, err)
	}
	defer crypto.ClearBytes(originalKey)

	// Get the original tier
	m.mu.RLock()
	bundle, exists := m.bundles[bundleID]
	m.mu.RUnlock()

	if !exists {
		return "", "", ErrKeyNotFound
	}

	tier := bundle.Tier

	// Store with new encryption
	newBundleID, newToken, err = m.StoreKey(originalKey, tier)
	if err != nil {
		return "", "", fmt.Errorf("%w: failed to store rotated key: %v", ErrKeyRotationFailed, err)
	}

	// Delete old bundle
	m.DeleteKey(bundleID, token)

	return newBundleID, newToken, nil
}

// DeleteKey deletes a key bundle
func (m *KeyOperationsManager) DeleteKey(bundleID, token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	bundle, exists := m.bundles[bundleID]
	if !exists {
		return ErrKeyNotFound
	}

	if bundle.Token != token {
		return ErrInvalidToken
	}

	// Clear sensitive data
	crypto.ClearBytes(bundle.MasterKey)
	crypto.ClearBytes(bundle.Salt)
	crypto.ClearBytes(bundle.EncryptedData)

	delete(m.bundles, bundleID)
	return nil
}

// DeriveKey derives a key using HKDF for a specific purpose
func (m *KeyOperationsManager) DeriveKey(masterKey []byte, purpose string, index uint32) ([]byte, error) {
	hkdfManager, err := crypto.NewHKDFManager(masterKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create HKDF manager: %w", err)
	}
	defer hkdfManager.Clear()

	// Create context from purpose and index
	context := []byte(fmt.Sprintf("%s:%d", purpose, index))
	return hkdfManager.DeriveKey(context)
}

// RegisterUsername registers a username to an address
func (m *KeyOperationsManager) RegisterUsername(username, address string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.usernames[username]; exists {
		return ErrUsernameExists
	}

	m.usernames[username] = address
	return nil
}

// ResolveUsername resolves a username to its address
func (m *KeyOperationsManager) ResolveUsername(username string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	address, exists := m.usernames[username]
	if !exists {
		return "", ErrUsernameNotFound
	}

	return address, nil
}

// LockScript builtin function implementations

// funcStoreKey is the LockScript builtin for storing a key
func funcStoreKey(args []interface{}) (interface{}, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("storeKey: expected 2 arguments (key, tier)")
	}

	keyStr, ok := args[0].(string)
	if !ok {
		return nil, fmt.Errorf("storeKey: key must be a string")
	}

	tierStr, ok := args[1].(string)
	if !ok {
		return nil, fmt.Errorf("storeKey: tier must be a string")
	}

	tier := SecurityTier(tierStr)
	bundleID, token, err := globalKeyManager.StoreKey([]byte(keyStr), tier)
	if err != nil {
		return nil, err
	}

	// Return as map with bundleId and token
	return map[string]interface{}{
		"bundleId": bundleID,
		"token":    token,
	}, nil
}

// funcGetKey is the LockScript builtin for retrieving a key
func funcGetKey(args []interface{}) (interface{}, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("getKey: expected 2 arguments (bundleId, token)")
	}

	bundleID, ok := args[0].(string)
	if !ok {
		return nil, fmt.Errorf("getKey: bundleId must be a string")
	}

	token, ok := args[1].(string)
	if !ok {
		return nil, fmt.Errorf("getKey: token must be a string")
	}

	key, err := globalKeyManager.GetKey(bundleID, token)
	if err != nil {
		return nil, err
	}

	return string(key), nil
}

// funcRotate is the LockScript builtin for rotating a key
func funcRotate(args []interface{}) (interface{}, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("rotate: expected 2 arguments (bundleId, token)")
	}

	bundleID, ok := args[0].(string)
	if !ok {
		return nil, fmt.Errorf("rotate: bundleId must be a string")
	}

	token, ok := args[1].(string)
	if !ok {
		return nil, fmt.Errorf("rotate: token must be a string")
	}

	newBundleID, newToken, err := globalKeyManager.RotateKey(bundleID, token)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"bundleId": newBundleID,
		"token":    newToken,
	}, nil
}

// funcDeriveKey is the LockScript builtin for HKDF key derivation
func funcDeriveKey(args []interface{}) (interface{}, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("deriveKey: expected 2 arguments (purpose, index)")
	}

	purpose, ok := args[0].(string)
	if !ok {
		return nil, fmt.Errorf("deriveKey: purpose must be a string")
	}

	index, ok := args[1].(int64)
	if !ok {
		return nil, fmt.Errorf("deriveKey: index must be an integer")
	}

	// Generate a temporary master key for derivation
	// In production, this would use a stored master key
	masterKey := make([]byte, crypto.HKDFKeySize)
	if _, err := io.ReadFull(rand.Reader, masterKey); err != nil {
		return nil, fmt.Errorf("deriveKey: failed to generate master key: %w", err)
	}
	defer crypto.ClearBytes(masterKey)

	derivedKey, err := globalKeyManager.DeriveKey(masterKey, purpose, uint32(index))
	if err != nil {
		return nil, err
	}

	return hex.EncodeToString(derivedKey), nil
}

// funcRegisterUsername is the LockScript builtin for username registration
func funcRegisterUsername(args []interface{}) (interface{}, error) {
	if len(args) != 2 {
		return nil, fmt.Errorf("registerUsername: expected 2 arguments (username, address)")
	}

	username, ok := args[0].(string)
	if !ok {
		return nil, fmt.Errorf("registerUsername: username must be a string")
	}

	address, ok := args[1].(string)
	if !ok {
		return nil, fmt.Errorf("registerUsername: address must be a string")
	}

	err := globalKeyManager.RegisterUsername(username, address)
	if err != nil {
		return nil, err
	}

	return true, nil
}

// funcResolveUsername is the LockScript builtin for username resolution
func funcResolveUsername(args []interface{}) (interface{}, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("resolveUsername: expected 1 argument (username)")
	}

	username, ok := args[0].(string)
	if !ok {
		return nil, fmt.Errorf("resolveUsername: username must be a string")
	}

	address, err := globalKeyManager.ResolveUsername(username)
	if err != nil {
		return nil, err
	}

	return address, nil
}

// GetKeyOperationsBuiltins returns the key operations builtin functions
func GetKeyOperationsBuiltins() []BuiltinFunction {
	return []BuiltinFunction{
		{
			Name:    "storeKey",
			MinArgs: 2,
			MaxArgs: 2,
			Handler: funcStoreKey,
		},
		{
			Name:    "getKey",
			MinArgs: 2,
			MaxArgs: 2,
			Handler: funcGetKey,
		},
		{
			Name:    "rotate",
			MinArgs: 2,
			MaxArgs: 2,
			Handler: funcRotate,
		},
		{
			Name:    "deriveKey",
			MinArgs: 2,
			MaxArgs: 2,
			Handler: funcDeriveKey,
		},
		{
			Name:    "registerUsername",
			MinArgs: 2,
			MaxArgs: 2,
			Handler: funcRegisterUsername,
		},
		{
			Name:    "resolveUsername",
			MinArgs: 1,
			MaxArgs: 1,
			Handler: funcResolveUsername,
		},
	}
}

// ResetGlobalKeyManager resets the global key manager (for testing)
func ResetGlobalKeyManager() {
	globalKeyManager = NewKeyOperationsManager()
}

// Exported wrappers for CLI tool

// FuncStoreKeyExported is the exported wrapper for storeKey builtin
func FuncStoreKeyExported(args []interface{}) (interface{}, error) {
	return funcStoreKey(args)
}

// FuncGetKeyExported is the exported wrapper for getKey builtin
func FuncGetKeyExported(args []interface{}) (interface{}, error) {
	return funcGetKey(args)
}

// FuncRotateExported is the exported wrapper for rotate builtin
func FuncRotateExported(args []interface{}) (interface{}, error) {
	return funcRotate(args)
}

// FuncDeriveKeyExported is the exported wrapper for deriveKey builtin
func FuncDeriveKeyExported(args []interface{}) (interface{}, error) {
	return funcDeriveKey(args)
}

// FuncRegisterUsernameExported is the exported wrapper for registerUsername builtin
func FuncRegisterUsernameExported(args []interface{}) (interface{}, error) {
	return funcRegisterUsername(args)
}

// FuncResolveUsernameExported is the exported wrapper for resolveUsername builtin
func FuncResolveUsernameExported(args []interface{}) (interface{}, error) {
	return funcResolveUsername(args)
}
