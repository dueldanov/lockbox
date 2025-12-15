# Phase 1: DEV — Detailed Implementation Guide

**Objective:** Make the system functional. Data persists correctly, basic operations work.
**Estimated Time:** 5-7 days
**Prerequisites:** Go 1.21+, access to codebase

---

## Table of Contents

1. [D1: Fix masterKey Copy Bug](#d1-fix-masterkey-copy-bug)
2. [D2: Implement deserializeShard()](#d2-implement-deserializeshard)
3. [D3: Implement getOwnershipProof()](#d3-implement-getownershipproof)
4. [D4: Implement Key Persistence](#d4-implement-key-persistence)
5. [D5: Implement Signature Verification](#d5-implement-signature-verification)
6. [D6: Replace XOR with SHA256 in ZKP](#d6-replace-xor-with-sha256-in-zkp)
7. [D7: Fix Import Cycle](#d7-fix-import-cycle)
8. [Testing Checklist](#testing-checklist)
9. [Definition of Done](#definition-of-done)

---

## D1: Fix masterKey Copy Bug

### Priority: CRITICAL
### Effort: 1 hour
### File: `internal/crypto/hkdf.go`
### Lines: 55-63

### Problem

The master key is never copied into the HKDFManager structure. The struct always contains zeros.

### Current Code (BROKEN)

```go
// internal/crypto/hkdf.go:43-63
func NewHKDFManager(masterKey []byte) (*HKDFManager, error) {
    if len(masterKey) != HKDFKeySize {
        return nil, fmt.Errorf("%w: expected %d, got %d", ErrInvalidKeySize, HKDFKeySize, len(masterKey))
    }

    // Generate random salt
    salt := make([]byte, HKDFSaltSize)
    if _, err := io.ReadFull(rand.Reader, salt); err != nil {
        return nil, fmt.Errorf("failed to generate salt: %w", err)
    }

    return &HKDFManager{
        masterKey: make([]byte, len(masterKey)),  // ❌ Creates zeros, never copies!
        salt:      salt,
        derivedKeysPool: sync.Pool{
            New: func() interface{} {
                return make([]byte, HKDFKeySize)
            },
        },
    }, nil
}
```

### Fixed Code

```go
// internal/crypto/hkdf.go:43-68
func NewHKDFManager(masterKey []byte) (*HKDFManager, error) {
    if len(masterKey) != HKDFKeySize {
        return nil, fmt.Errorf("%w: expected %d, got %d", ErrInvalidKeySize, HKDFKeySize, len(masterKey))
    }

    // Generate random salt
    salt := make([]byte, HKDFSaltSize)
    if _, err := io.ReadFull(rand.Reader, salt); err != nil {
        return nil, fmt.Errorf("failed to generate salt: %w", err)
    }

    // Create manager with properly copied key
    h := &HKDFManager{
        masterKey: make([]byte, len(masterKey)),
        salt:      salt,
        derivedKeysPool: sync.Pool{
            New: func() interface{} {
                return make([]byte, HKDFKeySize)
            },
        },
    }

    // ✅ FIX: Actually copy the master key
    copy(h.masterKey, masterKey)

    return h, nil
}
```

### Test

```go
// internal/crypto/hkdf_test.go
func TestNewHKDFManager_MasterKeyCopied(t *testing.T) {
    masterKey := make([]byte, HKDFKeySize)
    rand.Read(masterKey)

    manager, err := NewHKDFManager(masterKey)
    require.NoError(t, err)

    // Verify key is not all zeros
    allZeros := true
    for _, b := range manager.masterKey {
        if b != 0 {
            allZeros = false
            break
        }
    }
    assert.False(t, allZeros, "masterKey should not be all zeros")

    // Verify key matches input
    assert.Equal(t, masterKey, manager.masterKey)
}

func TestNewHKDFManager_DeriveKeyConsistent(t *testing.T) {
    masterKey := make([]byte, HKDFKeySize)
    rand.Read(masterKey)

    manager, _ := NewHKDFManager(masterKey)

    // Same context should produce same derived key
    key1, _ := manager.DeriveKey([]byte("test-context"))
    key2, _ := manager.DeriveKey([]byte("test-context"))

    assert.Equal(t, key1, key2)

    // Different context should produce different key
    key3, _ := manager.DeriveKey([]byte("other-context"))
    assert.NotEqual(t, key1, key3)
}
```

### Verification

```bash
go test -v ./internal/crypto/... -run TestNewHKDFManager
```

---

## D2: Implement deserializeShard()

### Priority: CRITICAL
### Effort: 1 day
### File: `internal/service/service.go`
### Lines: 365-369

### Problem

The function returns an empty struct, ignoring all input data.

### Current Code (BROKEN)

```go
// internal/service/service.go:365-369
func (s *Service) deserializeShard(data []byte) (*crypto.CharacterShard, error) {
    // Simple deserialization - in production use protobuf
    // This is a placeholder implementation
    return &crypto.CharacterShard{}, nil  // ❌ Always empty!
}
```

### Serialization Format Reference

First, look at how data is serialized in `serializeShard()`:

```go
// internal/service/service.go:351-363
func (s *Service) serializeShard(shard *crypto.CharacterShard) ([]byte, error) {
    // Format: ID|Index|Total|Timestamp|Data(hex)|Nonce(hex)|Checksum(hex)
    data := fmt.Sprintf("%d|%d|%d|%d|%s|%s|%s",
        shard.ID,
        shard.Index,
        shard.Total,
        shard.Timestamp,
        hex.EncodeToString(shard.Data),
        hex.EncodeToString(shard.Nonce),
        hex.EncodeToString(shard.Checksum),
    )
    return []byte(data), nil
}
```

### Fixed Code

```go
// internal/service/service.go:365-420
func (s *Service) deserializeShard(data []byte) (*crypto.CharacterShard, error) {
    if len(data) == 0 {
        return nil, errors.New("empty shard data")
    }

    // Format: ID|Index|Total|Timestamp|Data(hex)|Nonce(hex)|Checksum(hex)
    parts := strings.Split(string(data), "|")
    if len(parts) != 7 {
        return nil, fmt.Errorf("invalid shard format: expected 7 parts, got %d", len(parts))
    }

    // Parse ID
    id, err := strconv.ParseUint(parts[0], 10, 32)
    if err != nil {
        return nil, fmt.Errorf("invalid shard ID: %w", err)
    }

    // Parse Index
    index, err := strconv.ParseUint(parts[1], 10, 32)
    if err != nil {
        return nil, fmt.Errorf("invalid shard index: %w", err)
    }

    // Parse Total
    total, err := strconv.ParseUint(parts[2], 10, 32)
    if err != nil {
        return nil, fmt.Errorf("invalid shard total: %w", err)
    }

    // Parse Timestamp
    timestamp, err := strconv.ParseInt(parts[3], 10, 64)
    if err != nil {
        return nil, fmt.Errorf("invalid shard timestamp: %w", err)
    }

    // Decode Data (hex)
    shardData, err := hex.DecodeString(parts[4])
    if err != nil {
        return nil, fmt.Errorf("invalid shard data hex: %w", err)
    }

    // Decode Nonce (hex)
    nonce, err := hex.DecodeString(parts[5])
    if err != nil {
        return nil, fmt.Errorf("invalid shard nonce hex: %w", err)
    }

    // Decode Checksum (hex)
    checksum, err := hex.DecodeString(parts[6])
    if err != nil {
        return nil, fmt.Errorf("invalid shard checksum hex: %w", err)
    }

    return &crypto.CharacterShard{
        ID:        uint32(id),
        Index:     uint32(index),
        Total:     uint32(total),
        Timestamp: timestamp,
        Data:      shardData,
        Nonce:     nonce,
        Checksum:  checksum,
    }, nil
}
```

### Required Import

Add to imports at top of file:

```go
import (
    // ... existing imports ...
    "strconv"
    "strings"
)
```

### Test

```go
// internal/service/service_test.go
func TestShardSerializationRoundtrip(t *testing.T) {
    s := &Service{}

    original := &crypto.CharacterShard{
        ID:        12345,
        Index:     2,
        Total:     5,
        Timestamp: time.Now().Unix(),
        Data:      []byte("encrypted data here"),
        Nonce:     []byte("random-nonce-24bytes"),
        Checksum:  []byte("checksum-16bytes"),
    }

    // Serialize
    serialized, err := s.serializeShard(original)
    require.NoError(t, err)
    require.NotEmpty(t, serialized)

    // Deserialize
    restored, err := s.deserializeShard(serialized)
    require.NoError(t, err)

    // Verify all fields match
    assert.Equal(t, original.ID, restored.ID)
    assert.Equal(t, original.Index, restored.Index)
    assert.Equal(t, original.Total, restored.Total)
    assert.Equal(t, original.Timestamp, restored.Timestamp)
    assert.Equal(t, original.Data, restored.Data)
    assert.Equal(t, original.Nonce, restored.Nonce)
    assert.Equal(t, original.Checksum, restored.Checksum)
}

func TestDeserializeShard_InvalidInput(t *testing.T) {
    s := &Service{}

    testCases := []struct {
        name  string
        input []byte
    }{
        {"empty", []byte{}},
        {"wrong parts count", []byte("1|2|3")},
        {"invalid id", []byte("abc|2|3|4|aa|bb|cc")},
        {"invalid hex", []byte("1|2|3|4|ZZZZ|bb|cc")},
    }

    for _, tc := range testCases {
        t.Run(tc.name, func(t *testing.T) {
            _, err := s.deserializeShard(tc.input)
            assert.Error(t, err)
        })
    }
}
```

### Verification

```bash
go test -v ./internal/service/... -run TestShard
```

---

## D3: Implement getOwnershipProof()

### Priority: CRITICAL
### Effort: 4 hours
### File: `internal/service/service.go`
### Lines: 381-389

### Problem

Function reads data from storage but ignores it, returning empty proof.

### Current Code (BROKEN)

```go
// internal/service/service.go:381-389
func (s *Service) getOwnershipProof(assetID string) (*crypto.OwnershipProof, error) {
    key := fmt.Sprintf("proof_%s", assetID)
    _, err := s.storage.UTXOStore().Get([]byte(key))  // ❌ Data ignored!
    if err != nil {
        return nil, err
    }
    // Deserialize proof - placeholder
    return &crypto.OwnershipProof{}, nil  // ❌ Empty proof!
}
```

### Serialization Format Reference

Look at `storeOwnershipProof()`:

```go
// internal/service/service.go:371-379
func (s *Service) storeOwnershipProof(assetID string, proof *crypto.OwnershipProof) error {
    key := fmt.Sprintf("proof_%s", assetID)
    // Format: AssetCommitment(hex)|OwnerAddress(hex)|Timestamp
    value := fmt.Sprintf("%s|%s|%d",
        hex.EncodeToString(proof.AssetCommitment),
        hex.EncodeToString(proof.OwnerAddress),
        proof.Timestamp,
    )
    return s.storage.UTXOStore().Set([]byte(key), []byte(value))
}
```

### Fixed Code

```go
// internal/service/service.go:381-420
func (s *Service) getOwnershipProof(assetID string) (*crypto.OwnershipProof, error) {
    key := fmt.Sprintf("proof_%s", assetID)
    data, err := s.storage.UTXOStore().Get([]byte(key))
    if err != nil {
        return nil, fmt.Errorf("failed to get ownership proof: %w", err)
    }

    if len(data) == 0 {
        return nil, errors.New("ownership proof not found")
    }

    // Format: AssetCommitment(hex)|OwnerAddress(hex)|Timestamp
    parts := strings.Split(string(data), "|")
    if len(parts) != 3 {
        return nil, fmt.Errorf("invalid proof format: expected 3 parts, got %d", len(parts))
    }

    // Decode AssetCommitment
    assetCommitment, err := hex.DecodeString(parts[0])
    if err != nil {
        return nil, fmt.Errorf("invalid asset commitment hex: %w", err)
    }

    // Decode OwnerAddress
    ownerAddress, err := hex.DecodeString(parts[1])
    if err != nil {
        return nil, fmt.Errorf("invalid owner address hex: %w", err)
    }

    // Parse Timestamp
    timestamp, err := strconv.ParseInt(parts[2], 10, 64)
    if err != nil {
        return nil, fmt.Errorf("invalid timestamp: %w", err)
    }

    return &crypto.OwnershipProof{
        AssetCommitment: assetCommitment,
        OwnerAddress:    ownerAddress,
        Timestamp:       timestamp,
        // Note: Proof field (groth16.Proof) needs separate serialization
        // For now, we store only the public parts
    }, nil
}
```

### Test

```go
// internal/service/service_test.go
func TestOwnershipProofRoundtrip(t *testing.T) {
    // Setup mock storage
    mockStorage := newMockStorage()
    s := &Service{storage: mockStorage}

    assetID := "test-asset-123"
    original := &crypto.OwnershipProof{
        AssetCommitment: []byte("commitment-data-32bytes-here!!!"),
        OwnerAddress:    []byte("owner-address-32bytes-here!!!!!"),
        Timestamp:       time.Now().Unix(),
    }

    // Store
    err := s.storeOwnershipProof(assetID, original)
    require.NoError(t, err)

    // Retrieve
    restored, err := s.getOwnershipProof(assetID)
    require.NoError(t, err)

    // Verify
    assert.Equal(t, original.AssetCommitment, restored.AssetCommitment)
    assert.Equal(t, original.OwnerAddress, restored.OwnerAddress)
    assert.Equal(t, original.Timestamp, restored.Timestamp)
}

func TestGetOwnershipProof_NotFound(t *testing.T) {
    mockStorage := newMockStorage()
    s := &Service{storage: mockStorage}

    _, err := s.getOwnershipProof("non-existent-asset")
    assert.Error(t, err)
}
```

---

## D4: Implement Key Persistence

### Priority: CRITICAL
### Effort: 1 day
### File: `internal/service/service.go`
### Lines: 46-84

### Problem

Master key is generated randomly on each startup and never saved.

### Solution Overview

For DEV phase, we'll implement file-based key persistence. PROD phase will use KMS.

### New File: `internal/crypto/keystore.go`

```go
// internal/crypto/keystore.go
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

const (
    KeyFilePermissions = 0600  // Owner read/write only
    KeyFileName        = ".lockbox_master_key"
)

var (
    ErrKeyNotFound     = errors.New("master key not found")
    ErrInvalidKeyFile  = errors.New("invalid key file format")
)

// KeyStore manages master key persistence (DEV implementation)
// WARNING: For production, use KMS (Vault/AWS KMS/GCP KMS)
type KeyStore struct {
    keyPath string
}

// NewKeyStore creates a key store at the specified directory
func NewKeyStore(directory string) (*KeyStore, error) {
    if directory == "" {
        homeDir, err := os.UserHomeDir()
        if err != nil {
            return nil, fmt.Errorf("failed to get home directory: %w", err)
        }
        directory = filepath.Join(homeDir, ".lockbox")
    }

    // Ensure directory exists
    if err := os.MkdirAll(directory, 0700); err != nil {
        return nil, fmt.Errorf("failed to create key directory: %w", err)
    }

    return &KeyStore{
        keyPath: filepath.Join(directory, KeyFileName),
    }, nil
}

// LoadOrGenerate loads existing key or generates a new one
func (ks *KeyStore) LoadOrGenerate() ([]byte, error) {
    // Try to load existing key
    key, err := ks.Load()
    if err == nil {
        return key, nil
    }

    if !errors.Is(err, ErrKeyNotFound) {
        return nil, err
    }

    // Generate new key
    key = make([]byte, HKDFKeySize)
    if _, err := io.ReadFull(rand.Reader, key); err != nil {
        return nil, fmt.Errorf("failed to generate master key: %w", err)
    }

    // Save key
    if err := ks.Save(key); err != nil {
        return nil, fmt.Errorf("failed to save master key: %w", err)
    }

    return key, nil
}

// Load reads the master key from disk
func (ks *KeyStore) Load() ([]byte, error) {
    data, err := os.ReadFile(ks.keyPath)
    if err != nil {
        if os.IsNotExist(err) {
            return nil, ErrKeyNotFound
        }
        return nil, fmt.Errorf("failed to read key file: %w", err)
    }

    // Key is stored as hex
    key, err := hex.DecodeString(string(data))
    if err != nil {
        return nil, ErrInvalidKeyFile
    }

    if len(key) != HKDFKeySize {
        return nil, ErrInvalidKeyFile
    }

    return key, nil
}

// Save writes the master key to disk
func (ks *KeyStore) Save(key []byte) error {
    if len(key) != HKDFKeySize {
        return ErrInvalidKeySize
    }

    // Store as hex
    data := hex.EncodeToString(key)

    if err := os.WriteFile(ks.keyPath, []byte(data), KeyFilePermissions); err != nil {
        return fmt.Errorf("failed to write key file: %w", err)
    }

    return nil
}

// Path returns the key file path (for logging/debugging)
func (ks *KeyStore) Path() string {
    return ks.keyPath
}

// Delete removes the key file (use with caution!)
func (ks *KeyStore) Delete() error {
    if err := os.Remove(ks.keyPath); err != nil && !os.IsNotExist(err) {
        return fmt.Errorf("failed to delete key file: %w", err)
    }
    return nil
}
```

### Modified: `internal/service/service.go`

```go
// internal/service/service.go:46-90
func NewService(
    storage *storage.Storage,
    utxoManager *utxo.Manager,
    syncManager *syncmanager.SyncManager,
    protocolManager *protocol.Manager,
    config *lockbox.ServiceConfig,
) (*Service, error) {
    storageManager, err := lockbox.NewStorageManager(storage.UTXOStore())
    if err != nil {
        return nil, err
    }

    // ✅ FIX: Use KeyStore instead of generating new key each time
    keyStore, err := crypto.NewKeyStore(config.DataDir)
    if err != nil {
        return nil, fmt.Errorf("failed to initialize key store: %w", err)
    }

    masterKey, err := keyStore.LoadOrGenerate()
    if err != nil {
        return nil, fmt.Errorf("failed to load/generate master key: %w", err)
    }

    // Log key path (but never the key itself!)
    fmt.Printf("Using master key from: %s\n", keyStore.Path())

    // Initialize cryptography components
    shardEncryptor, err := crypto.NewShardEncryptor(masterKey, 4096)
    if err != nil {
        // Clear key from memory on error
        crypto.ClearBytes(masterKey)
        return nil, fmt.Errorf("failed to initialize shard encryptor: %w", err)
    }

    // Clear the local copy of the key (encryptor has its own copy now)
    crypto.ClearBytes(masterKey)

    zkpManager := crypto.NewZKPManager()

    return &Service{
        storage:         storage,
        utxoManager:     utxoManager,
        syncManager:     syncManager,
        protocolManager: protocolManager,
        config:          config,
        storageManager:  storageManager,
        shardEncryptor:  shardEncryptor,
        zkpManager:      zkpManager,
        lockedAssets:    make(map[string]*lockbox.LockedAsset),
        pendingUnlocks:  make(map[string]time.Time),
    }, nil
}
```

### Export clearBytes

Add to `internal/crypto/memory.go`:

```go
// ClearBytes is the exported version of clearBytes for use by other packages
func ClearBytes(b []byte) {
    clearBytes(b)
}
```

### Test

```go
// internal/crypto/keystore_test.go
func TestKeyStore_LoadOrGenerate(t *testing.T) {
    tmpDir := t.TempDir()

    // First call: should generate new key
    ks1, err := NewKeyStore(tmpDir)
    require.NoError(t, err)

    key1, err := ks1.LoadOrGenerate()
    require.NoError(t, err)
    require.Len(t, key1, HKDFKeySize)

    // Second call: should load same key
    ks2, err := NewKeyStore(tmpDir)
    require.NoError(t, err)

    key2, err := ks2.LoadOrGenerate()
    require.NoError(t, err)

    assert.Equal(t, key1, key2, "keys should match across restarts")
}

func TestKeyStore_Persistence(t *testing.T) {
    tmpDir := t.TempDir()

    // Generate and save
    ks, _ := NewKeyStore(tmpDir)
    originalKey, _ := ks.LoadOrGenerate()

    // Simulate restart: new KeyStore instance
    ks2, _ := NewKeyStore(tmpDir)
    loadedKey, err := ks2.Load()

    require.NoError(t, err)
    assert.Equal(t, originalKey, loadedKey)
}

func TestKeyStore_FilePermissions(t *testing.T) {
    tmpDir := t.TempDir()

    ks, _ := NewKeyStore(tmpDir)
    ks.LoadOrGenerate()

    info, err := os.Stat(ks.Path())
    require.NoError(t, err)

    // Check permissions are restrictive (0600)
    assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}
```

---

## D5: Implement Signature Verification

### Priority: HIGH
### Effort: 1 day
### File: `internal/lockscript/vm.go`
### Lines: 306-309

### Problem

Signature verification is a stub that accepts any non-empty string.

### Current Code (BROKEN)

```go
// internal/lockscript/vm.go:306-309
func (vm *VirtualMachine) verifySignature(pubKey, message, signature string) bool {
    // TODO: Implement actual signature verification
    return len(pubKey) > 0 && len(message) > 0 && len(signature) > 0
}
```

### Fixed Code

```go
// internal/lockscript/vm.go:306-350
func (vm *VirtualMachine) verifySignature(pubKeyHex, message, signatureHex string) bool {
    // Decode public key from hex
    pubKeyBytes, err := hex.DecodeString(pubKeyHex)
    if err != nil {
        return false
    }

    // Ed25519 public key must be 32 bytes
    if len(pubKeyBytes) != ed25519.PublicKeySize {
        return false
    }

    // Decode signature from hex
    signatureBytes, err := hex.DecodeString(signatureHex)
    if err != nil {
        return false
    }

    // Ed25519 signature must be 64 bytes
    if len(signatureBytes) != ed25519.SignatureSize {
        return false
    }

    // Verify signature
    return ed25519.Verify(pubKeyBytes, []byte(message), signatureBytes)
}
```

### Required Import

```go
import (
    "crypto/ed25519"
    "encoding/hex"
    // ... other imports
)
```

### Helper: Signing Function (for tests and clients)

```go
// internal/lockscript/signing.go
package lockscript

import (
    "crypto/ed25519"
    "encoding/hex"
)

// SignMessage signs a message with Ed25519 private key
// Returns hex-encoded signature
func SignMessage(privateKey ed25519.PrivateKey, message string) string {
    signature := ed25519.Sign(privateKey, []byte(message))
    return hex.EncodeToString(signature)
}

// GenerateKeyPair generates a new Ed25519 key pair
// Returns hex-encoded public key and private key
func GenerateKeyPair() (pubKeyHex string, privKey ed25519.PrivateKey, err error) {
    pub, priv, err := ed25519.GenerateKey(nil)
    if err != nil {
        return "", nil, err
    }
    return hex.EncodeToString(pub), priv, nil
}
```

### Test

```go
// internal/lockscript/vm_test.go
func TestVerifySignature_Valid(t *testing.T) {
    vm := NewVirtualMachine()

    // Generate key pair
    pubKeyHex, privKey, err := GenerateKeyPair()
    require.NoError(t, err)

    message := "unlock asset 12345"
    signature := SignMessage(privKey, message)

    // Valid signature should pass
    assert.True(t, vm.verifySignature(pubKeyHex, message, signature))
}

func TestVerifySignature_InvalidSignature(t *testing.T) {
    vm := NewVirtualMachine()

    pubKeyHex, _, _ := GenerateKeyPair()
    message := "unlock asset 12345"

    // Wrong signature should fail
    wrongSignature := hex.EncodeToString(make([]byte, 64))
    assert.False(t, vm.verifySignature(pubKeyHex, message, wrongSignature))
}

func TestVerifySignature_WrongKey(t *testing.T) {
    vm := NewVirtualMachine()

    // Sign with one key
    _, privKey, _ := GenerateKeyPair()
    message := "unlock asset 12345"
    signature := SignMessage(privKey, message)

    // Verify with different key
    differentPubKeyHex, _, _ := GenerateKeyPair()
    assert.False(t, vm.verifySignature(differentPubKeyHex, message, signature))
}

func TestVerifySignature_ModifiedMessage(t *testing.T) {
    vm := NewVirtualMachine()

    pubKeyHex, privKey, _ := GenerateKeyPair()
    originalMessage := "unlock asset 12345"
    signature := SignMessage(privKey, originalMessage)

    // Modified message should fail
    modifiedMessage := "unlock asset 99999"
    assert.False(t, vm.verifySignature(pubKeyHex, modifiedMessage, signature))
}

func TestVerifySignature_InvalidHex(t *testing.T) {
    vm := NewVirtualMachine()

    // Invalid hex should fail gracefully
    assert.False(t, vm.verifySignature("not-hex", "msg", "sig"))
    assert.False(t, vm.verifySignature("abcd", "msg", "not-hex"))
}

func TestVerifySignature_WrongKeySize(t *testing.T) {
    vm := NewVirtualMachine()

    // Too short public key
    shortKey := hex.EncodeToString(make([]byte, 16))
    signature := hex.EncodeToString(make([]byte, 64))
    assert.False(t, vm.verifySignature(shortKey, "msg", signature))
}
```

### Verification

```bash
go test -v ./internal/lockscript/... -run TestVerifySignature
```

---

## D6: Replace XOR with SHA256 in ZKP

### Priority: HIGH
### Effort: 4 hours
### File: `internal/crypto/zkp.go`
### Lines: 353-384

### Problem

Commitment functions use XOR which is reversible and provides no security.

### Current Code (BROKEN)

```go
// internal/crypto/zkp.go:353-384
func calculateCommitment(assetID, ownerSecret, nonce []byte) *big.Int {
    // Simplified - use proper hash in production
    h := make([]byte, 32)
    copy(h, assetID)
    for i := range ownerSecret {
        h[i%32] ^= ownerSecret[i]  // ❌ XOR is reversible!
    }
    for i := range nonce {
        h[i%32] ^= nonce[i]
    }
    return new(big.Int).SetBytes(h)
}

func calculateAddress(secret []byte) *big.Int {
    h := make([]byte, 32)
    copy(h, secret)  // ❌ No hashing at all!
    return new(big.Int).SetBytes(h)
}

func calculateUnlockCommitment(unlockSecret, assetID, additionalData []byte) *big.Int {
    h := make([]byte, 32)
    copy(h, unlockSecret)
    for i := range assetID {
        h[i%32] ^= assetID[i]  // ❌ XOR again
    }
    for i := range additionalData {
        h[i%32] ^= additionalData[i]
    }
    return new(big.Int).SetBytes(h)
}
```

### Fixed Code

```go
// internal/crypto/zkp.go:353-400
import (
    "crypto/sha256"
    // ... other imports
)

// calculateCommitment creates a commitment using SHA256
// commitment = H(assetID || ownerSecret || nonce)
func calculateCommitment(assetID, ownerSecret, nonce []byte) *big.Int {
    h := sha256.New()

    // Domain separator to prevent cross-protocol attacks
    h.Write([]byte("lockbox-commitment-v1"))

    // Length-prefix each input to prevent length extension attacks
    h.Write([]byte{byte(len(assetID))})
    h.Write(assetID)

    h.Write([]byte{byte(len(ownerSecret))})
    h.Write(ownerSecret)

    h.Write([]byte{byte(len(nonce))})
    h.Write(nonce)

    return new(big.Int).SetBytes(h.Sum(nil))
}

// calculateAddress derives address from secret using SHA256
// address = H("lockbox-address-v1" || secret)
func calculateAddress(secret []byte) *big.Int {
    h := sha256.New()
    h.Write([]byte("lockbox-address-v1"))
    h.Write(secret)
    return new(big.Int).SetBytes(h.Sum(nil))
}

// calculateUnlockCommitment creates an unlock commitment using SHA256
// commitment = H(unlockSecret || assetID || additionalData)
func calculateUnlockCommitment(unlockSecret, assetID, additionalData []byte) *big.Int {
    h := sha256.New()

    // Domain separator
    h.Write([]byte("lockbox-unlock-v1"))

    // Length-prefix each input
    h.Write([]byte{byte(len(unlockSecret))})
    h.Write(unlockSecret)

    h.Write([]byte{byte(len(assetID))})
    h.Write(assetID)

    h.Write([]byte{byte(len(additionalData))})
    h.Write(additionalData)

    return new(big.Int).SetBytes(h.Sum(nil))
}
```

### Test

```go
// internal/crypto/zkp_test.go
func TestCalculateCommitment_Deterministic(t *testing.T) {
    assetID := []byte("asset-123")
    secret := []byte("owner-secret")
    nonce := []byte("random-nonce")

    c1 := calculateCommitment(assetID, secret, nonce)
    c2 := calculateCommitment(assetID, secret, nonce)

    assert.Equal(t, c1, c2, "same inputs should produce same commitment")
}

func TestCalculateCommitment_DifferentInputs(t *testing.T) {
    assetID := []byte("asset-123")
    secret := []byte("owner-secret")
    nonce := []byte("random-nonce")

    c1 := calculateCommitment(assetID, secret, nonce)

    // Different asset ID
    c2 := calculateCommitment([]byte("asset-456"), secret, nonce)
    assert.NotEqual(t, c1, c2)

    // Different secret
    c3 := calculateCommitment(assetID, []byte("other-secret"), nonce)
    assert.NotEqual(t, c1, c3)

    // Different nonce
    c4 := calculateCommitment(assetID, secret, []byte("other-nonce"))
    assert.NotEqual(t, c1, c4)
}

func TestCalculateCommitment_NotReversible(t *testing.T) {
    // With XOR, you could recover secret as: secret = commitment ^ assetID ^ nonce
    // With SHA256, this is computationally infeasible

    assetID := []byte("known-asset-id")
    secret := []byte("this-should-be-hidden")
    nonce := []byte("known-nonce")

    commitment := calculateCommitment(assetID, secret, nonce)

    // Verify commitment is 32 bytes (256 bits)
    assert.Len(t, commitment.Bytes(), 32)

    // The secret should not appear in the commitment (basic check)
    assert.NotContains(t, commitment.Bytes(), secret)
}

func TestCalculateAddress_Deterministic(t *testing.T) {
    secret := []byte("my-secret")

    addr1 := calculateAddress(secret)
    addr2 := calculateAddress(secret)

    assert.Equal(t, addr1, addr2)
}

func TestCalculateAddress_DifferentSecrets(t *testing.T) {
    addr1 := calculateAddress([]byte("secret-1"))
    addr2 := calculateAddress([]byte("secret-2"))

    assert.NotEqual(t, addr1, addr2)
}
```

### Important Note

After PROD deployment, changing the hash function will invalidate all existing commitments. Ensure migration plan for existing data.

---

## D7: Fix Import Cycle

### Priority: HIGH
### Effort: 2-4 hours
### Files: Multiple

### Problem

```
service → monitoring → verification → service (cycle!)
```

### Diagnosis

```bash
go build ./... 2>&1 | grep cycle
```

### Solution Strategy

1. **Identify the cycle** — find what `verification` imports from `service`
2. **Extract interfaces** — create interface package that both can import
3. **Dependency injection** — pass dependencies at runtime, not import time

### Step 1: Create Interface Package

```go
// internal/interfaces/service.go
package interfaces

import (
    "context"
    "time"
)

// AssetService defines operations on locked assets
type AssetService interface {
    GetAssetStatus(ctx context.Context, assetID string) (*LockedAsset, error)
    ListAssets(ctx context.Context, owner string) ([]*LockedAsset, error)
}

// LockedAsset is the interface representation
type LockedAsset struct {
    ID         string
    Status     string
    LockTime   time.Time
    UnlockTime time.Time
}
```

### Step 2: Update Verification Package

Change `verification` to import `interfaces` instead of `service`:

```go
// internal/verification/verifier.go
package verification

import (
    "github.com/dueldanov/lockbox/v2/internal/interfaces"
)

type Verifier struct {
    assetService interfaces.AssetService  // Interface, not concrete type
}

func NewVerifier(svc interfaces.AssetService) *Verifier {
    return &Verifier{assetService: svc}
}
```

### Step 3: Update Service Package

Service implements the interface:

```go
// internal/service/service.go
// Service implicitly implements interfaces.AssetService
func (s *Service) GetAssetStatus(ctx context.Context, assetID string) (*interfaces.LockedAsset, error) {
    // ... implementation
}
```

### Step 4: Wire Up in Main

```go
// cmd/lockbox/main.go
svc := service.NewService(...)
verifier := verification.NewVerifier(svc)  // Pass service as interface
monitoring := monitoring.NewMonitor(verifier)
```

### Verification

```bash
go build ./...
# Should complete without cycle error
```

---

## Testing Checklist

### Unit Tests

```bash
# Run all unit tests
go test ./... -v

# Run with coverage
go test ./... -cover -coverprofile=coverage.out
go tool cover -html=coverage.out -o coverage.html
```

### Integration Test: Lock → Restart → Unlock

```bash
# Test script: test_persistence.sh
#!/bin/bash
set -e

echo "=== Starting service ==="
./lockbox serve &
PID=$!
sleep 2

echo "=== Locking asset ==="
ASSET_ID=$(./lockbox lock --owner "test" --duration "1h" | grep "AssetID" | awk '{print $2}')
echo "Locked asset: $ASSET_ID"

echo "=== Stopping service ==="
kill $PID
sleep 1

echo "=== Restarting service ==="
./lockbox serve &
PID=$!
sleep 2

echo "=== Checking asset status ==="
STATUS=$(./lockbox status --asset "$ASSET_ID" | grep "Status" | awk '{print $2}')

if [ "$STATUS" == "locked" ]; then
    echo "✅ SUCCESS: Asset survived restart"
else
    echo "❌ FAILURE: Asset status is $STATUS"
    exit 1
fi

kill $PID
```

### Specific Test Commands

```bash
# D1: HKDF key copy
go test -v ./internal/crypto/... -run TestNewHKDFManager

# D2: Shard serialization
go test -v ./internal/service/... -run TestShard

# D3: Ownership proof
go test -v ./internal/service/... -run TestOwnershipProof

# D4: Key persistence
go test -v ./internal/crypto/... -run TestKeyStore

# D5: Signature verification
go test -v ./internal/lockscript/... -run TestVerifySignature

# D6: ZKP commitments
go test -v ./internal/crypto/... -run TestCalculate
```

---

## Definition of Done

### D1: masterKey Copy ✅
- [ ] `copy()` added after struct creation
- [ ] Unit test verifies key is not zeros
- [ ] Unit test verifies derived keys are consistent

### D2: deserializeShard() ✅
- [ ] Function parses all 7 fields correctly
- [ ] Roundtrip test passes (serialize → deserialize)
- [ ] Error handling for malformed input

### D3: getOwnershipProof() ✅
- [ ] Function parses all fields from storage
- [ ] Roundtrip test passes (store → retrieve)
- [ ] Error handling for missing/invalid data

### D4: Key Persistence ✅
- [ ] KeyStore implementation complete
- [ ] Service uses KeyStore
- [ ] Key survives restart (integration test)
- [ ] File permissions are restrictive (0600)

### D5: Signature Verification ✅
- [ ] Ed25519 verification implemented
- [ ] Valid signatures pass
- [ ] Invalid signatures fail
- [ ] Wrong keys fail
- [ ] Modified messages fail

### D6: SHA256 in ZKP ✅
- [ ] All XOR replaced with SHA256
- [ ] Domain separators added
- [ ] Commitments are deterministic
- [ ] Different inputs produce different outputs

### D7: Import Cycle Fixed ✅
- [ ] `go build ./...` succeeds
- [ ] No circular dependencies
- [ ] All tests pass

---

## Rollback Plan

If issues are discovered after deployment:

1. **D1-D6**: These are additive fixes. Rollback simply means the bugs return.
2. **D4 (Key Persistence)**:
   - Old keys won't work with new system
   - Keep backup of key file
   - Document key migration path

### Key File Backup

```bash
# Before any changes
cp ~/.lockbox/.lockbox_master_key ~/.lockbox/.lockbox_master_key.backup.$(date +%Y%m%d)
```

---

## Next Steps

After completing Phase 1:

1. Run full test suite
2. Manual E2E testing
3. Code review
4. Merge to develop branch
5. Begin Phase 2 (Security Hardening)
