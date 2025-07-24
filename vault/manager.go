package vault

import (
    "context"
    "crypto/rand"
    "encoding/hex"
    "sync"
    "time"
    
    "github.com/iotaledger/hive.go/logger"
    "github.com/iotaledger/hive.go/runtime/event"
)

// Manager handles secure key management
type Manager struct {
    *logger.WrappedLogger
    
    vaults           map[string]*Vault
    vaultLock        sync.RWMutex
    rotationInterval time.Duration
    backupEnabled    bool
    
    Events *Events
}

type Events struct {
    VaultCreated   *event.Event1[string]
    VaultDestroyed *event.Event1[string]
    KeyRotated     *event.Event1[string]
}

// Vault represents a secure key storage
type Vault struct {
    ID            string
    Owner         string
    Keys          map[string]*Key
    CreatedAt     time.Time
    LastRotation  time.Time
    AccessControl *AccessControl
}

// Key represents a cryptographic key
type Key struct {
    ID        string
    Type      KeyType
    Value     []byte
    CreatedAt time.Time
    ExpiresAt *time.Time
}

type KeyType string

const (
    KeyTypeEd25519   KeyType = "ed25519"
    KeyTypeAES256    KeyType = "aes256"
    KeyTypeRSA4096   KeyType = "rsa4096"
    KeyTypeECDSAP256 KeyType = "ecdsa-p256"
)

// AccessControl defines access permissions
type AccessControl struct {
    Permissions map[string]Permission
    Whitelist   []string
    Blacklist   []string
}

type Permission struct {
    Read   bool
    Write  bool
    Delete bool
    Admin  bool
}

// NewManager creates a new vault manager
func NewManager(log *logger.Logger, rotationInterval time.Duration, backupEnabled bool) *Manager {
    return &Manager{
        WrappedLogger:    logger.NewWrappedLogger(log),
        vaults:           make(map[string]*Vault),
        rotationInterval: rotationInterval,
        backupEnabled:    backupEnabled,
        Events: &Events{
            VaultCreated:   event.New1[string](),
            VaultDestroyed: event.New1[string](),
            KeyRotated:     event.New1[string](),
        },
    }
}

// CreateVault creates a new vault
func (m *Manager) CreateVault(ctx context.Context, owner string) (*Vault, error) {
    m.vaultLock.Lock()
    defer m.vaultLock.Unlock()
    
    vaultID := m.generateVaultID()
    
    vault := &Vault{
        ID:           vaultID,
        Owner:        owner,
        Keys:         make(map[string]*Key),
        CreatedAt:    time.Now(),
        LastRotation: time.Now(),
        AccessControl: &AccessControl{
            Permissions: make(map[string]Permission),
            Whitelist:   []string{},
            Blacklist:   []string{},
        },
    }
    
    // Set owner permissions
    vault.AccessControl.Permissions[owner] = Permission{
        Read:   true,
        Write:  true,
        Delete: true,
        Admin:  true,
    }
    
    m.vaults[vaultID] = vault
    m.Events.VaultCreated.Trigger(vaultID)
    
    return vault, nil
}

// GenerateKey generates a new key in the vault
func (m *Manager) GenerateKey(ctx context.Context, vaultID string, keyType KeyType) (*Key, error) {
    m.vaultLock.Lock()
    defer m.vaultLock.Unlock()
    
    vault, exists := m.vaults[vaultID]
    if !exists {
        return nil, ErrVaultNotFound
    }
    
    keyID := m.generateKeyID()
    keyValue, err := m.generateKeyValue(keyType)
    if err != nil {
        return nil, err
    }
    
    key := &Key{
        ID:        keyID,
        Type:      keyType,
        Value:     keyValue,
        CreatedAt: time.Now(),
    }
    
    vault.Keys[keyID] = key
    
    return key, nil
}

// RotateKeys rotates all keys in a vault
func (m *Manager) RotateKeys(ctx context.Context, vaultID string) error {
    m.vaultLock.Lock()
    defer m.vaultLock.Unlock()
    
    vault, exists := m.vaults[vaultID]
    if !exists {
        return ErrVaultNotFound
    }
    
    for keyID, key := range vault.Keys {
        newValue, err := m.generateKeyValue(key.Type)
        if err != nil {
            return err
        }
        
        key.Value = newValue
        key.CreatedAt = time.Now()
    }
    
    vault.LastRotation = time.Now()
    m.Events.KeyRotated.Trigger(vaultID)
    
    return nil
}

func (m *Manager) generateVaultID() string {
    b := make([]byte, 16)
    rand.Read(b)
    return hex.EncodeToString(b)
}

func (m *Manager) generateKeyID() string {
    b := make([]byte, 8)
    rand.Read(b)
    return hex.EncodeToString(b)
}

func (m *Manager) generateKeyValue(keyType KeyType) ([]byte, error) {
    switch keyType {
    case KeyTypeAES256:
        key := make([]byte, 32)
        _, err := rand.Read(key)
        return key, err
    default:
        return nil, ErrUnsupportedKeyType
    }
}