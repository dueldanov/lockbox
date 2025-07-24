package tiering

import (
    "context"
    "sync"
    "time"
    
    "github.com/iotaledger/hive.go/logger"
    "github.com/iotaledger/hive.go/runtime/event"
)

// Manager handles account tiering
type Manager struct {
    *logger.WrappedLogger
    
    accounts     map[string]*Account
    accountsLock sync.RWMutex
    tiers        map[string]*Tier
    
    Events *Events
}

type Events struct {
    AccountCreated  *event.Event2[string, string] // accountID, tier
    TierUpgraded    *event.Event2[string, string] // accountID, newTier
    TierDowngraded  *event.Event2[string, string] // accountID, newTier
    LimitExceeded   *event.Event2[string, string] // accountID, limitType
}

// Account represents a user account with tier
type Account struct {
    ID               string
    Tier             string
    CreatedAt        time.Time
    LastActivity     time.Time
    Usage            *Usage
    CustomLimits     map[string]interface{}
}

// Usage tracks resource usage
type Usage struct {
    TransactionsHour   int
    StorageUsed        int64
    ContractsDeployed  int
    LastReset          time.Time
}

// Tier represents a service tier
type Tier struct {
    Name               string
    TransactionLimit   int
    StorageQuota       int64
    MaxContractSize    int
    PriorityMultiplier float64
    Features           []string
    Price              float64
}

// NewManager creates a new tier manager
func NewManager(log *logger.Logger) *Manager {
    m := &Manager{
        WrappedLogger: logger.NewWrappedLogger(log),
        accounts:      make(map[string]*Account),
        tiers:         make(map[string]*Tier),
        Events: &Events{
            AccountCreated: event.New2[string, string](),
            TierUpgraded:   event.New2[string, string](),
            TierDowngraded: event.New2[string, string](),
            LimitExceeded:  event.New2[string, string](),
        },
    }
    
    // Initialize default tiers
    m.initializeTiers()
    
    return m
}

func (m *Manager) initializeTiers() {
    m.tiers["Basic"] = &Tier{
        Name:               "Basic",
        TransactionLimit:   1000,
        StorageQuota:       1 * 1024 * 1024 * 1024, // 1GB
        MaxContractSize:    1 * 1024 * 1024,        // 1MB
        PriorityMultiplier: 1.0,
        Features:           []string{"basic_contracts", "standard_vault"},
        Price:              0,
    }
    
    m.tiers["Standard"] = &Tier{
        Name:               "Standard",
        TransactionLimit:   10000,
        StorageQuota:       10 * 1024 * 1024 * 1024, // 10GB
        MaxContractSize:    5 * 1024 * 1024,         // 5MB
        PriorityMultiplier: 1.5,
        Features:           []string{"basic_contracts", "standard_vault", "advanced_scripts", "api_access"},
        Price:              99,
    }
    
    m.tiers["Premium"] = &Tier{
        Name:               "Premium",
        TransactionLimit:   100000,
        StorageQuota:       100 * 1024 * 1024 * 1024, // 100GB
        MaxContractSize:    20 * 1024 * 1024,         // 20MB
        PriorityMultiplier: 2.0,
        Features:           []string{"basic_contracts", "standard_vault", "advanced_scripts", "api_access", "custom_tokens", "batch_operations"},
        Price:              499,
    }
    
    m.tiers["Elite"] = &Tier{
        Name:               "Elite",
        TransactionLimit:   -1,                         // Unlimited
        StorageQuota:       1024 * 1024 * 1024 * 1024, // 1TB
        MaxContractSize:    100 * 1024 * 1024,         // 100MB
        PriorityMultiplier: 3.0,
        Features:           []string{"all"},
        Price:              2499,
    }
}

// CreateAccount creates a new account with the specified tier
func (m *Manager) CreateAccount(ctx context.Context, accountID string, tierName string) (*Account, error) {
    m.accountsLock.Lock()
    defer m.accountsLock.Unlock()
    
    if _, exists := m.accounts[accountID]; exists {
        return nil, ErrAccountExists
    }
    
    tier, exists := m.tiers[tierName]
    if !exists {
        return nil, ErrInvalidTier
    }
    
    account := &Account{
        ID:           accountID,
        Tier:         tierName,
        CreatedAt:    time.Now(),
        LastActivity: time.Now(),
        Usage: &Usage{
            LastReset: time.Now(),
        },
        CustomLimits: make(map[string]interface{}),
    }
    
    m.accounts[accountID] = account
    m.Events.AccountCreated.Trigger(accountID, tierName)
    
    return account, nil
}

// UpgradeTier upgrades an account to a higher tier
func (m *Manager) UpgradeTier(ctx context.Context, accountID string, newTier string) error {
    m.accountsLock.Lock()
    defer m.accountsLock.Unlock()
    
    account, exists := m.accounts[accountID]
    if !exists {
        return ErrAccountNotFound
    }
    
    if _, exists := m.tiers[newTier]; !exists {
        return ErrInvalidTier
    }
    
    oldTier := account.Tier
    account.Tier = newTier
    
    m.Events.TierUpgraded.Trigger(accountID, newTier)
    
    m.LogInfof("Account %s upgraded from %s to %s", accountID, oldTier, newTier)
    
    return nil
}

// CheckLimit checks if an account has exceeded any limits
func (m *Manager) CheckLimit(ctx context.Context, accountID string, limitType string, value interface{}) (bool, error) {
    m.accountsLock.RLock()
    defer m.accountsLock.RUnlock()
    
    account, exists := m.accounts[accountID]
    if !exists {
        return false, ErrAccountNotFound
    }
    
    tier, exists := m.tiers[account.Tier]
    if !exists {
        return false, ErrInvalidTier
    }
    
    switch limitType {
    case "transaction":
        if tier.TransactionLimit == -1 {
            return true, nil
        }
        return account.Usage.TransactionsHour < tier.TransactionLimit, nil
        
    case "storage":
        if tier.StorageQuota == -1 {
            return true, nil
        }
        return account.Usage.StorageUsed < tier.StorageQuota, nil
        
    default:
        return false, ErrUnknownLimitType
    }
}

// RecordUsage records resource usage for an account
func (m *Manager) RecordUsage(ctx context.Context, accountID string, usageType string, amount int64) error {
    m.accountsLock.Lock()
    defer m.accountsLock.Unlock()
    
    account, exists := m.accounts[accountID]
    if !exists {
        return ErrAccountNotFound
    }
    
    // Check if we need to reset hourly counters
    if time.Since(account.Usage.LastReset) > time.Hour {
        account.Usage.TransactionsHour = 0
        account.Usage.LastReset = time.Now()
    }
    
    switch usageType {
    case "transaction":
        account.Usage.TransactionsHour++
    case "storage":
        account.Usage.StorageUsed += amount
    case "contract":
        account.Usage.ContractsDeployed++
    }
    
    account.LastActivity = time.Now()
    
    return nil
}

// GetTier returns tier information
func (m *Manager) GetTier(tierName string) (*Tier, error) {
    m.accountsLock.RLock()
    defer m.accountsLock.RUnlock()
    
    tier, exists := m.tiers[tierName]
    if !exists {
        return nil, ErrInvalidTier
    }
    
    return tier, nil
}

// HasFeature checks if an account's tier has a specific feature
func (m *Manager) HasFeature(ctx context.Context, accountID string, feature string) (bool, error) {
    m.accountsLock.RLock()
    defer m.accountsLock.RUnlock()
    
    account, exists := m.accounts[accountID]
    if !exists {
        return false, ErrAccountNotFound
    }
    
    tier, exists := m.tiers[account.Tier]
    if !exists {
        return false, ErrInvalidTier
    }
    
    // Elite tier has all features
    if len(tier.Features) > 0 && tier.Features[0] == "all" {
        return true, nil
    }
    
    for _, f := range tier.Features {
        if f == feature {
            return true, nil
        }
    }
    
    return false, nil
}