package service

import (
	"time"

	iotago "github.com/iotaledger/iota.go/v3"
)

// Tier represents the service tier level
type Tier int

const (
	TierBasic Tier = iota
	TierStandard
	TierPremium
	TierElite
)

// LockedAsset represents an asset that has been locked
type LockedAsset struct {
	ID              string              `json:"id"`
	OwnerAddress    iotago.Address      `json:"owner_address"`
	OutputID        iotago.OutputID     `json:"output_id"`
	Amount          uint64              `json:"amount"`
	TokenID         *iotago.NativeTokenID `json:"token_id,omitempty"`
	LockTime        time.Time           `json:"lock_time"`
	UnlockTime      time.Time           `json:"unlock_time"`
	LockScript      string              `json:"lock_script"`
	MultiSigAddresses []iotago.Address  `json:"multi_sig_addresses,omitempty"`
	MinSignatures   int                 `json:"min_signatures,omitempty"`
	Status          AssetStatus         `json:"status"`
	CreatedAt       time.Time           `json:"created_at"`
	UpdatedAt       time.Time           `json:"updated_at"`
	EmergencyUnlock bool                `json:"emergency_unlock"`
}

// AssetStatus represents the current status of a locked asset
type AssetStatus string

const (
	AssetStatusLocked    AssetStatus = "locked"
	AssetStatusUnlocking AssetStatus = "unlocking"
	AssetStatusUnlocked  AssetStatus = "unlocked"
	AssetStatusExpired   AssetStatus = "expired"
	AssetStatusEmergency AssetStatus = "emergency"
)

// ServiceConfig holds the configuration for the LockBox service
type ServiceConfig struct {
	Tier                  Tier
	DataDir               string        // Directory for persistent data storage (keys, state, etc.)
	MinLockPeriod         time.Duration
	MaxLockPeriod         time.Duration
	MinHoldingsUSD        float64
	GeographicRedundancy  int
	NodeLocations         []string
	MaxScriptSize         int
	MaxExecutionTime      time.Duration
	EnableEmergencyUnlock bool
	EmergencyDelayDays    int
	MultiSigRequired      bool
	MinMultiSigSigners    int
}

// LockAssetRequest represents a request to lock an asset
type LockAssetRequest struct {
	OwnerAddress      iotago.Address
	OutputID          iotago.OutputID
	LockDuration      time.Duration
	LockScript        string
	MultiSigAddresses []iotago.Address
	MinSignatures     int
}

// LockAssetResponse represents the response from locking an asset
type LockAssetResponse struct {
	AssetID    string
	LockTime   time.Time
	UnlockTime time.Time
	Status     AssetStatus
}

// UnlockAssetRequest represents a request to unlock an asset
type UnlockAssetRequest struct {
	AssetID       string
	Signatures    [][]byte
	UnlockParams  map[string]interface{}
}

// UnlockAssetResponse represents the response from unlocking an asset
type UnlockAssetResponse struct {
	AssetID    string
	OutputID   iotago.OutputID
	UnlockTime time.Time
	Status     AssetStatus
}

// MultiSigConfig represents a multi-signature configuration
type MultiSigConfig struct {
	ID            string
	Addresses     []iotago.Address
	MinSignatures int
	CreatedAt     time.Time
}

// VaultInfo represents information about a vault
type VaultInfo struct {
	ID        string
	Owner     iotago.Address
	CreatedAt time.Time
	Keys      []string
}