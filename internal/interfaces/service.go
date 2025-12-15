package interfaces

import (
	"context"
	"errors"
	"time"

	iotago "github.com/iotaledger/iota.go/v3"
)

var (
	ErrAssetNotFound = errors.New("asset not found")
)

// Tier represents the service tier level
type Tier int

const (
	TierBasic Tier = iota
	TierStandard
	TierPremium
	TierElite
)

// AssetStatus represents the current status of a locked asset
type AssetStatus string

const (
	AssetStatusLocked    AssetStatus = "locked"
	AssetStatusUnlocking AssetStatus = "unlocking"
	AssetStatusUnlocked  AssetStatus = "unlocked"
	AssetStatusExpired   AssetStatus = "expired"
	AssetStatusEmergency AssetStatus = "emergency"
)

// LockedAsset represents an asset that has been locked
type LockedAsset struct {
	ID                string
	OwnerAddress      iotago.Address
	OutputID          iotago.OutputID
	Amount            uint64
	TokenID           *iotago.NativeTokenID
	LockTime          time.Time
	UnlockTime        time.Time
	LockScript        string
	MultiSigAddresses []iotago.Address
	MinSignatures     int
	Status            AssetStatus
	CreatedAt         time.Time
	UpdatedAt         time.Time
	EmergencyUnlock   bool
}

// AssetService defines the interface for asset operations
// This breaks the import cycle between service and verification packages
type AssetService interface {
	// GetAssetStatus retrieves the current status of an asset
	GetAssetStatus(ctx context.Context, assetID string) (string, error)

	// ValidateAssetOwnership checks if an address owns an asset
	ValidateAssetOwnership(ctx context.Context, assetID string, address iotago.Address) (bool, error)

	// GetAssetLockTime retrieves when an asset was locked
	GetAssetLockTime(ctx context.Context, assetID string) (int64, error)
}

// StorageProvider defines the interface for storage operations
type StorageProvider interface {
	// Get retrieves data by key
	Get(key []byte) ([]byte, error)

	// Set stores data by key
	Set(key, value []byte) error

	// Delete removes data by key
	Delete(key []byte) error

	// Has checks if a key exists
	Has(key []byte) (bool, error)
}
