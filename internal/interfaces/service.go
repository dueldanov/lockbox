package interfaces

import (
	"context"
	"errors"
	"fmt"
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

// String returns the string representation of a tier
func (t Tier) String() string {
	switch t {
	case TierBasic:
		return "basic"
	case TierStandard:
		return "standard"
	case TierPremium:
		return "premium"
	case TierElite:
		return "elite"
	default:
		return "unknown"
	}
}

// TierFromString converts a string to a Tier
func TierFromString(s string) (Tier, error) {
	switch s {
	case "basic":
		return TierBasic, nil
	case "standard":
		return TierStandard, nil
	case "premium":
		return TierPremium, nil
	case "elite":
		return TierElite, nil
	default:
		return TierBasic, fmt.Errorf("unknown tier: %s", s)
	}
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

// LockedAsset represents an asset that has been locked
type LockedAsset struct {
	ID                string              `json:"id"`
	OwnerAddress      iotago.Address      `json:"owner_address"`
	OutputID          iotago.OutputID     `json:"output_id"`
	Amount            uint64              `json:"amount"`
	TokenID           *iotago.NativeTokenID `json:"token_id,omitempty"`
	LockTime          time.Time           `json:"lock_time"`
	UnlockTime        time.Time           `json:"unlock_time"`
	LockScript        string              `json:"lock_script"`
	MultiSigAddresses []iotago.Address    `json:"multi_sig_addresses,omitempty"`
	MinSignatures     int                 `json:"min_signatures,omitempty"`
	Status            AssetStatus         `json:"status"`
	CreatedAt         time.Time           `json:"created_at"`
	UpdatedAt         time.Time           `json:"updated_at"`
	EmergencyUnlock   bool                `json:"emergency_unlock"`
	// ShardIndexMap maps mixed shard positions to real shard indices
	// Used to extract real shards from decoy-mixed storage during unlock
	ShardIndexMap     map[uint32]uint32   `json:"shard_index_map,omitempty"`
	// ShardCount is the number of real shards (excluding decoys)
	ShardCount        int                 `json:"shard_count,omitempty"`
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

// OwnershipProof represents a zero-knowledge proof of asset ownership
type OwnershipProof struct {
	AssetCommitment []byte
	OwnerAddress    []byte
	Timestamp       int64
}

// UnlockProof represents a zero-knowledge proof for unlock conditions
type UnlockProof struct {
	UnlockCommitment []byte
	UnlockTime       int64
	CurrentTime      int64
}

// ZKPProvider defines the interface for zero-knowledge proof operations
// This allows mocking ZKP operations in tests without gnark complexity
type ZKPProvider interface {
	// GenerateOwnershipProof creates a proof that the caller owns an asset
	GenerateOwnershipProof(assetID []byte, ownerSecret []byte) (*OwnershipProof, error)

	// VerifyOwnershipProof verifies an ownership proof
	VerifyOwnershipProof(proof *OwnershipProof) error

	// GenerateUnlockProof creates a proof that unlock conditions are met
	GenerateUnlockProof(unlockSecret, assetID, additionalData []byte, unlockTime int64) (*UnlockProof, error)

	// VerifyUnlockProof verifies an unlock proof
	VerifyUnlockProof(proof *UnlockProof) error
}
