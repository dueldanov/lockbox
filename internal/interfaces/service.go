package interfaces

import (
	"context"
	"encoding/hex"
	"encoding/json"
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

	// === V2 Shard Indistinguishability Fields ===
	// These fields support trial decryption recovery without storing type info

	// TotalShards is the total number of shards (real + decoy)
	TotalShards       int                 `json:"total_shards,omitempty"`

	// RealCount is the number of real shards (used for trial decryption)
	RealCount         int                 `json:"real_count,omitempty"`

	// Salt is the bundle-specific HKDF salt for key derivation
	// CRITICAL: Must be persisted to enable recovery after restart
	Salt              []byte              `json:"salt,omitempty"`

	// DataLength is the original plaintext length before padding
	// Used to trim recovered data after trial decryption
	DataLength        int                 `json:"data_length,omitempty"`

	// ShardCount is DEPRECATED - use RealCount instead
	// Kept for backward compatibility during migration
	ShardCount        int                 `json:"shard_count,omitempty"`

	// ShardIndexMap is DEPRECATED - use trial decryption instead
	// SECURITY: This field leaks shard type information to storage
	// Will be removed in next major version. New code should NOT use this.
	// Deprecated: Use trial decryption with TotalShards/RealCount/Salt
	ShardIndexMap     map[uint32]uint32   `json:"shard_index_map,omitempty"`

	// === Metadata Decoy Fields (Premium/Elite tiers only) ===
	// MetadataShardCount is the total number of metadata shards (real + decoy)
	// Premium tier: ratio 1.0 → 2 total (1 real + 1 decoy)
	// Elite tier: ratio 2.0 → 3 total (1 real + 2 decoy)
	MetadataShardCount int               `json:"metadata_shard_count,omitempty"`

	// MetadataIndexMap maps shard index → is_real (true=real, false=decoy)
	// Used to identify which metadata shard contains real metadata
	MetadataIndexMap   map[int]bool      `json:"metadata_index_map,omitempty"`
}

// lockedAssetJSON is an internal type for JSON serialization
// that stores iotago.Address as bech32 strings
type lockedAssetJSON struct {
	ID                string            `json:"id"`
	OwnerAddressBech  string            `json:"owner_address"`
	OwnerAddressType  byte              `json:"owner_address_type"`
	OutputID          string            `json:"output_id"`
	Amount            uint64            `json:"amount"`
	TokenID           string            `json:"token_id,omitempty"`
	LockTime          time.Time         `json:"lock_time"`
	UnlockTime        time.Time         `json:"unlock_time"`
	LockScript        string            `json:"lock_script"`
	MultiSigBech      []string          `json:"multi_sig_addresses,omitempty"`
	MultiSigTypes     []byte            `json:"multi_sig_types,omitempty"`
	MinSignatures     int               `json:"min_signatures,omitempty"`
	Status            AssetStatus       `json:"status"`
	CreatedAt         time.Time         `json:"created_at"`
	UpdatedAt         time.Time         `json:"updated_at"`
	EmergencyUnlock   bool              `json:"emergency_unlock"`
	TotalShards       int               `json:"total_shards,omitempty"`
	RealCount         int               `json:"real_count,omitempty"`
	Salt              []byte            `json:"salt,omitempty"`
	DataLength           int               `json:"data_length,omitempty"`
	ShardCount           int               `json:"shard_count,omitempty"`
	ShardIndexMap        map[uint32]uint32 `json:"shard_index_map,omitempty"`
	MetadataShardCount   int               `json:"metadata_shard_count,omitempty"`
	MetadataIndexMap     map[int]bool      `json:"metadata_index_map,omitempty"`
}

// MarshalJSON implements json.Marshaler for LockedAsset
// Converts iotago.Address interface to bech32 string for serialization
func (a LockedAsset) MarshalJSON() ([]byte, error) {
	j := lockedAssetJSON{
		ID:            a.ID,
		Amount:        a.Amount,
		LockTime:      a.LockTime,
		UnlockTime:    a.UnlockTime,
		LockScript:    a.LockScript,
		MinSignatures: a.MinSignatures,
		Status:        a.Status,
		CreatedAt:     a.CreatedAt,
		UpdatedAt:     a.UpdatedAt,
		EmergencyUnlock: a.EmergencyUnlock,
		TotalShards:   a.TotalShards,
		RealCount:     a.RealCount,
		Salt:          a.Salt,
		DataLength:         a.DataLength,
		ShardCount:         a.ShardCount,
		ShardIndexMap:      a.ShardIndexMap,
		MetadataShardCount: a.MetadataShardCount,
		MetadataIndexMap:   a.MetadataIndexMap,
	}

	// Convert owner address to bech32
	if a.OwnerAddress != nil {
		j.OwnerAddressBech = a.OwnerAddress.Bech32(iotago.PrefixMainnet)
		j.OwnerAddressType = byte(a.OwnerAddress.Type())
	}

	// Convert output ID to hex
	j.OutputID = hex.EncodeToString(a.OutputID[:])

	// Convert token ID to hex if present
	if a.TokenID != nil {
		j.TokenID = hex.EncodeToString(a.TokenID[:])
	}

	// Convert multi-sig addresses
	for _, addr := range a.MultiSigAddresses {
		j.MultiSigBech = append(j.MultiSigBech, addr.Bech32(iotago.PrefixMainnet))
		j.MultiSigTypes = append(j.MultiSigTypes, byte(addr.Type()))
	}

	return json.Marshal(j)
}

// UnmarshalJSON implements json.Unmarshaler for LockedAsset
// Converts bech32 strings back to iotago.Address interface
func (a *LockedAsset) UnmarshalJSON(data []byte) error {
	var j lockedAssetJSON
	if err := json.Unmarshal(data, &j); err != nil {
		return err
	}

	a.ID = j.ID
	a.Amount = j.Amount
	a.LockTime = j.LockTime
	a.UnlockTime = j.UnlockTime
	a.LockScript = j.LockScript
	a.MinSignatures = j.MinSignatures
	a.Status = j.Status
	a.CreatedAt = j.CreatedAt
	a.UpdatedAt = j.UpdatedAt
	a.EmergencyUnlock = j.EmergencyUnlock
	a.TotalShards = j.TotalShards
	a.RealCount = j.RealCount
	a.Salt = j.Salt
	a.DataLength = j.DataLength
	a.ShardCount = j.ShardCount
	a.ShardIndexMap = j.ShardIndexMap
	a.MetadataShardCount = j.MetadataShardCount
	a.MetadataIndexMap = j.MetadataIndexMap

	// Parse owner address from bech32
	if j.OwnerAddressBech != "" {
		_, addr, err := iotago.ParseBech32(j.OwnerAddressBech)
		if err != nil {
			return fmt.Errorf("failed to parse owner address: %w", err)
		}
		a.OwnerAddress = addr
	}

	// Parse output ID from hex
	if j.OutputID != "" {
		outputBytes, err := hex.DecodeString(j.OutputID)
		if err != nil {
			return fmt.Errorf("failed to parse output ID: %w", err)
		}
		if len(outputBytes) == iotago.OutputIDLength {
			copy(a.OutputID[:], outputBytes)
		}
	}

	// Parse token ID from hex if present
	if j.TokenID != "" {
		tokenBytes, err := hex.DecodeString(j.TokenID)
		if err != nil {
			return fmt.Errorf("failed to parse token ID: %w", err)
		}
		if len(tokenBytes) == iotago.NativeTokenIDLength {
			var tokenID iotago.NativeTokenID
			copy(tokenID[:], tokenBytes)
			a.TokenID = &tokenID
		}
	}

	// Parse multi-sig addresses from bech32
	for _, bech := range j.MultiSigBech {
		_, addr, err := iotago.ParseBech32(bech)
		if err != nil {
			return fmt.Errorf("failed to parse multi-sig address: %w", err)
		}
		a.MultiSigAddresses = append(a.MultiSigAddresses, addr)
	}

	return nil
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
	ProofBytes      []byte // Serialized groth16.Proof - MUST be persisted for verification
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
