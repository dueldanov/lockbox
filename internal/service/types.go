package service

import (
	"time"

	"github.com/dueldanov/lockbox/v2/internal/interfaces"
	iotago "github.com/iotaledger/iota.go/v3"
)

// Type aliases from interfaces package to avoid duplication
// These types are defined in interfaces to break import cycles with verification

type Tier = interfaces.Tier

const (
	TierBasic    = interfaces.TierBasic
	TierStandard = interfaces.TierStandard
	TierPremium  = interfaces.TierPremium
	TierElite    = interfaces.TierElite
)

type LockedAsset = interfaces.LockedAsset

type AssetStatus = interfaces.AssetStatus

const (
	AssetStatusLocked    = interfaces.AssetStatusLocked
	AssetStatusUnlocking = interfaces.AssetStatusUnlocking
	AssetStatusUnlocked  = interfaces.AssetStatusUnlocked
	AssetStatusExpired   = interfaces.AssetStatusExpired
	AssetStatusEmergency = interfaces.AssetStatusEmergency
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

	// Logging configuration for AI verification
	EnableStructuredLogging bool   // Enable JSON logging for AI verification
	LogOutputDir            string // Directory for JSON log files (default: DataDir/logs)
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
	AssetID      string
	AccessToken  string                 // SECURITY: Required for authentication
	Nonce        string                 // SECURITY: Required for replay protection (5 min window)
	Signatures   [][]byte               // Multi-sig signatures (if multi-sig required)
	UnlockParams map[string]interface{} // Additional params for LockScript
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

// DeleteKeyRequest represents a request to permanently destroy a key
type DeleteKeyRequest struct {
	BundleID    string   // Bundle to destroy
	AccessToken string   // Single-use API key
	Nonce       string   // Nonce for authentication (5 min window)
	Signatures  [][]byte // Optional multi-sig for Premium/Elite tiers
}

// DeleteKeyResponse represents the response from key destruction
type DeleteKeyResponse struct {
	BundleID        string    // Destroyed bundle ID
	RequestID       string    // Destruction request UUID
	DestroyedAt     time.Time // When destruction completed
	ShardsDestroyed int       // Total shards destroyed (real + decoy)
	NodesConfirmed  int       // Number of nodes that confirmed destruction
	Status          string    // DESTROYED or FAILED
}

// RotateKeyRequest represents a request to rotate encryption keys
type RotateKeyRequest struct {
	BundleID    string   // Bundle to rotate
	AccessToken string   // Single-use API key
	Nonce       string   // Nonce for authentication
	Signatures  [][]byte // Optional multi-sig for Premium/Elite tiers
}

// RotateKeyResponse represents the response from key rotation
type RotateKeyResponse struct {
	BundleID       string    // Bundle ID (unchanged)
	NewVersion     int       // New version number
	RotatedAt      time.Time // When rotation completed
	ShardsRotated  int       // Number of shards re-encrypted
	NodesUpdated   int       // Nodes with updated shards
	Status         string    // ROTATED or FAILED
}