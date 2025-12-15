package service

import (
	"time"

	"github.com/dueldanov/lockbox/v2/internal/interfaces"
)

// TierFromString is re-exported from interfaces package for convenience
var TierFromString = interfaces.TierFromString

// TierCapabilities returns the capabilities for each tier
type TierCapabilities struct {
	MaxLockDuration      time.Duration
	MaxAssetsPerUser     int
	MultiSigSupported    bool
	EmergencyUnlock      bool
	GeographicRedundancy int
	ScriptComplexity     int
	APIRateLimit         int

	// Shard and decoy settings per LockBox requirements
	ShardCopies        int     // Number of redundant copies: Basic=3, Standard=5, Premium=7, Elite=10+
	DecoyRatio         float64 // Ratio of decoy chars to real: Basic=0.5, Standard=1.0, Premium=1.5, Elite=2.0
	MetadataDecoyRatio float64 // Ratio of decoy metadata: Basic=0, Standard=0, Premium=1.0, Elite=2.0
}

// GetCapabilities returns the capabilities for a tier
func GetCapabilities(tier Tier) TierCapabilities {
	switch tier {
	case TierBasic:
		return TierCapabilities{
			MaxLockDuration:      30 * 24 * time.Hour, // 30 days
			MaxAssetsPerUser:     10,
			MultiSigSupported:    false,
			EmergencyUnlock:      false,
			GeographicRedundancy: 3, // Minimum 3 regions per requirements
			ScriptComplexity:     1,
			APIRateLimit:         100,
			ShardCopies:          3,
			DecoyRatio:           0.5, // 0.5x real characters
			MetadataDecoyRatio:   0,   // No decoy metadata
		}
	case TierStandard:
		return TierCapabilities{
			MaxLockDuration:      365 * 24 * time.Hour, // 1 year
			MaxAssetsPerUser:     100,
			MultiSigSupported:    true,
			EmergencyUnlock:      true,
			GeographicRedundancy: 3, // Minimum 3 regions per requirements
			ScriptComplexity:     2,
			APIRateLimit:         1000,
			ShardCopies:          5,
			DecoyRatio:           1.0, // 1x real characters
			MetadataDecoyRatio:   0,   // No decoy metadata
		}
	case TierPremium:
		return TierCapabilities{
			MaxLockDuration:      5 * 365 * 24 * time.Hour, // 5 years
			MaxAssetsPerUser:     1000,
			MultiSigSupported:    true,
			EmergencyUnlock:      true,
			GeographicRedundancy: 3,
			ScriptComplexity:     3,
			APIRateLimit:         10000,
			ShardCopies:          7,
			DecoyRatio:           1.5, // 1.5x real characters
			MetadataDecoyRatio:   1.0, // 1:1 decoy metadata
		}
	case TierElite:
		return TierCapabilities{
			MaxLockDuration:      100 * 365 * 24 * time.Hour, // 100 years
			MaxAssetsPerUser:     -1,                          // unlimited
			MultiSigSupported:    true,
			EmergencyUnlock:      true,
			GeographicRedundancy: 5,
			ScriptComplexity:     4,
			APIRateLimit:         -1, // unlimited
			ShardCopies:          10,
			DecoyRatio:           2.0, // 2x real characters
			MetadataDecoyRatio:   2.0, // 2:1 decoy metadata
		}
	default:
		return TierCapabilities{} // minimal capabilities
	}
}