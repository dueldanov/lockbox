package service

import (
	"fmt"
	"time"
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

// TierCapabilities returns the capabilities for each tier
type TierCapabilities struct {
	MaxLockDuration      time.Duration
	MaxAssetsPerUser     int
	MultiSigSupported    bool
	EmergencyUnlock      bool
	GeographicRedundancy int
	ScriptComplexity     int
	APIRateLimit         int
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
			GeographicRedundancy: 1,
			ScriptComplexity:     1,
			APIRateLimit:         100,
		}
	case TierStandard:
		return TierCapabilities{
			MaxLockDuration:      365 * 24 * time.Hour, // 1 year
			MaxAssetsPerUser:     100,
			MultiSigSupported:    true,
			EmergencyUnlock:      true,
			GeographicRedundancy: 2,
			ScriptComplexity:     2,
			APIRateLimit:         1000,
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
		}
	default:
		return TierCapabilities{} // minimal capabilities
	}
}