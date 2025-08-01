package lockbox

import (
    "time"
    
    "github.com/iotaledger/hive.go/app"
)

type ParametersLockBox struct {
    Enabled bool `default:"true" usage:"whether the LockBox extension is enabled"`
    
    Consensus struct {
        TimeoutDuration time.Duration `default:"10s" usage:"consensus timeout duration"`
        MinNodes        int           `default:"3" usage:"minimum nodes for consensus"`
    }
    
    LockScript struct {
        MaxScriptSize    int           `default:"65536" usage:"maximum script size in bytes"`
        ExecutionTimeout time.Duration `default:"5s" usage:"script execution timeout"`
    }
    
    Vault struct {
        KeyRotationInterval time.Duration `default:"24h" usage:"key rotation interval"`
        BackupEnabled       bool          `default:"true" usage:"enable vault backups"`
    }
    
    Tiering struct {
        DefaultTier string `default:"Basic" usage:"default tier for new accounts"`
        Basic       TierConfig
        Standard    TierConfig
        Premium     TierConfig
        Elite       TierConfig
    }
    
    B2B struct {
        Enabled     bool   `default:"true" usage:"enable B2B gRPC API"`
        BindAddress string `default:"0.0.0.0:9090" usage:"B2B API bind address"`
        TLSEnabled  bool   `default:"true" usage:"enable TLS for B2B API"`
    }
}

type TierConfig struct {
    TransactionLimit   int           `default:"1000" usage:"transactions per hour limit"`
    StorageQuota       int64         `default:"1073741824" usage:"storage quota in bytes"`
    MaxContractSize    int           `default:"1048576" usage:"max contract size in bytes"`
    PriorityMultiplier float64       `default:"1.0" usage:"transaction priority multiplier"`
    Features           []string      `usage:"enabled features for this tier"`
}

var ParamsLockBox = &ParametersLockBox{
    Tiering: struct {
        DefaultTier string
        Basic       TierConfig
        Standard    TierConfig
        Premium     TierConfig
        Elite       TierConfig
    }{
        Basic: TierConfig{
            TransactionLimit:   1000,
            StorageQuota:       1 * 1024 * 1024 * 1024, // 1GB
            MaxContractSize:    1 * 1024 * 1024,        // 1MB
            PriorityMultiplier: 1.0,
            Features:           []string{"basic_contracts", "standard_vault"},
        },
        Standard: TierConfig{
            TransactionLimit:   10000,
            StorageQuota:       10 * 1024 * 1024 * 1024, // 10GB
            MaxContractSize:    5 * 1024 * 1024,         // 5MB
            PriorityMultiplier: 1.5,
            Features:           []string{"basic_contracts", "standard_vault", "advanced_scripts", "api_access"},
        },
        Premium: TierConfig{
            TransactionLimit:   100000,
            StorageQuota:       100 * 1024 * 1024 * 1024, // 100GB
            MaxContractSize:    20 * 1024 * 1024,         // 20MB
            PriorityMultiplier: 2.0,
            Features:           []string{"basic_contracts", "standard_vault", "advanced_scripts", "api_access", "custom_tokens", "batch_operations"},
        },
        Elite: TierConfig{
            TransactionLimit:   -1,                          // Unlimited
            StorageQuota:       1024 * 1024 * 1024 * 1024,  // 1TB
            MaxContractSize:    100 * 1024 * 1024,          // 100MB
            PriorityMultiplier: 3.0,
            Features:           []string{"all"},
        },
    },
}

var params = &app.ComponentParams{
    Params: map[string]any{
        "lockbox": ParamsLockBox,
    },
    Masked: []string{
        "lockbox.vault.encryptionKey",
    },
}