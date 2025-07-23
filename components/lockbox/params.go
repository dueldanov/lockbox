package lockbox

import (
	"time"

	"github.com/iotaledger/hive.go/app"
)

type ParametersLockBox struct {
	Enabled              bool          `default:"true" usage:"whether the LockBox plugin is enabled"`
	Tier                 string        `default:"basic" usage:"LockBox tier (basic, standard, premium, elite)"`
	MinLockPeriod       time.Duration `default:"24h" usage:"minimum lock period"`
	MaxLockPeriod       time.Duration `default:"8760h" usage:"maximum lock period (1 year)"`
	MinHoldingsUSD      float64       `default:"100" usage:"minimum holdings value in USD"`
	GeographicRedundancy int          `default:"1" usage:"number of geographic regions for redundancy"`
	NodeLocations       []string      `default:"us-east,eu-west" usage:"node geographic locations"`
	MaxScriptSize       int           `default:"1024" usage:"maximum LockScript size in bytes"`
	MaxExecutionTime    time.Duration `default:"100ms" usage:"maximum LockScript execution time"`
	EnableEmergencyUnlock bool        `default:"true" usage:"enable emergency unlock feature"`
	EmergencyDelayDays   int          `default:"30" usage:"emergency unlock delay in days"`
	MultiSigRequired     bool         `default:"false" usage:"require multi-signature for operations"`
	MinMultiSigSigners   int          `default:"2" usage:"minimum multi-sig signers"`
	
	GRPC struct {
		BindAddress string `default:"0.0.0.0:9050" usage:"bind address for LockBox gRPC API"`
		TLSEnabled  bool   `default:"true" usage:"enable TLS for gRPC"`
		TLSCertPath string `default:"" usage:"path to TLS certificate"`
		TLSKeyPath  string `default:"" usage:"path to TLS key"`
	}
}

var ParamsLockBox = &ParametersLockBox{}

var params = &app.ComponentParams{
	Params: map[string]any{
		"lockbox": ParamsLockBox,
	},
	Masked: []string{},
}