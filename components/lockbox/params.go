package lockbox

import (
	"github.com/iotaledger/hive.go/app"
)

type ParametersLockBox struct {
	Enabled bool `default:"true" usage:"whether the LockBox extension is enabled"`

	GRPC struct {
		BindAddress string `default:"0.0.0.0:50051" usage:"LockBox gRPC API bind address"`
		TLSEnabled  bool   `default:"false" usage:"enable TLS for gRPC API (required in production)"`
		TLSCertPath string `default:"" usage:"path to TLS certificate file"`
		TLSKeyPath  string `default:"" usage:"path to TLS key file"`
	}

	Tier string `default:"Standard" usage:"default service tier (Basic, Standard, Premium, Elite)"`
}

var ParamsLockBox = &ParametersLockBox{}

var params = &app.ComponentParams{
	Params: map[string]any{
		"lockbox": ParamsLockBox,
	},
	Masked: []string{},
}
