package restapi

import (
	"time"

	"github.com/iotaledger/hive.go/app"
)

// ParametersRestAPI contains the definition of the parameters used by REST API.
type ParametersRestAPI struct {
	// Enabled defines whether the REST API plugin is enabled.
	Enabled bool `default:"true" usage:"whether the REST API plugin is enabled"`
	// the bind address on which the REST API listens on
	// SECURITY: Changed default from 0.0.0.0 to 127.0.0.1 to prevent accidental internet exposure
	BindAddress string `default:"127.0.0.1:14265" usage:"the bind address on which the REST API listens on"`
	// the HTTP REST routes which can be called without authorization. Wildcards using * are allowed
	PublicRoutes []string `usage:"the HTTP REST routes which can be called without authorization. Wildcards using * are allowed"`
	// the HTTP REST routes which need to be called with authorization. Wildcards using * are allowed
	ProtectedRoutes []string `usage:"the HTTP REST routes which need to be called with authorization. Wildcards using * are allowed"`
	// UseGZIP defines whether to use the gzip middleware to compress HTTP responses
	UseGZIP bool `default:"true" usage:"use the gzip middleware to compress HTTP responses"`
	// whether the debug logging for requests should be enabled
	DebugRequestLoggerEnabled bool `default:"false" usage:"whether the debug logging for requests should be enabled"`

	JWTAuth struct {
		// salt used inside the JWT tokens for the REST API. Change this to a different value to invalidate JWT tokens not matching this new value
		Salt string `default:"HORNET" usage:"salt used inside the JWT tokens for the REST API. Change this to a different value to invalidate JWT tokens not matching this new value"`
		// SECURITY: Session timeout for JWT tokens. Tokens expire after this duration.
		// Set to 0 for non-expiring tokens (NOT RECOMMENDED for production!)
		SessionTimeout time.Duration `default:"1h" usage:"JWT token expiration time. Set to 0 for non-expiring tokens (not recommended)"`
	} `name:"jwtAuth"`

	PoW struct {
		// whether the node does PoW if blocks are received via API
		Enabled bool `default:"false" usage:"whether the node does PoW if blocks are received via API"`
		// the amount of workers used for calculating PoW when issuing blocks via API
		WorkerCount int `default:"1" usage:"the amount of workers used for calculating PoW when issuing blocks via API"`
	} `name:"pow"`

	Limits struct {
		// the maximum number of characters that the body of an API call may contain
		MaxBodyLength string `default:"1M" usage:"the maximum number of characters that the body of an API call may contain"`
		// the maximum number of results that may be returned by an endpoint
		MaxResults int `default:"1000" usage:"the maximum number of results that may be returned by an endpoint"`
	}

	// SECURITY: Rate limiting to prevent DoS attacks
	RateLimiting struct {
		// Enabled defines whether rate limiting is enabled
		Enabled bool `default:"true" usage:"whether rate limiting is enabled"`
		// MaxRequestsPerSecond defines the maximum requests per second from a single IP
		MaxRequestsPerSecond float64 `default:"10" usage:"maximum requests per second from a single IP"`
		// Burst defines the maximum burst size for rate limiting
		Burst int `default:"20" usage:"maximum burst size for rate limiting"`
	} `name:"rateLimiting"`
}

var ParamsRestAPI = &ParametersRestAPI{
	PublicRoutes: []string{
		"/health",
		"/api/routes",
		"/api/core/v2/info",
		"/api/core/v2/tips",
		"/api/core/v2/blocks*",
		"/api/core/v2/transactions*",
		"/api/core/v2/milestones*",
		"/api/core/v2/outputs*",
		"/api/core/v2/treasury",
		"/api/core/v2/receipts*",
		// SECURITY: Debug routes removed from public - require JWT authentication
		// "/api/debug/v1/*",
		"/api/indexer/v1/*",
		"/api/mqtt/v1",
		"/api/participation/v1/events*",
		"/api/participation/v1/outputs*",
		"/api/participation/v1/addresses*",
		"/api/core/v0/*",
		"/api/core/v1/*",
	},
	ProtectedRoutes: []string{
		"/api/*",
	},
}

var params = &app.ComponentParams{
	Params: map[string]any{
		"restAPI": ParamsRestAPI,
	},
	Masked: []string{"restAPI.jwtAuth.salt"},
}
