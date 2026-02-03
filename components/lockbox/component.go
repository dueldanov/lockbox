package lockbox

import (
	"context"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/iotaledger/hive.go/app"
	"go.uber.org/dig"

	"github.com/dueldanov/lockbox/v2/internal/b2b"
	"github.com/dueldanov/lockbox/v2/internal/crypto"
	"github.com/dueldanov/lockbox/v2/internal/service"
	"github.com/dueldanov/lockbox/v2/internal/tiering"
	"github.com/dueldanov/lockbox/v2/pkg/daemon"
	"github.com/dueldanov/lockbox/v2/pkg/model/storage"
	"github.com/dueldanov/lockbox/v2/pkg/model/syncmanager"
	"github.com/dueldanov/lockbox/v2/pkg/model/utxo"
	"github.com/dueldanov/lockbox/v2/pkg/protocol"
)

func init() {
	Component = &app.Component{
		Name:     "LockBox-Service",
		DepsFunc: func(cDeps dependencies) { deps = cDeps },
		Params:   params,
		IsEnabled: func(_ *dig.Container) bool {
			return ParamsLockBox.Enabled
		},
		Provide:   provide,
		Configure: configure,
		Run:       run,
	}
}

var (
	Component  *app.Component
	deps       dependencies
	grpcServer *service.GRPCServer
	lockboxSvc *service.Service
	b2bServer  *b2b.Server
)

type dependencies struct {
	dig.In

	Storage         *storage.Storage
	UTXOManager     *utxo.Manager
	SyncManager     *syncmanager.SyncManager
	ProtocolManager *protocol.Manager
}

func provide(c *dig.Container) error {
	return nil
}

func configure() error {
	Component.LogInfo("LockBox component configuring...")

	// P1-06: Binary integrity verification on startup
	if err := verifyBinaryIntegrity(); err != nil {
		Component.LogErrorf("Binary integrity verification failed: %v", err)
		return err
	}

	// Parse tier from config
	tier := service.TierStandard
	switch ParamsLockBox.Tier {
	case "Basic":
		tier = service.TierBasic
	case "Standard":
		tier = service.TierStandard
	case "Premium":
		tier = service.TierPremium
	case "Elite":
		tier = service.TierElite
	}

	config := &service.ServiceConfig{
		Tier:                       tier,
		DataDir:                    "lockbox_data",
		MinLockPeriod:              time.Hour,
		MaxLockPeriod:              365 * 24 * time.Hour,
		EnableEmergencyUnlock:      true,
		EmergencyDelayDays:         7,
		MultiSigRequired:           false,
		MinMultiSigSigners:         2,
		EnableTrialDecryptionDebug: ParamsLockBox.TrialDecryptionDebug,
	}

	// Create LockBox Service
	var err error
	lockboxSvc, err = service.NewService(
		Component.App().NewLogger("LockBox"),
		deps.Storage,
		deps.UTXOManager,
		deps.SyncManager,
		deps.ProtocolManager,
		config,
	)
	if err != nil {
		Component.LogErrorf("Failed to create LockBox service: %v", err)
		return err
	}
	Component.LogInfo("LockBox service created")

	// Initialize the LockScript compiler
	if err := lockboxSvc.InitializeCompiler(); err != nil {
		Component.LogWarnf("Failed to initialize LockScript compiler: %v", err)
	}

	// Create gRPC Server
	// NOTE: Rate limiter is nil here (default will be created automatically)
	// TODO P0-06: Create configured rate limiter when implementing token + nonce tracking
	grpcServer, err = service.NewGRPCServer(
		lockboxSvc,
		nil, // rateLimiter - uses default (5 req/min)
		ParamsLockBox.GRPC.BindAddress,
		ParamsLockBox.GRPC.TLSEnabled,
		ParamsLockBox.GRPC.TLSCertPath,
		ParamsLockBox.GRPC.TLSKeyPath,
	)
	if err != nil {
		Component.LogErrorf("Failed to create gRPC server: %v", err)
		return err
	}
	Component.LogInfo("LockBox gRPC server created")

	if ParamsLockBox.B2B.Enabled {
		tierManager := tiering.NewManager(Component.App().NewLogger("B2B-Tiering"))
		revenueManager, err := b2b.NewRevenueManager(Component.App().NewLogger("B2B-Revenue"), deps.Storage.UTXOStore(), tierManager)
		if err != nil {
			Component.LogErrorf("Failed to create B2B revenue manager: %v", err)
			return err
		}

		b2bSvc := b2b.NewB2BServer(
			Component.App().NewLogger("B2B"),
			lockboxSvc,
			revenueManager,
			nil,
			deps.Storage.UTXOStore(),
		)

		if err := registerDevB2BPartner(b2bSvc); err != nil {
			Component.LogWarnf("Failed to register dev B2B partner: %v", err)
		}

		b2bServer, err = b2b.NewServer(
			Component.App().NewLogger("B2B-gRPC"),
			b2bSvc,
			ParamsLockBox.B2B.GRPC.BindAddress,
			ParamsLockBox.B2B.GRPC.TLSEnabled,
			ParamsLockBox.B2B.GRPC.TLSCertPath,
			ParamsLockBox.B2B.GRPC.TLSKeyPath,
		)
		if err != nil {
			Component.LogErrorf("Failed to create B2B gRPC server: %v", err)
			return err
		}
		Component.LogInfo("B2B gRPC server created")
	}

	return nil
}

func run() error {
	if err := Component.Daemon().BackgroundWorker("LockBox-gRPC", func(ctx context.Context) {
		if grpcServer == nil {
			Component.LogWarn("GRPCServer not available - skipping gRPC startup")
			<-ctx.Done()
			return
		}

		Component.LogInfof("Starting LockBox gRPC server on %s...", ParamsLockBox.GRPC.BindAddress)

		if err := grpcServer.Start(); err != nil {
			Component.LogErrorf("Failed to start gRPC server: %v", err)
			return
		}
		Component.LogInfof("LockBox gRPC server started on %s", ParamsLockBox.GRPC.BindAddress)

		<-ctx.Done()

		Component.LogInfo("Stopping LockBox gRPC server...")
		grpcServer.Stop()
		Component.LogInfo("LockBox gRPC server stopped")
	}, daemon.PriorityLockBox); err != nil {
		return err
	}

	if ParamsLockBox.B2B.Enabled {
		if err := Component.Daemon().BackgroundWorker("B2B-gRPC", func(ctx context.Context) {
			if b2bServer == nil {
				Component.LogWarn("B2B server not available - skipping startup")
				<-ctx.Done()
				return
			}

			Component.LogInfof("Starting B2B gRPC server on %s...", ParamsLockBox.B2B.GRPC.BindAddress)

			if err := b2bServer.Start(); err != nil {
				Component.LogErrorf("Failed to start B2B gRPC server: %v", err)
				return
			}

			<-ctx.Done()

			Component.LogInfo("Stopping B2B gRPC server...")
			b2bServer.Stop()
			Component.LogInfo("B2B gRPC server stopped")
		}, daemon.PriorityLockBox); err != nil {
			return err
		}
	}

	return nil
}

func registerDevB2BPartner(server *b2b.B2BServer) error {
	if server == nil {
		return nil
	}

	devMode := os.Getenv("LOCKBOX_DEV_MODE") == "true"
	partnerID := os.Getenv("LOCKBOX_B2B_DEV_PARTNER_ID")
	apiKey := os.Getenv("LOCKBOX_B2B_DEV_API_KEY")
	if partnerID == "" && !devMode {
		return nil
	}

	if partnerID == "" {
		partnerID = "dev-partner"
	}
	if apiKey == "" {
		apiKey = "dev-api-key-000000000000000000000000"
	}

	share := 70.0
	if shareStr := os.Getenv("LOCKBOX_B2B_DEV_SHARE"); shareStr != "" {
		if parsed, err := strconv.ParseFloat(shareStr, 64); err == nil {
			share = parsed
		}
	}

	tier := service.TierStandard
	if tierStr := os.Getenv("LOCKBOX_B2B_DEV_TIER"); tierStr != "" {
		if parsed, err := service.TierFromString(strings.ToLower(tierStr)); err == nil {
			tier = parsed
		}
	}

	apiKeyHash := make([]byte, 32)
	copy(apiKeyHash, []byte(apiKey))

	return server.RegisterPartner(&b2b.Partner{
		ID:              partnerID,
		APIKeyHash:      apiKeyHash,
		Tier:            tier,
		SharePercentage: share,
		Active:          true,
		CreatedAt:       time.Now(),
	})
}

// verifyBinaryIntegrity verifies the integrity of the LockBox binary on startup.
//
// This implements P1-06: Wire binary hash verification to startup.
//
// Security: Uses SHA-256 to verify binary hasn't been tampered with.
// In production, LOCKBOX_BINARY_HASH environment variable should be set
// during build/deployment with the expected hash.
//
// Development mode: If no hash is set, verification is skipped with a warning.
// Production mode: If hash is set, verification is mandatory and will fail startup if mismatch.
func verifyBinaryIntegrity() error {
	// Get path to current executable
	execPath, err := os.Executable()
	if err != nil {
		if Component != nil {
			Component.LogWarnf("Failed to get executable path for integrity verification: %v", err)
		}
		return nil // Don't fail startup if we can't get path
	}

	// Get expected hash from environment variable
	expectedHash := os.Getenv("LOCKBOX_BINARY_HASH")

	return verifyBinaryIntegrityWithLogger(execPath, expectedHash, Component)
}

// verifyBinaryIntegrityWithLogger is the core verification logic (testable).
//
// Parameters:
//   - execPath: path to binary to verify
//   - expectedHash: expected SHA-256 hash (empty string = dev mode)
//   - logger: optional logger for output (can be nil for tests)
//
// Returns:
//   - error if verification fails (production mode only)
//   - nil if verification passes or skipped (dev mode)
func verifyBinaryIntegrityWithLogger(execPath string, expectedHash string, logger interface {
	LogWarn(...interface{})
	LogWarnf(string, ...interface{})
	LogInfo(...interface{})
	LogInfof(string, ...interface{})
	LogErrorf(string, ...interface{})
}) error {
	// Development mode: Skip verification if no hash is set
	if expectedHash == "" {
		if logger != nil {
			logger.LogWarn("Binary integrity verification SKIPPED (dev mode): LOCKBOX_BINARY_HASH not set")
			logger.LogWarnf("To enable verification, set LOCKBOX_BINARY_HASH environment variable")
			logger.LogInfof("Current binary path: %s", execPath)

			// Calculate and log current hash for convenience
			currentHash, err := crypto.CalculateBinaryHash(execPath)
			if err != nil {
				logger.LogWarnf("Could not calculate current binary hash: %v", err)
			} else {
				logger.LogInfof("Current binary hash (SHA-256): %s", currentHash)
			}
		}

		return nil
	}

	// Production mode: Verify binary integrity
	if logger != nil {
		logger.LogInfof("Verifying binary integrity: %s", execPath)
	}

	verifier := crypto.NewBinaryHashVerifier(map[string]string{
		execPath: expectedHash,
	})

	if err := verifier.VerifyBinary(execPath); err != nil {
		// CRITICAL: Binary integrity check failed
		if logger != nil {
			logger.LogErrorf("SECURITY ALERT: Binary integrity verification FAILED")
			logger.LogErrorf("Expected hash: %s", expectedHash)

			// Calculate actual hash for error message
			actualHash, calcErr := crypto.CalculateBinaryHash(execPath)
			if calcErr == nil {
				logger.LogErrorf("Actual hash:   %s", actualHash)
			}

			logger.LogErrorf("Binary may have been tampered with!")
			logger.LogErrorf("Refusing to start. Verify binary authenticity.")
		}

		return err
	}

	if logger != nil {
		logger.LogInfo("Binary integrity verified successfully ✓")
	}
	return nil
}
