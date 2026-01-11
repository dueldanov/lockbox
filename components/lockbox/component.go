package lockbox

import (
	"context"
	"time"

	"go.uber.org/dig"

	"github.com/iotaledger/hive.go/app"
	"github.com/dueldanov/lockbox/v2/internal/service"
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
	Component   *app.Component
	deps        dependencies
	grpcServer  *service.GRPCServer
	lockboxSvc  *service.Service
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
		Tier:                  tier,
		DataDir:               "lockbox_data",
		MinLockPeriod:         time.Hour,
		MaxLockPeriod:         365 * 24 * time.Hour,
		EnableEmergencyUnlock: true,
		EmergencyDelayDays:    7,
		MultiSigRequired:      false,
		MinMultiSigSigners:    2,
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
	grpcServer, err = service.NewGRPCServer(
		lockboxSvc,
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

	return nil
}
