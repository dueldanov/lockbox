package lockbox

import (
	"context"
	"time"

	"go.uber.org/dig"

	"github.com/iotaledger/hive.go/app"
	"github.com/iotaledger/hornet/v2/pkg/components"
	"github.com/iotaledger/hornet/v2/pkg/daemon"
	"github.com/iotaledger/hornet/v2/pkg/lockbox"
	"github.com/iotaledger/hornet/v2/pkg/model/storage"
	"github.com/iotaledger/hornet/v2/pkg/model/syncmanager"
	"github.com/iotaledger/hornet/v2/pkg/model/utxo"
	"github.com/iotaledger/hornet/v2/pkg/protocol"
	"github.com/iotaledger/hornet/v2/pkg/tangle"
	iotago "github.com/iotaledger/iota.go/v3"
)

func init() {
	Component = &app.Component{
		Name: "LockBox",
		DepsFunc: func(cDeps dependencies) {
			deps = cDeps
		},
		Params:    params,
		IsEnabled: func(c *dig.Container) bool {
			return components.IsAutopeeringEntryNodeDisabled(c) && ParamsLockBox.Enabled
		},
		Provide:   provide,
		Configure: configure,
		Run:       run,
	}
}

var (
	Component *app.Component
	deps      dependencies
)

type dependencies struct {
	dig.In

	Storage         *storage.Storage
	Tangle          *tangle.Tangle
	UTXOManager     *utxo.Manager
	SyncManager     *syncmanager.SyncManager
	ProtocolManager *protocol.Manager
	LockBoxService  *lockbox.Service
	GRPCServer      *lockbox.GRPCServer
}

func provide(c *dig.Container) error {
	type serviceDeps struct {
		dig.In
		Storage         *storage.Storage
		UTXOManager     *utxo.Manager
		SyncManager     *syncmanager.SyncManager
		ProtocolManager *protocol.Manager
	}

	if err := c.Provide(func(deps serviceDeps) (*lockbox.Service, error) {
		cfg := &lockbox.ServiceConfig{
			Tier:                  lockbox.Tier(ParamsLockBox.Tier),
			MinLockPeriod:         ParamsLockBox.MinLockPeriod,
			MaxLockPeriod:         ParamsLockBox.MaxLockPeriod,
			MinHoldingsUSD:        ParamsLockBox.MinHoldingsUSD,
			GeographicRedundancy:  ParamsLockBox.GeographicRedundancy,
			NodeLocations:         ParamsLockBox.NodeLocations,
			MaxScriptSize:         ParamsLockBox.MaxScriptSize,
			MaxExecutionTime:      ParamsLockBox.MaxExecutionTime,
			EnableEmergencyUnlock: ParamsLockBox.EnableEmergencyUnlock,
			EmergencyDelayDays:    ParamsLockBox.EmergencyDelayDays,
			MultiSigRequired:      ParamsLockBox.MultiSigRequired,
			MinMultiSigSigners:    ParamsLockBox.MinMultiSigSigners,
		}

		// Initialize service with proper logger
		service, err := lockbox.NewService(
			Component.Logger(),
			deps.Storage,
			deps.UTXOManager,
			deps.SyncManager,
			deps.ProtocolManager,
			cfg,
		)
		if err != nil {
			return nil, err
		}

		return service, nil
	}); err != nil {
		Component.LogPanic(err)
	}

	if err := c.Provide(func(service *lockbox.Service) (*lockbox.GRPCServer, error) {
		return lockbox.NewGRPCServer(
			service,
			ParamsLockBox.GRPC.BindAddress,
			ParamsLockBox.GRPC.TLSEnabled,
			ParamsLockBox.GRPC.TLSCertPath,
			ParamsLockBox.GRPC.TLSKeyPath,
		)
	}); err != nil {
		Component.LogPanic(err)
	}

	return nil
}

func configure() error {
	// Initialize verification system
	if err := deps.LockBoxService.InitializeVerification(); err != nil {
		return err
	}

	// Initialize LockScript compiler
	if err := deps.LockBoxService.InitializeCompiler(); err != nil {
		return err
	}

	// Hook into milestone events
	deps.Tangle.Events.ConfirmedMilestoneIndexChanged.Hook(func(msIndex iotago.MilestoneIndex) {
		if err := deps.LockBoxService.ProcessMilestone(context.Background(), msIndex); err != nil {
			Component.LogWarnf("error processing milestone %d: %s", msIndex, err)
		}
	})

	return nil
}

func run() error {
	// Start gRPC server
	if err := Component.Daemon().BackgroundWorker("LockBox gRPC", func(ctx context.Context) {
		Component.LogInfo("Starting LockBox gRPC server...")
		if err := deps.GRPCServer.Start(); err != nil {
			Component.LogPanicf("failed to start gRPC server: %s", err)
		}

		<-ctx.Done()

		Component.LogInfo("Stopping LockBox gRPC server...")
		deps.GRPCServer.Stop()
		Component.LogInfo("Stopping LockBox gRPC server... done")
	}, daemon.PriorityLockBox); err != nil {
		return err
	}

	// Start unlock processor
	if err := Component.Daemon().BackgroundWorker("LockBox Processor", func(ctx context.Context) {
		Component.LogInfo("Starting LockBox processor...")
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				Component.LogInfo("Stopping LockBox processor...")
				return
			case <-ticker.C:
				if err := deps.LockBoxService.ProcessPendingUnlocks(ctx); err != nil {
					Component.LogWarnf("error processing pending unlocks: %s", err)
				}
			}
		}
	}, daemon.PriorityLockBox); err != nil {
		return err
	}

	// Start verification health monitor
	if err := Component.Daemon().BackgroundWorker("LockBox Verification Monitor", func(ctx context.Context) {
		Component.LogInfo("Starting verification health monitor...")
		deps.LockBoxService.MonitorVerificationHealth(ctx)
		Component.LogInfo("Stopped verification health monitor")
	}, daemon.PriorityLockBox); err != nil {
		return err
	}

	// Start performance optimizer
	if err := Component.Daemon().BackgroundWorker("LockBox Performance Optimizer", func(ctx context.Context) {
		Component.LogInfo("Starting performance optimizer...")
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				Component.LogInfo("Stopping performance optimizer...")
				return
			case <-ticker.C:
				deps.LockBoxService.OptimizeNodeSelection()
			}
		}
	}, daemon.PriorityLockBox); err != nil {
		return err
	}

	return nil
}