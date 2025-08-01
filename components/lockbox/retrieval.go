package lockbox

import (
	"context"
	"time"

	"github.com/iotaledger/hornet/v2/pkg/daemon"
)

// StartRetrievalServices starts all retrieval and verification related services
func StartRetrievalServices() error {
	// Initialize verification system
	if err := deps.LockBoxService.InitializeVerification(); err != nil {
		Component.LogPanicf("failed to initialize verification system: %s", err)
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

// UpdateComponentRun updates the component run function to include retrieval services
func UpdateComponentRun() error {
	// Start retrieval and verification services
	if err := StartRetrievalServices(); err != nil {
		return err
	}
	
	// Continue with existing run logic...
	return nil
}