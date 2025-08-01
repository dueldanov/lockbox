package lockbox

import (
    "go.uber.org/dig"
    
    "github.com/iotaledger/hive.go/app"
    "github.com/iotaledger/lockbox/v2/lockbox/b2b"
    "github.com/iotaledger/lockbox/v2/lockbox/consensus"
    "github.com/iotaledger/lockbox/v2/lockbox/lockscript"
    "github.com/iotaledger/lockbox/v2/lockbox/tiering"
    "github.com/iotaledger/lockbox/v2/lockbox/vault"
    "github.com/iotaledger/lockbox/v2/pkg/daemon"
)

func init() {
    Component = &app.Component{
        Name:     "LockBox",
        DepsFunc: func(cDeps dependencies) { deps = cDeps },
        Params:   params,
        Provide:  provide,
        Configure: configure,
        Run:      run,
    }
}

var (
    Component *app.Component
    deps      dependencies
)

type dependencies struct {
    dig.In
    
    ConsensusManager  *consensus.Manager
    LockScriptEngine  *lockscript.Engine
    VaultManager      *vault.Manager
    TierManager       *tiering.Manager
    B2BServer         *b2b.Server
}

func provide(c *dig.Container) error {
    // Provide consensus manager
    if err := c.Provide(consensus.NewManager); err != nil {
        return err
    }
    
    // Provide LockScript engine
    if err := c.Provide(lockscript.NewEngine); err != nil {
        return err
    }
    
    // Provide vault manager
    if err := c.Provide(vault.NewManager); err != nil {
        return err
    }
    
    // Provide tier manager
    if err := c.Provide(tiering.NewManager); err != nil {
        return err
    }
    
    // Provide B2B server
    if err := c.Provide(b2b.NewServer); err != nil {
        return err
    }
    
    return nil
}

func configure() error {
    // Configure components
    return nil
}

func run() error {
    // Start background workers
    if err := Component.Daemon().BackgroundWorker("LockBox", func(ctx context.Context) {
        Component.LogInfo("Starting LockBox services...")
        
        // Start B2B server
        deps.B2BServer.Start()
        
        <-ctx.Done()
        
        // Cleanup
        deps.B2BServer.Stop()
        
        Component.LogInfo("Stopped LockBox services")
    }, daemon.PriorityLockBox); err != nil {
        return err
    }
    
    return nil
}