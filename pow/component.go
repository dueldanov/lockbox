package pow

import (
    "go.uber.org/dig"
    
    "github.com/iotaledger/hive.go/app"
)

func init() {
    Component = &app.Component{
        Name:       "PoW",
        IsEnabled:  func(c *dig.Container) bool { return false }, // Disabled for LockBox
        Provide:    provide,
        Configure:  configure,
    }
}

var Component *app.Component

func provide(c *dig.Container) error {
    // No PoW provider for LockBox
    return nil
}

func configure() error {
    // No PoW configuration for LockBox
    return nil
}