package vault

import (
	"time"
	
	"github.com/iotaledger/hive.go/logger"
)

// Manager manages vault operations
type Manager struct {
	*logger.WrappedLogger
	rotationInterval time.Duration
	backupEnabled    bool
}

// NewManager creates a new vault manager
func NewManager(log *logger.WrappedLogger, rotationInterval time.Duration, backupEnabled bool) *Manager {
	return &Manager{
		WrappedLogger:    log,
		rotationInterval: rotationInterval,
		backupEnabled:    backupEnabled,
	}
}

