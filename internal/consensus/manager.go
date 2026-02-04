package consensus

import (
	"context"
	"sync"
	"time"

	"github.com/dueldanov/lockbox/v2/pkg/model/storage"
	"github.com/dueldanov/lockbox/v2/pkg/protocol"
	"github.com/iotaledger/hive.go/logger"
	"github.com/iotaledger/hive.go/runtime/event"
	iotago "github.com/iotaledger/iota.go/v3"
)

// Manager handles the consensus mechanism without PoW
type Manager struct {
	*logger.WrappedLogger

	storage         *storage.Storage
	protocolManager *protocol.Manager

	consensusLock sync.RWMutex
	validators    map[string]*Validator

	Events *Events
}

type Events struct {
	ConsensusReached *event.Event1[*ConsensusResult]
	ValidatorAdded   *event.Event1[string]
	ValidatorRemoved *event.Event1[string]
}

type ConsensusResult struct {
	BlockID    iotago.BlockID
	Timestamp  time.Time
	Validators []string
	Signatures map[string][]byte
}

type Validator struct {
	ID        string
	PublicKey []byte
	Weight    float64
	Active    bool
}

const defaultMinPreviousRefs = 3

// NewManager creates a new consensus manager
func NewManager(log *logger.Logger, storage *storage.Storage, protocolManager *protocol.Manager) *Manager {
	return &Manager{
		WrappedLogger:   logger.NewWrappedLogger(log),
		storage:         storage,
		protocolManager: protocolManager,
		validators:      make(map[string]*Validator),
		Events: &Events{
			ConsensusReached: event.New1[*ConsensusResult](),
			ValidatorAdded:   event.New1[string](),
			ValidatorRemoved: event.New1[string](),
		},
	}
}

// ValidateBlock validates a block without PoW
func (m *Manager) ValidateBlock(ctx context.Context, block *iotago.Block) error {
	m.consensusLock.RLock()
	defer m.consensusLock.RUnlock()

	// Validate block structure
	if err := m.validateBlockStructure(block); err != nil {
		return err
	}

	// Validate signatures (for consensus)
	if err := m.validateBlockSignatures(block); err != nil {
		return err
	}

	// Check consensus rules
	if err := m.checkConsensusRules(ctx, block); err != nil {
		return err
	}

	return nil
}

func (m *Manager) validateBlockStructure(block *iotago.Block) error {
	// Validate protocol version
	if block.ProtocolVersion != m.protocolManager.Current().Version {
		return ErrInvalidProtocolVersion
	}

	// Validate parents
	if len(block.Parents) == 0 {
		return ErrNoParents
	}
	if len(block.Parents) != defaultMinPreviousRefs {
		return ErrInvalidParentsCount
	}
	seen := make(map[iotago.BlockID]struct{}, len(block.Parents))
	for _, parent := range block.Parents {
		if _, exists := seen[parent]; exists {
			return ErrDuplicateParents
		}
		seen[parent] = struct{}{}
	}

	// Additional structure validations
	return nil
}

func (m *Manager) validateBlockSignatures(block *iotago.Block) error {
	// Extract and validate signatures from block
	// This replaces PoW validation
	return nil
}

func (m *Manager) checkConsensusRules(ctx context.Context, block *iotago.Block) error {
	// Implement consensus rules specific to LockBox
	return nil
}

// AddValidator adds a new validator to the consensus
func (m *Manager) AddValidator(validator *Validator) error {
	m.consensusLock.Lock()
	defer m.consensusLock.Unlock()

	if _, exists := m.validators[validator.ID]; exists {
		return ErrValidatorExists
	}

	m.validators[validator.ID] = validator
	m.Events.ValidatorAdded.Trigger(validator.ID)

	return nil
}

// RemoveValidator removes a validator from consensus
func (m *Manager) RemoveValidator(validatorID string) error {
	m.consensusLock.Lock()
	defer m.consensusLock.Unlock()

	if _, exists := m.validators[validatorID]; !exists {
		return ErrValidatorNotFound
	}

	delete(m.validators, validatorID)
	m.Events.ValidatorRemoved.Trigger(validatorID)

	return nil
}

// GetActiveValidators returns all active validators
func (m *Manager) GetActiveValidators() []*Validator {
	m.consensusLock.RLock()
	defer m.consensusLock.RUnlock()

	var active []*Validator
	for _, v := range m.validators {
		if v.Active {
			active = append(active, v)
		}
	}

	return active
}
