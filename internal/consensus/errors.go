package consensus

import "errors"

var (
	ErrInvalidProtocolVersion = errors.New("invalid protocol version")
	ErrNoParents              = errors.New("block has no parents")
	ErrInvalidParentsCount    = errors.New("invalid parents count")
	ErrDuplicateParents       = errors.New("duplicate parents")
	ErrInvalidSignature       = errors.New("invalid block signature")
	ErrConsensusNotReached    = errors.New("consensus not reached")
	ErrValidatorExists        = errors.New("validator already exists")
	ErrValidatorNotFound      = errors.New("validator not found")
	ErrInsufficientValidators = errors.New("insufficient validators for consensus")
)
