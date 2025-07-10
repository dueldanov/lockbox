package tiering

import "errors"

var (
    ErrAccountExists    = errors.New("account already exists")
    ErrAccountNotFound  = errors.New("account not found")
    ErrInvalidTier      = errors.New("invalid tier")
    ErrUnknownLimitType = errors.New("unknown limit type")
    ErrLimitExceeded    = errors.New("limit exceeded")
)