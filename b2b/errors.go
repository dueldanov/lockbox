package b2b

import "errors"

var (
    ErrUnauthorized         = errors.New("unauthorized")
    ErrFeatureNotAvailable  = errors.New("feature not available in current tier")
    ErrInvalidRequest       = errors.New("invalid request")
    ErrInternalServerError  = errors.New("internal server error")
)