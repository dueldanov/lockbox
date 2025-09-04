package errors

import (
	"errors"
	"fmt"
	"runtime"
	"time"
)

// Error codes for different error categories
const (
	// General errors (1000-1999)
	ErrCodeUnknown             = 1000
	ErrCodeInternal            = 1001
	ErrCodeInvalidArgument     = 1002
	ErrCodeNotFound            = 1003
	ErrCodeAlreadyExists       = 1004
	ErrCodePermissionDenied    = 1005
	ErrCodeResourceExhausted   = 1006
	ErrCodeFailedPrecondition  = 1007
	ErrCodeAborted             = 1008
	ErrCodeOutOfRange          = 1009
	ErrCodeUnimplemented       = 1010
	ErrCodeDataLoss            = 1011
	ErrCodeUnauthenticated     = 1012
	
	// Asset errors (2000-2999)
	ErrCodeAssetNotFound       = 2001
	ErrCodeAssetLocked         = 2002
	ErrCodeAssetExpired        = 2003
	ErrCodeInvalidAssetID      = 2004
	ErrCodeInsufficientBalance = 2005
	
	// Script errors (3000-3999)
	ErrCodeScriptCompilation   = 3001
	ErrCodeScriptExecution     = 3002
	ErrCodeScriptTimeout       = 3003
	ErrCodeScriptTooLarge      = 3004
	ErrCodeInvalidScript       = 3005
	
	// Tier errors (4000-4999)
	ErrCodeTierLimitExceeded   = 4001
	ErrCodeInvalidTier         = 4002
	ErrCodeFeatureNotAvailable = 4003
	
	// Vault errors (5000-5999)
	ErrCodeVaultNotFound       = 5001
	ErrCodeKeyNotFound         = 5002
	ErrCodeAccessDenied        = 5003
	
	// Network errors (6000-6999)
	ErrCodeNetworkError        = 6001
	ErrCodeTimeout             = 6002
	ErrCodeConnectionFailed    = 6003
)

// LockBoxError represents a structured error with context
type LockBoxError struct {
	Code      int
	Message   string
	Details   map[string]interface{}
	Cause     error
	Timestamp time.Time
	Stack     []string
}

// Error implements the error interface
func (e *LockBoxError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("[%d] %s: %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("[%d] %s", e.Code, e.Message)
}

// Unwrap returns the underlying error
func (e *LockBoxError) Unwrap() error {
	return e.Cause
}

// WithDetail adds a detail to the error
func (e *LockBoxError) WithDetail(key string, value interface{}) *LockBoxError {
	if e.Details == nil {
		e.Details = make(map[string]interface{})
	}
	e.Details[key] = value
	return e
}

// New creates a new LockBoxError
func New(code int, message string) *LockBoxError {
	return &LockBoxError{
		Code:      code,
		Message:   message,
		Timestamp: time.Now(),
		Stack:     captureStack(),
	}
}

// Wrap wraps an existing error
func Wrap(err error, code int, message string) *LockBoxError {
	if err == nil {
		return nil
	}
	
	// If already a LockBoxError, preserve the original
	if lbErr, ok := err.(*LockBoxError); ok {
		return lbErr
	}
	
	return &LockBoxError{
		Code:      code,
		Message:   message,
		Cause:     err,
		Timestamp: time.Now(),
		Stack:     captureStack(),
	}
}

// Is checks if the error has the given code
func Is(err error, code int) bool {
	if err == nil {
		return false
	}
	
	var lbErr *LockBoxError
	if errors.As(err, &lbErr) {
		return lbErr.Code == code
	}
	
	return false
}

// captureStack captures the current stack trace
func captureStack() []string {
	stack := make([]string, 0, 10)
	
	for i := 2; i < 12; i++ {
		pc, file, line, ok := runtime.Caller(i)
		if !ok {
			break
		}
		
		fn := runtime.FuncForPC(pc)
		if fn == nil {
			continue
		}
		
		stack = append(stack, fmt.Sprintf("%s:%d %s", file, line, fn.Name()))
	}
	
	return stack
}

// Common error constructors
var (
	// General errors
	ErrUnknown = func(msg string) *LockBoxError {
		return New(ErrCodeUnknown, msg)
	}
	
	ErrInternal = func(msg string) *LockBoxError {
		return New(ErrCodeInternal, msg)
	}
	
	ErrInvalidArgument = func(msg string) *LockBoxError {
		return New(ErrCodeInvalidArgument, msg)
	}
	
	ErrNotFound = func(resource string) *LockBoxError {
		return New(ErrCodeNotFound, fmt.Sprintf("%s not found", resource))
	}
	
	ErrAlreadyExists = func(resource string) *LockBoxError {
		return New(ErrCodeAlreadyExists, fmt.Sprintf("%s already exists", resource))
	}
	
	ErrPermissionDenied = func(msg string) *LockBoxError {
		return New(ErrCodePermissionDenied, msg)
	}
	
	ErrResourceExhausted = func(resource string) *LockBoxError {
		return New(ErrCodeResourceExhausted, fmt.Sprintf("%s exhausted", resource))
	}
	
	// Asset errors
	ErrAssetNotFound = func(assetID string) *LockBoxError {
		return New(ErrCodeAssetNotFound, fmt.Sprintf("asset %s not found", assetID))
	}
	
	ErrAssetLocked = func(assetID string) *LockBoxError {
		return New(ErrCodeAssetLocked, fmt.Sprintf("asset %s is locked", assetID))
	}
	
	ErrAssetExpired = func(assetID string) *LockBoxError {
		return New(ErrCodeAssetExpired, fmt.Sprintf("asset %s has expired", assetID))
	}
	
	// Script errors
	ErrScriptCompilation = func(err error) *LockBoxError {
		return Wrap(err, ErrCodeScriptCompilation, "script compilation failed")
	}
	
	ErrScriptExecution = func(err error) *LockBoxError {
		return Wrap(err, ErrCodeScriptExecution, "script execution failed")
	}
	
	ErrScriptTimeout = func(duration time.Duration) *LockBoxError {
		return New(ErrCodeScriptTimeout, fmt.Sprintf("script execution timed out after %v", duration))
	}
	
	// Tier errors
	ErrTierLimitExceeded = func(tier, limit string) *LockBoxError {
		return New(ErrCodeTierLimitExceeded, fmt.Sprintf("tier %s limit exceeded: %s", tier, limit))
	}
	
	ErrFeatureNotAvailable = func(feature, tier string) *LockBoxError {
		return New(ErrCodeFeatureNotAvailable, fmt.Sprintf("feature %s not available in tier %s", feature, tier))
	}
)

// ErrorHandler provides centralized error handling
type ErrorHandler struct {
	logger Logger
}

// Logger interface for error logging
type Logger interface {
	Error(msg string, fields ...interface{})
	Warn(msg string, fields ...interface{})
}

// NewErrorHandler creates a new error handler
func NewErrorHandler(logger Logger) *ErrorHandler {
	return &ErrorHandler{
		logger: logger,
	}
}

// Handle processes an error
func (h *ErrorHandler) Handle(err error) {
	if err == nil {
		return
	}
	
	var lbErr *LockBoxError
	if errors.As(err, &lbErr) {
		h.handleLockBoxError(lbErr)
	} else {
		h.handleGenericError(err)
	}
}

// handleLockBoxError handles a LockBoxError
func (h *ErrorHandler) handleLockBoxError(err *LockBoxError) {
	fields := []interface{}{
		"code", err.Code,
		"timestamp", err.Timestamp,
	}
	
	if err.Details != nil {
		for k, v := range err.Details {
			fields = append(fields, k, v)
		}
	}
	
	if len(err.Stack) > 0 {
		fields = append(fields, "stack", err.Stack)
	}
	
	// Log based on error code severity
	if err.Code >= 5000 || err.Code < 2000 {
		h.logger.Error(err.Message, fields...)
	} else {
		h.logger.Warn(err.Message, fields...)
	}
}

// handleGenericError handles a generic error
func (h *ErrorHandler) handleGenericError(err error) {
	h.logger.Error("unhandled error", "error", err.Error())
}