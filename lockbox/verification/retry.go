package verification

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"time"

	"github.com/iotaledger/hive.go/logger"
)

// RetryConfig configures the retry behavior
type RetryConfig struct {
	MaxAttempts     int
	InitialBackoff  time.Duration
	MaxBackoff      time.Duration
	BackoffFactor   float64
	JitterFactor    float64
}

// DefaultRetryConfig returns the default retry configuration
func DefaultRetryConfig() *RetryConfig {
	return &RetryConfig{
		MaxAttempts:    5,
		InitialBackoff: 100 * time.Millisecond,
		MaxBackoff:     30 * time.Second,
		BackoffFactor:  2.0,
		JitterFactor:   0.1,
	}
}

// RetryManager handles retry logic with exponential backoff
type RetryManager struct {
	*logger.WrappedLogger
	config *RetryConfig
}

// NewRetryManager creates a new retry manager
func NewRetryManager(log *logger.Logger, config *RetryConfig) *RetryManager {
	if config == nil {
		config = DefaultRetryConfig()
	}
	
	return &RetryManager{
		WrappedLogger: logger.NewWrappedLogger(log),
		config:        config,
	}
}

// RetryableFunc is a function that can be retried
type RetryableFunc func(ctx context.Context) error

// RetryWithBackoff executes a function with exponential backoff retry
func (rm *RetryManager) RetryWithBackoff(ctx context.Context, operation string, fn RetryableFunc) error {
	var lastErr error
	
	for attempt := 0; attempt < rm.config.MaxAttempts; attempt++ {
		// Check context before attempting
		select {
		case <-ctx.Done():
			return fmt.Errorf("operation cancelled: %w", ctx.Err())
		default:
		}
		
		// Execute the function
		err := fn(ctx)
		if err == nil {
			if attempt > 0 {
				rm.LogDebugf("Operation '%s' succeeded after %d attempts", operation, attempt+1)
			}
			return nil
		}
		
		lastErr = err
		
		// Check if this is a permanent error that shouldn't be retried
		if !rm.isRetryableError(err) {
			rm.LogWarnf("Operation '%s' failed with non-retryable error: %v", operation, err)
			return err
		}
		
		// Calculate backoff duration
		backoff := rm.calculateBackoff(attempt)
		
		rm.LogDebugf("Operation '%s' failed (attempt %d/%d), retrying in %v: %v", 
			operation, attempt+1, rm.config.MaxAttempts, backoff, err)
		
		// Wait with backoff
		select {
		case <-ctx.Done():
			return fmt.Errorf("operation cancelled during backoff: %w", ctx.Err())
		case <-time.After(backoff):
			// Continue to next attempt
		}
	}
	
	return fmt.Errorf("operation '%s' failed after %d attempts: %w", operation, rm.config.MaxAttempts, lastErr)
}

// calculateBackoff calculates the backoff duration for a given attempt
func (rm *RetryManager) calculateBackoff(attempt int) time.Duration {
	// Calculate base backoff with exponential growth
	baseBackoff := float64(rm.config.InitialBackoff) * math.Pow(rm.config.BackoffFactor, float64(attempt))
	
	// Cap at maximum backoff
	if baseBackoff > float64(rm.config.MaxBackoff) {
		baseBackoff = float64(rm.config.MaxBackoff)
	}
	
	// Add jitter to prevent thundering herd
	jitter := baseBackoff * rm.config.JitterFactor * (rand.Float64()*2 - 1) // -jitter to +jitter
	finalBackoff := baseBackoff + jitter
	
	// Ensure we don't go negative
	if finalBackoff < 0 {
		finalBackoff = 0
	}
	
	return time.Duration(finalBackoff)
}

// isRetryableError determines if an error should trigger a retry
func (rm *RetryManager) isRetryableError(err error) bool {
	// TODO: Implement logic to identify permanent vs temporary errors
	// For now, retry all errors except context cancellation
	
	if err == context.Canceled || err == context.DeadlineExceeded {
		return false
	}
	
	// Check for specific error types that indicate permanent failure
	errStr := err.Error()
	permanentErrors := []string{
		"not authorized",
		"invalid request",
		"asset not found",
		"insufficient permissions",
	}
	
	for _, permErr := range permanentErrors {
		if contains(errStr, permErr) {
			return false
		}
	}
	
	return true
}

// RetryVerification wraps verification with retry logic
func (rm *RetryManager) RetryVerification(ctx context.Context, verifier *Verifier, req *VerificationRequest) (*VerificationResult, error) {
	var result *VerificationResult
	
	err := rm.RetryWithBackoff(ctx, fmt.Sprintf("verify-asset-%s", req.AssetID), func(ctx context.Context) error {
		var err error
		result, err = verifier.VerifyAsset(ctx, req)
		return err
	})
	
	if err != nil {
		return nil, err
	}
	
	return result, nil
}

// ParallelRetry performs retries on multiple operations in parallel
func (rm *RetryManager) ParallelRetry(ctx context.Context, operations map[string]RetryableFunc) map[string]error {
	results := make(map[string]error)
	resultsChan := make(chan struct {
		name string
		err  error
	}, len(operations))
	
	// Launch parallel operations
	for name, fn := range operations {
		go func(opName string, opFn RetryableFunc) {
			err := rm.RetryWithBackoff(ctx, opName, opFn)
			resultsChan <- struct {
				name string
				err  error
			}{name: opName, err: err}
		}(name, fn)
	}
	
	// Collect results
	for i := 0; i < len(operations); i++ {
		result := <-resultsChan
		results[result.name] = result.err
	}
	
	return results
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && s[:len(substr)] == substr
}