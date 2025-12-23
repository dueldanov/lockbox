package logging

import (
	"context"
	"time"
)

// ctxKey is the context key for the logger
type ctxKey struct{}

// WithLogger returns a new context with the logger attached
func WithLogger(ctx context.Context, logger LockBoxLogger) context.Context {
	return context.WithValue(ctx, ctxKey{}, logger)
}

// FromContext returns the logger from context, or nil if not present
func FromContext(ctx context.Context) LockBoxLogger {
	if ctx == nil {
		return nil
	}
	if logger, ok := ctx.Value(ctxKey{}).(LockBoxLogger); ok {
		return logger
	}
	return nil
}

// LogFromContext logs a step if a logger is present in context
// This is a convenience function that does nothing if no logger is present
func LogFromContext(ctx context.Context, phase, function, details string, err error) {
	if logger := FromContext(ctx); logger != nil {
		logger.LogStep(phase, function, details, err)
	}
}

// LogFromContextWithDuration logs a step with explicit duration if a logger is present
func LogFromContextWithDuration(ctx context.Context, phase, function, details string, duration time.Duration, err error) {
	if logger := FromContext(ctx); logger != nil {
		logger.LogStepWithDuration(phase, function, details, duration, err)
	}
}

// MeasureStep is a helper to measure and log a step
// Usage: defer logging.MeasureStep(ctx, phase, function, details)()
func MeasureStep(ctx context.Context, phase, function, details string) func() {
	start := time.Now()
	return func() {
		if logger := FromContext(ctx); logger != nil {
			logger.LogStepWithDuration(phase, function, details, time.Since(start), nil)
		}
	}
}

// MeasureStepWithError is a helper to measure and log a step with error capture
// Usage: err := doSomething(); logging.MeasureStepWithError(ctx, phase, function, details, start, err)
func MeasureStepWithError(ctx context.Context, phase, function, details string, start time.Time, err error) {
	if logger := FromContext(ctx); logger != nil {
		logger.LogStepWithDuration(phase, function, details, time.Since(start), err)
	}
}

// StepTimer is a helper struct for timing steps
type StepTimer struct {
	ctx      context.Context
	phase    string
	function string
	details  string
	start    time.Time
}

// NewStepTimer creates a new step timer
func NewStepTimer(ctx context.Context, phase, function string) *StepTimer {
	return &StepTimer{
		ctx:      ctx,
		phase:    phase,
		function: function,
		start:    time.Now(),
	}
}

// WithDetails adds details to the timer
func (t *StepTimer) WithDetails(details string) *StepTimer {
	t.details = details
	return t
}

// Done completes the step and logs it
func (t *StepTimer) Done(err error) {
	LogFromContextWithDuration(t.ctx, t.phase, t.function, t.details, time.Since(t.start), err)
}

// DoneWithDetails completes the step with updated details
func (t *StepTimer) DoneWithDetails(details string, err error) {
	LogFromContextWithDuration(t.ctx, t.phase, t.function, details, time.Since(t.start), err)
}
