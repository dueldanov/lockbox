// Package logging provides structured logging for LockBox operations.
//
// Per architecture requirements, all logging occurs exclusively in wallet software
// and B2B SDK implementations - NOT on SecureHornet nodes.
//
// Each operation (storeKey, retrieveKey, rotateKey, deleteKey) has phase-based
// logging with verbose function-level tracking for debugging and audit.
package logging

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Severity indicates the severity level of an error.
type Severity string

const (
	// SeverityCritical indicates a critical error requiring immediate attention.
	SeverityCritical Severity = "CRITICAL"

	// SeverityWarning indicates a warning that should be investigated.
	SeverityWarning Severity = "WARNING"

	// SeverityInfo indicates informational message.
	SeverityInfo Severity = "INFO"
)

// Operation represents the type of LockBox operation being performed.
type Operation string

const (
	OpStoreKey    Operation = "STORE_KEY"
	OpRetrieveKey Operation = "RETRIEVE_KEY"
	OpRotateKey   Operation = "ROTATE_KEY"
	OpDeleteKey   Operation = "DELETE_KEY"
)

// LogEntry represents a single log entry for LockBox operations.
// Extended version of LockBoxLogEntry with additional fields.
type LogEntry struct {
	// Timestamp when the log entry was created.
	Timestamp time.Time `json:"timestamp"`

	// Operation being performed (STORE_KEY, RETRIEVE_KEY, etc.)
	Operation Operation `json:"operation"`

	// Phase within the operation.
	Phase string `json:"phase"`

	// Function name being executed.
	Function string `json:"function"`

	// Status of the operation (SUCCESS, FAILURE, WARNING).
	Status string `json:"status"`

	// Duration of the operation in nanoseconds.
	DurationNs int64 `json:"duration_ns"`

	// Details contains non-sensitive context about the operation.
	Details string `json:"details,omitempty"`

	// BundleID is the transaction bundle identifier.
	BundleID string `json:"bundle_id,omitempty"`

	// RequestID is the unique request tracking ID.
	RequestID string `json:"request_id,omitempty"`

	// NewBundleID is set for rotation operations.
	NewBundleID string `json:"new_bundle_id,omitempty"`

	// VersionFrom is the previous version (for rotation).
	VersionFrom string `json:"version_from,omitempty"`

	// VersionTo is the new version (for rotation).
	VersionTo string `json:"version_to,omitempty"`

	// NodesSelected is the number of nodes selected (for distribution).
	NodesSelected int `json:"nodes_selected,omitempty"`

	// ShardsCount is the number of shards involved.
	ShardsCount int `json:"shards_count,omitempty"`

	// NodesAffected is the number of nodes affected (for deletion).
	NodesAffected int `json:"nodes_affected,omitempty"`
}

// LockBoxError represents a structured error for LockBox operations.
//
// This struct matches the specification:
//
//	type LockBoxError struct {
//	    Code        string  // Machine-readable
//	    Message     string  // Human-readable
//	    Details     string  // Optional context (non-sensitive)
//	    Severity    string  // CRITICAL, WARNING, INFO
//	    Recoverable bool
//	    RetryAfter  int     // Suggested retry delay in seconds
//	    Component   string  // Which component generated the error
//	    Timestamp   time.Time
//	}
type LockBoxError struct {
	// Code is the machine-readable error code.
	Code string `json:"code"`

	// Message is the human-readable error description.
	Message string `json:"message"`

	// Details contains optional non-sensitive context.
	Details string `json:"details,omitempty"`

	// Severity indicates error severity level.
	Severity Severity `json:"severity"`

	// Recoverable indicates if automatic recovery is possible.
	Recoverable bool `json:"recoverable"`

	// RetryAfter is the suggested retry delay in seconds.
	RetryAfter int `json:"retry_after,omitempty"`

	// Component is which component generated the error.
	Component string `json:"component"`

	// Timestamp is when the error occurred.
	Timestamp time.Time `json:"timestamp"`
}

// Error implements the error interface.
func (e *LockBoxError) Error() string {
	return fmt.Sprintf("[%s] %s: %s", e.Severity, e.Code, e.Message)
}

// Common error codes per specification
const (
	// Token/Auth errors
	ErrCodeTokenInvalid     = "TOKEN_INVALID"
	ErrCodeTokenExpired     = "TOKEN_EXPIRED"
	ErrCodeNonceInvalid     = "NONCE_INVALID"
	ErrCodeOwnershipInvalid = "OWNERSHIP_INVALID"

	// Payment errors
	ErrCodePaymentInvalid      = "PAYMENT_INVALID"
	ErrCodePaymentInsufficient = "PAYMENT_INSUFFICIENT"

	// Rotation errors
	ErrCodeIntervalTooShort = "INTERVAL_TOO_SHORT"
	ErrCodeRotationFailed   = "ROTATION_FAILED"

	// Destruction errors
	ErrCodeDestructionIncomplete = "DESTRUCTION_INCOMPLETE"

	// Crypto errors
	ErrCodeEncryptionFailed = "ENCRYPTION_FAILED"
	ErrCodeDecryptionFailed = "DECRYPTION_FAILED"
	ErrCodeZKPFailed        = "ZKP_VERIFICATION_FAILED"
	ErrCodeSignatureFailed  = "SIGNATURE_VERIFICATION_FAILED"

	// Network errors
	ErrCodeNodeUnavailable  = "NODE_UNAVAILABLE"
	ErrCodeShardFetchFailed = "SHARD_FETCH_FAILED"

	// Memory errors
	ErrCodeMemoryWipeFailed = "MEMORY_WIPE_FAILED"
)

// OperationLogger is the main logging interface for LockBox operations.
// This is separate from StructuredLogger to provide operation-specific functionality.
type OperationLogger struct {
	mu        sync.Mutex
	output    io.Writer
	operation Operation
	bundleID  string
	requestID string
	entries   []LogEntry
	startTime time.Time
}

// NewOperationLogger creates a new logger for the specified operation.
func NewOperationLogger(op Operation, bundleID, requestID string) *OperationLogger {
	return &OperationLogger{
		output:    os.Stdout,
		operation: op,
		bundleID:  bundleID,
		requestID: requestID,
		entries:   make([]LogEntry, 0),
		startTime: time.Now(),
	}
}

// SetOutput sets the output writer for log entries.
func (l *OperationLogger) SetOutput(w io.Writer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.output = w
}

// LogFunc logs a function execution within a phase.
//
// Example:
//
//	defer logger.LogFunc(PhaseEncryption, "XChaCha20Poly1305Encrypt", start)()
func (l *OperationLogger) LogFunc(phase string, function string, start time.Time) func() {
	return func() {
		l.Log(phase, function, StatusSuccess, time.Since(start), "")
	}
}

// Log records a log entry.
func (l *OperationLogger) Log(phase string, function string, status string, duration time.Duration, details string) {
	entry := LogEntry{
		Timestamp:  time.Now(),
		Operation:  l.operation,
		Phase:      phase,
		Function:   function,
		Status:     status,
		DurationNs: duration.Nanoseconds(),
		Details:    details,
		BundleID:   l.bundleID,
		RequestID:  l.requestID,
	}

	l.mu.Lock()
	l.entries = append(l.entries, entry)
	l.mu.Unlock()

	l.writeEntry(entry)
}

// LogSuccess logs a successful operation.
func (l *OperationLogger) LogSuccess(phase string, function string, duration time.Duration, details string) {
	l.Log(phase, function, StatusSuccess, duration, details)
}

// LogFailure logs a failed operation.
func (l *OperationLogger) LogFailure(phase string, function string, duration time.Duration, details string) {
	l.Log(phase, function, StatusFailure, duration, details)
}

// LogWarning logs a warning.
func (l *OperationLogger) LogWarning(phase string, function string, duration time.Duration, details string) {
	l.Log(phase, function, StatusWarning, duration, details)
}

// LogWithExtras logs with additional fields (for rotation/deletion).
func (l *OperationLogger) LogWithExtras(phase string, function string, status string, duration time.Duration, extras map[string]interface{}) {
	entry := LogEntry{
		Timestamp:  time.Now(),
		Operation:  l.operation,
		Phase:      phase,
		Function:   function,
		Status:     status,
		DurationNs: duration.Nanoseconds(),
		BundleID:   l.bundleID,
		RequestID:  l.requestID,
	}

	// Apply extras
	if v, ok := extras["details"].(string); ok {
		entry.Details = v
	}
	if v, ok := extras["new_bundle_id"].(string); ok {
		entry.NewBundleID = v
	}
	if v, ok := extras["version_from"].(string); ok {
		entry.VersionFrom = v
	}
	if v, ok := extras["version_to"].(string); ok {
		entry.VersionTo = v
	}
	if v, ok := extras["nodes_selected"].(int); ok {
		entry.NodesSelected = v
	}
	if v, ok := extras["shards_count"].(int); ok {
		entry.ShardsCount = v
	}
	if v, ok := extras["nodes_affected"].(int); ok {
		entry.NodesAffected = v
	}

	l.mu.Lock()
	l.entries = append(l.entries, entry)
	l.mu.Unlock()

	l.writeEntry(entry)
}

// writeEntry writes an entry to the output.
func (l *OperationLogger) writeEntry(entry LogEntry) {
	l.mu.Lock()
	defer l.mu.Unlock()

	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	l.output.Write(data)
	l.output.Write([]byte("\n"))
}

// GetEntries returns all recorded log entries.
func (l *OperationLogger) GetEntries() []LogEntry {
	l.mu.Lock()
	defer l.mu.Unlock()

	result := make([]LogEntry, len(l.entries))
	copy(result, l.entries)
	return result
}

// TotalDuration returns the total duration since logger creation.
func (l *OperationLogger) TotalDuration() time.Duration {
	return time.Since(l.startTime)
}

// Summary returns a summary of the operation.
func (l *OperationLogger) Summary() string {
	l.mu.Lock()
	defer l.mu.Unlock()

	successCount := 0
	failureCount := 0
	warningCount := 0

	for _, entry := range l.entries {
		switch entry.Status {
		case StatusSuccess:
			successCount++
		case StatusFailure:
			failureCount++
		case StatusWarning:
			warningCount++
		}
	}

	return fmt.Sprintf(
		"Operation: %s | BundleID: %s | Total: %d entries | Success: %d | Failures: %d | Warnings: %d | Duration: %v",
		l.operation, l.bundleID, len(l.entries), successCount, failureCount, warningCount, time.Since(l.startTime),
	)
}

// NewError creates a new LockBoxError.
func NewError(code, message, component string, severity Severity, recoverable bool) *LockBoxError {
	return &LockBoxError{
		Code:        code,
		Message:     message,
		Severity:    severity,
		Recoverable: recoverable,
		Component:   component,
		Timestamp:   time.Now(),
	}
}

// NewCriticalError creates a critical non-recoverable error.
func NewCriticalError(code, message, component string) *LockBoxError {
	return NewError(code, message, component, SeverityCritical, false)
}

// NewRecoverableError creates a recoverable error with retry suggestion.
func NewRecoverableError(code, message, component string, retryAfter int) *LockBoxError {
	err := NewError(code, message, component, SeverityWarning, true)
	err.RetryAfter = retryAfter
	return err
}

// SecurityAlert logs a security alert that must always be logged.
// Per spec: triggers on encryption failure, crypto failure, memory lock failure.
func (l *OperationLogger) SecurityAlert(phase string, function string, details string) {
	entry := LogEntry{
		Timestamp:  time.Now(),
		Operation:  l.operation,
		Phase:      phase,
		Function:   function,
		Status:     StatusFailure,
		DurationNs: 0,
		Details:    fmt.Sprintf("SECURITY ALERT: %s", details),
		BundleID:   l.bundleID,
		RequestID:  l.requestID,
	}

	l.mu.Lock()
	l.entries = append(l.entries, entry)
	l.mu.Unlock()

	// Security alerts always get written immediately
	l.writeEntry(entry)
}
