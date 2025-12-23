package logging

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// LockBoxLogger is the interface for structured logging
type LockBoxLogger interface {
	// LogStep logs a single step in the workflow
	LogStep(phase, function, details string, err error)

	// LogStepWithDuration logs a step with explicit duration
	LogStepWithDuration(phase, function, details string, duration time.Duration, err error)

	// WithBundleID returns a logger with the given bundle ID
	WithBundleID(id string) LockBoxLogger

	// WithTier sets the tier for the logger
	WithTier(tier string) LockBoxLogger

	// Flush writes all entries to the output file
	Flush() error

	// GetEntries returns all logged entries
	GetEntries() []LockBoxLogEntry

	// GetReport generates the complete report
	GetReport() *LockBoxReport
}

// StructuredLogger implements LockBoxLogger with JSON output
type StructuredLogger struct {
	mu          sync.Mutex
	workflow    string
	bundleID    string
	tier        string
	outputPath  string
	entries     []LockBoxLogEntry
	startTime   time.Time
	lastStepEnd time.Time
	enabled     bool
}

// NewLogger creates a new structured logger
func NewLogger(workflow, outputPath string) *StructuredLogger {
	return &StructuredLogger{
		workflow:    workflow,
		outputPath:  outputPath,
		entries:     make([]LockBoxLogEntry, 0, 100),
		startTime:   time.Now(),
		lastStepEnd: time.Now(),
		enabled:     true,
	}
}

// NewDisabledLogger creates a no-op logger
func NewDisabledLogger() *StructuredLogger {
	return &StructuredLogger{
		enabled: false,
	}
}

// LogStep logs a single step with automatic duration calculation
func (l *StructuredLogger) LogStep(phase, function, details string, err error) {
	now := time.Now()
	duration := now.Sub(l.lastStepEnd)
	l.LogStepWithDuration(phase, function, details, duration, err)
}

// LogStepWithDuration logs a step with explicit duration
func (l *StructuredLogger) LogStepWithDuration(phase, function, details string, duration time.Duration, err error) {
	if !l.enabled {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	status := StatusSuccess
	if err != nil {
		status = StatusFailure
		if details != "" {
			details = fmt.Sprintf("%s; error: %v", details, err)
		} else {
			details = fmt.Sprintf("error: %v", err)
		}
	}

	entry := LockBoxLogEntry{
		Timestamp:  time.Now(),
		Phase:      phase,
		Function:   function,
		Status:     status,
		DurationNs: duration.Nanoseconds(),
		Details:    details,
		BundleID:   l.bundleID,
	}

	l.entries = append(l.entries, entry)
	l.lastStepEnd = time.Now()

	// Print live progress to console
	statusColor := "\033[32m" // green
	if err != nil {
		statusColor = "\033[31m" // red
	}
	fmt.Printf("  [%d] %s.%s: %s%s\033[0m (%dns)\n",
		len(l.entries), phase[:min(20, len(phase))], function, statusColor, status, duration.Nanoseconds())
}

// WithBundleID returns a new logger with the given bundle ID
func (l *StructuredLogger) WithBundleID(id string) LockBoxLogger {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.bundleID = id
	return l
}

// WithTier sets the tier for the logger
func (l *StructuredLogger) WithTier(tier string) LockBoxLogger {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.tier = tier
	return l
}

// GetEntries returns all logged entries
func (l *StructuredLogger) GetEntries() []LockBoxLogEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	result := make([]LockBoxLogEntry, len(l.entries))
	copy(result, l.entries)
	return result
}

// GetReport generates the complete report
func (l *StructuredLogger) GetReport() *LockBoxReport {
	l.mu.Lock()
	defer l.mu.Unlock()

	completedAt := time.Now()
	passed := 0
	failed := 0
	phases := make(map[string]int)

	for _, entry := range l.entries {
		if entry.Status == StatusSuccess {
			passed++
		} else {
			failed++
		}
		phases[entry.Phase]++
	}

	return &LockBoxReport{
		Workflow:        l.workflow,
		BundleID:        l.bundleID,
		Tier:            l.tier,
		StartedAt:       l.startTime,
		CompletedAt:     completedAt,
		TotalDurationMs: completedAt.Sub(l.startTime).Milliseconds(),
		Entries:         l.entries,
		Summary: LockBoxSummary{
			TotalSteps: len(l.entries),
			Passed:     passed,
			Failed:     failed,
			Phases:     phases,
		},
	}
}

// Flush writes all entries to the output file
func (l *StructuredLogger) Flush() error {
	if !l.enabled || l.outputPath == "" {
		return nil
	}

	report := l.GetReport()

	// Ensure directory exists
	dir := filepath.Dir(l.outputPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create log directory: %w", err)
	}

	// Write JSON file
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal report: %w", err)
	}

	if err := os.WriteFile(l.outputPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write log file: %w", err)
	}

	// Print summary
	l.PrintSummary()

	return nil
}

// PrintSummary prints a human-readable summary to console
func (l *StructuredLogger) PrintSummary() {
	report := l.GetReport()

	fmt.Println()
	fmt.Println("============================================================")
	fmt.Printf("LOCKBOX VERIFICATION REPORT: %s\n", report.Workflow)
	fmt.Println("============================================================")
	fmt.Printf("Bundle ID: %s\n", report.BundleID)
	fmt.Printf("Tier: %s\n", report.Tier)
	fmt.Printf("Duration: %dms\n", report.TotalDurationMs)
	fmt.Printf("Total Steps: %d\n", report.Summary.TotalSteps)
	fmt.Printf("Passed: \033[32m%d\033[0m\n", report.Summary.Passed)
	fmt.Printf("Failed: \033[31m%d\033[0m\n", report.Summary.Failed)
	fmt.Println()
	fmt.Println("Phases:")
	for phase, count := range report.Summary.Phases {
		fmt.Printf("  - %s: %d\n", phase, count)
	}
	if l.outputPath != "" {
		fmt.Printf("\nReport written to: %s\n", l.outputPath)
	}
	fmt.Println("============================================================")
}

// helper function
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
