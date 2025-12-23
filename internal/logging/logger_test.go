package logging

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStructuredLogger(t *testing.T) {
	// Create temp dir for output
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "test_storeKey.json")

	// Create logger
	logger := NewLogger(WorkflowStoreKey, outputPath)
	logger.WithTier("Standard")
	logger.WithBundleID("test-bundle-123")

	// Log some steps
	logger.LogStepWithDuration(PhaseInputValidation, "validate_length", "length=256", 100*time.Microsecond, nil)
	logger.LogStepWithDuration(PhaseKeyDerivation, "DeriveHKDFKey", "purpose=shard", 200*time.Microsecond, nil)
	logger.LogStepWithDuration(PhaseEncryption, "EncryptData", "shardCount=5", 500*time.Microsecond, nil)

	// Flush to file
	if err := logger.Flush(); err != nil {
		t.Fatalf("Failed to flush: %v", err)
	}

	// Read and verify JSON
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read output: %v", err)
	}

	var report LockBoxReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	// Verify report fields
	if report.Workflow != WorkflowStoreKey {
		t.Errorf("Expected workflow %s, got %s", WorkflowStoreKey, report.Workflow)
	}
	if report.BundleID != "test-bundle-123" {
		t.Errorf("Expected bundle ID test-bundle-123, got %s", report.BundleID)
	}
	if report.Tier != "Standard" {
		t.Errorf("Expected tier Standard, got %s", report.Tier)
	}
	if len(report.Entries) != 3 {
		t.Errorf("Expected 3 entries, got %d", len(report.Entries))
	}
	if report.Summary.TotalSteps != 3 {
		t.Errorf("Expected 3 total steps, got %d", report.Summary.TotalSteps)
	}
	if report.Summary.Passed != 3 {
		t.Errorf("Expected 3 passed, got %d", report.Summary.Passed)
	}

	t.Logf("Report JSON:\n%s", string(data))
}

func TestDisabledLogger(t *testing.T) {
	logger := NewDisabledLogger()

	// Should not panic
	logger.LogStep(PhaseInputValidation, "test", "details", nil)
	logger.LogStepWithDuration(PhaseEncryption, "test", "details", time.Second, nil)

	// Flush should be no-op
	if err := logger.Flush(); err != nil {
		t.Errorf("Flush should not error: %v", err)
	}

	// GetEntries should return empty
	entries := logger.GetEntries()
	if len(entries) != 0 {
		t.Errorf("Expected 0 entries, got %d", len(entries))
	}
}
