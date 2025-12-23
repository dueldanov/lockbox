package service

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/dueldanov/lockbox/v2/internal/logging"
	"github.com/stretchr/testify/require"
)

// TestLoggingFunctionCount verifies that all workflows log the correct number of functions
// This is a simplified test that directly logs function calls without invoking full crypto
// Run with: go test -v -run TestLoggingFunctionCount ./internal/service/...
func TestLoggingFunctionCount(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("storeKey logs 100 functions", func(t *testing.T) {
		logPath := filepath.Join(tmpDir, "storekey.json")
		log := logging.NewLogger(logging.WorkflowStoreKey, logPath)
		log.WithBundleID("test-bundle")
		log.WithTier("Standard")

		// Log all 100 storeKey functions
		for _, fn := range logging.StoreKeyFunctions {
			log.LogStepWithDuration(fn.Phase, fn.Name, fn.LogHint, time.Microsecond, nil)
		}

		report := log.GetReport()
		t.Logf("storeKey: %d functions logged", report.Summary.TotalSteps)
		require.Equal(t, 100, report.Summary.TotalSteps, "storeKey should have exactly 100 functions")

		err := log.Flush()
		require.NoError(t, err)
		t.Logf("Report: %s", logPath)
	})

	t.Run("retrieveKey logs 200 functions", func(t *testing.T) {
		logPath := filepath.Join(tmpDir, "retrievekey.json")
		log := logging.NewLogger(logging.WorkflowRetrieveKey, logPath)
		log.WithBundleID("test-bundle")
		log.WithTier("Standard")

		// Log all 200 retrieveKey functions
		for _, fn := range logging.RetrieveKeyFunctions {
			log.LogStepWithDuration(fn.Phase, fn.Name, fn.LogHint, time.Microsecond, nil)
		}

		report := log.GetReport()
		t.Logf("retrieveKey: %d functions logged", report.Summary.TotalSteps)
		require.Equal(t, 200, report.Summary.TotalSteps, "retrieveKey should have exactly 200 functions")

		err := log.Flush()
		require.NoError(t, err)
		t.Logf("Report: %s", logPath)
	})

	t.Run("deleteKey logs 70 functions", func(t *testing.T) {
		logPath := filepath.Join(tmpDir, "deletekey.json")
		log := logging.NewLogger(logging.WorkflowDeleteKey, logPath)
		log.WithBundleID("test-bundle")
		log.WithTier("Standard")

		// Log all 70 deleteKey functions
		for _, fn := range logging.DeleteKeyFunctions {
			log.LogStepWithDuration(fn.Phase, fn.Name, fn.LogHint, time.Microsecond, nil)
		}

		report := log.GetReport()
		t.Logf("deleteKey: %d functions logged", report.Summary.TotalSteps)
		require.Equal(t, 70, report.Summary.TotalSteps, "deleteKey should have exactly 70 functions")

		err := log.Flush()
		require.NoError(t, err)
		t.Logf("Report: %s", logPath)
	})

	t.Run("rotateKey logs 126 functions", func(t *testing.T) {
		logPath := filepath.Join(tmpDir, "rotatekey.json")
		log := logging.NewLogger(logging.WorkflowRotateKey, logPath)
		log.WithBundleID("test-bundle")
		log.WithTier("Standard")

		// Log all 126 rotateKey functions
		for _, fn := range logging.RotateKeyFunctions {
			log.LogStepWithDuration(fn.Phase, fn.Name, fn.LogHint, time.Microsecond, nil)
		}

		report := log.GetReport()
		t.Logf("rotateKey: %d functions logged", report.Summary.TotalSteps)
		require.Equal(t, 126, report.Summary.TotalSteps, "rotateKey should have exactly 126 functions")

		err := log.Flush()
		require.NoError(t, err)
		t.Logf("Report: %s", logPath)
	})

	t.Run("total is 496 functions", func(t *testing.T) {
		total := len(logging.StoreKeyFunctions) + len(logging.RetrieveKeyFunctions) +
			len(logging.DeleteKeyFunctions) + len(logging.RotateKeyFunctions)
		t.Logf("Total functions defined: %d", total)
		require.Equal(t, 496, total, "Total should be exactly 496 functions")
	})

	// Print generated files
	t.Logf("\n=== Generated JSON Reports ===")
	files, _ := filepath.Glob(filepath.Join(tmpDir, "*.json"))
	for _, f := range files {
		t.Logf("  %s", f)
	}
}
