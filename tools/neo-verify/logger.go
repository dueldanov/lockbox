package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// NEOReport is the top-level verification report
type NEOReport struct {
	Workflow   string     `json:"workflow"`
	Timestamp  string     `json:"timestamp"`
	Tier       string     `json:"tier"`
	Steps      []NEOStep  `json:"steps"`
	TotalSteps int        `json:"total_steps"`
	Passed     int        `json:"passed"`
	Failed     int        `json:"failed"`
	Summary    NEOSummary `json:"summary"`
}

// NEOStep represents a single step in the workflow
type NEOStep struct {
	Step           int         `json:"step"`
	Function       string      `json:"function"`
	File           string      `json:"file"`
	Purpose        string      `json:"purpose"`
	RequirementRef string      `json:"requirement_ref"`
	Input          interface{} `json:"input,omitempty"`
	Output         interface{} `json:"output,omitempty"`
	DurationMs     int64       `json:"duration_ms"`
	Result         string      `json:"result"`
	Error          string      `json:"error,omitempty"`
}

// NEOSummary provides aggregate statistics
type NEOSummary struct {
	TotalFunctions   int            `json:"total_functions"`
	CryptoOperations int            `json:"crypto_operations"`
	StorageOps       int            `json:"storage_operations"`
	ZKPOperations    int            `json:"zkp_operations"`
	Categories       map[string]int `json:"categories"`
}

// NEOLogger handles NEO format logging
type NEOLogger struct {
	workflow  string
	tier      string
	steps     []NEOStep
	stepNum   int
	startTime time.Time
}

// NewNEOLogger creates a new NEO logger
func NewNEOLogger(workflow, tier string) *NEOLogger {
	return &NEOLogger{
		workflow:  workflow,
		tier:      tier,
		steps:     make([]NEOStep, 0),
		stepNum:   0,
		startTime: time.Now(),
	}
}

// LogStep logs a single workflow step
func (l *NEOLogger) LogStep(function, file, purpose, reqRef string, input, output interface{}, duration time.Duration, err error) {
	l.stepNum++

	step := NEOStep{
		Step:           l.stepNum,
		Function:       function,
		File:           file,
		Purpose:        purpose,
		RequirementRef: reqRef,
		Input:          input,
		Output:         output,
		DurationMs:     duration.Milliseconds(),
		Result:         "PASS",
	}

	if err != nil {
		step.Result = "FAIL"
		step.Error = err.Error()
	}

	l.steps = append(l.steps, step)

	// Print live progress
	status := "\033[32mPASS\033[0m"
	if err != nil {
		status = "\033[31mFAIL\033[0m"
	}
	fmt.Printf("  [%d] %s: %s (%dms) %s\n", l.stepNum, function, purpose, duration.Milliseconds(), status)
}

// GenerateReport creates the final NEO report
func (l *NEOLogger) GenerateReport() *NEOReport {
	passed := 0
	failed := 0
	categories := make(map[string]int)
	cryptoOps := 0
	storageOps := 0
	zkpOps := 0

	for _, step := range l.steps {
		if step.Result == "PASS" {
			passed++
		} else {
			failed++
		}

		// Categorize operations
		switch {
		case contains(step.Function, "Encrypt", "Decrypt", "HKDF", "Derive", "ChaCha"):
			cryptoOps++
			categories["crypto"]++
		case contains(step.Function, "Store", "Get", "Delete", "Retrieve", "storage"):
			storageOps++
			categories["storage"]++
		case contains(step.Function, "ZKP", "Proof", "Verify", "Commitment"):
			zkpOps++
			categories["zkp"]++
		case contains(step.Function, "Decoy", "Mix", "Shard"):
			categories["obfuscation"]++
		default:
			categories["general"]++
		}
	}

	return &NEOReport{
		Workflow:   l.workflow,
		Timestamp:  time.Now().Format(time.RFC3339),
		Tier:       l.tier,
		Steps:      l.steps,
		TotalSteps: len(l.steps),
		Passed:     passed,
		Failed:     failed,
		Summary: NEOSummary{
			TotalFunctions:   len(l.steps),
			CryptoOperations: cryptoOps,
			StorageOps:       storageOps,
			ZKPOperations:    zkpOps,
			Categories:       categories,
		},
	}
}

// WriteJSON writes the report to a JSON file
func (l *NEOLogger) WriteJSON(filename string) error {
	report := l.GenerateReport()

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal report: %w", err)
	}

	if err := os.WriteFile(filename, data, 0644); err != nil {
		return fmt.Errorf("failed to write report: %w", err)
	}

	return nil
}

// PrintSummary prints a human-readable summary
func (l *NEOLogger) PrintSummary() {
	report := l.GenerateReport()

	fmt.Println("\n" + repeatStr("=", 60))
	fmt.Printf("NEO VERIFICATION REPORT: %s\n", report.Workflow)
	fmt.Println(repeatStr("=", 60))
	fmt.Printf("Tier: %s\n", report.Tier)
	fmt.Printf("Timestamp: %s\n", report.Timestamp)
	fmt.Printf("Total Steps: %d\n", report.TotalSteps)
	fmt.Printf("Passed: \033[32m%d\033[0m\n", report.Passed)
	fmt.Printf("Failed: \033[31m%d\033[0m\n", report.Failed)
	fmt.Println()
	fmt.Println("Categories:")
	for cat, count := range report.Summary.Categories {
		fmt.Printf("  - %s: %d\n", cat, count)
	}
	fmt.Println(repeatStr("=", 60))
}

// Helper function to check if string contains any of the patterns
func contains(s string, patterns ...string) bool {
	for _, p := range patterns {
		if len(s) >= len(p) {
			for i := 0; i <= len(s)-len(p); i++ {
				if s[i:i+len(p)] == p {
					return true
				}
			}
		}
	}
	return false
}

// String repeat helper
func repeatStr(s string, n int) string {
	result := ""
	for i := 0; i < n; i++ {
		result += s
	}
	return result
}
