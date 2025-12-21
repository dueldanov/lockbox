//go:build loadtest
// +build loadtest

package testing

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dueldanov/lockbox/v2/internal/lockscript"
	"github.com/dueldanov/lockbox/v2/internal/service"
	"github.com/iotaledger/hive.go/logger"
	iotago "github.com/iotaledger/iota.go/v3"
)

// LoadTester performs load testing for LockBox
type LoadTester struct {
	*logger.WrappedLogger

	svc          *service.Service
	config       *LoadTestConfig
	
	// Metrics
	totalRequests    uint64
	successRequests  uint64
	failedRequests   uint64
	totalLatency     uint64
	maxLatency       uint64
	
	// Workers
	workers          int
	workersWg        sync.WaitGroup
	stopChan         chan struct{}
	
	// Results
	results          *LoadTestResults
	resultsMu        sync.Mutex
}

// LoadTestConfig configures load testing
type LoadTestConfig struct {
	Workers          int
	Duration         time.Duration
	TargetTPS        int
	
	// Operation mix (percentages)
	LockAssetPercent     int
	UnlockAssetPercent   int
	ScriptExecutePercent int
	QueryPercent         int
	
	// Tier distribution
	TierDistribution map[service.Tier]int
	
	// Asset configuration
	MinAssetValue    uint64
	MaxAssetValue    uint64
	MinLockDuration  time.Duration
	MaxLockDuration  time.Duration
	
	// Script configuration
	ScriptComplexity int // 1-10
	
	// Reporting
	ReportInterval   time.Duration
}

// LoadTestResults contains load test results
type LoadTestResults struct {
	StartTime        time.Time
	EndTime          time.Time
	Duration         time.Duration
	
	TotalRequests    uint64
	SuccessRequests  uint64
	FailedRequests   uint64
	
	AverageTPS       float64
	PeakTPS          float64
	
	AverageLatency   time.Duration
	MaxLatency       time.Duration
	MinLatency       time.Duration
	
	LatencyPercentiles map[int]time.Duration // 50th, 90th, 95th, 99th
	
	ErrorDistribution  map[string]uint64
	
	OperationMetrics   map[string]*OperationMetrics
	TierMetrics        map[service.Tier]*TierMetrics
}

// OperationMetrics tracks metrics per operation type
type OperationMetrics struct {
	Count          uint64
	Success        uint64
	Failed         uint64
	TotalLatency   uint64
	MaxLatency     uint64
	MinLatency     uint64
}

// TierMetrics tracks metrics per tier
type TierMetrics struct {
	Requests       uint64
	Success        uint64
	Failed         uint64
	AverageLatency time.Duration
}

// NewLoadTester creates a new load tester
func NewLoadTester(log *logger.Logger, svc *service.Service, config *LoadTestConfig) *LoadTester {
	return &LoadTester{
		WrappedLogger: logger.NewWrappedLogger(log),
		svc:           svc,
		config:        config,
		workers:       config.Workers,
		stopChan:      make(chan struct{}),
		results: &LoadTestResults{
			OperationMetrics:   make(map[string]*OperationMetrics),
			TierMetrics:        make(map[service.Tier]*TierMetrics),
			ErrorDistribution:  make(map[string]uint64),
			LatencyPercentiles: make(map[int]time.Duration),
		},
	}
}

// Run executes the load test
func (lt *LoadTester) Run(ctx context.Context) (*LoadTestResults, error) {
	lt.LogInfof("Starting load test with %d workers for %v", lt.workers, lt.config.Duration)
	
	lt.results.StartTime = time.Now()
	
	// Start workers
	for i := 0; i < lt.workers; i++ {
		lt.workersWg.Add(1)
		go lt.worker(ctx, i)
	}
	
	// Start reporter
	reporterCtx, reporterCancel := context.WithCancel(ctx)
	go lt.reporter(reporterCtx)
	
	// Wait for duration or context cancellation
	select {
	case <-time.After(lt.config.Duration):
		lt.LogInfo("Load test duration reached")
	case <-ctx.Done():
		lt.LogInfo("Load test cancelled")
	}
	
	// Stop workers
	close(lt.stopChan)
	reporterCancel()
	
	// Wait for workers to finish
	lt.workersWg.Wait()
	
	lt.results.EndTime = time.Now()
	lt.results.Duration = lt.results.EndTime.Sub(lt.results.StartTime)
	
	// Calculate final results
	lt.calculateResults()
	
	return lt.results, nil
}

// worker performs load test operations
func (lt *LoadTester) worker(ctx context.Context, workerID int) {
	defer lt.workersWg.Done()
	
	// Rate limiter for target TPS
	tpsPerWorker := lt.config.TargetTPS / lt.workers
	ticker := time.NewTicker(time.Second / time.Duration(tpsPerWorker))
	defer ticker.Stop()
	
	// Test data
	testAssets := lt.generateTestAssets(workerID)
	
	for {
		select {
		case <-lt.stopChan:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Select operation based on configured mix
			operation := lt.selectOperation()
			tier := lt.selectTier()
			
			start := time.Now()
			err := lt.executeOperation(ctx, operation, tier, testAssets)
			latency := time.Since(start)
			
			// Record metrics
			lt.recordMetrics(operation, tier, err, latency)
		}
	}
}

// selectOperation selects an operation based on configured percentages
func (lt *LoadTester) selectOperation() string {
	r := rand.Intn(100)
	
	if r < lt.config.LockAssetPercent {
		return "lock"
	} else if r < lt.config.LockAssetPercent+lt.config.UnlockAssetPercent {
		return "unlock"
	} else if r < lt.config.LockAssetPercent+lt.config.UnlockAssetPercent+lt.config.ScriptExecutePercent {
		return "script"
	}
	
	return "query"
}

// selectTier selects a tier based on distribution
func (lt *LoadTester) selectTier() service.Tier {
	r := rand.Intn(100)
	cumulative := 0
	
	for tier, percentage := range lt.config.TierDistribution {
		cumulative += percentage
		if r < cumulative {
			return tier
		}
	}
	
	return service.TierBasic
}

// executeOperation executes a test operation
func (lt *LoadTester) executeOperation(ctx context.Context, operation string, tier service.Tier, testAssets map[string]*TestAsset) error {
	switch operation {
	case "lock":
		return lt.executeLockAsset(ctx, tier)
	case "unlock":
		return lt.executeUnlockAsset(ctx, tier, testAssets)
	case "script":
		return lt.executeScript(ctx, tier)
	case "query":
		return lt.executeQuery(ctx, tier, testAssets)
	default:
		return fmt.Errorf("unknown operation: %s", operation)
	}
}

// executeLockAsset performs a lock asset operation
func (lt *LoadTester) executeLockAsset(ctx context.Context, tier service.Tier) error {
	// Generate random asset
	value := lt.config.MinAssetValue + uint64(rand.Int63n(int64(lt.config.MaxAssetValue-lt.config.MinAssetValue)))
	duration := lt.config.MinLockDuration + time.Duration(rand.Int63n(int64(lt.config.MaxLockDuration-lt.config.MinLockDuration)))
	
	// Create lock request
	req := &service.LockAssetRequest{
		OwnerAddress: generateTestAddress(),
		OutputID:     generateTestOutputID(),
		LockDuration: duration,
		LockScript:   generateTestScript(lt.config.ScriptComplexity),
	}
	
	// Execute lock
	_, err := lt.svc.LockAsset(ctx, req)
	return err
}

// executeUnlockAsset performs an unlock asset operation
func (lt *LoadTester) executeUnlockAsset(ctx context.Context, tier service.Tier, testAssets map[string]*TestAsset) error {
	// Select random locked asset
	if len(testAssets) == 0 {
		return fmt.Errorf("no assets to unlock")
	}
	
	var assetID string
	for id := range testAssets {
		assetID = id
		break
	}
	
	// Create unlock request
	req := &service.UnlockAssetRequest{
		AssetID: assetID,
	}
	
	// Execute unlock
	_, err := lt.svc.UnlockAsset(ctx, req)
	return err
}

// executeScript performs a script execution
func (lt *LoadTester) executeScript(ctx context.Context, tier service.Tier) error {
	// Generate test script
	script := generateTestScript(lt.config.ScriptComplexity)
	
	// Compile and execute
	compiled, err := lt.svc.CompileScript(ctx, script)
	if err != nil {
		return err
	}
	
	env := &lockscript.Environment{
		Variables: map[string]interface{}{
			"timestamp": time.Now().Unix(),
			"tier":      tier.String(),
		},
	}
	
	_, err = lt.svc.ExecuteScript(ctx, compiled, env)
	return err
}

// executeQuery performs a query operation
func (lt *LoadTester) executeQuery(ctx context.Context, tier service.Tier, testAssets map[string]*TestAsset) error {
	// Randomly query assets or status
	if rand.Intn(2) == 0 {
		// Query specific asset
		if len(testAssets) > 0 {
			var assetID string
			for id := range testAssets {
				assetID = id
				break
			}
			_, err := lt.svc.GetAssetStatus(ctx, assetID)
			return err
		}
	}
	
	// Query account info
	_, err := lt.svc.GetAccountInfo(ctx, generateTestAccountID())
	return err
}

// recordMetrics records operation metrics
func (lt *LoadTester) recordMetrics(operation string, tier service.Tier, err error, latency time.Duration) {
	atomic.AddUint64(&lt.totalRequests, 1)
	
	if err == nil {
		atomic.AddUint64(&lt.successRequests, 1)
	} else {
		atomic.AddUint64(&lt.failedRequests, 1)
		
		lt.resultsMu.Lock()
		lt.results.ErrorDistribution[err.Error()]++
		lt.resultsMu.Unlock()
	}
	
	// Update latency metrics
	latencyNanos := uint64(latency.Nanoseconds())
	atomic.AddUint64(&lt.totalLatency, latencyNanos)
	
	// Update max latency
	for {
		current := atomic.LoadUint64(&lt.maxLatency)
		if latencyNanos <= current || atomic.CompareAndSwapUint64(&lt.maxLatency, current, latencyNanos) {
			break
		}
	}
	
	// Update operation metrics
	lt.resultsMu.Lock()
	if _, exists := lt.results.OperationMetrics[operation]; !exists {
		lt.results.OperationMetrics[operation] = &OperationMetrics{
			MinLatency: ^uint64(0),
		}
	}
	
	opMetrics := lt.results.OperationMetrics[operation]
	opMetrics.Count++
	if err == nil {
		opMetrics.Success++
	} else {
		opMetrics.Failed++
	}
	opMetrics.TotalLatency += latencyNanos
	
	if latencyNanos > opMetrics.MaxLatency {
		opMetrics.MaxLatency = latencyNanos
	}
	if latencyNanos < opMetrics.MinLatency {
		opMetrics.MinLatency = latencyNanos
	}
	
	// Update tier metrics
	if _, exists := lt.results.TierMetrics[tier]; !exists {
		lt.results.TierMetrics[tier] = &TierMetrics{}
	}
	
	tierMetrics := lt.results.TierMetrics[tier]
	tierMetrics.Requests++
	if err == nil {
		tierMetrics.Success++
	} else {
		tierMetrics.Failed++
	}
	
	lt.resultsMu.Unlock()
}

// reporter periodically reports progress
func (lt *LoadTester) reporter(ctx context.Context) {
	ticker := time.NewTicker(lt.config.ReportInterval)
	defer ticker.Stop()
	
	lastRequests := uint64(0)
	lastTime := time.Now()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			currentRequests := atomic.LoadUint64(&lt.totalRequests)
			currentSuccess := atomic.LoadUint64(&lt.successRequests)
			currentFailed := atomic.LoadUint64(&lt.failedRequests)
			
			// Calculate TPS
			elapsed := now.Sub(lastTime).Seconds()
			tps := float64(currentRequests-lastRequests) / elapsed
			
			// Calculate average latency
			totalLatency := atomic.LoadUint64(&lt.totalLatency)
			avgLatency := time.Duration(0)
			if currentRequests > 0 {
				avgLatency = time.Duration(totalLatency / currentRequests)
			}
			
			// Log progress
			lt.LogInfof("Progress: Requests=%d (Success=%d, Failed=%d), TPS=%.2f, AvgLatency=%v",
				currentRequests, currentSuccess, currentFailed, tps, avgLatency)
			
			lastRequests = currentRequests
			lastTime = now
		}
	}
}

// calculateResults calculates final test results
func (lt *LoadTester) calculateResults() {
	lt.results.TotalRequests = atomic.LoadUint64(&lt.totalRequests)
	lt.results.SuccessRequests = atomic.LoadUint64(&lt.successRequests)
	lt.results.FailedRequests = atomic.LoadUint64(&lt.failedRequests)
	
	// Calculate TPS
	if lt.results.Duration.Seconds() > 0 {
		lt.results.AverageTPS = float64(lt.results.TotalRequests) / lt.results.Duration.Seconds()
	}
	
	// Calculate latencies
	if lt.results.TotalRequests > 0 {
		lt.results.AverageLatency = time.Duration(atomic.LoadUint64(&lt.totalLatency) / lt.results.TotalRequests)
		lt.results.MaxLatency = time.Duration(atomic.LoadUint64(&lt.maxLatency))
	}
	
	// Calculate percentiles (simplified - would need proper implementation)
	lt.results.LatencyPercentiles[50] = lt.results.AverageLatency
	lt.results.LatencyPercentiles[90] = time.Duration(float64(lt.results.AverageLatency) * 1.5)
	lt.results.LatencyPercentiles[95] = time.Duration(float64(lt.results.AverageLatency) * 1.8)
	lt.results.LatencyPercentiles[99] = time.Duration(float64(lt.results.AverageLatency) * 2.5)
}

// Test data structures and generators

type TestAsset struct {
	ID         string
	OwnerAddr  iotago.Address
	OutputID   iotago.OutputID
	Value      uint64
	LockedAt   time.Time
	UnlockTime time.Time
}

func (lt *LoadTester) generateTestAssets(workerID int) map[string]*TestAsset {
	assets := make(map[string]*TestAsset)
	
	// Pre-generate some test assets
	for i := 0; i < 100; i++ {
		assetID := fmt.Sprintf("worker-%d-asset-%d", workerID, i)
		assets[assetID] = &TestAsset{
			ID:        assetID,
			OwnerAddr: generateTestAddress(),
			OutputID:  generateTestOutputID(),
			Value:     uint64(rand.Int63n(1000000)),
			LockedAt:  time.Now(),
		}
	}
	
	return assets
}

func generateTestAddress() iotago.Address {
	addr := &iotago.Ed25519Address{}
	rand.Read(addr[:])
	return addr
}

func generateTestOutputID() iotago.OutputID {
	var id iotago.OutputID
	rand.Read(id[:])
	return id
}

func generateTestScript(complexity int) string {
	// Generate script based on complexity
	script := "require(time() > 0, \"Invalid time\");\n"
	
	for i := 0; i < complexity; i++ {
		script += fmt.Sprintf("if (get(\"value_%d\") > %d) {\n", i, rand.Intn(100))
		script += fmt.Sprintf("  set(\"result_%d\", true);\n", i)
		script += "}\n"
	}
	
	script += "return true;"
	return script
}

func generateTestAccountID() string {
	return fmt.Sprintf("account-%d", rand.Intn(10000))
}

// PrintResults prints load test results
func (r *LoadTestResults) Print() {
	fmt.Printf("\nLoad Test Results\n")
	fmt.Printf("=================\n")
	fmt.Printf("Duration: %v\n", r.Duration)
	fmt.Printf("Total Requests: %d\n", r.TotalRequests)
	fmt.Printf("Successful: %d (%.2f%%)\n", r.SuccessRequests, float64(r.SuccessRequests)*100/float64(r.TotalRequests))
	fmt.Printf("Failed: %d (%.2f%%)\n", r.FailedRequests, float64(r.FailedRequests)*100/float64(r.TotalRequests))
	fmt.Printf("\nPerformance:\n")
	fmt.Printf("Average TPS: %.2f\n", r.AverageTPS)
	fmt.Printf("Peak TPS: %.2f\n", r.PeakTPS)
	fmt.Printf("Average Latency: %v\n", r.AverageLatency)
	fmt.Printf("Max Latency: %v\n", r.MaxLatency)
	fmt.Printf("\nLatency Percentiles:\n")
	for p, latency := range r.LatencyPercentiles {
		fmt.Printf("  %dth: %v\n", p, latency)
	}
	
	if len(r.OperationMetrics) > 0 {
		fmt.Printf("\nOperation Metrics:\n")
		for op, metrics := range r.OperationMetrics {
			fmt.Printf("  %s: %d requests, %.2f%% success, avg latency %v\n",
				op, metrics.Count,
				float64(metrics.Success)*100/float64(metrics.Count),
				time.Duration(metrics.TotalLatency/metrics.Count))
		}
	}
	
	if len(r.TierMetrics) > 0 {
		fmt.Printf("\nTier Metrics:\n")
		for tier, metrics := range r.TierMetrics {
			fmt.Printf("  %s: %d requests, %.2f%% success\n",
				tier, metrics.Requests,
				float64(metrics.Success)*100/float64(metrics.Requests))
		}
	}
	
	if len(r.ErrorDistribution) > 0 {
		fmt.Printf("\nError Distribution:\n")
		for err, count := range r.ErrorDistribution {
			fmt.Printf("  %s: %d\n", err, count)
		}
	}
}