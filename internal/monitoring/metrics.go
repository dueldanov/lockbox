package monitoring

import (
	"context"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/iotaledger/hive.go/logger"
)

// MetricsCollector collects and exposes LockBox metrics
type MetricsCollector struct {
	*logger.WrappedLogger
	
	// Transaction metrics
	transactionsTotal       *prometheus.CounterVec
	transactionDuration     *prometheus.HistogramVec
	transactionErrors       *prometheus.CounterVec
	
	// Asset metrics
	assetsLocked           prometheus.Gauge
	assetsUnlocked         prometheus.Gauge
	assetsTotalValue       prometheus.Gauge
	
	// Performance metrics
	tps                    prometheus.Gauge
	latency                *prometheus.HistogramVec
	throughput             prometheus.Gauge
	
	// System metrics
	activeConnections      prometheus.Gauge
	memoryUsage           prometheus.Gauge
	goroutines            prometheus.Gauge
	
	// Script metrics
	scriptCompilations     *prometheus.CounterVec
	scriptExecutions       *prometheus.CounterVec
	scriptErrors          *prometheus.CounterVec
	scriptGasUsed         prometheus.Histogram
	
	// Tier metrics
	tierUsage             *prometheus.GaugeVec
	tierLimitExceeded     *prometheus.CounterVec
	
	// Alert metrics
	alertsTriggered       *prometheus.CounterVec
	alertsResolved        *prometheus.CounterVec
	
	mu                    sync.RWMutex
	tpsCalculator        *TPSCalculator
}

// NewMetricsCollector creates a new metrics collector
func NewMetricsCollector(log *logger.Logger) *MetricsCollector {
	mc := &MetricsCollector{
		WrappedLogger: logger.NewWrappedLogger(log),
		
		transactionsTotal: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: "lockbox",
			Subsystem: "transactions",
			Name:      "total",
			Help:      "Total number of transactions processed",
		}, []string{"type", "tier", "status"}),
		
		transactionDuration: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "lockbox",
			Subsystem: "transactions",
			Name:      "duration_seconds",
			Help:      "Transaction processing duration in seconds",
			Buckets:   prometheus.DefBuckets,
		}, []string{"type", "tier"}),
		
		transactionErrors: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: "lockbox",
			Subsystem: "transactions",
			Name:      "errors_total",
			Help:      "Total number of transaction errors",
		}, []string{"type", "tier", "error"}),
		
		assetsLocked: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: "lockbox",
			Subsystem: "assets",
			Name:      "locked_total",
			Help:      "Total number of locked assets",
		}),
		
		assetsUnlocked: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: "lockbox",
			Subsystem: "assets",
			Name:      "unlocked_total",
			Help:      "Total number of unlocked assets",
		}),
		
		assetsTotalValue: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: "lockbox",
			Subsystem: "assets",
			Name:      "value_total",
			Help:      "Total value of all assets in USD",
		}),
		
		tps: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: "lockbox",
			Subsystem: "performance",
			Name:      "tps",
			Help:      "Transactions per second",
		}),
		
		latency: promauto.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: "lockbox",
			Subsystem: "performance",
			Name:      "latency_milliseconds",
			Help:      "Operation latency in milliseconds",
			Buckets:   []float64{1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000},
		}, []string{"operation", "tier"}),
		
		throughput: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: "lockbox",
			Subsystem: "performance",
			Name:      "throughput_bytes_per_second",
			Help:      "Data throughput in bytes per second",
		}),
		
		activeConnections: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: "lockbox",
			Subsystem: "system",
			Name:      "connections_active",
			Help:      "Number of active connections",
		}),
		
		memoryUsage: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: "lockbox",
			Subsystem: "system",
			Name:      "memory_usage_bytes",
			Help:      "Current memory usage in bytes",
		}),
		
		goroutines: promauto.NewGauge(prometheus.GaugeOpts{
			Namespace: "lockbox",
			Subsystem: "system",
			Name:      "goroutines",
			Help:      "Number of active goroutines",
		}),
		
		scriptCompilations: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: "lockbox",
			Subsystem: "scripts",
			Name:      "compilations_total",
			Help:      "Total number of script compilations",
		}, []string{"status"}),
		
		scriptExecutions: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: "lockbox",
			Subsystem: "scripts",
			Name:      "executions_total",
			Help:      "Total number of script executions",
		}, []string{"status"}),
		
		scriptErrors: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: "lockbox",
			Subsystem: "scripts",
			Name:      "errors_total",
			Help:      "Total number of script errors",
		}, []string{"error_type"}),
		
		scriptGasUsed: promauto.NewHistogram(prometheus.HistogramOpts{
			Namespace: "lockbox",
			Subsystem: "scripts",
			Name:      "gas_used",
			Help:      "Gas used by script executions",
			Buckets:   prometheus.ExponentialBuckets(100, 2, 20),
		}),
		
		tierUsage: promauto.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "lockbox",
			Subsystem: "tiers",
			Name:      "usage",
			Help:      "Current usage by tier",
		}, []string{"tier", "resource"}),
		
		tierLimitExceeded: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: "lockbox",
			Subsystem: "tiers",
			Name:      "limit_exceeded_total",
			Help:      "Total number of tier limit exceeded events",
		}, []string{"tier", "limit_type"}),
		
		alertsTriggered: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: "lockbox",
			Subsystem: "alerts",
			Name:      "triggered_total",
			Help:      "Total number of alerts triggered",
		}, []string{"severity", "type"}),
		
		alertsResolved: promauto.NewCounterVec(prometheus.CounterOpts{
			Namespace: "lockbox",
			Subsystem: "alerts",
			Name:      "resolved_total",
			Help:      "Total number of alerts resolved",
		}, []string{"severity", "type"}),
		
		tpsCalculator: NewTPSCalculator(),
	}
	
	// Start background metrics collector
	go mc.collectSystemMetrics(context.Background())
	
	return mc
}

// RecordTransaction records a transaction metric
func (mc *MetricsCollector) RecordTransaction(txType, tier, status string, duration time.Duration) {
	mc.transactionsTotal.WithLabelValues(txType, tier, status).Inc()
	mc.transactionDuration.WithLabelValues(txType, tier).Observe(duration.Seconds())
	
	if status == "success" {
		mc.tpsCalculator.RecordTransaction()
		mc.tps.Set(mc.tpsCalculator.GetTPS())
	}
}

// RecordTransactionError records a transaction error
func (mc *MetricsCollector) RecordTransactionError(txType, tier, errorType string) {
	mc.transactionErrors.WithLabelValues(txType, tier, errorType).Inc()
}

// RecordLatency records operation latency
func (mc *MetricsCollector) RecordLatency(operation, tier string, latency time.Duration) {
	mc.latency.WithLabelValues(operation, tier).Observe(float64(latency.Milliseconds()))
}

// UpdateAssetMetrics updates asset-related metrics
func (mc *MetricsCollector) UpdateAssetMetrics(locked, unlocked int, totalValue float64) {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	
	mc.assetsLocked.Set(float64(locked))
	mc.assetsUnlocked.Set(float64(unlocked))
	mc.assetsTotalValue.Set(totalValue)
}

// RecordScriptCompilation records a script compilation
func (mc *MetricsCollector) RecordScriptCompilation(success bool) {
	status := "success"
	if !success {
		status = "failure"
	}
	mc.scriptCompilations.WithLabelValues(status).Inc()
}

// RecordScriptExecution records a script execution
func (mc *MetricsCollector) RecordScriptExecution(success bool, gasUsed uint64) {
	status := "success"
	if !success {
		status = "failure"
	}
	mc.scriptExecutions.WithLabelValues(status).Inc()
	mc.scriptGasUsed.Observe(float64(gasUsed))
}

// RecordScriptError records a script error
func (mc *MetricsCollector) RecordScriptError(errorType string) {
	mc.scriptErrors.WithLabelValues(errorType).Inc()
}

// UpdateTierUsage updates tier usage metrics
func (mc *MetricsCollector) UpdateTierUsage(tier, resource string, value float64) {
	mc.tierUsage.WithLabelValues(tier, resource).Set(value)
}

// RecordTierLimitExceeded records a tier limit exceeded event
func (mc *MetricsCollector) RecordTierLimitExceeded(tier, limitType string) {
	mc.tierLimitExceeded.WithLabelValues(tier, limitType).Inc()
}

// RecordAlert records an alert event
func (mc *MetricsCollector) RecordAlert(severity, alertType string, triggered bool) {
	if triggered {
		mc.alertsTriggered.WithLabelValues(severity, alertType).Inc()
	} else {
		mc.alertsResolved.WithLabelValues(severity, alertType).Inc()
	}
}

// UpdateConnectionCount updates the active connection count
func (mc *MetricsCollector) UpdateConnectionCount(count int) {
	mc.activeConnections.Set(float64(count))
}

// UpdateThroughput updates the throughput metric
func (mc *MetricsCollector) UpdateThroughput(bytesPerSecond float64) {
	mc.throughput.Set(bytesPerSecond)
}

// collectSystemMetrics collects system metrics periodically
func (mc *MetricsCollector) collectSystemMetrics(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Collect memory stats
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			mc.memoryUsage.Set(float64(m.Alloc))
			
			// Collect goroutine count
			mc.goroutines.Set(float64(runtime.NumGoroutine()))
		}
	}
}

// GetMetrics returns current metrics snapshot
func (mc *MetricsCollector) GetMetrics() map[string]interface{} {
	mc.mu.RLock()
	defer mc.mu.RUnlock()
	
	return map[string]interface{}{
		"tps":               mc.tpsCalculator.GetTPS(),
		"active_connections": mc.activeConnections,
		"memory_usage":      mc.memoryUsage,
		"goroutines":        mc.goroutines,
	}
}

// TPSCalculator calculates transactions per second
type TPSCalculator struct {
	mu              sync.Mutex
	transactions    []time.Time
	windowDuration  time.Duration
}

// NewTPSCalculator creates a new TPS calculator
func NewTPSCalculator() *TPSCalculator {
	return &TPSCalculator{
		transactions:   make([]time.Time, 0, 10000),
		windowDuration: time.Minute,
	}
}

// RecordTransaction records a transaction timestamp
func (tc *TPSCalculator) RecordTransaction() {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	
	now := time.Now()
	tc.transactions = append(tc.transactions, now)
	
	// Clean old transactions
	cutoff := now.Add(-tc.windowDuration)
	validIdx := 0
	for i, t := range tc.transactions {
		if t.After(cutoff) {
			validIdx = i
			break
		}
	}
	tc.transactions = tc.transactions[validIdx:]
}

// GetTPS returns the current TPS
func (tc *TPSCalculator) GetTPS() float64 {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	
	if len(tc.transactions) == 0 {
		return 0
	}
	
	now := time.Now()
	cutoff := now.Add(-time.Second)
	
	count := 0
	for i := len(tc.transactions) - 1; i >= 0; i-- {
		if tc.transactions[i].Before(cutoff) {
			break
		}
		count++
	}
	
	return float64(count)
}