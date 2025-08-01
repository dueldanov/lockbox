package verification

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Metrics tracks verification performance metrics
type Metrics struct {
	verificationLatency   prometheus.Histogram
	verificationTotal     prometheus.Counter
	verificationSuccess   prometheus.Counter
	verificationFailures  prometheus.Counter
	tokenRotations        prometheus.Counter
	nodeSelectionLatency  prometheus.Histogram
	cacheHits            prometheus.Counter
	cacheMisses          prometheus.Counter
	
	mu sync.RWMutex
	latencyBuckets []time.Duration
}

// NewMetrics creates new verification metrics
func NewMetrics(registry prometheus.Registerer) *Metrics {
	m := &Metrics{
		latencyBuckets: []time.Duration{
			100 * time.Millisecond,
			250 * time.Millisecond,
			500 * time.Millisecond,
			1 * time.Second,
			2 * time.Second,
			5 * time.Second,
		},
	}
	
	// Define metrics
	m.verificationLatency = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: "lockbox",
		Subsystem: "verification",
		Name:      "latency_seconds",
		Help:      "Verification latency in seconds",
		Buckets:   prometheus.DefBuckets,
	})
	
	m.verificationTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "lockbox",
		Subsystem: "verification",
		Name:      "total",
		Help:      "Total number of verifications",
	})
	
	m.verificationSuccess = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "lockbox",
		Subsystem: "verification",
		Name:      "success_total",
		Help:      "Total number of successful verifications",
	})
	
	m.verificationFailures = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "lockbox",
		Subsystem: "verification",
		Name:      "failures_total",
		Help:      "Total number of failed verifications",
	})
	
	m.tokenRotations = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "lockbox",
		Subsystem: "verification",
		Name:      "token_rotations_total",
		Help:      "Total number of token rotations",
	})
	
	m.nodeSelectionLatency = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: "lockbox",
		Subsystem: "verification",
		Name:      "node_selection_latency_seconds",
		Help:      "Node selection latency in seconds",
		Buckets:   prometheus.DefBuckets,
	})
	
	m.cacheHits = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "lockbox",
		Subsystem: "verification",
		Name:      "cache_hits_total",
		Help:      "Total number of cache hits",
	})
	
	m.cacheMisses = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "lockbox",
		Subsystem: "verification",
		Name:      "cache_misses_total",
		Help:      "Total number of cache misses",
	})
	
	// Register metrics
	registry.MustRegister(
		m.verificationLatency,
		m.verificationTotal,
		m.verificationSuccess,
		m.verificationFailures,
		m.tokenRotations,
		m.nodeSelectionLatency,
		m.cacheHits,
		m.cacheMisses,
	)
	
	return m
}

// RecordVerification records a verification attempt
func (m *Metrics) RecordVerification(duration time.Duration, success bool) {
	m.verificationTotal.Inc()
	m.verificationLatency.Observe(duration.Seconds())
	
	if success {
		m.verificationSuccess.Inc()
	} else {
		m.verificationFailures.Inc()
	}
}

// RecordTokenRotation records a token rotation event
func (m *Metrics) RecordTokenRotation() {
	m.tokenRotations.Inc()
}

// RecordNodeSelection records node selection performance
func (m *Metrics) RecordNodeSelection(duration time.Duration) {
	m.nodeSelectionLatency.Observe(duration.Seconds())
}

// RecordCacheHit records a cache hit
func (m *Metrics) RecordCacheHit() {
	m.cacheHits.Inc()
}

// RecordCacheMiss records a cache miss
func (m *Metrics) RecordCacheMiss() {
	m.cacheMisses.Inc()
}

// GetLatencyPercentile calculates latency percentile
func (m *Metrics) GetLatencyPercentile(percentile float64) time.Duration {
	// This would require storing raw latency data
	// For now, return a placeholder
	return 2 * time.Second
}