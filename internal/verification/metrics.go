package verification

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Metrics tracks verification performance metrics
type Metrics struct {
	VerificationLatency   prometheus.Histogram
	VerificationTotal     prometheus.Counter
	VerificationSuccess   prometheus.Counter
	VerificationFailures  prometheus.Counter
	TokenRotations        prometheus.Counter
	NodeSelectionLatency  prometheus.Histogram
	CacheHits            prometheus.Counter
	CacheMisses          prometheus.Counter

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
	m.VerificationLatency = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: "lockbox",
		Subsystem: "verification",
		Name:      "latency_seconds",
		Help:      "Verification latency in seconds",
		Buckets:   prometheus.DefBuckets,
	})

	m.VerificationTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "lockbox",
		Subsystem: "verification",
		Name:      "total",
		Help:      "Total number of verifications",
	})

	m.VerificationSuccess = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "lockbox",
		Subsystem: "verification",
		Name:      "success_total",
		Help:      "Total number of successful verifications",
	})

	m.VerificationFailures = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "lockbox",
		Subsystem: "verification",
		Name:      "failures_total",
		Help:      "Total number of failed verifications",
	})

	m.TokenRotations = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "lockbox",
		Subsystem: "verification",
		Name:      "token_rotations_total",
		Help:      "Total number of token rotations",
	})

	m.NodeSelectionLatency = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: "lockbox",
		Subsystem: "verification",
		Name:      "node_selection_latency_seconds",
		Help:      "Node selection latency in seconds",
		Buckets:   prometheus.DefBuckets,
	})

	m.CacheHits = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "lockbox",
		Subsystem: "verification",
		Name:      "cache_hits_total",
		Help:      "Total number of cache hits",
	})

	m.CacheMisses = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "lockbox",
		Subsystem: "verification",
		Name:      "cache_misses_total",
		Help:      "Total number of cache misses",
	})

	// Register metrics
	registry.MustRegister(
		m.VerificationLatency,
		m.VerificationTotal,
		m.VerificationSuccess,
		m.VerificationFailures,
		m.TokenRotations,
		m.NodeSelectionLatency,
		m.CacheHits,
		m.CacheMisses,
	)
	
	return m
}

// RecordVerification records a verification attempt
func (m *Metrics) RecordVerification(duration time.Duration, success bool) {
	m.VerificationTotal.Inc()
	m.VerificationLatency.Observe(duration.Seconds())

	if success {
		m.VerificationSuccess.Inc()
	} else {
		m.VerificationFailures.Inc()
	}
}

// RecordTokenRotation records a token rotation event
func (m *Metrics) RecordTokenRotation() {
	m.TokenRotations.Inc()
}

// RecordNodeSelection records node selection performance
func (m *Metrics) RecordNodeSelection(duration time.Duration) {
	m.NodeSelectionLatency.Observe(duration.Seconds())
}

// RecordCacheHit records a cache hit
func (m *Metrics) RecordCacheHit() {
	m.CacheHits.Inc()
}

// RecordCacheMiss records a cache miss
func (m *Metrics) RecordCacheMiss() {
	m.CacheMisses.Inc()
}

// GetLatencyPercentile calculates latency percentile
func (m *Metrics) GetLatencyPercentile(percentile float64) time.Duration {
	// This would require storing raw latency data
	// For now, return a placeholder
	return 2 * time.Second
}