package monitoring

import (
	"github.com/iotaledger/hive.go/logger"
	"github.com/iotaledger/lockbox/v2/lockbox/verification"
	"github.com/prometheus/client_golang/prometheus"
	"time"
)

// PrometheusCollector integrates LockBox metrics with Prometheus for external monitoring
type PrometheusCollector struct {
	*logger.WrappedLogger
	registry *prometheus.Registry
	metrics  *verification.Metrics
}

// NewPrometheusCollector creates a new Prometheus collector for LockBox metrics
func NewPrometheusCollector(log *logger.Logger, metrics *verification.Metrics) *PrometheusCollector {
	return &PrometheusCollector{
		WrappedLogger: logger.NewWrappedLogger(log),
		registry:      prometheus.NewRegistry(),
		metrics:       metrics,
	}
}

// Start registers the metrics with Prometheus and starts collection
func (pc *PrometheusCollector) Start() error {
	// Register existing verification metrics with the Prometheus registry
	pc.registry.MustRegister(pc.metrics.VerificationLatency)
	pc.registry.MustRegister(pc.metrics.VerificationTotal)
	pc.registry.MustRegister(pc.metrics.VerificationSuccess)
	pc.registry.MustRegister(pc.metrics.VerificationFailures)
	pc.registry.MustRegister(pc.metrics.TokenRotations)
	pc.registry.MustRegister(pc.metrics.NodeSelectionLatency)
	pc.registry.MustRegister(pc.metrics.CacheHits)
	pc.registry.MustRegister(pc.metrics.CacheMisses)

	pc.LogInfo("Prometheus collector started for LockBox metrics")
	return nil
}

// GetRegistry returns the Prometheus registry for external scraping
func (pc *PrometheusCollector) GetRegistry() *prometheus.Registry {
	return pc.registry
}

// UpdateMetrics updates additional metrics or custom collectors if needed
func (pc *PrometheusCollector) UpdateMetrics() {
	// Placeholder for additional metric updates or custom collectors
	pc.LogDebug("Updating Prometheus metrics for LockBox")
}

// RecordCustomMetric allows recording of custom metrics not covered by verification
func (pc *PrometheusCollector) RecordCustomMetric(name string, value float64, labels map[string]string) {
	gauge := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: "lockbox",
		Subsystem: "custom",
		Name:      name,
		Help:      fmt.Sprintf("Custom metric for %s", name),
	}, getLabelKeys(labels))
	pc.registry.MustRegister(gauge)
	gauge.With(labels).Set(value)
}

// getLabelKeys extracts keys from a map for Prometheus label registration
func getLabelKeys(labels map[string]string) []string {
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	return keys
}