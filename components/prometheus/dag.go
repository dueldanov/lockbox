package prometheus

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	dagApprovals       *prometheus.GaugeVec
	dagApprovalLatency prometheus.Gauge
)

func configureDAG() {
	dagApprovals = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "iota",
			Subsystem: "dag",
			Name:      "approvals",
			Help:      "Number of DAG approvals.",
		},
		[]string{"type"},
	)

	dagApprovalLatency = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: "iota",
			Subsystem: "dag",
			Name:      "approval_latency_seconds",
			Help:      "Last DAG approval latency in seconds.",
		},
	)

	registry.MustRegister(dagApprovals)
	registry.MustRegister(dagApprovalLatency)

	addCollect(collectDAG)
}

func collectDAG() {
	dagApprovals.WithLabelValues("added").Set(float64(deps.ServerMetrics.DAGApprovalsAdded.Load()))
	dagApprovals.WithLabelValues("confirmed").Set(float64(deps.ServerMetrics.DAGApprovalsConfirmed.Load()))

	latencyNanos := deps.ServerMetrics.DAGApprovalLatencyNanos.Load()
	dagApprovalLatency.Set(float64(latencyNanos) / float64(time.Second))
}
