package monitoring

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/iotaledger/hive.go/logger"
	"github.com/iotaledger/hive.go/runtime/event"
)

// AlertSeverity represents the severity of an alert
type AlertSeverity string

const (
	SeverityInfo     AlertSeverity = "info"
	SeverityWarning  AlertSeverity = "warning"
	SeverityCritical AlertSeverity = "critical"
)

// AlertType represents the type of alert
type AlertType string

const (
	AlertTypePerformance    AlertType = "performance"
	AlertTypeSecurity       AlertType = "security"
	AlertTypeAvailability   AlertType = "availability"
	AlertTypeCapacity       AlertType = "capacity"
	AlertTypeError          AlertType = "error"
	AlertTypeThreshold      AlertType = "threshold"
)

// Alert represents a system alert
type Alert struct {
	ID          string
	Type        AlertType
	Severity    AlertSeverity
	Title       string
	Description string
	Source      string
	Timestamp   time.Time
	Resolved    bool
	ResolvedAt  *time.Time
	Metadata    map[string]interface{}
}

// AlertRule defines conditions for triggering alerts
type AlertRule struct {
	ID          string
	Name        string
	Type        AlertType
	Severity    AlertSeverity
	Condition   AlertCondition
	Actions     []AlertAction
	Cooldown    time.Duration
	LastFired   time.Time
}

// AlertCondition interface for alert conditions
type AlertCondition interface {
	Evaluate(ctx context.Context, data interface{}) (bool, string)
}

// AlertAction interface for alert actions
type AlertAction interface {
	Execute(ctx context.Context, alert *Alert) error
}

// AlertManager manages system alerts
type AlertManager struct {
	*logger.WrappedLogger
	
	rules        map[string]*AlertRule
	activeAlerts map[string]*Alert
	history      []*Alert
	
	metrics      *MetricsCollector
	mu           sync.RWMutex
	
	Events struct {
		AlertTriggered *event.Event1[*Alert]
		AlertResolved  *event.Event1[*Alert]
	}
}

// NewAlertManager creates a new alert manager
func NewAlertManager(log *logger.Logger, metrics *MetricsCollector) *AlertManager {
	am := &AlertManager{
		WrappedLogger: logger.NewWrappedLogger(log),
		rules:         make(map[string]*AlertRule),
		activeAlerts:  make(map[string]*Alert),
		history:       make([]*Alert, 0, 1000),
		metrics:       metrics,
	}
	
	am.Events.AlertTriggered = event.New1[*Alert]()
	am.Events.AlertResolved = event.New1[*Alert]()
	
	// Initialize default alert rules
	am.initializeDefaultRules()
	
	return am
}

// initializeDefaultRules sets up default alert rules
func (am *AlertManager) initializeDefaultRules() {
	// High TPS alert for Elite tier
	am.AddRule(&AlertRule{
		ID:       "high-tps",
		Name:     "High TPS Alert",
		Type:     AlertTypePerformance,
		Severity: SeverityWarning,
		Condition: &ThresholdCondition{
			Metric:    "tps",
			Threshold: 450,
			Operator:  ">",
		},
		Actions: []AlertAction{
			&LogAction{},
			&MetricAction{metrics: am.metrics},
		},
		Cooldown: 5 * time.Minute,
	})
	
	// Low TPS alert
	am.AddRule(&AlertRule{
		ID:       "low-tps",
		Name:     "Low TPS Alert",
		Type:     AlertTypePerformance,
		Severity: SeverityCritical,
		Condition: &ThresholdCondition{
			Metric:    "tps",
			Threshold: 10,
			Operator:  "<",
		},
		Actions: []AlertAction{
			&LogAction{},
			&MetricAction{metrics: am.metrics},
		},
		Cooldown: 5 * time.Minute,
	})
	
	// High memory usage alert
	am.AddRule(&AlertRule{
		ID:       "high-memory",
		Name:     "High Memory Usage",
		Type:     AlertTypeCapacity,
		Severity: SeverityWarning,
		Condition: &ThresholdCondition{
			Metric:    "memory_usage",
			Threshold: 4 * 1024 * 1024 * 1024, // 4GB
			Operator:  ">",
		},
		Actions: []AlertAction{
			&LogAction{},
			&MetricAction{metrics: am.metrics},
		},
		Cooldown: 10 * time.Minute,
	})
	
	// High error rate alert
	am.AddRule(&AlertRule{
		ID:       "high-error-rate",
		Name:     "High Error Rate",
		Type:     AlertTypeError,
		Severity: SeverityCritical,
		Condition: &RateCondition{
			Metric:    "transaction_errors",
			Threshold: 0.05, // 5% error rate
			Window:    time.Minute,
		},
		Actions: []AlertAction{
			&LogAction{},
			&MetricAction{metrics: am.metrics},
		},
		Cooldown: 5 * time.Minute,
	})
	
	// Script execution failure alert
	am.AddRule(&AlertRule{
		ID:       "script-failure",
		Name:     "Script Execution Failures",
		Type:     AlertTypeError,
		Severity: SeverityWarning,
		Condition: &CountCondition{
			Metric:    "script_errors",
			Threshold: 10,
			Window:    5 * time.Minute,
		},
		Actions: []AlertAction{
			&LogAction{},
			&MetricAction{metrics: am.metrics},
		},
		Cooldown: 10 * time.Minute,
	})
}

// AddRule adds a new alert rule
func (am *AlertManager) AddRule(rule *AlertRule) {
	am.mu.Lock()
	defer am.mu.Unlock()
	
	am.rules[rule.ID] = rule
	am.LogInfof("Added alert rule: %s", rule.Name)
}

// RemoveRule removes an alert rule
func (am *AlertManager) RemoveRule(ruleID string) {
	am.mu.Lock()
	defer am.mu.Unlock()
	
	delete(am.rules, ruleID)
	am.LogInfof("Removed alert rule: %s", ruleID)
}

// EvaluateRules evaluates all alert rules
func (am *AlertManager) EvaluateRules(ctx context.Context, data interface{}) {
	am.mu.RLock()
	rules := make([]*AlertRule, 0, len(am.rules))
	for _, rule := range am.rules {
		rules = append(rules, rule)
	}
	am.mu.RUnlock()
	
	for _, rule := range rules {
		am.evaluateRule(ctx, rule, data)
	}
}

// evaluateRule evaluates a single alert rule
func (am *AlertManager) evaluateRule(ctx context.Context, rule *AlertRule, data interface{}) {
	// Check cooldown
	if time.Since(rule.LastFired) < rule.Cooldown {
		return
	}
	
	// Evaluate condition
	triggered, description := rule.Condition.Evaluate(ctx, data)
	if !triggered {
		// Check if we need to resolve an active alert
		am.checkResolveAlert(rule.ID)
		return
	}
	
	// Create alert
	alert := &Alert{
		ID:          fmt.Sprintf("%s-%d", rule.ID, time.Now().Unix()),
		Type:        rule.Type,
		Severity:    rule.Severity,
		Title:       rule.Name,
		Description: description,
		Source:      rule.ID,
		Timestamp:   time.Now(),
		Resolved:    false,
		Metadata:    make(map[string]interface{}),
	}
	
	// Trigger alert
	am.triggerAlert(ctx, alert, rule)
}

// triggerAlert triggers an alert
func (am *AlertManager) triggerAlert(ctx context.Context, alert *Alert, rule *AlertRule) {
	am.mu.Lock()
	am.activeAlerts[alert.ID] = alert
	am.history = append(am.history, alert)
	if len(am.history) > 10000 {
		am.history = am.history[1:]
	}
	rule.LastFired = time.Now()
	am.mu.Unlock()
	
	// Record metric
	am.metrics.RecordAlert(string(alert.Severity), string(alert.Type), true)
	
	// Execute actions
	for _, action := range rule.Actions {
		if err := action.Execute(ctx, alert); err != nil {
			am.LogErrorf("Failed to execute alert action: %v", err)
		}
	}
	
	// Trigger event
	am.Events.AlertTriggered.Trigger(alert)
	
	am.LogWarnf("Alert triggered: %s - %s", alert.Title, alert.Description)
}

// checkResolveAlert checks if an alert should be resolved
func (am *AlertManager) checkResolveAlert(ruleID string) {
	am.mu.Lock()
	defer am.mu.Unlock()
	
	for id, alert := range am.activeAlerts {
		if alert.Source == ruleID && !alert.Resolved {
			am.resolveAlert(id)
		}
	}
}

// resolveAlert resolves an active alert
func (am *AlertManager) resolveAlert(alertID string) {
	alert, exists := am.activeAlerts[alertID]
	if !exists || alert.Resolved {
		return
	}
	
	now := time.Now()
	alert.Resolved = true
	alert.ResolvedAt = &now
	
	// Record metric
	am.metrics.RecordAlert(string(alert.Severity), string(alert.Type), false)
	
	// Trigger event
	am.Events.AlertResolved.Trigger(alert)
	
	am.LogInfof("Alert resolved: %s", alert.Title)
}

// GetActiveAlerts returns all active alerts
func (am *AlertManager) GetActiveAlerts() []*Alert {
	am.mu.RLock()
	defer am.mu.RUnlock()
	
	alerts := make([]*Alert, 0, len(am.activeAlerts))
	for _, alert := range am.activeAlerts {
		if !alert.Resolved {
			alerts = append(alerts, alert)
		}
	}
	
	return alerts
}

// GetAlertHistory returns alert history
func (am *AlertManager) GetAlertHistory(limit int) []*Alert {
	am.mu.RLock()
	defer am.mu.RUnlock()
	
	start := len(am.history) - limit
	if start < 0 {
		start = 0
	}
	
	return am.history[start:]
}

// ThresholdCondition checks if a metric exceeds a threshold
type ThresholdCondition struct {
	Metric    string
	Threshold float64
	Operator  string // ">", "<", ">=", "<=", "=="
}

func (tc *ThresholdCondition) Evaluate(ctx context.Context, data interface{}) (bool, string) {
	metrics, ok := data.(map[string]interface{})
	if !ok {
		return false, ""
	}
	
	value, ok := metrics[tc.Metric].(float64)
	if !ok {
		return false, ""
	}
	
	var triggered bool
	switch tc.Operator {
	case ">":
		triggered = value > tc.Threshold
	case "<":
		triggered = value < tc.Threshold
	case ">=":
		triggered = value >= tc.Threshold
	case "<=":
		triggered = value <= tc.Threshold
	case "==":
		triggered = value == tc.Threshold
	}
	
	if triggered {
		return true, fmt.Sprintf("%s is %f (threshold: %s %f)", tc.Metric, value, tc.Operator, tc.Threshold)
	}
	
	return false, ""
}

// RateCondition checks if a rate exceeds a threshold
type RateCondition struct {
	Metric    string
	Threshold float64
	Window    time.Duration
}

func (rc *RateCondition) Evaluate(ctx context.Context, data interface{}) (bool, string) {
	// Implementation would calculate rate over window
	// For now, simplified version
	return false, ""
}

// CountCondition checks if a count exceeds a threshold
type CountCondition struct {
	Metric    string
	Threshold int
	Window    time.Duration
}

func (cc *CountCondition) Evaluate(ctx context.Context, data interface{}) (bool, string) {
	// Implementation would count events over window
	// For now, simplified version
	return false, ""
}

// LogAction logs the alert
type LogAction struct{}

func (la *LogAction) Execute(ctx context.Context, alert *Alert) error {
	// Log alert details
	return nil
}

// MetricAction records alert metrics
type MetricAction struct {
	metrics *MetricsCollector
}

func (ma *MetricAction) Execute(ctx context.Context, alert *Alert) error {
	// Metrics are recorded in triggerAlert
	return nil
}