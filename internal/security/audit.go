package security

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/iotaledger/hive.go/logger"
	"github.com/iotaledger/hive.go/runtime/event"
)

// AuditLogger provides comprehensive audit logging
type AuditLogger struct {
	*logger.WrappedLogger
	
	storage      AuditStorage
	buffer       chan *AuditEntry
	bufferSize   int
	flushInterval time.Duration
	
	mu           sync.RWMutex
	stopped      bool
	stopChan     chan struct{}
	
	Events struct {
		EntryLogged *event.Event1[*AuditEntry]
		FlushCompleted *event.Event
	}
}

// AuditEntry represents an audit log entry
type AuditEntry struct {
	ID            string
	Timestamp     time.Time
	Level         AuditLevel
	Category      AuditCategory
	Action        string
	Actor         *Actor
	Resource      *Resource
	Result        AuditResult
	Details       map[string]interface{}
	RequestID     string
	SessionID     string
	CorrelationID string
	Hash          string
}

// AuditLevel represents the severity level
type AuditLevel string

const (
	AuditLevelInfo     AuditLevel = "info"
	AuditLevelWarning  AuditLevel = "warning"
	AuditLevelError    AuditLevel = "error"
	AuditLevelCritical AuditLevel = "critical"
)

// AuditCategory represents the category of audit event
type AuditCategory string

const (
	AuditCategoryAuth        AuditCategory = "authentication"
	AuditCategoryAccess      AuditCategory = "access"
	AuditCategoryData        AuditCategory = "data"
	AuditCategoryConfig      AuditCategory = "configuration"
	AuditCategorySecurity    AuditCategory = "security"
	AuditCategoryCompliance  AuditCategory = "compliance"
	AuditCategorySystem      AuditCategory = "system"
)

// AuditResult represents the result of an action
type AuditResult string

const (
	AuditResultSuccess AuditResult = "success"
	AuditResultFailure AuditResult = "failure"
	AuditResultDenied  AuditResult = "denied"
)

// Actor represents who performed the action
type Actor struct {
	ID       string
	Type     string
	Name     string
	IP       string
	Location string
	Metadata map[string]interface{}
}

// Resource represents what was acted upon
type Resource struct {
	ID       string
	Type     string
	Name     string
	Owner    string
	Metadata map[string]interface{}
}

// AuditStorage interface for storing audit logs
type AuditStorage interface {
	Store(ctx context.Context, entries []*AuditEntry) error
	Query(ctx context.Context, filter *AuditFilter) ([]*AuditEntry, error)
}

// AuditFilter for querying audit logs
type AuditFilter struct {
	StartTime     *time.Time
	EndTime       *time.Time
	Level         []AuditLevel
	Category      []AuditCategory
	Actor         string
	Resource      string
	Action        string
	Result        []AuditResult
	CorrelationID string
	Limit         int
	Offset        int
}

// NewAuditLogger creates a new audit logger
func NewAuditLogger(log *logger.Logger, storage AuditStorage, bufferSize int) *AuditLogger {
	al := &AuditLogger{
		WrappedLogger: logger.NewWrappedLogger(log),
		storage:       storage,
		buffer:        make(chan *AuditEntry, bufferSize),
		bufferSize:    bufferSize,
		flushInterval: 5 * time.Second,
		stopChan:      make(chan struct{}),
	}
	
	al.Events.EntryLogged = event.New1[*AuditEntry]()
	al.Events.FlushCompleted = event.New()
	
	// Start background worker
	go al.worker()
	
	return al
}

// LogAuthentication logs authentication events
func (al *AuditLogger) LogAuthentication(actor *Actor, success bool, details map[string]interface{}) {
	result := AuditResultSuccess
	if !success {
		result = AuditResultFailure
	}
	
	al.log(&AuditEntry{
		Level:    AuditLevelInfo,
		Category: AuditCategoryAuth,
		Action:   "login",
		Actor:    actor,
		Result:   result,
		Details:  details,
	})
}

// LogAccess logs access control events
func (al *AuditLogger) LogAccess(actor *Actor, resource *Resource, action string, allowed bool, details map[string]interface{}) {
	result := AuditResultSuccess
	level := AuditLevelInfo
	
	if !allowed {
		result = AuditResultDenied
		level = AuditLevelWarning
	}
	
	al.log(&AuditEntry{
		Level:    level,
		Category: AuditCategoryAccess,
		Action:   action,
		Actor:    actor,
		Resource: resource,
		Result:   result,
		Details:  details,
	})
}

// LogDataChange logs data modification events
func (al *AuditLogger) LogDataChange(actor *Actor, resource *Resource, action string, before, after interface{}) {
	details := map[string]interface{}{
		"before": before,
		"after":  after,
	}
	
	al.log(&AuditEntry{
		Level:    AuditLevelInfo,
		Category: AuditCategoryData,
		Action:   action,
		Actor:    actor,
		Resource: resource,
		Result:   AuditResultSuccess,
		Details:  details,
	})
}

// LogSecurityEvent logs security-related events
func (al *AuditLogger) LogSecurityEvent(level AuditLevel, action string, actor *Actor, details map[string]interface{}) {
	al.log(&AuditEntry{
		Level:    level,
		Category: AuditCategorySecurity,
		Action:   action,
		Actor:    actor,
		Result:   AuditResultFailure,
		Details:  details,
	})
}

// LogError logs error events
func (al *AuditLogger) LogError(action string, actor *Actor, resource *Resource, err error, details map[string]interface{}) {
	if details == nil {
		details = make(map[string]interface{})
	}
	details["error"] = err.Error()
	
	al.log(&AuditEntry{
		Level:    AuditLevelError,
		Category: AuditCategorySystem,
		Action:   action,
		Actor:    actor,
		Resource: resource,
		Result:   AuditResultFailure,
		Details:  details,
	})
}

// log creates and queues an audit entry
func (al *AuditLogger) log(entry *AuditEntry) {
	al.mu.RLock()
	if al.stopped {
		al.mu.RUnlock()
		return
	}
	al.mu.RUnlock()
	
	// Set defaults
	entry.ID = generateID()
	entry.Timestamp = time.Now()
	
	// Calculate hash for integrity
	entry.Hash = al.calculateHash(entry)
	
	// Send to buffer
	select {
	case al.buffer <- entry:
		// Trigger event
		al.Events.EntryLogged.Trigger(entry)
	default:
		// Buffer full, log warning
		al.LogWarnf("audit buffer full, dropping entry: %s", entry.ID)
	}
}

// calculateHash calculates a hash of the audit entry
func (al *AuditLogger) calculateHash(entry *AuditEntry) string {
	h := sha256.New()
	
	// Hash key fields
	h.Write([]byte(entry.ID))
	h.Write([]byte(entry.Timestamp.Format(time.RFC3339Nano)))
	h.Write([]byte(entry.Level))
	h.Write([]byte(entry.Category))
	h.Write([]byte(entry.Action))
	
	if entry.Actor != nil {
		h.Write([]byte(entry.Actor.ID))
	}
	
	if entry.Resource != nil {
		h.Write([]byte(entry.Resource.ID))
	}
	
	h.Write([]byte(entry.Result))
	
	return hex.EncodeToString(h.Sum(nil))
}

// worker processes audit entries
func (al *AuditLogger) worker() {
	ticker := time.NewTicker(al.flushInterval)
	defer ticker.Stop()
	
	batch := make([]*AuditEntry, 0, al.bufferSize)
	
	for {
		select {
		case entry := <-al.buffer:
			batch = append(batch, entry)
			
			// Flush if batch is full
			if len(batch) >= al.bufferSize {
				al.flush(batch)
				batch = make([]*AuditEntry, 0, al.bufferSize)
			}
			
		case <-ticker.C:
			// Periodic flush
			if len(batch) > 0 {
				al.flush(batch)
				batch = make([]*AuditEntry, 0, al.bufferSize)
			}
			
		case <-al.stopChan:
			// Final flush
			if len(batch) > 0 {
				al.flush(batch)
			}
			return
		}
	}
}

// flush writes audit entries to storage
func (al *AuditLogger) flush(entries []*AuditEntry) {
	if len(entries) == 0 {
		return
	}
	
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	
	if err := al.storage.Store(ctx, entries); err != nil {
		al.LogErrorf("Failed to store audit entries: %v", err)
		// Could implement retry logic here
	} else {
		al.Events.FlushCompleted.Trigger()
		al.LogDebugf("Flushed %d audit entries", len(entries))
	}
}

// Query queries audit logs
func (al *AuditLogger) Query(ctx context.Context, filter *AuditFilter) ([]*AuditEntry, error) {
	return al.storage.Query(ctx, filter)
}

// Stop stops the audit logger
func (al *AuditLogger) Stop() {
	al.mu.Lock()
	if al.stopped {
		al.mu.Unlock()
		return
	}
	al.stopped = true
	al.mu.Unlock()
	
	close(al.stopChan)
}

// generateID generates a unique ID
func generateID() string {
	return fmt.Sprintf("%d-%d", time.Now().UnixNano(), rand.Int63())
}

// InMemoryAuditStorage provides in-memory audit storage for testing
type InMemoryAuditStorage struct {
	entries []*AuditEntry
	mu      sync.RWMutex
}

// NewInMemoryAuditStorage creates new in-memory audit storage
func NewInMemoryAuditStorage() *InMemoryAuditStorage {
	return &InMemoryAuditStorage{
		entries: make([]*AuditEntry, 0),
	}
}

// Store stores audit entries
func (s *InMemoryAuditStorage) Store(ctx context.Context, entries []*AuditEntry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	s.entries = append(s.entries, entries...)
	
	// Keep only last 100k entries
	if len(s.entries) > 100000 {
		s.entries = s.entries[len(s.entries)-100000:]
	}
	
	return nil
}

// Query queries audit entries
func (s *InMemoryAuditStorage) Query(ctx context.Context, filter *AuditFilter) ([]*AuditEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	results := make([]*AuditEntry, 0)
	
	for _, entry := range s.entries {
		if matchesFilter(entry, filter) {
			results = append(results, entry)
		}
	}
	
	// Apply limit and offset
	start := filter.Offset
	if start > len(results) {
		start = len(results)
	}
	
	end := start + filter.Limit
	if end > len(results) || filter.Limit == 0 {
		end = len(results)
	}
	
	return results[start:end], nil
}

// matchesFilter checks if an entry matches the filter
func matchesFilter(entry *AuditEntry, filter *AuditFilter) bool {
	if filter.StartTime != nil && entry.Timestamp.Before(*filter.StartTime) {
		return false
	}
	
	if filter.EndTime != nil && entry.Timestamp.After(*filter.EndTime) {
		return false
	}
	
	if len(filter.Level) > 0 && !contains(filter.Level, entry.Level) {
		return false
	}
	
	if len(filter.Category) > 0 && !contains(filter.Category, entry.Category) {
		return false
	}
	
	if filter.Actor != "" && (entry.Actor == nil || entry.Actor.ID != filter.Actor) {
		return false
	}
	
	if filter.Resource != "" && (entry.Resource == nil || entry.Resource.ID != filter.Resource) {
		return false
	}
	
	if filter.Action != "" && entry.Action != filter.Action {
		return false
	}
	
	if len(filter.Result) > 0 && !contains(filter.Result, entry.Result) {
		return false
	}
	
	if filter.CorrelationID != "" && entry.CorrelationID != filter.CorrelationID {
		return false
	}
	
	return true
}

// contains checks if a slice contains an element
func contains[T comparable](slice []T, item T) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}