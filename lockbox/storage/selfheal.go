package storage

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/pkg/errors"

	"github.com/iotaledger/hive.go/logger"
	"github.com/iotaledger/hive.go/runtime/event"
)

// SelfHealingManager manages automatic recovery of failed shards
type SelfHealingManager struct {
	*logger.WrappedLogger
	storage            StorageInterface
	healthManager      *ShardHealthManager
	redundancyManager  *RedundancyManager
	geographicVerifier *GeographicVerifier
	
	// Configuration
	maxRetries        int
	retryDelay        time.Duration
	pingFailureLimit  int
	healingBatchSize  int
	
	// State
	healingQueue      chan *HealingTask
	activeHealings    map[string]*HealingTask
	mu                sync.RWMutex
	
	// Events
	Events *SelfHealingEvents
}

// StorageInterface defines the interface for storage operations
type StorageInterface interface {
	GetShard(shardID string) (*Shard, error)
	GetShardDistribution(shardID string) (*ShardDistribution, error)
	UpdateShardDistribution(distribution *ShardDistribution) error
	CopyShardData(shardID string, sourceNode string, targetNode string) error
}

// SelfHealingEvents contains events emitted by self-healing manager
type SelfHealingEvents struct {
	HealingStarted   *event.Event1[*HealingTask]
	HealingCompleted *event.Event1[*HealingTask]
	HealingFailed    *event.Event2[*HealingTask, error]
	ReplicaRecovered *event.Event2[string, string] // shardID, location
}

// HealingTask represents a healing operation
type HealingTask struct {
	ShardID        string
	FailedReplicas []string
	StartTime      time.Time
	Attempts       int
	Status         HealingStatus
	Error          error
}

// HealingStatus represents the status of a healing operation
type HealingStatus int

const (
	HealingStatusPending HealingStatus = iota
	HealingStatusInProgress
	HealingStatusCompleted
	HealingStatusFailed
)

// NewSelfHealingManager creates a new self-healing manager
func NewSelfHealingManager(
	log *logger.Logger,
	storage StorageInterface,
	healthManager *ShardHealthManager,
	redundancyManager *RedundancyManager,
	geographicVerifier *GeographicVerifier,
) *SelfHealingManager {
	return &SelfHealingManager{
		WrappedLogger:      logger.NewWrappedLogger(log),
		storage:            storage,
		healthManager:      healthManager,
		redundancyManager:  redundancyManager,
		geographicVerifier: geographicVerifier,
		maxRetries:         3,
		retryDelay:         30 * time.Second,
		pingFailureLimit:   3,
		healingBatchSize:   10,
		healingQueue:       make(chan *HealingTask, 100),
		activeHealings:     make(map[string]*HealingTask),
		Events: &SelfHealingEvents{
			HealingStarted:   event.New1[*HealingTask](),
			HealingCompleted: event.New1[*HealingTask](),
			HealingFailed:    event.New2[*HealingTask, error](),
			ReplicaRecovered: event.New2[string, string](),
		},
	}
}

// Start begins the self-healing process
func (shm *SelfHealingManager) Start(ctx context.Context) {
	// Start healing workers
	for i := 0; i < shm.healingBatchSize; i++ {
		go shm.healingWorker(ctx)
	}

	// Start monitoring
	go shm.monitorHealth(ctx)
}

// monitorHealth continuously monitors shard health
func (shm *SelfHealingManager) monitorHealth(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			shm.checkAndQueueFailedShards()
		}
	}
}

// checkAndQueueFailedShards checks for failed shards and queues healing tasks
func (shm *SelfHealingManager) checkAndQueueFailedShards() {
	// This would iterate through all shards and check their health
	// For now, we'll simulate the process
	shm.LogDebug("Checking shard health...")
}

// QueueHealing queues a shard for healing
func (shm *SelfHealingManager) QueueHealing(shardID string, failedReplicas []string) error {
	shm.mu.Lock()
	defer shm.mu.Unlock()

	// Check if already healing
	if _, exists := shm.activeHealings[shardID]; exists {
		return errors.New("healing already in progress for this shard")
	}

	task := &HealingTask{
		ShardID:        shardID,
		FailedReplicas: failedReplicas,
		StartTime:      time.Now(),
		Status:         HealingStatusPending,
	}

	select {
	case shm.healingQueue <- task:
		shm.activeHealings[shardID] = task
		return nil
	default:
		return errors.New("healing queue is full")
	}
}

// healingWorker processes healing tasks
func (shm *SelfHealingManager) healingWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case task := <-shm.healingQueue:
			shm.processHealingTask(ctx, task)
		}
	}
}

// processHealingTask processes a single healing task
func (shm *SelfHealingManager) processHealingTask(ctx context.Context, task *HealingTask) {
	task.Status = HealingStatusInProgress
	shm.Events.HealingStarted.Trigger(task)

	defer func() {
		shm.mu.Lock()
		delete(shm.activeHealings, task.ShardID)
		shm.mu.Unlock()
	}()

	// Retry loop
	for task.Attempts < shm.maxRetries {
		task.Attempts++
		
		if err := shm.healShard(ctx, task); err != nil {
			task.Error = err
			shm.LogWarnf("Healing attempt %d failed for shard %s: %v", task.Attempts, task.ShardID, err)
			
			if task.Attempts < shm.maxRetries {
				time.Sleep(shm.retryDelay)
				continue
			}
			
			task.Status = HealingStatusFailed
			shm.Events.HealingFailed.Trigger(task, err)
			return
		}

		task.Status = HealingStatusCompleted
		shm.Events.HealingCompleted.Trigger(task)
		return
	}
}

// healShard performs the actual healing of a shard
func (shm *SelfHealingManager) healShard(ctx context.Context, task *HealingTask) error {
	// Get shard and distribution info
	shard, err := shm.storage.GetShard(task.ShardID)
	if err != nil {
		return errors.Wrap(err, "failed to get shard")
	}

	distribution, err := shm.storage.GetShardDistribution(task.ShardID)
	if err != nil {
		return errors.Wrap(err, "failed to get shard distribution")
	}

	// Find healthy replicas
	healthyReplicas := shm.findHealthyReplicas(distribution)
	if len(healthyReplicas) == 0 {
		return errors.New("no healthy replicas available for healing")
	}

	// Heal each failed replica
	for _, failedLocation := range task.FailedReplicas {
		if err := shm.healReplica(ctx, shard, distribution, failedLocation, healthyReplicas[0]); err != nil {
			shm.LogErrorf("Failed to heal replica at %s: %v", failedLocation, err)
			continue
		}
		
		shm.Events.ReplicaRecovered.Trigger(task.ShardID, failedLocation)
	}

	// Update distribution
	distribution.LastChecked = time.Now()
	if err := shm.storage.UpdateShardDistribution(distribution); err != nil {
		return errors.Wrap(err, "failed to update distribution")
	}

	return nil
}

// healReplica heals a single replica
func (shm *SelfHealingManager) healReplica(ctx context.Context, shard *Shard, distribution *ShardDistribution, failedLocation string, healthyLocation string) error {
	// Select new node for the failed location
	newNodeID := shm.selectNewNode(failedLocation)
	
	// Get healthy replica info
	healthyReplica := distribution.Replicas[healthyLocation]
	if healthyReplica == nil {
		return errors.New("healthy replica not found")
	}

	// Copy data from healthy replica to new node
	shm.LogInfof("Copying shard %s from %s to new node %s at %s", 
		shard.ID, healthyReplica.NodeID, newNodeID, failedLocation)

	if err := shm.storage.CopyShardData(shard.ID, healthyReplica.NodeID, newNodeID); err != nil {
		return errors.Wrap(err, "failed to copy shard data")
	}

	// Update replica info
	distribution.Replicas[failedLocation] = &ShardReplica{
		Location:     failedLocation,
		NodeID:       newNodeID,
		Status:       ReplicaStatusHealthy,
		LastUpdate:   time.Now(),
		FailureCount: 0,
	}

	return nil
}

// findHealthyReplicas finds all healthy replicas for a shard
func (shm *SelfHealingManager) findHealthyReplicas(distribution *ShardDistribution) []string {
	var healthy []string
	
	for location, replica := range distribution.Replicas {
		if replica.Status == ReplicaStatusHealthy {
			healthy = append(healthy, location)
		}
	}
	
	return healthy
}

// selectNewNode selects a new node for a location
func (shm *SelfHealingManager) selectNewNode(location string) string {
	// In production, this would select from available nodes in the location
	return fmt.Sprintf("node-%s-%d", location, time.Now().Unix())
}

// PerformEmergencyHealing performs immediate healing without waiting
func (shm *SelfHealingManager) PerformEmergencyHealing(shardID string) error {
	distribution, err := shm.storage.GetShardDistribution(shardID)
	if err != nil {
		return err
	}

	// Check health
	report := shm.healthManager.CheckShardHealth(distribution)
	if report.Healthy {
		return nil // No healing needed
	}

	// Find failed replicas
	var failedReplicas []string
	for location, detail := range report.Details {
		if detail.Status != ReplicaStatusHealthy {
			failedReplicas = append(failedReplicas, location)
		}
	}

	// Create high-priority healing task
	task := &HealingTask{
		ShardID:        shardID,
		FailedReplicas: failedReplicas,
		StartTime:      time.Now(),
		Status:         HealingStatusInProgress,
	}

	// Process immediately
	return shm.healShard(context.Background(), task)
}

// GetHealingStatus returns the status of active healings
func (shm *SelfHealingManager) GetHealingStatus() map[string]*HealingTask {
	shm.mu.RLock()
	defer shm.mu.RUnlock()

	status := make(map[string]*HealingTask)
	for shardID, task := range shm.activeHealings {
		status[shardID] = task
	}

	return status
}