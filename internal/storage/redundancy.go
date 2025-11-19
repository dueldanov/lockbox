package storage

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/pkg/errors"

	"github.com/iotaledger/hive.go/logger"
	"github.com/dueldanov/lockbox/v2/internal/service"
)

// RedundancyManager manages tier-based redundancy for shards
type RedundancyManager struct {
	*logger.WrappedLogger
	tierConfigs      map[lockbox.Tier]*RedundancyConfig
	distributionAlgo *ShardDistributionAlgorithm
	healthManager    *ShardHealthManager
	mu               sync.RWMutex
}

// RedundancyConfig defines redundancy settings for a tier
type RedundancyConfig struct {
	MinCopies      int
	MaxCopies      int
	GeoRedundancy  int
	SelfHealDelay  time.Duration
	CheckInterval  time.Duration
}

// NewRedundancyManager creates a new redundancy manager
func NewRedundancyManager(log *logger.Logger, distributionAlgo *ShardDistributionAlgorithm, healthManager *ShardHealthManager) *RedundancyManager {
	rm := &RedundancyManager{
		WrappedLogger:    logger.NewWrappedLogger(log),
		tierConfigs:      make(map[lockbox.Tier]*RedundancyConfig),
		distributionAlgo: distributionAlgo,
		healthManager:    healthManager,
	}
	rm.initializeTierConfigs()
	return rm
}

// initializeTierConfigs sets up default tier configurations
func (rm *RedundancyManager) initializeTierConfigs() {
	rm.tierConfigs[lockbox.TierBasic] = &RedundancyConfig{
		MinCopies:     1,
		MaxCopies:     2,
		GeoRedundancy: 1,
		SelfHealDelay: 5 * time.Minute,
		CheckInterval: 10 * time.Minute,
	}

	rm.tierConfigs[lockbox.TierStandard] = &RedundancyConfig{
		MinCopies:     2,
		MaxCopies:     3,
		GeoRedundancy: 2,
		SelfHealDelay: 2 * time.Minute,
		CheckInterval: 5 * time.Minute,
	}

	rm.tierConfigs[lockbox.TierPremium] = &RedundancyConfig{
		MinCopies:     3,
		MaxCopies:     5,
		GeoRedundancy: 3,
		SelfHealDelay: 1 * time.Minute,
		CheckInterval: 2 * time.Minute,
	}

	rm.tierConfigs[lockbox.TierElite] = &RedundancyConfig{
		MinCopies:     5,
		MaxCopies:     7,
		GeoRedundancy: 5,
		SelfHealDelay: 30 * time.Second,
		CheckInterval: 1 * time.Minute,
	}
}

// GetRedundancyConfig returns the redundancy configuration for a tier
func (rm *RedundancyManager) GetRedundancyConfig(tier lockbox.Tier) (*RedundancyConfig, error) {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	config, ok := rm.tierConfigs[tier]
	if !ok {
		return nil, fmt.Errorf("unknown tier: %s", tier)
	}

	return config, nil
}

// EnsureRedundancy ensures proper redundancy for a shard based on tier
func (rm *RedundancyManager) EnsureRedundancy(ctx context.Context, shardID string, tier lockbox.Tier, distribution *ShardDistribution) error {
	config, err := rm.GetRedundancyConfig(tier)
	if err != nil {
		return err
	}

	// Check current redundancy level
	healthReport := rm.healthManager.CheckShardHealth(distribution)
	currentHealthyReplicas := healthReport.HealthyReplicas

	// Need more replicas?
	if currentHealthyReplicas < config.MinCopies {
		additionalCopies := config.MinCopies - currentHealthyReplicas
		return rm.addReplicas(ctx, shardID, distribution, additionalCopies)
	}

	// Too many replicas?
	if currentHealthyReplicas > config.MaxCopies {
		excessCopies := currentHealthyReplicas - config.MaxCopies
		return rm.removeReplicas(ctx, distribution, excessCopies)
	}

	return nil
}

// addReplicas adds additional replicas to meet redundancy requirements
func (rm *RedundancyManager) addReplicas(ctx context.Context, shardID string, distribution *ShardDistribution, count int) error {
	rm.LogInfof("Adding %d replicas for shard %s", count, shardID)

	// Find new locations for replicas
	existingLocations := make(map[string]bool)
	for location := range distribution.Replicas {
		existingLocations[location] = true
	}

	// Select new locations
	newLocations := rm.selectNewLocations(existingLocations, count)
	if len(newLocations) < count {
		return errors.New("insufficient locations available for redundancy")
	}

	// Create new replicas
	for _, location := range newLocations {
		replica := &ShardReplica{
			Location:   location,
			NodeID:     rm.selectNodeForLocation(location),
			Status:     ReplicaStatusPending,
			LastUpdate: time.Now(),
		}
		distribution.Replicas[location] = replica
	}

	distribution.Redundancy = len(distribution.Replicas)
	return nil
}

// removeReplicas removes excess replicas
func (rm *RedundancyManager) removeReplicas(ctx context.Context, distribution *ShardDistribution, count int) error {
	rm.LogInfof("Removing %d excess replicas for shard %s", count, distribution.ShardID)

	// Select replicas to remove (prefer unhealthy ones)
	toRemove := rm.selectReplicasToRemove(distribution, count)

	for _, location := range toRemove {
		delete(distribution.Replicas, location)
	}

	distribution.Redundancy = len(distribution.Replicas)
	return nil
}

// selectNewLocations selects new locations for replicas
func (rm *RedundancyManager) selectNewLocations(existing map[string]bool, count int) []string {
	available := []string{"us-east-1", "us-west-1", "eu-west-1", "ap-south-1", "ap-northeast-1"}
	selected := make([]string, 0, count)

	for _, location := range available {
		if !existing[location] && len(selected) < count {
			selected = append(selected, location)
		}
	}

	return selected
}

// selectReplicasToRemove selects which replicas to remove
func (rm *RedundancyManager) selectReplicasToRemove(distribution *ShardDistribution, count int) []string {
	toRemove := make([]string, 0, count)

	// First, remove unhealthy replicas
	for location, replica := range distribution.Replicas {
		if replica.Status != ReplicaStatusHealthy && len(toRemove) < count {
			toRemove = append(toRemove, location)
		}
	}

	// If needed, remove healthy replicas (prefer those with higher latency)
	if len(toRemove) < count {
		for location, replica := range distribution.Replicas {
			if replica.Status == ReplicaStatusHealthy && len(toRemove) < count {
				toRemove = append(toRemove, location)
			}
		}
	}

	return toRemove
}

// selectNodeForLocation selects an appropriate node for a location
func (rm *RedundancyManager) selectNodeForLocation(location string) string {
	// In production, this would integrate with node selection logic
	return fmt.Sprintf("node-%s-%d", location, time.Now().Unix())
}

// MonitorRedundancy continuously monitors redundancy levels
func (rm *RedundancyManager) MonitorRedundancy(ctx context.Context, shardID string, tier lockbox.Tier, distribution *ShardDistribution) {
	config, err := rm.GetRedundancyConfig(tier)
	if err != nil {
		rm.LogErrorf("Failed to get redundancy config: %v", err)
		return
	}

	ticker := time.NewTicker(config.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := rm.EnsureRedundancy(ctx, shardID, tier, distribution); err != nil {
				rm.LogErrorf("Redundancy check failed for shard %s: %v", shardID, err)
			}
		}
	}
}