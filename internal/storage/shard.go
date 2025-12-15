package storage

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/pkg/errors"

	"github.com/iotaledger/hive.go/logger"
	"github.com/iotaledger/hive.go/objectstorage"
)

// Shard represents a data shard in the storage system
type Shard struct {
	objectstorage.StorableObjectFlags
	ID          string
	Index       uint32
	TotalShards uint32
	Data        []byte
	Hash        []byte
	CreatedAt   time.Time
	Size        uint64
	Metadata    map[string]interface{}
}

// ShardDistribution represents how a shard is distributed across nodes
type ShardDistribution struct {
	objectstorage.StorableObjectFlags
	ShardID     string
	Locations   []string
	Redundancy  int
	CreatedAt   time.Time
	LastChecked time.Time
	Replicas    map[string]*ShardReplica
}

// ShardReplica represents a single replica of a shard
type ShardReplica struct {
	Location     string
	NodeID       string
	Status       ReplicaStatus
	LastUpdate   time.Time
	FailureCount int
	Latency      time.Duration
}

// ReplicaStatus represents the status of a shard replica
type ReplicaStatus int

const (
	ReplicaStatusUnknown ReplicaStatus = iota
	ReplicaStatusPending
	ReplicaStatusHealthy
	ReplicaStatusDegraded
	ReplicaStatusFailed
)

// ShardDistributionAlgorithm handles shard distribution logic
type ShardDistributionAlgorithm struct {
	*logger.WrappedLogger
	minRedundancy    int
	maxRedundancy    int
	targetLocations  []string
	replicationFactor int
}

// NewShardDistributionAlgorithm creates a new shard distribution algorithm
func NewShardDistributionAlgorithm(log *logger.Logger, minRedundancy, maxRedundancy int, locations []string) *ShardDistributionAlgorithm {
	return &ShardDistributionAlgorithm{
		WrappedLogger:     logger.NewWrappedLogger(log),
		minRedundancy:     minRedundancy,
		maxRedundancy:     maxRedundancy,
		targetLocations:   locations,
		replicationFactor: minRedundancy,
	}
}

// DistributeShards determines how to distribute shards across nodes
func (sda *ShardDistributionAlgorithm) DistributeShards(totalShards int, tier string) (map[int][]string, error) {
	redundancy := sda.getRedundancyForTier(tier)
	if redundancy > len(sda.targetLocations) {
		return nil, errors.New("insufficient locations for requested redundancy")
	}

	distribution := make(map[int][]string)
	
	// Round-robin distribution with geographic diversity
	for shardIndex := 0; shardIndex < totalShards; shardIndex++ {
		locations := sda.selectLocationsForShard(shardIndex, redundancy)
		distribution[shardIndex] = locations
	}

	return distribution, nil
}

// selectLocationsForShard selects locations for a specific shard
func (sda *ShardDistributionAlgorithm) selectLocationsForShard(shardIndex int, redundancy int) []string {
	selected := make([]string, 0, redundancy)
	startIdx := shardIndex % len(sda.targetLocations)

	// Select locations with wraparound
	for i := 0; i < redundancy; i++ {
		idx := (startIdx + i) % len(sda.targetLocations)
		selected = append(selected, sda.targetLocations[idx])
	}

	return selected
}

// getRedundancyForTier returns the redundancy level for a given tier
func (sda *ShardDistributionAlgorithm) getRedundancyForTier(tier string) int {
	switch tier {
	case "Elite":
		return sda.maxRedundancy
	case "Premium":
		return int(math.Ceil(float64(sda.maxRedundancy+sda.minRedundancy) / 2))
	case "Standard":
		return sda.minRedundancy + 1
	default:
		return sda.minRedundancy
	}
}

// ShardHealthManager manages shard health monitoring
type ShardHealthManager struct {
	*logger.WrappedLogger
	pingTimeout       time.Duration
	maxFailureCount   int
	healthCheckPeriod time.Duration
	mu                sync.RWMutex
	healthCache       map[string]*ShardHealthReport
}

// NewShardHealthManager creates a new shard health manager
func NewShardHealthManager(log *logger.Logger) *ShardHealthManager {
	return &ShardHealthManager{
		WrappedLogger:     logger.NewWrappedLogger(log),
		pingTimeout:       5 * time.Second,
		maxFailureCount:   3,
		healthCheckPeriod: 30 * time.Second,
		healthCache:       make(map[string]*ShardHealthReport),
	}
}

// ShardHealthReport represents a health check report for a shard
type ShardHealthReport struct {
	ShardID         string
	Timestamp       time.Time
	Healthy         bool
	TotalReplicas   int
	HealthyReplicas int
	FailedReplicas  int
	Details         map[string]*ReplicaHealthDetail
}

// ReplicaHealthDetail contains health details for a single replica
type ReplicaHealthDetail struct {
	Location     string
	NodeID       string
	Status       ReplicaStatus
	LastPingTime time.Time
	Latency      time.Duration
	ErrorMessage string
}

// CheckShardHealth performs health check on shard distribution
func (shm *ShardHealthManager) CheckShardHealth(distribution *ShardDistribution) *ShardHealthReport {
	shm.mu.Lock()
	defer shm.mu.Unlock()

	report := &ShardHealthReport{
		ShardID:       distribution.ShardID,
		Timestamp:     time.Now(),
		TotalReplicas: len(distribution.Replicas),
		Details:       make(map[string]*ReplicaHealthDetail),
	}

	// Check each replica
	for location, replica := range distribution.Replicas {
		detail := shm.checkReplicaHealth(replica)
		report.Details[location] = detail

		if detail.Status == ReplicaStatusHealthy {
			report.HealthyReplicas++
		} else {
			report.FailedReplicas++
		}
	}

	// Determine overall health
	report.Healthy = report.HealthyReplicas >= distribution.Redundancy

	// Cache the report
	shm.healthCache[distribution.ShardID] = report

	return report
}

// checkReplicaHealth checks health of individual replica
func (shm *ShardHealthManager) checkReplicaHealth(replica *ShardReplica) *ReplicaHealthDetail {
	detail := &ReplicaHealthDetail{
		Location: replica.Location,
		NodeID:   replica.NodeID,
		Status:   replica.Status,
	}

	// Simulate ping check (in production, this would make actual network call)
	start := time.Now()
	if shm.performPingCheck(replica.NodeID) {
		detail.Latency = time.Since(start)
		detail.LastPingTime = time.Now()
		detail.Status = ReplicaStatusHealthy
		
		// Update replica status
		replica.Status = ReplicaStatusHealthy
		replica.LastUpdate = time.Now()
		replica.FailureCount = 0
	} else {
		detail.Status = ReplicaStatusFailed
		detail.ErrorMessage = "ping timeout"
		
		// Update failure count
		replica.FailureCount++
		if replica.FailureCount >= shm.maxFailureCount {
			replica.Status = ReplicaStatusFailed
		} else {
			replica.Status = ReplicaStatusDegraded
		}
	}

	return detail
}

// performPingCheck simulates a ping check to a node
func (shm *ShardHealthManager) performPingCheck(nodeID string) bool {
	// In production, this would perform actual network ping
	// For now, simulate with 95% success rate
	return time.Now().UnixNano()%100 < 95
}

// Shard implementation of objectstorage.StorableObject

func (s *Shard) Update(_ objectstorage.StorableObject) {
	// Shards are immutable
	panic("shards cannot be updated")
}

func (s *Shard) ObjectStorageKey() []byte {
	return []byte(s.ID)
}

func (s *Shard) ObjectStorageValue() []byte {
	data, _ := s.Serialize()
	return data
}

func (s *Shard) Serialize() ([]byte, error) {
	// Calculate hash if not set
	if len(s.Hash) == 0 {
		h := sha256.Sum256(s.Data)
		s.Hash = h[:]
	}

	// Use JSON serialization for simplicity
	return json.Marshal(s)
}

func (s *Shard) Deserialize(data []byte) error {
	// Use JSON deserialization for simplicity
	return json.Unmarshal(data, s)
}

// ShardDistribution implementation of objectstorage.StorableObject

func (sd *ShardDistribution) Update(_ objectstorage.StorableObject) {
	// Allow updates for distribution status
}

func (sd *ShardDistribution) ObjectStorageKey() []byte {
	return []byte(sd.ShardID)
}

func (sd *ShardDistribution) ObjectStorageValue() []byte {
	data, _ := sd.Serialize()
	return data
}

func (sd *ShardDistribution) Serialize() ([]byte, error) {
	// Convert to JSON for flexibility
	return json.Marshal(sd)
}

func (sd *ShardDistribution) Deserialize(data []byte) error {
	return json.Unmarshal(data, sd)
}

// GeographicVerifier verifies geographic diversity of shard placement
type GeographicVerifier struct {
	regions map[string]*Region
	mu      sync.RWMutex
}

// Region represents a geographic region
type Region struct {
	Name      string
	Locations []string
	Latencies map[string]time.Duration // Latency to other regions
}

// NewGeographicVerifier creates a new geographic verifier
func NewGeographicVerifier() *GeographicVerifier {
	gv := &GeographicVerifier{
		regions: make(map[string]*Region),
	}
	gv.initializeRegions()
	return gv
}

// initializeRegions sets up default regions
func (gv *GeographicVerifier) initializeRegions() {
	gv.regions["us-east"] = &Region{
		Name:      "US East",
		Locations: []string{"us-east-1", "us-east-2"},
		Latencies: map[string]time.Duration{
			"us-west":      40 * time.Millisecond,
			"eu-west":      80 * time.Millisecond,
			"asia-pacific": 150 * time.Millisecond,
		},
	}
	
	gv.regions["us-west"] = &Region{
		Name:      "US West",
		Locations: []string{"us-west-1", "us-west-2"},
		Latencies: map[string]time.Duration{
			"us-east":      40 * time.Millisecond,
			"eu-west":      120 * time.Millisecond,
			"asia-pacific": 100 * time.Millisecond,
		},
	}
	
	gv.regions["eu-west"] = &Region{
		Name:      "EU West",
		Locations: []string{"eu-west-1", "eu-west-2"},
		Latencies: map[string]time.Duration{
			"us-east":      80 * time.Millisecond,
			"us-west":      120 * time.Millisecond,
			"asia-pacific": 200 * time.Millisecond,
		},
	}
	
	gv.regions["asia-pacific"] = &Region{
		Name:      "Asia Pacific",
		Locations: []string{"ap-south-1", "ap-northeast-1"},
		Latencies: map[string]time.Duration{
			"us-east": 150 * time.Millisecond,
			"us-west": 100 * time.Millisecond,
			"eu-west": 200 * time.Millisecond,
		},
	}
}

// VerifyDiversity verifies geographic diversity of locations
func (gv *GeographicVerifier) VerifyDiversity(locations []string) error {
	gv.mu.RLock()
	defer gv.mu.RUnlock()

	if len(locations) < 2 {
		return errors.New("at least 2 locations required for geographic diversity")
	}

	// Map locations to regions
	regionCount := make(map[string]int)
	for _, location := range locations {
		region := gv.getRegionForLocation(location)
		if region == "" {
			return fmt.Errorf("unknown location: %s", location)
		}
		regionCount[region]++
	}

	// Require at least 2 different regions
	if len(regionCount) < 2 {
		return errors.New("locations must span at least 2 different regions")
	}

	return nil
}

// getRegionForLocation finds the region for a given location
func (gv *GeographicVerifier) getRegionForLocation(location string) string {
	for regionName, region := range gv.regions {
		for _, loc := range region.Locations {
			if loc == location {
				return regionName
			}
		}
	}
	return ""
}

// MeasureLatency measures latency between two locations
func (gv *GeographicVerifier) MeasureLatency(from, to string) (time.Duration, error) {
	gv.mu.RLock()
	defer gv.mu.RUnlock()

	fromRegion := gv.getRegionForLocation(from)
	toRegion := gv.getRegionForLocation(to)

	if fromRegion == "" || toRegion == "" {
		return 0, errors.New("unknown location")
	}

	if fromRegion == toRegion {
		// Same region, very low latency
		return 5 * time.Millisecond, nil
	}

	// Look up inter-region latency
	if region, ok := gv.regions[fromRegion]; ok {
		if latency, ok := region.Latencies[toRegion]; ok {
			return latency, nil
		}
	}

	// Default fallback latency
	return 100 * time.Millisecond, nil
}