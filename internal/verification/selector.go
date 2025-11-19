package verification

import (
	"context"
	"fmt"
	"math/rand"
	"sort"
	"sync"
	"time"

	"github.com/iotaledger/hive.go/logger"
	"github.com/dueldanov/lockbox/v2/internal/service"
)

// NodeSelector selects verification nodes based on tier requirements and geographic distribution
type NodeSelector struct {
	*logger.WrappedLogger
	
	nodes         map[string]*VerificationNode
	nodesByRegion map[string][]*VerificationNode
	mu            sync.RWMutex
}

// VerificationNode represents a node that can perform verification
type VerificationNode struct {
	ID         string
	Region     string
	Capacity   int
	Latency    time.Duration
	Reputation float64
	LastUsed   time.Time
	Available  bool
}

// NewNodeSelector creates a new node selector
func NewNodeSelector(log *logger.Logger) *NodeSelector {
	return &NodeSelector{
		WrappedLogger: logger.NewWrappedLogger(log),
		nodes:         make(map[string]*VerificationNode),
		nodesByRegion: make(map[string][]*VerificationNode),
	}
}

// RegisterNode registers a verification node
func (ns *NodeSelector) RegisterNode(node *VerificationNode) error {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	
	if _, exists := ns.nodes[node.ID]; exists {
		return fmt.Errorf("node %s already registered", node.ID)
	}
	
	ns.nodes[node.ID] = node
	ns.nodesByRegion[node.Region] = append(ns.nodesByRegion[node.Region], node)
	
	ns.LogInfof("Registered verification node %s in region %s", node.ID, node.Region)
	return nil
}

// SelectNodes selects verification nodes based on tier requirements
func (ns *NodeSelector) SelectNodes(ctx context.Context, tier lockbox.Tier, preferredRegions []string) ([]*VerificationNode, error) {
	ns.mu.RLock()
	defer ns.mu.RUnlock()
	
	var count int
	switch tier {
	case lockbox.TierBasic, lockbox.TierStandard, lockbox.TierPremium:
		count = 3 // Triple verification
	case lockbox.TierElite:
		count = 2 // Dual verification
	default:
		return nil, fmt.Errorf("unknown tier: %v", tier)
	}
	
	// Prioritize geographic distribution
	selected := make([]*VerificationNode, 0, count)
	usedRegions := make(map[string]bool)
	
	// First, try to select from preferred regions
	for _, region := range preferredRegions {
		if nodes, ok := ns.nodesByRegion[region]; ok && len(nodes) > 0 {
			node := ns.selectBestNode(nodes, usedRegions)
			if node != nil {
				selected = append(selected, node)
				usedRegions[node.Region] = true
				if len(selected) >= count {
					return selected, nil
				}
			}
		}
	}
	
	// Then select from other regions
	regions := ns.getAvailableRegions(usedRegions)
	for _, region := range regions {
		nodes := ns.nodesByRegion[region]
		node := ns.selectBestNode(nodes, usedRegions)
		if node != nil {
			selected = append(selected, node)
			usedRegions[node.Region] = true
			if len(selected) >= count {
				return selected, nil
			}
		}
	}
	
	if len(selected) < count {
		return nil, fmt.Errorf("insufficient verification nodes available: need %d, found %d", count, len(selected))
	}
	
	return selected, nil
}

// selectBestNode selects the best node from a list based on availability, capacity, and reputation
func (ns *NodeSelector) selectBestNode(nodes []*VerificationNode, usedRegions map[string]bool) *VerificationNode {
	available := make([]*VerificationNode, 0)
	
	for _, node := range nodes {
		if node.Available && !usedRegions[node.Region] {
			available = append(available, node)
		}
	}
	
	if len(available) == 0 {
		return nil
	}
	
	// Sort by score (combination of capacity, latency, and reputation)
	sort.Slice(available, func(i, j int) bool {
		scoreI := ns.calculateNodeScore(available[i])
		scoreJ := ns.calculateNodeScore(available[j])
		return scoreI > scoreJ
	})
	
	// Add some randomness to distribute load
	if len(available) > 3 {
		idx := rand.Intn(3)
		return available[idx]
	}
	
	return available[0]
}

// calculateNodeScore calculates a score for node selection
func (ns *NodeSelector) calculateNodeScore(node *VerificationNode) float64 {
	// Higher capacity is better
	capacityScore := float64(node.Capacity) / 100.0
	
	// Lower latency is better
	latencyScore := 1.0 / (1.0 + node.Latency.Seconds())
	
	// Higher reputation is better
	reputationScore := node.Reputation
	
	// Penalize recently used nodes
	timeSinceUse := time.Since(node.LastUsed).Minutes()
	recencyScore := math.Min(1.0, timeSinceUse/60.0)
	
	// Weighted combination
	return capacityScore*0.3 + latencyScore*0.3 + reputationScore*0.3 + recencyScore*0.1
}

// getAvailableRegions returns all regions not in the used set
func (ns *NodeSelector) getAvailableRegions(usedRegions map[string]bool) []string {
	regions := make([]string, 0)
	for region := range ns.nodesByRegion {
		if !usedRegions[region] {
			regions = append(regions, region)
		}
	}
	
	// Shuffle for randomness
	rand.Shuffle(len(regions), func(i, j int) {
		regions[i], regions[j] = regions[j], regions[i]
	})
	
	return regions
}

// UpdateNodeStatus updates the status of a verification node
func (ns *NodeSelector) UpdateNodeStatus(nodeID string, available bool) error {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	
	node, exists := ns.nodes[nodeID]
	if !exists {
		return fmt.Errorf("node %s not found", nodeID)
	}
	
	node.Available = available
	if available {
		ns.LogDebugf("Node %s marked as available", nodeID)
	} else {
		ns.LogDebugf("Node %s marked as unavailable", nodeID)
	}
	
	return nil
}

// UpdateNodeMetrics updates performance metrics for a node
func (ns *NodeSelector) UpdateNodeMetrics(nodeID string, latency time.Duration, success bool) error {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	
	node, exists := ns.nodes[nodeID]
	if !exists {
		return fmt.Errorf("node %s not found", nodeID)
	}
	
	// Update latency with exponential moving average
	alpha := 0.3
	node.Latency = time.Duration(float64(node.Latency)*(1-alpha) + float64(latency)*alpha)
	
	// Update reputation based on success
	if success {
		node.Reputation = math.Min(1.0, node.Reputation*1.01)
	} else {
		node.Reputation = math.Max(0.0, node.Reputation*0.95)
	}
	
	node.LastUsed = time.Now()
	
	return nil
}