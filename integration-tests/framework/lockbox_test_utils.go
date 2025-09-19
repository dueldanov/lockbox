package framework

import (
	"context"
	"testing"
	"time"
	
	"github.com/stretchr/testify/require"
	
	"github.com/iotaledger/lockbox/v2/lockbox"
	"github.com/iotaledger/lockbox/v2/lockbox/verification"
	iotago "github.com/iotaledger/iota.go/v3"
)

// LockBoxTestClient provides test utilities for LockBox functionality
type LockBoxTestClient struct {
	node *Node
	client *lockbox.Client
}

func NewLockBoxTestClient(node *Node) *LockBoxTestClient {
	return &LockBoxTestClient{
		node: node,
		client: lockbox.NewClient(node.APIURI()),
	}
}

func (c *LockBoxTestClient) LockAsset(ctx context.Context, t *testing.T, outputID iotago.OutputID, duration time.Duration) string {
	addr := &iotago.Ed25519Address{}
	req := &lockbox.LockAssetRequest{
		OwnerAddress: addr,
		OutputID:     outputID,
		LockDuration: duration,
	}
	
	resp, err := c.client.LockAsset(ctx, req)
	require.NoError(t, err)
	require.NotEmpty(t, resp.AssetID)
	
	return resp.AssetID
}

func (c *LockBoxTestClient) UnlockAsset(ctx context.Context, t *testing.T, assetID string) {
	req := &lockbox.UnlockAssetRequest{
		AssetID: assetID,
	}
	
	resp, err := c.client.UnlockAsset(ctx, req)
	require.NoError(t, err)
	require.Equal(t, string(lockbox.AssetStatusUnlocked), resp.Status)
}

func (c *LockBoxTestClient) WaitForUnlockTime(ctx context.Context, t *testing.T, assetID string) {
	for {
		select {
		case <-ctx.Done():
			t.Fatal("timeout waiting for unlock time")
		case <-time.After(1 * time.Second):
			status, err := c.client.GetAssetStatus(ctx, assetID)
			require.NoError(t, err)
			
			if time.Now().After(status.UnlockTime) {
				return
			}
		}
	}
}

// VerificationTestHelper provides utilities for testing verification system
type VerificationTestHelper struct {
	nodes []*verification.VerificationNode
}

func NewVerificationTestHelper() *VerificationTestHelper {
	return &VerificationTestHelper{
		nodes: make([]*verification.VerificationNode, 0),
	}
}

func (h *VerificationTestHelper) AddNode(region string, capacity int, latency time.Duration) {
	node := &verification.VerificationNode{
		ID:         fmt.Sprintf("test-node-%d", len(h.nodes)),
		Region:     region,
		Capacity:   capacity,
		Latency:    latency,
		Reputation: 0.95,
		Available:  true,
	}
	h.nodes = append(h.nodes, node)
}

func (h *VerificationTestHelper) SimulateVerification(ctx context.Context, t *testing.T, assetID string, tier lockbox.Tier) *verification.VerificationResult {
	// Simulate verification across nodes
	results := make([]*verification.VerificationResult, 0)
	
	for _, node := range h.nodes {
		result := &verification.VerificationResult{
			Valid:     true,
			AssetID:   assetID,
			NodeID:    node.ID,
			Timestamp: time.Now(),
			LatencyMs: node.Latency.Milliseconds(),
		}
		results = append(results, result)
		
		// Simulate network latency
		time.Sleep(node.Latency)
	}
	
	// Return best result
	require.NotEmpty(t, results)
	return results[0]
}