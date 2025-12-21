package verification

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/dueldanov/lockbox/v2/internal/interfaces"
	"github.com/iotaledger/hive.go/app/configuration"
	appLogger "github.com/iotaledger/hive.go/app/logger"
	"github.com/iotaledger/hive.go/logger"
	"github.com/stretchr/testify/require"
)

var initLoggerOnce sync.Once

// initTestLogger initializes the global logger for tests
func initTestLogger() {
	initLoggerOnce.Do(func() {
		cfg := configuration.New()
		// Ignore error - global logger may already be initialized
		_ = appLogger.InitGlobalLogger(cfg)
	})
}

// TestNodeSelection tests the selection of nodes for verification based on tier.
func TestNodeSelection(t *testing.T) {
	selector := setupTestNodeSelector(t)
	nodes, err := selector.SelectNodes(context.Background(), interfaces.TierStandard, []string{"us-east", "eu-west"})
	require.NoError(t, err)
	require.Len(t, nodes, 3) // Standard tier requires 3 nodes
	regions := make(map[string]bool)
	for _, node := range nodes {
		regions[node.Region] = true
	}
	require.GreaterOrEqual(t, len(regions), 2) // Ensure geographic diversity
}

// TestTokenRotation tests token rotation functionality.
func TestTokenRotation(t *testing.T) {
	initTestLogger()
	tokenMgr := NewTokenManager(logger.NewLogger("test"), time.Second, 5*time.Second)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go tokenMgr.Start(ctx)

	// Wait for initial token generation
	time.Sleep(100 * time.Millisecond)
	initialToken := tokenMgr.GetCurrentToken()
	require.NotNil(t, initialToken)

	// Wait for rotation
	time.Sleep(1100 * time.Millisecond)
	newToken := tokenMgr.GetCurrentToken()
	require.NotNil(t, newToken)
	require.NotEqual(t, initialToken.ID, newToken.ID)
	require.True(t, tokenMgr.ValidateToken(newToken.ID))
	// Old token is still valid within grace period (tokenValidity = 5s)
	// This is intentional - grace period prevents race conditions during rotation
	require.True(t, tokenMgr.ValidateToken(initialToken.ID))
}

// TestRetryMechanism tests the retry mechanism for verification failures.
func TestRetryMechanism(t *testing.T) {
	initTestLogger()
	retryMgr := NewRetryManager(logger.NewLogger("test"), DefaultRetryConfig())
	attempts := 0
	err := retryMgr.RetryWithBackoff(context.Background(), "test-retry", func(ctx context.Context) error {
		attempts++
		if attempts < 3 {
			return errors.New("temporary failure")
		}
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, 3, attempts)
}

// setupTestNodeSelector sets up a test node selector with mock nodes.
func setupTestNodeSelector(t *testing.T) *NodeSelector {
	initTestLogger()
	selector := NewNodeSelector(logger.NewLogger("test"))
	// Add mock nodes for different regions
	helper := &VerificationTestHelper{}
	helper.AddNode("us-east", 100, 50*time.Millisecond)
	helper.AddNode("us-west", 100, 60*time.Millisecond)
	helper.AddNode("eu-west", 100, 70*time.Millisecond)
	for _, node := range helper.nodes {
		err := selector.RegisterNode(node)
		require.NoError(t, err)
	}
	return selector
}

// VerificationTestHelper helps create test nodes for verification tests
type VerificationTestHelper struct {
	nodes []*VerificationNode
}

// AddNode adds a test node with given region, reliability and latency
func (h *VerificationTestHelper) AddNode(region string, reliability int, latency time.Duration) {
	h.nodes = append(h.nodes, &VerificationNode{
		ID:         region + "-node",
		Region:     region,
		Capacity:   100,
		Latency:    latency,
		Reputation: float64(reliability) / 100.0,
		Available:  true,
	})
}