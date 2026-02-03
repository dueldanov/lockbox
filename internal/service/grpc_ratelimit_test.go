package service

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	pb "github.com/dueldanov/lockbox/v2/internal/proto"
	"github.com/dueldanov/lockbox/v2/internal/verification"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// TestGRPCServer_RateLimiting tests that rate limiter is enforced
func TestGRPCServer_RateLimiting(t *testing.T) {
	os.Setenv("LOCKBOX_DEV_MODE", "true")
	defer os.Unsetenv("LOCKBOX_DEV_MODE")

	svc := createTestService(t)

	// Create rate limiter with strict limits for testing (2 req/min)
	rateLimiter := verification.NewRateLimiter(&verification.RateLimiterConfig{
		MaxRequests:   2,
		WindowSize:    time.Minute,
		CleanupPeriod: 5 * time.Minute,
	})

	// Start gRPC server with rate limiter
	addr := listenTestGRPC(t)

	grpcServer, err := NewGRPCServer(svc, rateLimiter, addr, false, "", "")
	require.NoError(t, err)

	go func() {
		grpcServer.Start()
	}()
	defer grpcServer.Stop()
	time.Sleep(100 * time.Millisecond)

	// Create client
	conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	client := pb.NewLockBoxServiceClient(conn)

	// Add authorization header to identify user
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", "test-user"))

	// First 2 requests should succeed (within rate limit)
	for i := 0; i < 2; i++ {
		req := &pb.LockAssetRequest{
			OwnerAddress:        "rms1qpllaj0pyveqfkwxmnngz2c488hfdtmfrj3wfkgxtk4gtyrax0jaxzt70zy",
			LockDurationSeconds: 3600,
		}
		_, err := client.LockAsset(ctx, req)
		// May fail for business logic reasons, but should NOT be rate limited
		if err != nil {
			s := status.Convert(err)
			require.NotEqual(t, codes.ResourceExhausted, s.Code(),
				"Request %d should NOT be rate limited", i+1)
		}
	}

	// Third request should be rate limited
	req := &pb.LockAssetRequest{
		OwnerAddress:        "rms1qpllaj0pyveqfkwxmnngz2c488hfdtmfrj3wfkgxtk4gtyrax0jaxzt70zy",
		LockDurationSeconds: 3600,
	}
	_, err = client.LockAsset(ctx, req)
	require.Error(t, err)

	s := status.Convert(err)
	require.Equal(t, codes.ResourceExhausted, s.Code(), "Third request should be rate limited")
	require.Contains(t, s.Message(), "rate limit exceeded")
}

// TestGRPCServer_RateLimiting_DifferentUsers tests that different users have independent limits
func TestGRPCServer_RateLimiting_DifferentUsers(t *testing.T) {
	os.Setenv("LOCKBOX_DEV_MODE", "true")
	defer os.Unsetenv("LOCKBOX_DEV_MODE")

	svc := createTestService(t)

	// Create rate limiter with strict limits (2 req/min)
	rateLimiter := verification.NewRateLimiter(&verification.RateLimiterConfig{
		MaxRequests:   2,
		WindowSize:    time.Minute,
		CleanupPeriod: 5 * time.Minute,
	})

	// Start gRPC server
	addr := listenTestGRPC(t)

	grpcServer, err := NewGRPCServer(svc, rateLimiter, addr, false, "", "")
	require.NoError(t, err)

	go func() {
		grpcServer.Start()
	}()
	defer grpcServer.Stop()
	time.Sleep(100 * time.Millisecond)

	// Create client
	conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	client := pb.NewLockBoxServiceClient(conn)

	// User 1: exhaust their rate limit (2 requests)
	ctx1 := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", "user-1"))
	for i := 0; i < 2; i++ {
		req := &pb.LockAssetRequest{
			OwnerAddress:        "rms1qpllaj0pyveqfkwxmnngz2c488hfdtmfrj3wfkgxtk4gtyrax0jaxzt70zy",
			LockDurationSeconds: 3600,
		}
		_, err := client.LockAsset(ctx1, req)
		if err != nil {
			s := status.Convert(err)
			require.NotEqual(t, codes.ResourceExhausted, s.Code())
		}
	}

	// User 1: third request should be rate limited
	req := &pb.LockAssetRequest{
		OwnerAddress:        "rms1qpllaj0pyveqfkwxmnngz2c488hfdtmfrj3wfkgxtk4gtyrax0jaxzt70zy",
		LockDurationSeconds: 3600,
	}
	_, err = client.LockAsset(ctx1, req)
	require.Error(t, err)
	s := status.Convert(err)
	require.Equal(t, codes.ResourceExhausted, s.Code())

	// User 2: should have independent limit and NOT be rate limited
	ctx2 := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", "user-2"))
	_, err = client.LockAsset(ctx2, req)
	// May fail for business logic, but NOT rate limited
	if err != nil {
		s := status.Convert(err)
		require.NotEqual(t, codes.ResourceExhausted, s.Code(),
			"User 2 should NOT be rate limited (independent limit)")
	}
}

// TestGRPCServer_RateLimiting_PublicMethods tests that public methods are not rate limited
func TestGRPCServer_RateLimiting_PublicMethods(t *testing.T) {
	os.Setenv("LOCKBOX_DEV_MODE", "true")
	defer os.Unsetenv("LOCKBOX_DEV_MODE")

	svc := createTestService(t)

	// Create rate limiter with very strict limits (1 req/min)
	rateLimiter := verification.NewRateLimiter(&verification.RateLimiterConfig{
		MaxRequests:   1,
		WindowSize:    time.Minute,
		CleanupPeriod: 5 * time.Minute,
	})

	// Start gRPC server
	addr := listenTestGRPC(t)

	grpcServer, err := NewGRPCServer(svc, rateLimiter, addr, false, "", "")
	require.NoError(t, err)

	go func() {
		grpcServer.Start()
	}()
	defer grpcServer.Stop()
	time.Sleep(100 * time.Millisecond)

	// Create client
	conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	client := pb.NewLockBoxServiceClient(conn)
	ctx := context.Background()

	// GetServiceInfo is a public method and should NOT be rate limited
	// Call it 5 times (more than the limit of 1 req/min)
	for i := 0; i < 5; i++ {
		resp, err := client.GetServiceInfo(ctx, &pb.GetServiceInfoRequest{})
		require.NoError(t, err, "GetServiceInfo should NOT be rate limited (public method)")
		require.NotNil(t, resp)
	}
}

// TestGRPCServer_RateLimiting_RetryAfter tests that retry-after is returned correctly
func TestGRPCServer_RateLimiting_RetryAfter(t *testing.T) {
	os.Setenv("LOCKBOX_DEV_MODE", "true")
	defer os.Unsetenv("LOCKBOX_DEV_MODE")

	svc := createTestService(t)

	// Create rate limiter with strict limits
	rateLimiter := verification.NewRateLimiter(&verification.RateLimiterConfig{
		MaxRequests:   2,
		WindowSize:    time.Minute,
		CleanupPeriod: 5 * time.Minute,
	})

	// Start gRPC server
	addr := listenTestGRPC(t)

	grpcServer, err := NewGRPCServer(svc, rateLimiter, addr, false, "", "")
	require.NoError(t, err)

	go func() {
		grpcServer.Start()
	}()
	defer grpcServer.Stop()
	time.Sleep(100 * time.Millisecond)

	// Create client
	conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	defer conn.Close()

	client := pb.NewLockBoxServiceClient(conn)
	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("authorization", "test-user"))

	// Exhaust rate limit
	for i := 0; i < 2; i++ {
		req := &pb.LockAssetRequest{
			OwnerAddress:        "rms1qpllaj0pyveqfkwxmnngz2c488hfdtmfrj3wfkgxtk4gtyrax0jaxzt70zy",
			LockDurationSeconds: 3600,
		}
		client.LockAsset(ctx, req)
	}

	// Next request should be rate limited with retry-after
	req := &pb.LockAssetRequest{
		OwnerAddress:        "rms1qpllaj0pyveqfkwxmnngz2c488hfdtmfrj3wfkgxtk4gtyrax0jaxzt70zy",
		LockDurationSeconds: 3600,
	}
	_, err = client.LockAsset(ctx, req)
	require.Error(t, err)

	s := status.Convert(err)
	require.Equal(t, codes.ResourceExhausted, s.Code())
	require.Contains(t, s.Message(), "retry after")

	// Error message should contain duration
	require.True(t, strings.Contains(s.Message(), "s") || strings.Contains(s.Message(), "m"),
		"Error should contain retry-after duration")
}
