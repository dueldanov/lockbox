package lockbox

import (
	"context"
	"crypto/tls"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	pb "github.com/iotaledger/hornet/v2/pkg/lockbox/proto"
)

// GRPCServer implements the LockBox gRPC server
type GRPCServer struct {
	pb.UnimplementedLockBoxServiceServer

	service      *Service
	grpcServer   *grpc.Server
	bindAddress  string
	tlsEnabled   bool
	tlsCertPath  string
	tlsKeyPath   string
}

// NewGRPCServer creates a new gRPC server
func NewGRPCServer(service *Service, bindAddress string, tlsEnabled bool, tlsCertPath, tlsKeyPath string) (*GRPCServer, error) {
	s := &GRPCServer{
		service:     service,
		bindAddress: bindAddress,
		tlsEnabled:  tlsEnabled,
		tlsCertPath: tlsCertPath,
		tlsKeyPath:  tlsKeyPath,
	}

	var opts []grpc.ServerOption

	// Add keepalive parameters
	opts = append(opts, grpc.KeepaliveParams(keepalive.ServerParameters{
		Time:    20 * time.Second,
		Timeout: 5 * time.Second,
	}))

	// Add TLS if enabled
	if tlsEnabled {
		creds, err := credentials.NewServerTLSFromFile(tlsCertPath, tlsKeyPath)
		if err != nil {
			return nil, err
		}
		opts = append(opts, grpc.Creds(creds))
	}

	// Create gRPC server
	s.grpcServer = grpc.NewServer(opts...)
	pb.RegisterLockBoxServiceServer(s.grpcServer, s)

	return s, nil
}

// Start starts the gRPC server
func (s *GRPCServer) Start() error {
	listener, err := net.Listen("tcp", s.bindAddress)
	if err != nil {
		return err
	}

	return s.grpcServer.Serve(listener)
}

// Stop stops the gRPC server
func (s *GRPCServer) Stop() {
	s.grpcServer.GracefulStop()
}

// LockAsset handles asset locking requests
func (s *GRPCServer) LockAsset(ctx context.Context, req *pb.LockAssetRequest) (*pb.LockAssetResponse, error) {
	// Convert protobuf request to service request
	serviceReq := &LockAssetRequest{
		// Map fields from protobuf
	}

	resp, err := s.service.LockAsset(ctx, serviceReq)
	if err != nil {
		return nil, err
	}

	// Convert service response to protobuf
	return &pb.LockAssetResponse{
		AssetId:    resp.AssetID,
		LockTime:   resp.LockTime.Unix(),
		UnlockTime: resp.UnlockTime.Unix(),
		Status:     resp.Status,
	}, nil
}

// UnlockAsset handles asset unlocking requests
func (s *GRPCServer) UnlockAsset(ctx context.Context, req *pb.UnlockAssetRequest) (*pb.UnlockAssetResponse, error) {
	// Convert protobuf request to service request
	serviceReq := &UnlockAssetRequest{
		AssetID: req.AssetId,
		// Map other fields
	}

	resp, err := s.service.UnlockAsset(ctx, serviceReq)
	if err != nil {
		return nil, err
	}

	// Convert service response to protobuf
	return &pb.UnlockAssetResponse{
		AssetId:    resp.AssetID,
		OutputId:   resp.OutputID[:],
		UnlockTime: resp.UnlockTime.Unix(),
		Status:     resp.Status,
	}, nil
}

// GetAssetStatus returns the status of a locked asset
func (s *GRPCServer) GetAssetStatus(ctx context.Context, req *pb.GetAssetStatusRequest) (*pb.GetAssetStatusResponse, error) {
	// Implementation
	return &pb.GetAssetStatusResponse{}, nil
}

// ListAssets lists locked assets based on filters
func (s *GRPCServer) ListAssets(req *pb.ListAssetsRequest, stream pb.LockBoxService_ListAssetsServer) error {
	// Implementation
	return nil
}

// CreateMultiSig creates a multi-signature configuration
func (s *GRPCServer) CreateMultiSig(ctx context.Context, req *pb.CreateMultiSigRequest) (*pb.CreateMultiSigResponse, error) {
	// Implementation
	return &pb.CreateMultiSigResponse{}, nil
}

// EmergencyUnlock initiates an emergency unlock
func (s *GRPCServer) EmergencyUnlock(ctx context.Context, req *pb.EmergencyUnlockRequest) (*pb.EmergencyUnlockResponse, error) {
	// Implementation
	return &pb.EmergencyUnlockResponse{}, nil
}

// GetServiceInfo returns service information
func (s *GRPCServer) GetServiceInfo(ctx context.Context, req *pb.GetServiceInfoRequest) (*pb.GetServiceInfoResponse, error) {
	return &pb.GetServiceInfoResponse{
		Version:     "1.0.0",
		Tier:        s.service.config.Tier.String(),
		MaxLockTime: int64(s.service.config.MaxLockPeriod.Seconds()),
		Features: &pb.ServiceFeatures{
			MultiSigSupport:      s.service.config.MultiSigRequired,
			EmergencyUnlock:      s.service.config.EnableEmergencyUnlock,
			GeographicRedundancy: int32(s.service.config.GeographicRedundancy),
			ScriptingEnabled:     true,
		},
		NodeLocations: s.service.config.NodeLocations,
	}, nil
}