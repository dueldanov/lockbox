package lockbox

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"
	
	pb "github.com/iotaledger/hornet/v2/pkg/lockbox/proto"
	iotago "github.com/iotaledger/iota.go/v3"
)

type GRPCServer struct {
	pb.UnimplementedLockBoxServiceServer
	
	service      *Service
	grpcServer   *grpc.Server
	bindAddress  string
	tlsEnabled   bool
	tlsCertPath  string
	tlsKeyPath   string
}

func NewGRPCServer(
	service *Service,
	bindAddress string,
	tlsEnabled bool,
	tlsCertPath, tlsKeyPath string,
) (*GRPCServer, error) {
	s := &GRPCServer{
		service:     service,
		bindAddress: bindAddress,
		tlsEnabled:  tlsEnabled,
		tlsCertPath: tlsCertPath,
		tlsKeyPath:  tlsKeyPath,
	}

	// Create gRPC server with options
	var opts []grpc.ServerOption
	
	// Keepalive settings
	opts = append(opts, grpc.KeepaliveParams(keepalive.ServerParameters{
		Time:    20 * time.Second,
		Timeout: 5 * time.Second,
	}))
	
	// TLS configuration
	if tlsEnabled {
		creds, err := credentials.NewServerTLSFromFile(tlsCertPath, tlsKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS credentials: %w", err)
		}
		opts = append(opts, grpc.Creds(creds))
	}
	
	// Create server
	s.grpcServer = grpc.NewServer(opts...)
	pb.RegisterLockBoxServiceServer(s.grpcServer, s)
	
	return s, nil
}

func (s *GRPCServer) Start() error {
	listener, err := net.Listen("tcp", s.bindAddress)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}
	
	return s.grpcServer.Serve(listener)
}

func (s *GRPCServer) Stop() {
	s.grpcServer.GracefulStop()
}

// LockAsset implements the gRPC method
func (s *GRPCServer) LockAsset(ctx context.Context, req *pb.LockAssetRequest) (*pb.LockAssetResponse, error) {
	// Parse owner address
	ownerAddr, err := iotago.ParseBech32(req.OwnerAddress)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid owner address: %v", err)
	}
	
	// Parse output ID
	var outputID iotago.OutputID
	if len(req.OutputId) != iotago.OutputIDLength {
		return nil, status.Error(codes.InvalidArgument, "invalid output ID length")
	}
	copy(outputID[:], req.OutputId)
	
	// Parse multi-sig addresses if provided
	var multiSigAddresses []iotago.Address
	for _, addrStr := range req.MultiSigAddresses {
		addr, err := iotago.ParseBech32(addrStr)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid multi-sig address: %v", err)
		}
		multiSigAddresses = append(multiSigAddresses, addr)
	}
	
	// Create service request
	serviceReq := &LockAssetRequest{
		OwnerAddress:      ownerAddr,
		OutputID:          outputID,
		LockDuration:      time.Duration(req.LockDurationSeconds) * time.Second,
		LockScript:        req.LockScript,
		MultiSigAddresses: multiSigAddresses,
		MinSignatures:     int(req.MinSignatures),
	}
	
	// Call service
	resp, err := s.service.LockAsset(ctx, serviceReq)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to lock asset: %v", err)
	}
	
	// Convert response
	return &pb.LockAssetResponse{
		AssetId:    resp.AssetID,
		LockTime:   resp.LockTime.Unix(),
		UnlockTime: resp.UnlockTime.Unix(),
		Status:     resp.Status,
	}, nil
}

// UnlockAsset implements the gRPC method
func (s *GRPCServer) UnlockAsset(ctx context.Context, req *pb.UnlockAssetRequest) (*pb.UnlockAssetResponse, error) {
	// Create service request
	serviceReq := &UnlockAssetRequest{
		AssetID:      req.AssetId,
		Signatures:   req.Signatures,
		UnlockParams: req.UnlockParams,
	}
	
	// Call service
	resp, err := s.service.UnlockAsset(ctx, serviceReq)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to unlock asset: %v", err)
	}
	
	// Convert response
	return &pb.UnlockAssetResponse{
		AssetId:    resp.AssetID,
		OutputId:   resp.OutputID[:],
		UnlockTime: resp.UnlockTime.Unix(),
		Status:     resp.Status,
	}, nil
}

// GetAssetStatus implements the gRPC method
func (s *GRPCServer) GetAssetStatus(ctx context.Context, req *pb.GetAssetStatusRequest) (*pb.GetAssetStatusResponse, error) {
	asset, err := s.service.GetAssetStatus(ctx, req.AssetId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "asset not found: %v", err)
	}
	
	return &pb.GetAssetStatusResponse{
		AssetId:      asset.ID,
		Status:       string(asset.Status),
		LockTime:     asset.LockTime.Unix(),
		UnlockTime:   asset.UnlockTime.Unix(),
		OwnerAddress: asset.OwnerAddress.Bech32(iotago.PrefixMainnet),
		Amount:       asset.Amount,
	}, nil
}

// ListAssets implements the gRPC method
func (s *GRPCServer) ListAssets(req *pb.ListAssetsRequest, stream pb.LockBoxService_ListAssetsServer) error {
	// Parse owner address if provided
	var ownerAddr iotago.Address
	if req.OwnerAddress != "" {
		addr, err := iotago.ParseBech32(req.OwnerAddress)
		if err != nil {
			return status.Errorf(codes.InvalidArgument, "invalid owner address: %v", err)
		}
		ownerAddr = addr
	}
	
	// Get assets from service
	assets, err := s.service.ListAssets(stream.Context(), ownerAddr, AssetStatus(req.Status))
	if err != nil {
		return status.Errorf(codes.Internal, "failed to list assets: %v", err)
	}
	
	// Stream assets
	for _, asset := range assets {
		pbAsset := &pb.AssetInfo{
			AssetId:    asset.ID,
			Status:     string(asset.Status),
			LockTime:   asset.LockTime.Unix(),
			UnlockTime: asset.UnlockTime.Unix(),
			Amount:     asset.Amount,
		}
		
		resp := &pb.ListAssetsResponse{
			Assets: []*pb.AssetInfo{pbAsset},
		}
		
		if err := stream.Send(resp); err != nil {
			return err
		}
	}
	
	return nil
}

// CreateMultiSig implements the gRPC method
func (s *GRPCServer) CreateMultiSig(ctx context.Context, req *pb.CreateMultiSigRequest) (*pb.CreateMultiSigResponse, error) {
	// Parse addresses
	var addresses []iotago.Address
	for _, addrStr := range req.Addresses {
		addr, err := iotago.ParseBech32(addrStr)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid address: %v", err)
		}
		addresses = append(addresses, addr)
	}
	
	// Create multi-sig configuration
	config, err := s.service.CreateMultiSig(ctx, addresses, int(req.MinSignatures))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create multi-sig: %v", err)
	}
	
	return &pb.CreateMultiSigResponse{
		MultiSigId: config.ID,
		Address:    "", // TODO: Generate multi-sig address
	}, nil
}

// EmergencyUnlock implements the gRPC method
func (s *GRPCServer) EmergencyUnlock(ctx context.Context, req *pb.EmergencyUnlockRequest) (*pb.EmergencyUnlockResponse, error) {
	resp, err := s.service.EmergencyUnlock(ctx, req.AssetId, req.Reason, req.EmergencySignatures)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to emergency unlock: %v", err)
	}
	
	return &pb.EmergencyUnlockResponse{
		AssetId:    resp.AssetID,
		Status:     resp.Status,
		UnlockTime: resp.UnlockTime.Unix(),
	}, nil
}

// GetServiceInfo implements the gRPC method
func (s *GRPCServer) GetServiceInfo(ctx context.Context, req *pb.GetServiceInfoRequest) (*pb.GetServiceInfoResponse, error) {
	return &pb.GetServiceInfoResponse{
		Version:      "1.0.0",
		Tier:         s.service.config.Tier.String(),
		MaxLockTime:  int64(s.service.config.MaxLockPeriod.Seconds()),
		Features: &pb.ServiceFeatures{
			MultiSigSupport:      s.service.config.MultiSigRequired,
			EmergencyUnlock:      s.service.config.EnableEmergencyUnlock,
			GeographicRedundancy: int32(s.service.config.GeographicRedundancy),
			ScriptingEnabled:     true,
		},
		NodeLocations: s.service.config.NodeLocations,
	}, nil
}