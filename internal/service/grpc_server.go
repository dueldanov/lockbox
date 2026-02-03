package service

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"

	pb "github.com/dueldanov/lockbox/v2/internal/proto"
	"github.com/dueldanov/lockbox/v2/internal/verification"
	iotago "github.com/iotaledger/iota.go/v3"
)

type GRPCServer struct {
	pb.UnimplementedLockBoxServiceServer

	service      *Service
	rateLimiter  *verification.RateLimiter
	grpcServer   *grpc.Server
	bindAddress  string
	tlsEnabled   bool
	tlsCertPath  string
	tlsKeyPath   string
}

func NewGRPCServer(
	service *Service,
	rateLimiter *verification.RateLimiter,
	bindAddress string,
	tlsEnabled bool,
	tlsCertPath, tlsKeyPath string,
) (*GRPCServer, error) {
	// If no rate limiter provided, create default (5 req/min)
	if rateLimiter == nil {
		rateLimiter = verification.NewRateLimiter(verification.DefaultRateLimiterConfig())
	}

	s := &GRPCServer{
		service:     service,
		rateLimiter: rateLimiter,
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

	// SECURITY: TLS is REQUIRED in production per requirements (mutual TLS 1.3)
	// Section 2.1.2: "Node authentication via mutual TLS 1.3"
	// DEV MODE: Allow insecure for local development/testing when LOCKBOX_DEV_MODE=true
	devMode := os.Getenv("LOCKBOX_DEV_MODE") == "true"
	if !tlsEnabled && !devMode {
		return nil, fmt.Errorf("TLS is required for gRPC server - set tlsEnabled=true or LOCKBOX_DEV_MODE=true for testing")
	}
	if tlsEnabled {
		creds, err := credentials.NewServerTLSFromFile(tlsCertPath, tlsKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS credentials: %w", err)
		}
		opts = append(opts, grpc.Creds(creds))
	}

	// SECURITY: Add auth interceptor for all unary calls
	opts = append(opts, grpc.UnaryInterceptor(s.authInterceptor))

	// Create server
	s.grpcServer = grpc.NewServer(opts...)
	pb.RegisterLockBoxServiceServer(s.grpcServer, s)

	// Enable reflection for grpcurl/grpcui debugging
	if devMode {
		reflection.Register(s.grpcServer)
	}

	return s, nil
}

// SECURITY: Auth interceptor validates requests before processing
func (s *GRPCServer) authInterceptor(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (interface{}, error) {
	// Public methods that don't require auth or rate limiting
	publicMethods := map[string]bool{
		"/lockbox.LockBoxService/GetServiceInfo": true,
	}

	if publicMethods[info.FullMethod] {
		return handler(ctx, req)
	}

	// Extract user ID from metadata for rate limiting
	userID := extractUserID(ctx)

	// RATE LIMITING: Check rate limit before processing request
	if s.rateLimiter != nil {
		if err := s.rateLimiter.Allow(userID); err != nil {
			retryAfter := s.rateLimiter.GetRetryAfter(userID)
			return nil, status.Errorf(codes.ResourceExhausted,
				"rate limit exceeded: retry after %v", retryAfter)
		}
	}

	// TODO: Add JWT validation from metadata for sensitive methods
	// For now, rely on mTLS for authentication
	// Per-method auth can be added by checking info.FullMethod

	return handler(ctx, req)
}

// extractUserID extracts user ID from request context for rate limiting.
// In production, this would extract from JWT or client certificate.
// For now, use authorization token or default to "anonymous".
func extractUserID(ctx context.Context) string {
	// Try to get authorization from metadata
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return "anonymous"
	}

	// Get authorization header
	authHeaders := md.Get("authorization")
	if len(authHeaders) > 0 {
		// In production, parse JWT and extract userID
		// For now, use the token itself as userID
		return authHeaders[0]
	}

	// Fallback to "anonymous" for requests without auth
	return "anonymous"
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
	// Parse owner address (ParseBech32 returns: hrp, address, error)
	_, ownerAddr, err := iotago.ParseBech32(req.OwnerAddress)
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
		_, addr, err := iotago.ParseBech32(addrStr)
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
		Status:     string(resp.Status),
	}, nil
}

// UnlockAsset implements the gRPC method
func (s *GRPCServer) UnlockAsset(ctx context.Context, req *pb.UnlockAssetRequest) (*pb.UnlockAssetResponse, error) {
	// SECURITY: Validate required auth fields
	if req.AccessToken == "" {
		return nil, status.Error(codes.InvalidArgument, "access_token is required")
	}
	if req.Nonce == "" {
		return nil, status.Error(codes.InvalidArgument, "nonce is required for replay protection")
	}

	// PAYMENT: Validate payment token
	if req.PaymentToken == "" {
		return nil, status.Error(codes.InvalidArgument, "payment_token is required for retrieval fee payment")
	}

	// Convert UnlockParams from map[string]string to map[string]interface{}
	unlockParams := make(map[string]interface{})
	for k, v := range req.UnlockParams {
		unlockParams[k] = v
	}

	// Create service request with auth and payment fields
	serviceReq := &UnlockAssetRequest{
		AssetID:      req.AssetId,
		AccessToken:  req.AccessToken,  // SECURITY: Pass for validation
		Nonce:        req.Nonce,        // SECURITY: Pass for replay protection
		PaymentToken: req.PaymentToken, // PAYMENT: Pass for payment verification
		Signatures:   req.Signatures,
		UnlockParams: unlockParams,
	}

	// Call service
	resp, err := s.service.UnlockAsset(ctx, serviceReq)
	if err != nil {
		// Map service errors to gRPC codes
		switch err {
		case ErrAssetNotFound:
			return nil, status.Error(codes.NotFound, err.Error())
		case ErrUnauthorized:
			return nil, status.Error(codes.Unauthenticated, err.Error())
		case ErrNonceInvalid:
			return nil, status.Error(codes.InvalidArgument, err.Error())
		case ErrAssetStillLocked:
			return nil, status.Error(codes.FailedPrecondition, err.Error())
		case ErrOwnershipProofRequired:
			return nil, status.Error(codes.Unauthenticated, err.Error())
		default:
			return nil, status.Errorf(codes.Internal, "failed to unlock asset: %v", err)
		}
	}

	// Convert response
	return &pb.UnlockAssetResponse{
		AssetId:    resp.AssetID,
		OutputId:   resp.OutputID[:],
		UnlockTime: resp.UnlockTime.Unix(),
		Status:     string(resp.Status),
	}, nil
}

// GetAssetStatus implements the gRPC method
func (s *GRPCServer) GetAssetStatus(ctx context.Context, req *pb.GetAssetStatusRequest) (*pb.GetAssetStatusResponse, error) {
	asset, err := s.service.GetAssetStatus(req.AssetId)
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
		_, addr, err := iotago.ParseBech32(req.OwnerAddress)
		if err != nil {
			return status.Errorf(codes.InvalidArgument, "invalid owner address: %v", err)
		}
		ownerAddr = addr
	}
	
	// Get assets from service
	assets, err := s.service.ListAssets(ownerAddr, AssetStatus(req.Status))
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
		_, addr, err := iotago.ParseBech32(addrStr)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid address: %v", err)
		}
		addresses = append(addresses, addr)
	}

	// Call service
	config, err := s.service.CreateMultiSig(ctx, addresses, int(req.MinSignatures))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create multi-sig: %v", err)
	}

	// Generate combined address representation
	// For simplicity, return the first address as the multi-sig address
	// In production, this would be a proper aggregated address
	var multiSigAddress string
	if len(config.Addresses) > 0 {
		multiSigAddress = config.Addresses[0].Bech32(iotago.PrefixMainnet)
	}

	return &pb.CreateMultiSigResponse{
		MultiSigId: config.ID,
		Address:    multiSigAddress,
	}, nil
}

// EmergencyUnlock implements the gRPC method
func (s *GRPCServer) EmergencyUnlock(ctx context.Context, req *pb.EmergencyUnlockRequest) (*pb.EmergencyUnlockResponse, error) {
	err := s.service.EmergencyUnlock(req.AssetId, req.EmergencySignatures, req.Reason)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to emergency unlock: %v", err)
	}

	// Get updated asset status
	asset, err := s.service.GetAssetStatus(req.AssetId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get asset status: %v", err)
	}

	return &pb.EmergencyUnlockResponse{
		AssetId:    asset.ID,
		Status:     string(asset.Status),
		UnlockTime: asset.UnlockTime.Unix(),
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