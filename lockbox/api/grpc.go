package api

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
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/iotaledger/hive.go/logger"
	"github.com/iotaledger/lockbox/v2/lockbox"
	"github.com/iotaledger/lockbox/v2/lockbox/b2b"
	"github.com/iotaledger/lockbox/v2/lockbox/b2b/api"
	"github.com/iotaledger/lockbox/v2/lockbox/lockscript"
)

type GRPCServer struct {
	*logger.WrappedLogger
	service         *lockbox.Service
	scriptEngine    *lockscript.Engine
	revenueManager  *b2b.RevenueManager
	grpcServer      *grpc.Server
	bindAddress     string
	tlsEnabled      bool
	api.UnimplementedLockBoxAPIServer
}

func NewGRPCServer(
	log *logger.Logger,
	service *lockbox.Service,
	scriptEngine *lockscript.Engine,
	revenueManager *b2b.RevenueManager,
	bindAddress string,
	tlsEnabled bool,
	tlsCertPath string,
	tlsKeyPath string,
) (*GRPCServer, error) {
	opts := []grpc.ServerOption{
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    20 * time.Second,
			Timeout: 5 * time.Second,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             5 * time.Second,
			PermitWithoutStream: true,
		}),
		grpc.MaxConcurrentStreams(100),
		grpc.UnaryInterceptor(authInterceptor),
	}

	if tlsEnabled {
		creds, err := credentials.NewServerTLSFromFile(tlsCertPath, tlsKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS credentials: %w", err)
		}
		opts = append(opts, grpc.Creds(creds))
	}

	grpcServer := grpc.NewServer(opts...)

	s := &GRPCServer{
		WrappedLogger:  logger.NewWrappedLogger(log),
		service:        service,
		scriptEngine:   scriptEngine,
		revenueManager: revenueManager,
		grpcServer:     grpcServer,
		bindAddress:    bindAddress,
		tlsEnabled:     tlsEnabled,
	}

	api.RegisterLockBoxAPIServer(grpcServer, s)

	return s, nil
}

func (s *GRPCServer) Start() error {
	listener, err := net.Listen("tcp", s.bindAddress)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	s.LogInfof("gRPC server listening on %s (TLS: %v)", s.bindAddress, s.tlsEnabled)

	go func() {
		if err := s.grpcServer.Serve(listener); err != nil {
			s.LogErrorf("gRPC server error: %v", err)
		}
	}()

	return nil
}

func (s *GRPCServer) Stop() {
	s.LogInfo("Stopping gRPC server...")
	s.grpcServer.GracefulStop()
	s.LogInfo("gRPC server stopped")
}

// CompileScript compiles a LockScript
func (s *GRPCServer) CompileScript(ctx context.Context, req *api.CompileScriptRequest) (*api.CompileScriptResponse, error) {
	partnerID, err := extractPartnerID(ctx)
	if err != nil {
		return nil, err
	}

	// Check if partner has required feature
	hasFeature, err := s.checkPartnerFeature(ctx, partnerID, "advanced_scripts")
	if err != nil {
		return nil, err
	}
	if !hasFeature {
		return nil, status.Error(codes.PermissionDenied, "advanced scripts not available in current tier")
	}

	// Validate script size
	if len(req.Source) > s.service.GetConfig().MaxScriptSize {
		return nil, status.Errorf(codes.InvalidArgument, "script size exceeds maximum of %d bytes", s.service.GetConfig().MaxScriptSize)
	}

	// Compile script
	compiled, err := s.scriptEngine.CompileScript(ctx, req.Source)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "compilation failed: %v", err)
	}

	// Store compiled script
	scriptID := fmt.Sprintf("script_%s_%d", partnerID, time.Now().Unix())
	if err := s.service.StoreScript(scriptID, compiled); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to store script: %v", err)
	}

	return &api.CompileScriptResponse{
		ScriptId:      scriptID,
		Bytecode:      compiled.Bytecode,
		CompiledAt:    compiled.Timestamp.Unix(),
	}, nil
}

// ExecuteScript executes a compiled script
func (s *GRPCServer) ExecuteScript(ctx context.Context, req *api.ExecuteScriptRequest) (*api.ExecuteScriptResponse, error) {
	partnerID, err := extractPartnerID(ctx)
	if err != nil {
		return nil, err
	}

	// Load compiled script
	script, err := s.service.LoadScript(req.ScriptId)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "script not found: %v", err)
	}

	// Create execution environment
	env := &lockscript.Environment{
		Variables: req.Variables,
		Functions: s.scriptEngine.GetBuiltinFunctions(),
		Sender:    partnerID,
		Timestamp: time.Now(),
	}

	// Execute script
	result, err := s.scriptEngine.ExecuteScript(ctx, script, env)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "execution failed: %v", err)
	}

	// Record revenue for script execution
	if err := s.revenueManager.RecordRevenue(ctx, partnerID, 1000, req.ScriptId); err != nil {
		s.LogWarnf("Failed to record revenue: %v", err)
	}

	return &api.ExecuteScriptResponse{
		Success: result.Success,
		Result:  fmt.Sprintf("%v", result.Value),
		GasUsed: result.GasUsed,
		Logs:    result.Logs,
	}, nil
}

// GetRevenueReport retrieves revenue report for a partner
func (s *GRPCServer) GetRevenueReport(ctx context.Context, req *api.GetRevenueReportRequest) (*api.GetRevenueReportResponse, error) {
	partnerID, err := extractPartnerID(ctx)
	if err != nil {
		return nil, err
	}

	stats, err := s.revenueManager.GetPartnerStatistics(partnerID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get statistics: %v", err)
	}

	return &api.GetRevenueReportResponse{
		PartnerId:         partnerID,
		TotalRevenue:      stats.TotalRevenue,
		TotalTransactions: stats.TotalTransactions,
		LastActivityDate:  stats.LastActivityDate.Unix(),
		ActiveUsers:       stats.ActiveUsers,
	}, nil
}

// ProcessPayment processes a manual payment request
func (s *GRPCServer) ProcessPayment(ctx context.Context, req *api.ProcessPaymentRequest) (*api.ProcessPaymentResponse, error) {
	partnerID, err := extractPartnerID(ctx)
	if err != nil {
		return nil, err
	}

	// Check if partner is authorized to request payments
	if !s.isAuthorizedForPayments(partnerID) {
		return nil, status.Error(codes.PermissionDenied, "not authorized for manual payments")
	}

	// Process payment
	if err := s.revenueManager.ProcessDailyPayments(ctx); err != nil {
		return nil, status.Errorf(codes.Internal, "payment processing failed: %v", err)
	}

	return &api.ProcessPaymentResponse{
		Success:     true,
		ProcessedAt: time.Now().Unix(),
	}, nil
}

// Helper functions

func authInterceptor(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "missing metadata")
	}

	apiKeys := md.Get("api-key")
	if len(apiKeys) == 0 {
		return nil, status.Error(codes.Unauthenticated, "missing API key")
	}

	// TODO: Validate API key and extract partner ID
	// For now, use the API key as partner ID
	ctx = context.WithValue(ctx, "partner_id", apiKeys[0])

	return handler(ctx, req)
}

func extractPartnerID(ctx context.Context) (string, error) {
	partnerID, ok := ctx.Value("partner_id").(string)
	if !ok {
		return "", status.Error(codes.Unauthenticated, "invalid authentication")
	}
	return partnerID, nil
}

func (s *GRPCServer) checkPartnerFeature(ctx context.Context, partnerID string, feature string) (bool, error) {
	// TODO: Check partner tier and features
	return true, nil
}

func (s *GRPCServer) isAuthorizedForPayments(partnerID string) bool {
	// TODO: Check partner authorization
	return true
}