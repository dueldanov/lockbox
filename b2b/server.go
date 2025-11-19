package b2b

import (
    "context"
    "crypto/tls"
    "net"
    "time"
    
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials"
    "google.golang.org/grpc/keepalive"
    
    "github.com/iotaledger/hive.go/logger"
    "github.com/dueldanov/lockbox/v2/internal/b2b/api"
    "github.com/dueldanov/lockbox/v2/internal/lockscript"
    "github.com/dueldanov/lockbox/v2/internal/tiering"
    "github.com/dueldanov/lockbox/v2/internal/vault"
)

// Server implements the B2B gRPC API
type Server struct {
    *logger.WrappedLogger
    
    grpcServer    *grpc.Server
    bindAddress   string
    tlsEnabled    bool
    
    lockScriptEngine *lockscript.Engine
    vaultManager     *vault.Manager
    tierManager      *tiering.Manager
    
    api.UnimplementedLockBoxAPIServer
}

// NewServer creates a new B2B server
func NewServer(
    log *logger.Logger,
    bindAddress string,
    tlsEnabled bool,
    lockScriptEngine *lockscript.Engine,
    vaultManager *vault.Manager,
    tierManager *tiering.Manager,
) *Server {
    opts := []grpc.ServerOption{
        grpc.KeepaliveParams(keepalive.ServerParameters{
            Time:    20 * time.Second,
            Timeout: 5 * time.Second,
        }),
        grpc.MaxConcurrentStreams(100),
    }
    
    if tlsEnabled {
        // Load TLS credentials
        creds, err := loadTLSCredentials()
        if err != nil {
            log.Panicf("Failed to load TLS credentials: %v", err)
        }
        opts = append(opts, grpc.Creds(creds))
    }
    
    grpcServer := grpc.NewServer(opts...)
    
    s := &Server{
        WrappedLogger:    logger.NewWrappedLogger(log),
        grpcServer:       grpcServer,
        bindAddress:      bindAddress,
        tlsEnabled:       tlsEnabled,
        lockScriptEngine: lockScriptEngine,
        vaultManager:     vaultManager,
        tierManager:      tierManager,
    }
    
    api.RegisterLockBoxAPIServer(grpcServer, s)
    
    return s
}

// Start starts the B2B server
func (s *Server) Start() error {
    listener, err := net.Listen("tcp", s.bindAddress)
    if err != nil {
        return err
    }
    
    s.LogInfof("B2B gRPC server listening on %s", s.bindAddress)
    
    go func() {
        if err := s.grpcServer.Serve(listener); err != nil {
            s.LogErrorf("Failed to serve: %v", err)
        }
    }()
    
    return nil
}

// Stop stops the B2B server
func (s *Server) Stop() {
    s.grpcServer.GracefulStop()
}

// CompileScript implements the CompileScript RPC
func (s *Server) CompileScript(ctx context.Context, req *api.CompileScriptRequest) (*api.CompileScriptResponse, error) {
    // Check authorization
    accountID, err := s.extractAccountID(ctx)
    if err != nil {
        return nil, err
    }
    
    // Check tier features
    hasFeature, err := s.tierManager.HasFeature(ctx, accountID, "advanced_scripts")
    if err != nil {
        return nil, err
    }
    if !hasFeature {
        return nil, ErrFeatureNotAvailable
    }
    
    // Compile the script
    compiled, err := s.lockScriptEngine.CompileScript(ctx, req.Source)
    if err != nil {
        return nil, err
    }
    
    return &api.CompileScriptResponse{
        ScriptId: compiled.ID,
        Bytecode: compiled.Bytecode,
    }, nil
}

// ExecuteScript implements the ExecuteScript RPC
func (s *Server) ExecuteScript(ctx context.Context, req *api.ExecuteScriptRequest) (*api.ExecuteScriptResponse, error) {
    // Implementation
    return nil, nil
}

// CreateVault implements the CreateVault RPC
func (s *Server) CreateVault(ctx context.Context, req *api.CreateVaultRequest) (*api.CreateVaultResponse, error) {
    accountID, err := s.extractAccountID(ctx)
    if err != nil {
        return nil, err
    }
    
    vault, err := s.vaultManager.CreateVault(ctx, accountID)
    if err != nil {
        return nil, err
    }
    
    return &api.CreateVaultResponse{
        VaultId: vault.ID,
    }, nil
}

// GenerateKey implements the GenerateKey RPC
func (s *Server) GenerateKey(ctx context.Context, req *api.GenerateKeyRequest) (*api.GenerateKeyResponse, error) {
    // Implementation
    return nil, nil
}

// GetAccountInfo implements the GetAccountInfo RPC
func (s *Server) GetAccountInfo(ctx context.Context, req *api.GetAccountInfoRequest) (*api.AccountInfo, error) {
    // Implementation
    return nil, nil
}

// UpgradeTier implements the UpgradeTier RPC
func (s *Server) UpgradeTier(ctx context.Context, req *api.UpgradeTierRequest) (*api.UpgradeTierResponse, error) {
    accountID, err := s.extractAccountID(ctx)
    if err != nil {
        return nil, err
    }
    
    err = s.tierManager.UpgradeTier(ctx, accountID, req.NewTier)
    if err != nil {
        return nil, err
    }
    
    return &api.UpgradeTierResponse{
        Success: true,
    }, nil
}

func (s *Server) extractAccountID(ctx context.Context) (string, error) {
    // Extract account ID from context (e.g., from JWT or API key)
    // This is a placeholder implementation
    return "account-id", nil
}

func loadTLSCredentials() (credentials.TransportCredentials, error) {
    // Load server certificate and key
    // This is a placeholder implementation
    cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
    if err != nil {
        return nil, err
    }
    
    config := &tls.Config{
        Certificates: []tls.Certificate{cert},
        ClientAuth:   tls.RequireAndVerifyClientCert,
    }
    
    return credentials.NewTLS(config), nil
}