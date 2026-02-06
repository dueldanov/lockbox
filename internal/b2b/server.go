package b2b

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	"github.com/iotaledger/hive.go/logger"

	"github.com/dueldanov/lockbox/v2/internal/b2b/api"
)

// Server hosts the B2B gRPC API.
type Server struct {
	*logger.WrappedLogger

	grpcServer  *grpc.Server
	bindAddress string
	tlsEnabled  bool
}

// B2BServerConfig holds configuration for creating a B2B Server.
type B2BServerConfig struct {
	BindAddress   string
	TLSEnabled    bool
	TLSCertPath   string
	TLSKeyPath    string
	TLSCACertPath string // CA certificate for verifying client certs (mTLS)
	DevMode       bool   // Allow insecure mode for local development/testing
}

// NewServer creates a new B2B gRPC server wrapper.
func NewServer(
	log *logger.Logger,
	service *B2BServer,
	config B2BServerConfig,
) (*Server, error) {
	if service == nil {
		return nil, fmt.Errorf("b2b service is required")
	}

	if config.DevMode {
		fmt.Fprintln(os.Stderr, "WARNING: B2B gRPC server running in dev mode — TLS not enforced. Do NOT use in production.")
	}

	opts := []grpc.ServerOption{
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    20 * time.Second,
			Timeout: 5 * time.Second,
		}),
	}

	if !config.TLSEnabled && !config.DevMode {
		return nil, fmt.Errorf("TLS is required for B2B gRPC server — set TLSEnabled=true or DevMode=true for testing")
	}
	if config.TLSEnabled {
		tlsConfig, err := buildB2BMTLSConfig(config.TLSCertPath, config.TLSKeyPath, config.TLSCACertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to configure mTLS: %w", err)
		}
		opts = append(opts, grpc.Creds(credentials.NewTLS(tlsConfig)))
	}

	grpcServer := grpc.NewServer(opts...)
	api.RegisterLockBoxAPIServer(grpcServer, service)

	return &Server{
		WrappedLogger: logger.NewWrappedLogger(log),
		grpcServer:    grpcServer,
		bindAddress:   config.BindAddress,
		tlsEnabled:    config.TLSEnabled,
	}, nil
}

// buildB2BMTLSConfig creates a TLS configuration with mutual TLS 1.3.
func buildB2BMTLSConfig(certPath, keyPath, caCertPath string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load server certificate: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}

	if caCertPath != "" {
		caCert, err := os.ReadFile(caCertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}

		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}

		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		tlsConfig.ClientCAs = certPool
	}

	return tlsConfig, nil
}

// Start begins serving the B2B gRPC server.
func (s *Server) Start() error {
	listener, err := net.Listen("tcp", s.bindAddress)
	if err != nil {
		return fmt.Errorf("failed to listen: %w", err)
	}

	return s.grpcServer.Serve(listener)
}

// Stop stops the B2B gRPC server gracefully.
func (s *Server) Stop() {
	s.grpcServer.GracefulStop()
}
