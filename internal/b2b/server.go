package b2b

import (
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

// NewServer creates a new B2B gRPC server wrapper.
func NewServer(
	log *logger.Logger,
	service *B2BServer,
	bindAddress string,
	tlsEnabled bool,
	tlsCertPath string,
	tlsKeyPath string,
) (*Server, error) {
	if service == nil {
		return nil, fmt.Errorf("b2b service is required")
	}

	opts := []grpc.ServerOption{
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    20 * time.Second,
			Timeout: 5 * time.Second,
		}),
	}

	devMode := os.Getenv("LOCKBOX_DEV_MODE") == "true"
	if !tlsEnabled && !devMode {
		return nil, fmt.Errorf("TLS is required for B2B gRPC server - set tlsEnabled=true or LOCKBOX_DEV_MODE=true for testing")
	}
	if tlsEnabled {
		creds, err := credentials.NewServerTLSFromFile(tlsCertPath, tlsKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS credentials: %w", err)
		}
		opts = append(opts, grpc.Creds(creds))
	}

	grpcServer := grpc.NewServer(opts...)
	api.RegisterLockBoxAPIServer(grpcServer, service)

	return &Server{
		WrappedLogger: logger.NewWrappedLogger(log),
		grpcServer:    grpcServer,
		bindAddress:   bindAddress,
		tlsEnabled:    tlsEnabled,
	}, nil
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
