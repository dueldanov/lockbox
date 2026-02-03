package service

import (
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// listenTestGRPC returns a free localhost address or skips if binding is not permitted.
func listenTestGRPC(t *testing.T) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		if isListenPermissionError(err) {
			t.Skipf("Skipping gRPC test: cannot bind to loopback in this environment: %v", err)
		}
		require.NoError(t, err)
	}
	addr := listener.Addr().String()
	_ = listener.Close()
	return addr
}

func isListenPermissionError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "operation not permitted") || strings.Contains(msg, "permission denied")
}
