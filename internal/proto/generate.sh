#!/bin/bash
# Generate protobuf and gRPC code for LockBox

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Ensure Go bin is in PATH for protoc plugins
export PATH="$PATH:$(go env GOPATH)/bin"

echo "Generating protobuf code..."
protoc \
    --go_out=. \
    --go_opt=paths=source_relative \
    --go-grpc_out=. \
    --go-grpc_opt=paths=source_relative \
    lockbox.proto

echo "Done! Generated files:"
ls -la *.pb.go
