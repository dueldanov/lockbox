# LockBox Quick Start Guide

Get LockBox running in 5 minutes.

## Prerequisites

- Go 1.21+
- Docker (for private tangle, optional)
- macOS or Linux

```bash
# Check Go version
go version  # Should be 1.21+
```

---

## Quick Commands (Makefile)

```bash
make help       # Show all available commands
make build      # Build binary
make test       # Run all tests
make start      # Start devnet node
make stop       # Stop node
```

---

## Option 1: Unit Tests Only (No Node)

Fastest way to verify everything works:

```bash
# Run all tests
make test

# Or run specific test suites
make test-crypto      # Crypto primitives
make test-lockscript  # LockScript VM (80+ tests)
make test-grpc        # gRPC E2E tests
```

---

## Option 2: Devnet Node (Recommended)

Single-node development network:

```bash
# 1. Build
make build

# 2. Start node
make start

# 3. Verify it's running
make status

# Endpoints:
# - gRPC: localhost:50051
# - REST: localhost:14265

# 4. Stop when done
make stop
```

### Test gRPC Endpoints

```bash
# Install grpcurl if needed
brew install grpcurl  # macOS

# List available services
grpcurl -plaintext localhost:50051 list

# Get service info
grpcurl -plaintext localhost:50051 lockbox.LockBoxService/GetServiceInfo

# Lock an asset
grpcurl -plaintext -d '{
  "owner_address": "tst1qpszqzadsym6wpppd6z037dvlejmjuke7s24hm95s9fg9vpua7vlupxvxq2",
  "output_id": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
  "lock_duration_seconds": 3600,
  "lock_script": "after(unlock_time)"
}' localhost:50051 lockbox.LockBoxService/LockAsset
```

### REST API

```bash
# Health check
curl http://127.0.0.1:14265/health

# Node info
curl http://127.0.0.1:14265/api/core/v2/info | jq .
```

---

## Option 3: Private Tangle (Full Network)

Multi-node network for integration testing:

```bash
# 1. First time setup
make tangle-bootstrap

# 2. Start 2-node network
make tangle-start

# Ports:
# - Node 1: REST=14265, P2P=15611
# - Node 2: REST=14266, P2P=15612
# - Faucet: 8091
# - Dashboard: 8011 (admin/admin)

# 3. Get test tokens
curl -X POST http://localhost:8091/api/enqueue \
  -H "Content-Type: application/json" \
  -d '{"address": "YOUR_ADDRESS"}'

# 4. Stop network
make tangle-stop
```

---

## Development Workflow

```bash
# 1. Make changes to code

# 2. Run tests
make test

# 3. Build and test gRPC
make build
make test-grpc

# 4. Manual testing with node
make start
# ... test with grpcurl ...
make stop
```

---

## Project Structure

```
lockbox/
├── internal/
│   ├── service/      # Core business logic (Lock/Unlock)
│   ├── crypto/       # HKDF, ChaCha20, ZKP
│   ├── lockscript/   # DSL VM and parser
│   ├── proto/        # gRPC definitions
│   └── verification/ # Node verification
├── private_tangle/   # Docker-based test network
├── docs/             # Architecture, requirements
├── Makefile          # Build/test commands
└── CLAUDE.md         # AI assistant instructions
```

---

## Common Commands Reference

| Command | Description |
|---------|-------------|
| `make build` | Build binary |
| `make test` | Run all tests |
| `make test-grpc` | Run gRPC E2E tests |
| `make test-coverage` | Generate coverage report |
| `make start` | Start devnet node |
| `make stop` | Stop node |
| `make status` | Check node status |
| `make clean-all` | Full cleanup |
| `make proto` | Regenerate protobuf |
| `make fmt` | Format code |

---

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `LOCKBOX_DEV_MODE` | Enable insecure gRPC (for testing) | `false` |
| `LOCKBOX_LOG_LEVEL` | Log level | `info` |

---

## Tier System

LockBox has 4 service tiers:

| Tier | Shard Copies | Decoy Ratio | Multi-Sig | Emergency Unlock |
|------|--------------|-------------|-----------|------------------|
| Basic | 3 | 0.5 | No | No |
| Standard | 5 | 1.0 | Yes | Yes |
| Premium | 7 | 1.5 | Yes | Yes |
| Elite | 10 | 2.0 | Yes | Yes |

---

## Troubleshooting

### Build fails

```bash
make clean
make deps
make build
```

### Tests fail with "logger not initialized"

```bash
LOCKBOX_DEV_MODE=true make test-grpc
```

### Node won't start

```bash
make status     # Check if already running
make stop       # Kill existing
make clean-data # Remove stale data
make start      # Start fresh
```

### gRPC connection refused

```bash
make status        # Verify node is running
lsof -i :50051     # Check port
```

### Database locked

```bash
./stop.sh   # Cleans lock files
./start.sh
```

---

## Next Steps

1. Read [ARCHITECTURE.md](docs/ARCHITECTURE.md) for system design
2. Read [CLAUDE.md](CLAUDE.md) for development guidelines
3. Check [docs/LOCKBOX_REQUIREMENTS.md](docs/LOCKBOX_REQUIREMENTS.md) for full specs

---

## Manual Commands (Alternative to Makefile)

If you prefer shell scripts:

```bash
./build.sh    # Build binary
./start.sh    # Start node
./status.sh   # Check status
./stop.sh     # Stop node
./clean.sh    # Clean all data
```

Build manually:

```bash
go build -o lockbox-node -ldflags="-s -w"
```

Run tests manually:

```bash
go test ./internal/service/... -v
go test ./internal/crypto/... -v
go test ./internal/lockscript/... -v
```
