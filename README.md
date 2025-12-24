# LockBox - Private IOTA Node

![GitHub](https://img.shields.io/github/license/dueldanov/lockbox?style=for-the-badge)

LockBox is a fork of IOTA HORNET v2.0.2, designed for running private, isolated IOTA networks.
It is a powerful fullnode software written in Go, optimized for private devnet deployments.

---

## Quick Start

### Building from Source

```bash
# Clone the repository
git clone https://github.com/dueldanov/lockbox.git
cd lockbox

# Build the binary (recommended - handles macOS code signing automatically)
./build.sh

# Or build manually
go build -o lockbox-node
```

**Build time:** ~30-60 seconds
**Binary size:** ~44MB

> **macOS Users:** The build script automatically code-signs the binary using ad-hoc signing. This is required for the executable to run properly on macOS. If you build manually with `go build`, you must sign it yourself:
> ```bash
> codesign --force --deep --sign - ./lockbox-node
> ```

📖 **See [BUILD.md](BUILD.md) or [СБОРКА_И_ЗАПУСК.md](СБОРКА_И_ЗАПУСК.md) (Russian) for detailed build instructions.**

### 🚀 Running a Devnet Node (Easy Way)

```bash
# Start the node (auto-creates snapshot if needed)
./start.sh

# Check status
./status.sh

# Stop the node
./stop.sh
```

📖 **See [QUICKSTART.md](QUICKSTART.md) for detailed instructions and troubleshooting.**

### 📖 Manual Start

```bash
# 1. Create genesis snapshot (first time only)
./lockbox-node tool snap-gen \
  --protocolParametersPath=protocol_parameters_devnet.json \
  --mintAddress=tst1qpszqzadsym6wpppd6z037dvlejmjuke7s24hm95s9fg9vpua7vlupxvxq2 \
  --treasuryAllocation=0 \
  --outputPath=lockbox_devnet_snapshots/full_snapshot.bin

# 2. Start the node
./lockbox-node --config config_lockbox_devnet.json
```

The node will:
- Start on localhost (127.0.0.1) only
- Use REST API on port 14265
- Store data in `lockbox_devnet_db/`
- NOT connect to any public IOTA networks

### Accessing the Node

Once running, you can access the REST API:

```bash
# Check node health
curl http://127.0.0.1:14265/health

# Get node info
curl http://127.0.0.1:14265/api/core/v2/info | jq .
```

---

## Configuration

- **Devnet Config**: `config_lockbox_devnet.json` - Isolated private network
- **Private Tangle**: `private_tangle/config_private_tangle.json` - Multi-node setup
- **Defaults**: `config_defaults.json` - Base configuration

An overview of all configuration parameters can be found [here.](configuration.md)

---

## Testing

### Run All Tests

```bash
# Run all tests
go test ./... -v

# Run specific package tests
go test ./internal/lockscript/... -v
go test ./internal/service/... -v
go test ./internal/crypto/... -v
```

### LockScript Testing

LockScript is a DSL for defining unlock conditions. Test the key operations:

```bash
# Build the CLI tool
go build -o /tmp/lockscript-test ./tools/lockscript-test

# Store a key
/tmp/lockscript-test -store "my-secret-key:Standard" -json

# Derive a key
/tmp/lockscript-test -derive "shard-encrypt:0" -json

# List available functions
/tmp/lockscript-test -list
```

### Test Coverage

```bash
# Generate coverage report
go test ./internal/... -coverprofile=coverage.out
go tool cover -html=coverage.out
```

---

## Differences from IOTA HORNET

This fork includes:
- Renamed module path: `github.com/dueldanov/lockbox/v2`
- Binary name: `lockbox-node` (instead of `hornet`)
- Devnet configuration for isolated testing
- LockBox branding in logs and CLI
- **LockScript DSL** for programmable unlock conditions
- **Key Operations**: storeKey, getKey, rotate, deriveKey
- **Cryptographic features**: HKDF key derivation, ChaCha20-Poly1305 encryption

All protocol logic, consensus mechanisms, and tangle internals remain unchanged from HORNET v2.0.2.

---

## Troubleshooting

### macOS: Node hangs without output

**Symptom:** Running `./lockbox-node` or `./start.sh` hangs indefinitely with no output or error messages.

**Cause:** On macOS, unsigned executables may fail to run properly due to Gatekeeper security policies.

**Solution:** Code-sign the binary using ad-hoc signing:

```bash
codesign --force --deep --sign - ./lockbox-node
```

This is automatically handled by `./build.sh`, but if you built manually with `go build` or downloaded a pre-built binary, you'll need to sign it yourself.

**Verification:** After signing, test with:
```bash
./lockbox-node --help
```

If it displays help text, the binary is properly signed and ready to use.

---

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

Original HORNET project: https://github.com/iotaledger/hornet
