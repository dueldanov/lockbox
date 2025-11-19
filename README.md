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

# Build the binary
go build -o lockbox-node
```

**Build time:** ~30-60 seconds
**Binary size:** ~44MB

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

## Differences from IOTA HORNET

This fork includes:
- Renamed module path: `github.com/dueldanov/lockbox/v2`
- Binary name: `lockbox-node` (instead of `hornet`)
- Devnet configuration for isolated testing
- LockBox branding in logs and CLI

All protocol logic, consensus mechanisms, and tangle internals remain unchanged from HORNET v2.0.2.

---

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

Original HORNET project: https://github.com/iotaledger/hornet
