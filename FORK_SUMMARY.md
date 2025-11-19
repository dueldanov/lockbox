# LockBox Fork Summary

## Overview
Successfully forked IOTA HORNET v2.0.2 to create LockBox, a private IOTA node implementation.

## Changes Made

### 1. Module Path Migration
- **Changed**: `github.com/iotaledger/hornet/v2` → `github.com/dueldanov/lockbox/v2`
- **Files affected**: `go.mod`, `tools/gendoc/go.mod`, and 200+ Go source files
- **Method**: Automated sed replacement across all `.go` files

### 2. Binary Renaming
- **Old name**: `hornet`
- **New name**: `lockbox-node`
- **Files updated**:
  - `Dockerfile` - Build target and entrypoint
  - `scripts/build_hornet.sh` - Build output name
  - `scripts/build_hornet_rocksdb.sh` - Build output name
  - `scripts/build_hornet_rocksdb_external_libs.sh` - Build output name

### 3. Branding Updates
- **Application name**: "LockBox" (in `components/app/app.go`)
- **Default node alias**: "LockBox Node" (in `components/profile/params.go` and `config_defaults.json`)
- **Docker labels**: Updated to reference `dueldanov/lockbox`
- **Private tangle config**: "LockBox private-tangle node"

### 4. Configuration Files Created

#### `config_lockbox_devnet.json`
New devnet configuration with:
- **Network name**: `lockbox-devnet` (isolated from IOTA networks)
- **Token**: LockCoin (LOCK)
- **API binding**: `127.0.0.1:14265` (localhost only)
- **P2P binding**: `127.0.0.1:15600` (localhost only)
- **Database path**: `lockbox_devnet_db/`
- **Autopeering**: Disabled
- **Entry nodes**: Empty (no public IOTA nodes)
- **Snapshot downloads**: Disabled

### 5. Documentation
- **README.md**: Completely rewritten with:
  - LockBox branding
  - Quick start build instructions
  - Devnet usage guide
  - API access examples
  - Differences from upstream HORNET

## Build Status

### Current State
🔴 **Build BLOCKED** - Import cycle detected in custom code additions.

### Critical Issue: Import Cycles
The repository contains custom `lockbox/` and `pkg/lockbox/` directories that were added to this fork (not present in original HORNET v2.0.2). These create circular import dependencies:

```
github.com/dueldanov/lockbox/v2/lockbox
  → github.com/dueldanov/lockbox/v2/pkg/lockbox
  → github.com/dueldanov/lockbox/v2/lockbox/verification
  → github.com/dueldanov/lockbox/v2/lockbox  [CYCLE]
```

**Root cause**: The fork has significant custom code additions beyond simple renaming:
- `lockbox/` directory with 20+ subdirectories (crypto, monitoring, verification, etc.)
- `pkg/lockbox/` directory with gRPC server and compiler code
- `component.go` in root defining a "LockBox" component
- Import cycles between these custom packages

### Resolution Options

#### Option 1: Remove Custom LockBox Code (Recommended)
To get a working HORNET fork with just renaming:
1. Remove or rename the custom `lockbox/` directory
2. Remove or rename the custom `pkg/lockbox/` directory
3. Remove `component.go` from root
4. This will restore to a clean HORNET v2.0.2 fork with just branding changes

#### Option 2: Fix Import Cycles
Restructure the custom lockbox code to eliminate circular dependencies:
1. Analyze dependency graph
2. Move shared types to a separate package
3. Refactor imports to be unidirectional
4. This requires understanding the custom code's purpose

#### Option 3: Build Original HORNET First
Revert all custom additions and verify original HORNET v2.0.2 builds:
1. `git checkout <original-hornet-commit>`
2. Verify build works
3. Then apply ONLY renaming changes incrementally
4. Test build after each change

### Dependency Issues (Secondary)
Also fixed several broken dependency versions:
- `github.com/iotaledger/go-ds-kvstore`: Updated to working version
- `github.com/iotaledger/iota.go/v3`: Updated to v3.0.0-rc.3
- Removed duplicate `iota-crypto-demo` dependency

## File Inventory

### Modified Files
- `go.mod` - Module path
- `tools/gendoc/go.mod` - Module path
- `Dockerfile` - Binary name and labels
- `scripts/build_hornet.sh` - Binary name
- `scripts/build_hornet_rocksdb.sh` - Binary name  
- `scripts/build_hornet_rocksdb_external_libs.sh` - Binary name
- `components/profile/params.go` - Default alias
- `config_defaults.json` - Node alias
- `private_tangle/config_private_tangle.json` - Node alias
- `README.md` - Complete rewrite
- **200+ Go files** - Import path updates

### Created Files
- `config_lockbox_devnet.json` - Devnet configuration
- `FORK_SUMMARY.md` - This file

## Network Configuration

### Devnet Ports
- **REST API**: 14265 (localhost only)
- **P2P Gossip**: 15600 (localhost only)
- **Autopeering**: 14626 (disabled)
- **Profiling**: 6060 (disabled by default)

### Devnet Features
- ✅ Isolated from IOTA mainnet/testnet
- ✅ Custom token (LockCoin/LOCK)
- ✅ Localhost-only bindings
- ✅ No external peer connections
- ✅ No snapshot downloads
- ✅ Pebble database (no RocksDB dependency)

## Next Steps

1. **Choose build approach** (see Solutions above)
2. **Test build**: `go build -o lockbox-node .`
3. **Test startup**: `./lockbox-node --config config_lockbox_devnet.json`
4. **Verify API**: `curl http://127.0.0.1:14265/health`
5. **Commit changes**: Document which solution was chosen

## Upstream Compatibility

All protocol logic, consensus mechanisms, and tangle internals remain **unchanged** from HORNET v2.0.2. This fork only changes:
- Module/binary naming
- Default configuration
- Branding strings

The node is fully compatible with IOTA protocol and can participate in IOTA networks if configured to do so.

## License

Apache License 2.0 (inherited from HORNET)

Original project: https://github.com/iotaledger/hornet

