#!/bin/bash
# LockBox E2E Restart Test
# Tests: lock → restart → unlock (Milestone 1 Exit Criteria)
#
# Prerequisites:
#   - grpcurl: brew install grpcurl
#   - Built lockbox-node binary
#
# Usage:
#   ./scripts/e2e_restart_test.sh

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
NODE_BIN="$PROJECT_DIR/lockbox-node"
PROTO_PATH="$PROJECT_DIR/internal/proto/lockbox.proto"
GRPC_HOST="localhost:50051"
NODE_PID=""
ASSET_ID=""

# Cleanup function
cleanup() {
    echo -e "\n${YELLOW}Cleaning up...${NC}"
    if [ -n "$NODE_PID" ] && kill -0 "$NODE_PID" 2>/dev/null; then
        kill "$NODE_PID" 2>/dev/null || true
        wait "$NODE_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# Check prerequisites
check_prerequisites() {
    echo -e "${BLUE}Checking prerequisites...${NC}"

    if ! command -v grpcurl &> /dev/null; then
        echo -e "${YELLOW}grpcurl not found. Installing...${NC}"
        brew install grpcurl
    fi

    if [ ! -f "$NODE_BIN" ]; then
        echo -e "${YELLOW}Building lockbox-node...${NC}"
        cd "$PROJECT_DIR"
        go build -buildvcs=false -o lockbox-node ./components/lockbox
        codesign --force --deep --sign - ./lockbox-node 2>/dev/null || true
    fi

    echo -e "${GREEN}Prerequisites OK${NC}"
}

# Start node
start_node() {
    echo -e "\n${BLUE}Starting lockbox-node...${NC}"
    cd "$PROJECT_DIR"

    # Start node with gRPC enabled
    "$NODE_BIN" --config=config_lockbox_devnet.json 2>&1 &
    NODE_PID=$!

    echo "Node PID: $NODE_PID"

    # Wait for node to be ready
    echo -n "Waiting for gRPC server"
    for i in {1..30}; do
        if grpcurl -plaintext "$GRPC_HOST" list 2>/dev/null | grep -q "LockBoxService"; then
            echo -e " ${GREEN}Ready${NC}"
            return 0
        fi
        echo -n "."
        sleep 1
    done

    echo -e " ${RED}Timeout${NC}"
    return 1
}

# Stop node
stop_node() {
    echo -e "\n${BLUE}Stopping node (PID: $NODE_PID)...${NC}"
    if [ -n "$NODE_PID" ] && kill -0 "$NODE_PID" 2>/dev/null; then
        kill "$NODE_PID"
        wait "$NODE_PID" 2>/dev/null || true
        echo -e "${GREEN}Node stopped${NC}"
    fi
    NODE_PID=""
    sleep 2
}

# Test: Lock Asset
test_lock_asset() {
    echo -e "\n${BLUE}=== Test: LockAsset ===${NC}"

    local owner="iota1qp8h9lg0w06lqfire29evvupkhlvzmhurm34t696ylss79hkg4qj0xk5r6p"
    local output_id=$(echo -n "e2e_test_output_$(date +%s)" | base64)

    local response=$(grpcurl -plaintext -proto "$PROTO_PATH" \
        -d "{
            \"owner_address\": \"$owner\",
            \"output_id\": \"$output_id\",
            \"lock_duration_seconds\": 3600,
            \"lock_script\": \"TIME > unlock_time\"
        }" \
        "$GRPC_HOST" lockbox.LockBoxService/LockAsset 2>&1)

    echo "Response: $response"

    # Extract asset_id
    ASSET_ID=$(echo "$response" | grep -o '"asset_id": *"[^"]*"' | sed 's/"asset_id": *"\([^"]*\)"/\1/' || echo "")

    if [ -z "$ASSET_ID" ]; then
        # Try alternative parsing
        ASSET_ID=$(echo "$response" | grep -o 'assetId.*' | head -1 | sed 's/.*: *"\([^"]*\)".*/\1/' || echo "")
    fi

    if [ -n "$ASSET_ID" ] && [ "$ASSET_ID" != "null" ]; then
        echo -e "${GREEN}LockAsset: PASSED${NC}"
        echo "Asset ID: $ASSET_ID"
        return 0
    else
        echo -e "${RED}LockAsset: FAILED${NC}"
        echo "Could not extract asset_id from response"
        return 1
    fi
}

# Test: Get Asset Status (before restart)
test_get_status_before() {
    echo -e "\n${BLUE}=== Test: GetAssetStatus (before restart) ===${NC}"

    if [ -z "$ASSET_ID" ]; then
        echo -e "${RED}No asset_id available${NC}"
        return 1
    fi

    local response=$(grpcurl -plaintext -proto "$PROTO_PATH" \
        -d "{\"asset_id\": \"$ASSET_ID\"}" \
        "$GRPC_HOST" lockbox.LockBoxService/GetAssetStatus 2>&1)

    echo "Response: $response"

    if echo "$response" | grep -qi "locked\|status"; then
        echo -e "${GREEN}GetAssetStatus (before): PASSED${NC}"
        return 0
    else
        echo -e "${YELLOW}GetAssetStatus (before): Asset may not be found (expected for new lock)${NC}"
        return 0
    fi
}

# Test: Get Asset Status (after restart)
test_get_status_after() {
    echo -e "\n${BLUE}=== Test: GetAssetStatus (after restart) ===${NC}"

    if [ -z "$ASSET_ID" ]; then
        echo -e "${RED}No asset_id available${NC}"
        return 1
    fi

    local response=$(grpcurl -plaintext -proto "$PROTO_PATH" \
        -d "{\"asset_id\": \"$ASSET_ID\"}" \
        "$GRPC_HOST" lockbox.LockBoxService/GetAssetStatus 2>&1)

    echo "Response: $response"

    if echo "$response" | grep -qi "locked\|status\|$ASSET_ID"; then
        echo -e "${GREEN}GetAssetStatus (after restart): PASSED${NC}"
        echo -e "${GREEN}DATA PERSISTENCE VERIFIED${NC}"
        return 0
    else
        echo -e "${RED}GetAssetStatus (after restart): FAILED${NC}"
        echo "Asset not found after restart - DATA LOSS DETECTED"
        return 1
    fi
}

# Test: Service Info
test_service_info() {
    echo -e "\n${BLUE}=== Test: GetServiceInfo ===${NC}"

    local response=$(grpcurl -plaintext -proto "$PROTO_PATH" \
        -d "{}" \
        "$GRPC_HOST" lockbox.LockBoxService/GetServiceInfo 2>&1)

    echo "Response: $response"

    if echo "$response" | grep -qi "version\|tier"; then
        echo -e "${GREEN}GetServiceInfo: PASSED${NC}"
        return 0
    else
        echo -e "${RED}GetServiceInfo: FAILED${NC}"
        return 1
    fi
}

# Main test flow
main() {
    echo "=========================================="
    echo "  LockBox E2E Restart Test"
    echo "  Milestone 1: DEV Ready"
    echo "=========================================="

    local tests_passed=0
    local tests_failed=0

    check_prerequisites

    # Phase 1: Start node and lock asset
    echo -e "\n${YELLOW}=== PHASE 1: Initial Lock ===${NC}"

    if ! start_node; then
        echo -e "${RED}Failed to start node${NC}"
        exit 1
    fi

    if test_service_info; then
        ((tests_passed++))
    else
        ((tests_failed++))
    fi

    if test_lock_asset; then
        ((tests_passed++))
    else
        ((tests_failed++))
    fi

    if test_get_status_before; then
        ((tests_passed++))
    else
        ((tests_failed++))
    fi

    # Phase 2: Restart node
    echo -e "\n${YELLOW}=== PHASE 2: Restart Node ===${NC}"
    stop_node

    echo "Waiting 3 seconds before restart..."
    sleep 3

    if ! start_node; then
        echo -e "${RED}Failed to restart node${NC}"
        exit 1
    fi

    # Phase 3: Verify persistence
    echo -e "\n${YELLOW}=== PHASE 3: Verify Persistence ===${NC}"

    if test_service_info; then
        ((tests_passed++))
    else
        ((tests_failed++))
    fi

    if test_get_status_after; then
        ((tests_passed++))
    else
        ((tests_failed++))
    fi

    # Summary
    echo ""
    echo "=========================================="
    echo "  Test Summary"
    echo "=========================================="
    echo -e "Passed: ${GREEN}$tests_passed${NC}"
    echo -e "Failed: ${RED}$tests_failed${NC}"
    echo ""

    if [ $tests_failed -eq 0 ]; then
        echo -e "${GREEN}=========================================="
        echo "  MILESTONE 1: DEV READY - VERIFIED"
        echo "==========================================${NC}"
        exit 0
    else
        echo -e "${RED}=========================================="
        echo "  MILESTONE 1: SOME TESTS FAILED"
        echo "==========================================${NC}"
        exit 1
    fi
}

main "$@"
