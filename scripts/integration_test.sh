#!/bin/bash
# LockBox Integration Test Script
# Tests the gRPC API endpoints locally
#
# Prerequisites:
#   - grpcurl: brew install grpcurl
#   - LockBox server running on localhost:50051
#
# Usage:
#   ./scripts/integration_test.sh [--host HOST:PORT] [--verbose]

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Default values
HOST="localhost:50051"
VERBOSE=false
PROTO_PATH="internal/proto/lockbox.proto"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --host)
            HOST="$2"
            shift 2
            ;;
        --verbose|-v)
            VERBOSE=true
            shift
            ;;
        --help|-h)
            echo "LockBox Integration Test Script"
            echo ""
            echo "Usage: $0 [--host HOST:PORT] [--verbose]"
            echo ""
            echo "Options:"
            echo "  --host HOST:PORT    Server address (default: localhost:50051)"
            echo "  --verbose, -v       Show detailed output"
            echo "  --help, -h          Show this help"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Check for grpcurl
if ! command -v grpcurl &> /dev/null; then
    echo -e "${YELLOW}grpcurl not found. Installing via Homebrew...${NC}"
    brew install grpcurl
fi

# Test counter
TESTS_PASSED=0
TESTS_FAILED=0

# Test function
run_test() {
    local name="$1"
    local method="$2"
    local data="$3"
    local expected_status="${4:-0}"

    echo -n "Testing $name... "

    if $VERBOSE; then
        echo ""
        echo "  Method: $method"
        echo "  Data: $data"
    fi

    # Run grpcurl
    result=$(grpcurl -plaintext -proto "$PROTO_PATH" -d "$data" "$HOST" "$method" 2>&1) || true
    exit_code=$?

    if $VERBOSE; then
        echo "  Response: $result"
    fi

    # Check result
    if [[ $exit_code -eq $expected_status ]] || [[ "$result" != *"Error"* && $expected_status -eq 0 ]]; then
        echo -e "${GREEN}PASSED${NC}"
        ((TESTS_PASSED++))
    else
        echo -e "${RED}FAILED${NC}"
        if ! $VERBOSE; then
            echo "  Response: $result"
        fi
        ((TESTS_FAILED++))
    fi
}

echo "=========================================="
echo "LockBox Integration Tests"
echo "Server: $HOST"
echo "=========================================="
echo ""

# Test 1: GetServiceInfo (should always work)
echo "--- Service Health ---"
run_test "GetServiceInfo" \
    "lockbox.LockBoxService/GetServiceInfo" \
    '{}'

# Test 2: LockAsset
echo ""
echo "--- Lock/Unlock Flow ---"
OWNER_ADDRESS="iota1qp8h9lg0w06lqfire29evvupkhlvzmhurm34t696ylss79hkg4qj0xk5r6p"
OUTPUT_ID="$(echo -n "test_output_123" | base64)"

run_test "LockAsset" \
    "lockbox.LockBoxService/LockAsset" \
    "{
        \"owner_address\": \"$OWNER_ADDRESS\",
        \"output_id\": \"$OUTPUT_ID\",
        \"lock_duration_seconds\": 3600,
        \"lock_script\": \"TIME > unlock_time\"
    }"

# Test 3: GetAssetStatus (may fail if lock didn't work)
TEST_ASSET_ID="test-asset-001"
run_test "GetAssetStatus" \
    "lockbox.LockBoxService/GetAssetStatus" \
    "{\"asset_id\": \"$TEST_ASSET_ID\"}"

# Test 4: ListAssets
run_test "ListAssets (streaming)" \
    "lockbox.LockBoxService/ListAssets" \
    "{\"owner_address\": \"$OWNER_ADDRESS\", \"page_size\": 10}"

# Test 5: EmergencyUnlock (should fail without proper signatures)
echo ""
echo "--- Security Tests ---"
run_test "EmergencyUnlock (no signatures - should fail)" \
    "lockbox.LockBoxService/EmergencyUnlock" \
    "{\"asset_id\": \"$TEST_ASSET_ID\", \"reason\": \"test\"}" \
    1

# Test 6: CreateMultiSig
run_test "CreateMultiSig" \
    "lockbox.LockBoxService/CreateMultiSig" \
    "{
        \"addresses\": [
            \"$OWNER_ADDRESS\",
            \"iota1qp8h9lg0w06lqfire29evvupkhlvzmhurm34t696ylss79hkg4qj0xk5r61\"
        ],
        \"min_signatures\": 2
    }"

# Summary
echo ""
echo "=========================================="
echo "Test Summary"
echo "=========================================="
echo -e "Passed: ${GREEN}$TESTS_PASSED${NC}"
echo -e "Failed: ${RED}$TESTS_FAILED${NC}"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed.${NC}"
    exit 1
fi
