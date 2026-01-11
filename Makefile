# LockBox Makefile
# ================
# Unified entry point for build, test, and run operations

.PHONY: build test test-unit test-e2e test-coverage start stop clean proto lint help

# Variables
BINARY_NAME := lockbox-node
COMMIT_HASH := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
LDFLAGS := -s -w -X github.com/dueldanov/lockbox/v2/components/app.Version=$(COMMIT_HASH)

# Go settings
GOCMD := go
GOBUILD := $(GOCMD) build
GOTEST := $(GOCMD) test
GOCLEAN := $(GOCMD) clean
GOMOD := $(GOCMD) mod

# Colors for output
GREEN := \033[0;32m
YELLOW := \033[0;33m
RED := \033[0;31m
NC := \033[0m # No Color

# ============================================================================
# BUILD
# ============================================================================

## build: Build the lockbox-node binary
build:
	@echo "$(GREEN)🔨 Building LockBox Node...$(NC)"
	$(GOBUILD) -o $(BINARY_NAME) -ldflags="$(LDFLAGS)"
	@if [ "$(shell uname)" = "Darwin" ]; then \
		echo "$(YELLOW)🍎 Applying macOS code signature...$(NC)"; \
		codesign --force --deep --sign - ./$(BINARY_NAME) 2>/dev/null || true; \
	fi
	@echo "$(GREEN)✅ Build successful!$(NC)"

## build-race: Build with race detector (for debugging)
build-race:
	@echo "$(YELLOW)🔨 Building with race detector...$(NC)"
	$(GOBUILD) -race -o $(BINARY_NAME) -ldflags="$(LDFLAGS)"

# ============================================================================
# TEST
# ============================================================================

## test: Run all tests
test: test-unit

## test-unit: Run unit tests for main packages
test-unit:
	@echo "$(GREEN)🧪 Running unit tests...$(NC)"
	$(GOTEST) -v ./internal/service/... ./internal/crypto/... ./internal/lockscript/... ./internal/verification/...

## test-grpc: Run gRPC E2E tests (requires LOCKBOX_DEV_MODE)
test-grpc:
	@echo "$(GREEN)🧪 Running gRPC E2E tests...$(NC)"
	LOCKBOX_DEV_MODE=true $(GOTEST) -v -run TestGRPC ./internal/service/...

## test-lockscript: Run LockScript VM tests
test-lockscript:
	@echo "$(GREEN)🧪 Running LockScript tests...$(NC)"
	$(GOTEST) -v ./internal/lockscript/...

## test-crypto: Run crypto module tests
test-crypto:
	@echo "$(GREEN)🧪 Running crypto tests...$(NC)"
	$(GOTEST) -v ./internal/crypto/...

## test-coverage: Run tests with coverage report
test-coverage:
	@echo "$(GREEN)📊 Running tests with coverage...$(NC)"
	$(GOTEST) -coverprofile=coverage.out ./internal/service/... ./internal/crypto/... ./internal/lockscript/...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "$(GREEN)✅ Coverage report: coverage.html$(NC)"

## test-short: Run tests in short mode (skip slow tests)
test-short:
	@echo "$(GREEN)🧪 Running short tests...$(NC)"
	$(GOTEST) -short -v ./internal/...

# ============================================================================
# RUN
# ============================================================================

## start: Start the LockBox devnet node
start:
	@echo "$(GREEN)🚀 Starting LockBox Node...$(NC)"
	@./start.sh

## stop: Stop the LockBox node
stop:
	@echo "$(RED)🛑 Stopping LockBox Node...$(NC)"
	@./stop.sh

## status: Check node status
status:
	@./status.sh

## run-dev: Build and run in dev mode (single command)
run-dev: build
	@echo "$(GREEN)🚀 Starting in dev mode...$(NC)"
	LOCKBOX_DEV_MODE=true ./$(BINARY_NAME) --config config_lockbox_devnet.json

# ============================================================================
# CLEAN
# ============================================================================

## clean: Remove build artifacts
clean:
	@echo "$(YELLOW)🧹 Cleaning build artifacts...$(NC)"
	$(GOCLEAN)
	rm -f $(BINARY_NAME)
	rm -f coverage.out coverage.html

## clean-data: Remove all node data (DB, snapshots)
clean-data:
	@echo "$(RED)🗑️  Removing node data...$(NC)"
	rm -rf lockbox_devnet_db/
	rm -rf lockbox_devnet_p2pstore/
	rm -rf lockbox_devnet_snapshots/
	rm -f shutdown.log
	@echo "$(GREEN)✅ Data cleaned$(NC)"

## clean-all: Full clean (build artifacts + data)
clean-all: clean clean-data

# ============================================================================
# PROTO
# ============================================================================

## proto: Generate protobuf files
proto:
	@echo "$(GREEN)📝 Generating protobuf...$(NC)"
	cd internal/proto && ./generate.sh
	@echo "$(GREEN)✅ Protobuf generated$(NC)"

# ============================================================================
# DEPS
# ============================================================================

## deps: Download and tidy dependencies
deps:
	@echo "$(GREEN)📦 Downloading dependencies...$(NC)"
	$(GOMOD) download
	$(GOMOD) tidy
	@echo "$(GREEN)✅ Dependencies ready$(NC)"

## deps-update: Update all dependencies
deps-update:
	@echo "$(YELLOW)📦 Updating dependencies...$(NC)"
	$(GOMOD) get -u ./...
	$(GOMOD) tidy

# ============================================================================
# LINT
# ============================================================================

## lint: Run linters
lint:
	@echo "$(GREEN)🔍 Running linters...$(NC)"
	@if command -v golangci-lint &> /dev/null; then \
		golangci-lint run ./...; \
	else \
		echo "$(YELLOW)⚠️  golangci-lint not installed. Running gofmt only...$(NC)"; \
		gofmt -s -d .; \
	fi

## fmt: Format code
fmt:
	@echo "$(GREEN)✨ Formatting code...$(NC)"
	gofmt -s -w .

# ============================================================================
# PRIVATE TANGLE
# ============================================================================

## tangle-bootstrap: Bootstrap private tangle (first time setup)
tangle-bootstrap:
	@echo "$(GREEN)🌐 Bootstrapping private tangle...$(NC)"
	cd private_tangle && ./bootstrap.sh

## tangle-start: Start private tangle (2 nodes)
tangle-start:
	@echo "$(GREEN)🌐 Starting private tangle...$(NC)"
	cd private_tangle && ./run.sh

## tangle-stop: Stop private tangle
tangle-stop:
	@echo "$(RED)🌐 Stopping private tangle...$(NC)"
	cd private_tangle && docker compose down

## tangle-clean: Clean private tangle data
tangle-clean:
	@echo "$(YELLOW)🧹 Cleaning private tangle...$(NC)"
	cd private_tangle && ./cleanup.sh

# ============================================================================
# DOCKER (future)
# ============================================================================

## docker-build: Build Docker image
docker-build:
	@echo "$(RED)❌ Docker build not yet implemented$(NC)"

# ============================================================================
# HELP
# ============================================================================

## help: Show this help message
help:
	@echo ""
	@echo "$(GREEN)LockBox Makefile Commands$(NC)"
	@echo "=========================="
	@echo ""
	@echo "$(YELLOW)Build:$(NC)"
	@echo "  make build          - Build the lockbox-node binary"
	@echo "  make build-race     - Build with race detector"
	@echo ""
	@echo "$(YELLOW)Test:$(NC)"
	@echo "  make test           - Run all unit tests"
	@echo "  make test-grpc      - Run gRPC E2E tests"
	@echo "  make test-lockscript - Run LockScript VM tests"
	@echo "  make test-crypto    - Run crypto module tests"
	@echo "  make test-coverage  - Generate coverage report"
	@echo ""
	@echo "$(YELLOW)Run:$(NC)"
	@echo "  make start          - Start devnet node"
	@echo "  make stop           - Stop devnet node"
	@echo "  make status         - Check node status"
	@echo "  make run-dev        - Build and run in dev mode"
	@echo ""
	@echo "$(YELLOW)Clean:$(NC)"
	@echo "  make clean          - Remove build artifacts"
	@echo "  make clean-data     - Remove node data"
	@echo "  make clean-all      - Full clean"
	@echo ""
	@echo "$(YELLOW)Other:$(NC)"
	@echo "  make proto          - Generate protobuf files"
	@echo "  make deps           - Download dependencies"
	@echo "  make lint           - Run linters"
	@echo "  make fmt            - Format code"
	@echo ""
	@echo "$(YELLOW)Private Tangle:$(NC)"
	@echo "  make tangle-bootstrap - First time setup"
	@echo "  make tangle-start     - Start 2-node tangle"
	@echo "  make tangle-stop      - Stop tangle"
	@echo ""

# Default target
.DEFAULT_GOAL := help
