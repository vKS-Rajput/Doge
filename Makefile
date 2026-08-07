# Doge — AI Security Research Workspace
# Makefile for build, test, lint, and development tasks.

# Build variables
BINARY_NAME := doge
BUILD_DIR := ./build
MAIN_PKG := ./cmd/workspace
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -ldflags "-X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)"

# Go commands
GO := go
GOTEST := $(GO) test
GOBUILD := $(GO) build
GOVET := $(GO) vet
GOMOD := $(GO) mod
GOFMT := gofmt

.PHONY: all build test lint fmt vet tidy clean run help

## help: Print this help message
help:
	@echo "Doge — AI Security Research Workspace"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@sed -n 's/^## //p' $(MAKEFILE_LIST) | column -t -s ':' 2>/dev/null || \
		sed -n 's/^## //p' $(MAKEFILE_LIST)

## all: Run fmt, vet, lint, test, and build
all: fmt vet lint test build

## build: Build the binary
build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME).exe $(MAIN_PKG)
	@echo "Built $(BUILD_DIR)/$(BINARY_NAME).exe"

## test: Run all tests with coverage
test:
	@echo "Running tests..."
	$(GOTEST) -coverprofile=coverage.out ./...
	@echo "Coverage report: coverage.out"

## test-short: Run short tests only (skip integration tests)
test-short:
	$(GOTEST) -short ./...

## test-integration: Run integration tests
test-integration:
	$(GOTEST) -tags=integration ./...

## lint: Run golangci-lint
lint:
	@echo "Running linter..."
	golangci-lint run ./...

## fmt: Format all Go files
fmt:
	@echo "Formatting..."
	$(GOFMT) -s -w .

## vet: Run go vet
vet:
	@echo "Running vet..."
	$(GOVET) ./...

## tidy: Tidy and verify module dependencies
tidy:
	$(GOMOD) tidy
	$(GOMOD) verify

## clean: Remove build artifacts
clean:
	@echo "Cleaning..."
	rm -rf $(BUILD_DIR)
	rm -f coverage.out

## run: Build and run the binary
run: build
	$(BUILD_DIR)/$(BINARY_NAME).exe
