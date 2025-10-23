# Makefile for k8s-cve-analyzer

BINARY_NAME=vex8s
BINARY_PATH=./bin/$(BINARY_NAME)
BUILD_VARS=GOTOOLCHAIN=go1.25.3 GOEXPERIMENT=jsonv2

.PHONY: all build clean deps lint install-tools help

# Default target
all: deps build

## build: Build the binary
build:
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p ./bin
	$(BUILD_VARS) go build -o $(BINARY_PATH) main.go
	chmod +x $(BINARY_PATH)
	@echo "✓ Binary built: $(BINARY_PATH)"

## test: Test unit tests
test:
	@echo "Testing $(BINARY_NAME)..."
	$(BUILD_VARS) go test -v ./...
	@echo "✓ Tests ran"

## clean: Remove build artifacts
clean:
	@echo "Cleaning..."
	@rm -rf ./bin
	@rm -rf ./output
	go clean
	@echo "✓ Cleaned"

## deps: Download Go dependencies
deps:
	@echo "Downloading dependencies..."
	go mod download
	go mod tidy
	@echo "✓ Dependencies updated"

## lint: Run golangci-lint
lint:
	@echo "Running linter..."
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./... ; \
		echo "✓ Lint passed" ; \
	else \
		echo "ERROR: golangci-lint not installed. Run: make install-tools" ; \
		exit 1 ; \
	fi

## install-tools: Install trivy and golangci-lint
install-tools:
	@echo "Installing tools..."
	@echo "Installing golangci-lint..."
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@echo "✓ Tools installed"
