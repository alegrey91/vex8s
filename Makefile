# Makefile for vex8s

BINARY_NAME=vex8s
BINARY_PATH=./bin/$(BINARY_NAME)
BUILD_VARS=GOTOOLCHAIN=go1.25.3 GOEXPERIMENT=jsonv2

.PHONY: all build clean deps lint install-tools help

# Default target
all: deps build

## build: Build the binary
build: download-model
	@echo "Building $(BINARY_NAME)..."
	@mkdir -p ./bin
	$(BUILD_VARS) go build -o $(BINARY_PATH) main.go
	chmod +x $(BINARY_PATH)
	@echo "✓ Binary built: $(BINARY_PATH)"

## test: Run all tests
.PHONY: test
test: test-unit test-integration

## test: Test unit tests
test-unit:
	@echo "Testing $(BINARY_NAME)..."
	$(BUILD_VARS) go test -v ./...
	@echo "✓ Tests ran"

## test: Test integration tests
test-integration: install
	@echo "Testing $(BINARY_NAME)..."
	$(BUILD_VARS) go test -tags=integration ./test/ -v
	@echo "✓ Tests ran"

## install vex8s locally
install: build
	@echo "Installing vex8s locally"
	cp ./bin/vex8s $(HOME)/go/bin/
	@echo "✓ Installation succeded"

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

## download-model: Download the latest model artifact if not present
.PHONY: download-model
download-model:
	@if [ -f pkg/inference/nn/vex8s_cve_classifier.onnx ]; then \
		echo "Model artifact already present at pkg/inference/nn/vex8s_cve_classifier.onnx"; \
	else \
		echo "Model artifact not found. Downloading latest from GitHub..."; \
		LATEST_URL=$$(curl -s https://api.github.com/repos/alegrey91/vex8s-model/releases/latest | grep browser_download_url | grep vex8s_cve_classifier.onnx | cut -d '"' -f 4); \
		if [ -z "$$LATEST_URL" ]; then \
			echo "Could not find model artifact in latest release."; exit 1; \
		fi; \
		mkdir -p pkg/inference/nn/; \
		curl -L -o pkg/inference/nn/vex8s_cve_classifier.onnx "$$LATEST_URL"; \
		if [ $$? -eq 0 ]; then \
			echo "Model downloaded to pkg/inference/nn/vex8s_cve_classifier.onnx"; \
		else \
			echo "Failed to download model artifact."; exit 1; \
		fi; \
	fi

## install-tools: Install trivy and golangci-lint
install-tools:
	@echo "Installing tools..."
	@echo "Installing golangci-lint..."
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@echo "✓ Tools installed"
