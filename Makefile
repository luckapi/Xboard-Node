VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
BUILD_TIME ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME) -X main.commit=$(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
NODE_TAGS := with_quic with_utls with_wireguard with_acme with_clash_api
REQUIRED_NODE_TAGS := with_utls
BUILD_DIR ?= .
KERNEL_TEST_PACKAGES := github.com/sagernet/sing-box/adapter github.com/xtls/xray-core/features/bandwidth github.com/xtls/xray-core/app/dispatcher github.com/xtls/xray-core/common/mux github.com/ohmycggk/nowhere-go/wire github.com/ohmycggk/nowhere-go/dgram github.com/ohmycggk/nowhere-go/morph
KERNEL_TEST_PACKAGES += github.com/SUDOKU-ASCII/sudoku/apis github.com/SUDOKU-ASCII/sudoku/internal/tunnel github.com/SUDOKU-ASCII/sudoku/pkg/obfs/sudoku

.PHONY: deps build clean test docker install build-linux build-linux-arm64 build-all

deps:
	GO111MODULE=off go run scripts/prepare-kernels.go

# Build for current platform
build: deps
	go build -ldflags "$(LDFLAGS)" -tags "$(NODE_TAGS)" -o xboard-node ./cmd/xboard-node
	sh scripts/check-node-build-tags.sh xboard-node $(REQUIRED_NODE_TAGS)
	go build -ldflags "$(LDFLAGS)" -o xbctl ./cmd/xbctl

# Build for Linux amd64
build-linux: deps
	mkdir -p "$(BUILD_DIR)"
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -tags "$(NODE_TAGS)" -o "$(BUILD_DIR)/xboard-node-linux-amd64" ./cmd/xboard-node
	sh scripts/check-node-build-tags.sh "$(BUILD_DIR)/xboard-node-linux-amd64" $(REQUIRED_NODE_TAGS)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o "$(BUILD_DIR)/xbctl-linux-amd64" ./cmd/xbctl

# Build for Linux arm64
build-linux-arm64: deps
	mkdir -p "$(BUILD_DIR)"
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -tags "$(NODE_TAGS)" -o "$(BUILD_DIR)/xboard-node-linux-arm64" ./cmd/xboard-node
	sh scripts/check-node-build-tags.sh "$(BUILD_DIR)/xboard-node-linux-arm64" $(REQUIRED_NODE_TAGS)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o "$(BUILD_DIR)/xbctl-linux-arm64" ./cmd/xbctl

# Build all platforms
build-all: build-linux build-linux-arm64

# Run tests
test: deps
	go test -v -race -count=1 -tags "$(NODE_TAGS)" ./internal/... ./cmd/... $(KERNEL_TEST_PACKAGES)

# Clean build artifacts
clean:
	rm -f xboard-node xbctl xboard-node-linux-* xbctl-linux-*

# Build Docker image
docker:
	docker build -t xboard-node:$(VERSION) -t xboard-node:latest .

# Install to system (single node, legacy compat)
install: build
	sudo cp xboard-node /usr/local/bin/
	sudo cp xbctl /usr/local/bin/
	sudo mkdir -p /etc/xboard-node
	@if [ ! -f /etc/xboard-node/config.yml ]; then \
		sudo cp config.yml.example /etc/xboard-node/config.yml; \
		echo "Config copied to /etc/xboard-node/config.yml - please edit it"; \
	fi
