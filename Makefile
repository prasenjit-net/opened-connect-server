BINARY := $(notdir $(CURDIR))
BUILD_DIR := build
UI_DIR := ui
GO := go
GO_PACKAGES := $(shell go list ./... | grep -v '/ui/' || true)

PORT ?=
CONFIG ?=

VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LD_FLAGS := -s -w \
	-X github.com/your-org/go-app-template/internal/version.Version=$(VERSION) \
	-X github.com/your-org/go-app-template/internal/version.Commit=$(COMMIT) \
	-X github.com/your-org/go-app-template/internal/version.BuildDate=$(BUILD_DATE)

.PHONY: all build build-ui build-go run dev dev-ui dev-all test lint lint-ui fmt install-deps clean init help

all: build

build: build-ui build-go

build-ui:
	@echo "> Building UI…"
	cd $(UI_DIR) && npm run build
	@echo "✓ UI build complete"

build-go:
	@echo "> Building Go binary ($(VERSION))…"
	@mkdir -p $(BUILD_DIR)
	$(GO) build -ldflags "$(LD_FLAGS)" -o $(BUILD_DIR)/$(BINARY) .
	@echo "✓ Binary: $(BUILD_DIR)/$(BINARY)"

run: build
	@echo "> Starting $(BINARY)…"
	./$(BUILD_DIR)/$(BINARY) serve $(if $(PORT),--port $(PORT),) $(if $(CONFIG),--config $(CONFIG),)

dev:
	@echo "> Starting Go server in development mode…"
	$(GO) run . serve --dev $(if $(PORT),--port $(PORT),) $(if $(CONFIG),--config $(CONFIG),)

dev-ui:
	@echo "> Starting Vite dev server…"
	cd $(UI_DIR) && npm run dev

dev-all:
	@echo "> Starting backend + frontend…"
	cd $(UI_DIR) && npx concurrently --names "server,ui" --prefix-colors "cyan,magenta" \
		"cd .. && $(GO) run . serve --dev $(if $(PORT),--port $(PORT),) $(if $(CONFIG),--config $(CONFIG),)" \
		"npm run dev"

test:
	@echo "> Running Go tests…"
	$(GO) test $(GO_PACKAGES)

lint:
	@echo "> Running go vet…"
	$(GO) vet $(GO_PACKAGES)

lint-ui:
	@echo "> Running UI lint…"
	cd $(UI_DIR) && npm run lint

fmt:
	$(GO) fmt $(GO_PACKAGES)

install-deps:
	@echo "> Installing Go dependencies…"
	$(GO) mod download
	$(GO) mod tidy
	@echo "> Installing UI dependencies…"
	cd $(UI_DIR) && npm install
	@echo "✓ Dependencies installed"

init:
	$(GO) run . init $(if $(CONFIG),--config $(CONFIG),)

clean:
	rm -rf $(BUILD_DIR) $(UI_DIR)/node_modules coverage.out coverage.html
	find $(UI_DIR)/dist -mindepth 1 ! -name '.gitkeep' -delete

help:
	@echo "Usage: make <target>"
	@echo ""
	@echo "Targets:"
	@echo "  build       Build UI and Go binary"
	@echo "  run         Build and run the production binary"
	@echo "  dev         Run the Go server with Vite proxy support"
	@echo "  dev-ui      Run the Vite development server"
	@echo "  dev-all     Run backend and frontend together"
	@echo "  test        Run Go tests"
	@echo "  lint        Run go vet"
	@echo "  lint-ui     Run frontend lint"
	@echo "  install-deps Install Go and UI dependencies"
