BINARY := openid-connect-server
BUILD_DIR := build
UI_DIR := ui
E2E_DIR := tests
GO := go
GO_PACKAGES := $(shell go list ./... | grep -v '/ui/' || true)

PORT ?=
CONFIG ?=

VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LD_FLAGS := -s -w \
	-X github.com/prasenjit-net/openid-connect-server/internal/version.Version=$(VERSION) \
	-X github.com/prasenjit-net/openid-connect-server/internal/version.Commit=$(COMMIT) \
	-X github.com/prasenjit-net/openid-connect-server/internal/version.BuildDate=$(BUILD_DATE)

.PHONY: all build build-ui build-go run dev dev-ui dev-all test test-ui lint lint-ui fmt install-deps clean init help e2e-server e2e-install e2e

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

test-ui:
	cd $(UI_DIR) && npm test

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

# --- Manual-only e2e suite (never run by CI; see tests/README.md) ---
e2e-server:
	@echo "> Starting a disposable e2e server (leave this running)…"
	cd $(E2E_DIR) && bash scripts/run-server.sh

e2e-install:
	@echo "> Installing e2e suite dependencies…"
	cd $(E2E_DIR) && npm install && npx playwright install chromium

e2e:
	@echo "> Running e2e suite (reads $(E2E_DIR)/.env — see tests/README.md if it's missing)…"
	cd $(E2E_DIR) && npm test

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
	@echo "  test-ui     Run frontend tests"
	@echo "  lint        Run go vet"
	@echo "  lint-ui     Run frontend lint"
	@echo "  install-deps Install Go and UI dependencies"
	@echo ""
	@echo "  e2e-server  Start a disposable server for the manual e2e suite (tests/)"
	@echo "  e2e-install Install the e2e suite's dependencies (Playwright + browser)"
	@echo "  e2e         Run the e2e suite (reads tests/.env; see tests/README.md)"
