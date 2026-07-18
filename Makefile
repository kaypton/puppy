BINARY := puppy-server

# Build output reflects the host OS and Node-style arch so the desktop manager can
# resolve it at runtime without relying on unsuffixed fallbacks.
HOST_OS := $(shell uname -s | tr '[:upper:]' '[:lower:]')
HOST_ARCH := $(shell uname -m)
ifeq ($(HOST_ARCH),x86_64)
  HOST_ARCH := x64
else ifeq ($(HOST_ARCH),aarch64)
  HOST_ARCH := arm64
endif

BIN_DIR := bin
BINARY_NAME := $(BINARY)-$(HOST_OS)-$(HOST_ARCH)
BINARY_PATH := $(BIN_DIR)/$(BINARY_NAME)
CMD := ./cmd/puppy-server

GO ?= go
GOFLAGS ?=
PROJECT_GOFLAGS := -mod=vendor $(GOFLAGS)
CONFIG ?=

DESKTOP_DIR := app/desktop/puppy
DESKTOP_ELECTRON_BIN := ./node_modules/.bin/electron-builder

# Desktop packaging defaults: target current host OS and architecture unless overridden.
# DESKTOP_ARCH is the electron-builder arch name: x64, arm64, armv7l, ia32.
# DESKTOP_GO_ARCH maps it to the Go $GOARCH value.
DESKTOP_OS ?= $(HOST_OS)
DESKTOP_ARCH ?= $(HOST_ARCH)
ifeq ($(DESKTOP_ARCH),x64)
  DESKTOP_GO_ARCH := amd64
else ifeq ($(DESKTOP_ARCH),arm64)
  DESKTOP_GO_ARCH := arm64
else ifeq ($(DESKTOP_ARCH),armv7l)
  DESKTOP_GO_ARCH := arm
else ifeq ($(DESKTOP_ARCH),ia32)
  DESKTOP_GO_ARCH := 386
else
  DESKTOP_GO_ARCH := $(DESKTOP_ARCH)
endif

# Name the bundled binary with OS and arch (Node-style, e.g. puppy-server-linux-x64)
# so it matches process.platform/process.arch at runtime. Go is still compiled with
# the corresponding GOARCH mapping (x64 -> amd64, arm64 -> arm64).
DESKTOP_SERVER_NAME := puppy-server-$(DESKTOP_OS)-$(DESKTOP_ARCH)
DESKTOP_SERVER_BIN := $(DESKTOP_DIR)/bin/$(DESKTOP_SERVER_NAME)

GO_SOURCES := $(shell find . -type f -name '*.go' -not -path './vendor/*' -not -path './app/desktop/*')

.DEFAULT_GOAL := build

.PHONY: build clean vendor test test-race test-cover run fmt vet check help \
	desktop-deps desktop-build desktop-package desktop-clean \
	desktop-package-mac desktop-package-linux

build: $(BINARY_PATH) ## Build the puppy-server binary.

$(BINARY_PATH): $(GO_SOURCES)
	@mkdir -p $(BIN_DIR)
	$(GO) build $(PROJECT_GOFLAGS) -trimpath -o $(BINARY_PATH) $(CMD)

clean: desktop-clean ## Remove generated binaries, coverage output, and desktop build artifacts.
	rm -rf $(BIN_DIR) coverage.out

vendor: ## Synchronize dependencies into the vendor directory.
	$(GO) mod vendor

test: ## Run all Go tests.
	$(GO) test $(PROJECT_GOFLAGS) ./...

test-race: ## Run all Go tests with the race detector.
	$(GO) test $(PROJECT_GOFLAGS) -race ./...

test-cover: ## Run all Go tests and write coverage.out.
	$(GO) test $(PROJECT_GOFLAGS) -coverprofile=coverage.out ./...

run: build ## Build and run with CONFIG=/path/to/puppy.toml.
	@test -n "$(CONFIG)" || (echo "CONFIG is required; use: make run CONFIG=/path/to/puppy.toml" >&2; exit 2)
	$(BINARY_PATH) --config "$(CONFIG)"

fmt: ## Format all Go packages.
	$(GO) fmt ./...

vet: ## Run go vet for all packages.
	$(GO) vet $(PROJECT_GOFLAGS) ./...

check: test vet ## Run the standard validation suite.

help: ## Show available targets.
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z0-9_-]+:.*## / {printf "  %-12s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# ---------------------------------------------------------------------------
# Electron desktop app packaging (app/desktop/puppy)
# ---------------------------------------------------------------------------

desktop-deps: ## Install Node dependencies for the desktop app.
	cd $(DESKTOP_DIR) && npm ci

desktop-build: desktop-deps ## Compile the desktop app's renderer/main/preload bundles.
	cd $(DESKTOP_DIR) && npm run build

desktop-clean: ## Remove desktop build artifacts and bundled server binaries.
	rm -rf $(DESKTOP_DIR)/dist \
		$(DESKTOP_DIR)/bin/puppy-server-*

# Bundle the puppy-server binary for the target OS/arch into the Electron resources
# so electron-builder packages it alongside the app. The binary is named
# puppy-server-<os>-<arch> and referenced by src/main/server/manager.ts at runtime
# via process.resourcesPath.
$(DESKTOP_SERVER_BIN):
	@mkdir -p $(DESKTOP_DIR)/bin
	GOOS=$(DESKTOP_OS) GOARCH=$(DESKTOP_GO_ARCH) CGO_ENABLED=0 \
		$(GO) build $(PROJECT_GOFLAGS) -trimpath -o $@ ./cmd/puppy-server

desktop-package: desktop-build $(DESKTOP_SERVER_BIN) ## Build the desktop installer for the current host OS/arch.
ifeq ($(DESKTOP_OS),darwin)
	cd $(DESKTOP_DIR) && $(DESKTOP_ELECTRON_BIN) --mac --$(DESKTOP_ARCH) $(ELECTRON_BUILDER_ARGS)
else
	cd $(DESKTOP_DIR) && $(DESKTOP_ELECTRON_BIN) --linux --$(DESKTOP_ARCH) $(ELECTRON_BUILDER_ARGS)
endif

desktop-package-mac: ## Build the desktop app for macOS. Defaults to the host architecture; set DESKTOP_ARCH=... to override.
	$(MAKE) desktop-package DESKTOP_OS=darwin DESKTOP_ARCH=$(DESKTOP_ARCH)

desktop-package-linux: ## Build the desktop app for Linux. Defaults to the host architecture; set DESKTOP_ARCH=... to override.
	$(MAKE) desktop-package DESKTOP_OS=linux DESKTOP_ARCH=$(DESKTOP_ARCH)
