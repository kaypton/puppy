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

# Rust workspace root (cargo invocations run from here).
RUST_DIR := rust
CARGO ?= cargo
CARGO_BUILD_TARGET_DIR := $(RUST_DIR)/target
CONFIG ?=

# Track all Rust sources so the binary rebuilds when any file changes.
RUST_SOURCES := $(shell find $(RUST_DIR) -type f \( -name '*.rs' -o -name 'Cargo.toml' -o -name 'Cargo.lock' \) 2>/dev/null)

DESKTOP_DIR := app/desktop/puppy
DESKTOP_ELECTRON_BIN := ./node_modules/.bin/electron-builder

# Desktop packaging defaults: target current host OS and architecture unless overridden.
# DESKTOP_ARCH is the electron-builder arch name: x64, arm64, armv7l, ia32.
# DESKTOP_RUST_ARCH maps it to the Rust target triple component.
DESKTOP_OS ?= $(HOST_OS)
DESKTOP_ARCH ?= $(HOST_ARCH)
ifeq ($(DESKTOP_ARCH),x64)
  DESKTOP_RUST_ARCH := x86_64
else ifeq ($(DESKTOP_ARCH),arm64)
  DESKTOP_RUST_ARCH := aarch64
else ifeq ($(DESKTOP_ARCH),armv7l)
  DESKTOP_RUST_ARCH := armv7
else ifeq ($(DESKTOP_ARCH),ia32)
  DESKTOP_RUST_ARCH := i686
else
  DESKTOP_RUST_ARCH := $(DESKTOP_ARCH)
endif

# Name the bundled binary with OS and arch (Node-style, e.g. puppy-server-linux-x64)
# so it matches process.platform/process.arch at runtime. The Rust binary is still
# compiled with the corresponding target triple (x64 -> x86_64, arm64 -> aarch64).
DESKTOP_SERVER_NAME := puppy-server-$(DESKTOP_OS)-$(DESKTOP_ARCH)
DESKTOP_SERVER_BIN := $(DESKTOP_DIR)/bin/$(DESKTOP_SERVER_NAME)
DESKTOP_RUST_TARGET := $(DESKTOP_RUST_ARCH)-$(if $(filter darwin,$(DESKTOP_OS)),apple-darwin,unknown-linux-gnu)

.DEFAULT_GOAL := build

.PHONY: build clean vendor test test-race test-cover run fmt vet check help \
	cargo-build cargo-run cargo-test cargo-clippy cargo-fmt-check \
	desktop-deps desktop-build desktop-package desktop-clean \
	desktop-package-mac desktop-package-linux

build: $(BINARY_PATH) ## Build the puppy-server binary.

# Cargo produces the server binary at <target_dir>/<profile>/puppy-server. We copy
# it to bin/puppy-server-<os>-<arch> so the Electron manager can resolve it.
$(BINARY_PATH): $(RUST_SOURCES)
	@mkdir -p $(BIN_DIR)
	cd $(RUST_DIR) && $(CARGO) build --release --bin puppy-server
	cp $(CARGO_BUILD_TARGET_DIR)/release/puppy-server $(BINARY_PATH)

clean: desktop-clean ## Remove generated binaries, coverage output, and desktop build artifacts.
	rm -rf $(BIN_DIR) coverage.out $(CARGO_BUILD_TARGET_DIR)

vendor: ## No-op: Rust uses Cargo.lock, not a vendored directory. Kept for compatibility.
	@echo "Rust workspace does not use vendoring; nothing to do"

test: ## Run all Rust tests.
	cd $(RUST_DIR) && $(CARGO) test --workspace

test-race: ## Run all Rust tests. (Rust has no race detector; equivalent to `test`.)
	cd $(RUST_DIR) && $(CARGO) test --workspace

test-cover: ## Run all Rust tests and write coverage.out (requires cargo-llvm-cov).
	cd $(RUST_DIR) && $(CARGO) llvm-cov --workspace --lcov --output-path ../coverage.out

run: build ## Build and run with CONFIG=/path/to/puppy.toml.
	@test -n "$(CONFIG)" || (echo "CONFIG is required; use: make run CONFIG=/path/to/puppy.toml" >&2; exit 2)
	$(BINARY_PATH) --config "$(CONFIG)"

fmt: ## Format all Rust crates.
	cd $(RUST_DIR) && $(CARGO) fmt

vet: ## Run clippy on all crates.
	cd $(RUST_DIR) && $(CARGO) clippy --workspace --all-targets -- -D warnings

check: test vet ## Run the standard validation suite (tests + clippy).

cargo-build: ## Forward to `cargo build`.
	cd $(RUST_DIR) && $(CARGO) build --workspace

cargo-run: ## Forward to `cargo run` (use -- ARGS to pass args, e.g. `make cargo-run -- --config x.toml`).
	cd $(RUST_DIR) && $(CARGO) run --bin puppy-server $(ARGS)

cargo-test: ## Forward to `cargo test`.
	cd $(RUST_DIR) && $(CARGO) test --workspace

cargo-clippy: ## Forward to `cargo clippy`.
	cd $(RUST_DIR) && $(CARGO) clippy --workspace --all-targets -- -D warnings

cargo-fmt-check: ## Forward to `cargo fmt --check`.
	cd $(RUST_DIR) && $(CARGO) fmt --check

help: ## Show available targets.
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z0-9_-]+:.*## / {printf "  %-18s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

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
$(DESKTOP_SERVER_BIN): $(RUST_SOURCES)
	@mkdir -p $(DESKTOP_DIR)/bin
	cd $(RUST_DIR) && $(CARGO) build --release --bin puppy-server --target $(DESKTOP_RUST_TARGET)
	cp $(CARGO_BUILD_TARGET_DIR)/$(DESKTOP_RUST_TARGET)/release/puppy-server $@

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
