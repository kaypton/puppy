BINARY := puppy-server
TUI_BINARY := puppy-tui

# Build output reflects the host OS and Node-style architecture.
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
TUI_BINARY_NAME := $(TUI_BINARY)-$(HOST_OS)-$(HOST_ARCH)
TUI_BINARY_PATH := $(BIN_DIR)/$(TUI_BINARY_NAME)

# Rust workspace root (cargo invocations run from here).
RUST_DIR := rust
CARGO ?= cargo
CARGO_BUILD_TARGET_DIR := $(RUST_DIR)/target
CONFIG ?=

# Track all Rust sources so the binary rebuilds when any file changes.
RUST_SOURCES := $(shell find $(RUST_DIR) -type f \( -name '*.rs' -o -name 'Cargo.toml' -o -name 'Cargo.lock' \) 2>/dev/null)

.DEFAULT_GOAL := build

.PHONY: build tui-build clean test test-race test-cover run tui-run fmt vet check help \
	cargo-build cargo-run cargo-test cargo-clippy cargo-fmt-check

build: $(BINARY_PATH) ## Build the puppy-server binary.

# Cargo produces the server binary at <target_dir>/<profile>/puppy-server.
$(BINARY_PATH): $(RUST_SOURCES)
	@mkdir -p $(BIN_DIR)
	cd $(RUST_DIR) && $(CARGO) build --release --bin puppy-server
	cp $(CARGO_BUILD_TARGET_DIR)/release/puppy-server $(BINARY_PATH)

tui-build: $(TUI_BINARY_PATH) ## Build the puppy-tui binary.

$(TUI_BINARY_PATH): $(RUST_SOURCES)
	@mkdir -p $(BIN_DIR)
	cd $(RUST_DIR) && $(CARGO) build --release --bin puppy-tui
	cp $(CARGO_BUILD_TARGET_DIR)/release/puppy-tui $(TUI_BINARY_PATH)

clean: ## Remove generated binaries and coverage output.
	rm -rf $(BIN_DIR) coverage.out $(CARGO_BUILD_TARGET_DIR)

test: ## Run all Rust tests.
	cd $(RUST_DIR) && $(CARGO) test --workspace

test-race: ## Run all Rust tests. (Rust has no race detector; equivalent to `test`.)
	cd $(RUST_DIR) && $(CARGO) test --workspace

test-cover: ## Run all Rust tests and write coverage.out (requires cargo-llvm-cov).
	cd $(RUST_DIR) && $(CARGO) llvm-cov --workspace --lcov --output-path ../coverage.out

run: build ## Build and run with CONFIG=/path/to/puppy.toml.
	@test -n "$(CONFIG)" || (echo "CONFIG is required; use: make run CONFIG=/path/to/puppy.toml" >&2; exit 2)
	$(BINARY_PATH) --config "$(CONFIG)"

tui-run: ## Run puppy-tui; pass client flags with ARGS="...".
	cd $(RUST_DIR) && $(CARGO) run --bin puppy-tui -- $(ARGS)

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
