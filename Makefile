BINARY := puppy-server
BIN_DIR := bin
BINARY_PATH := $(BIN_DIR)/$(BINARY)
CMD := ./cmd/puppy-server

GO ?= go
GOFLAGS ?=
PROJECT_GOFLAGS := -mod=vendor $(GOFLAGS)
CONFIG ?=

.DEFAULT_GOAL := build

.PHONY: build clean vendor test test-race test-cover run fmt vet check help

build: ## Build the puppy-server binary.
	@mkdir -p $(BIN_DIR)
	$(GO) build $(PROJECT_GOFLAGS) -trimpath -o $(BINARY_PATH) $(CMD)

clean: ## Remove generated binaries and coverage output.
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
