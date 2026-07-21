# Repository Guidelines

## Project Structure & Module Organization

This is a Rust 1.95 proxy workspace. The executable and frontend/backend assembly live in `rust/crates/server/`. Reusable crates are under `rust/crates/`: `httpproxy-fe`, `socksproxy-fe`, and `tun` provide inbound frontends; `direct`, `httpproxy-be`, and `socksproxy-be` provide outbound backends; `puppy-core` contains shared traits, traffic copying, and statistics; and `config` owns strict TOML decoding. Tests live beside implementations or in each crate's `tests/` directory. `config.toml` documents supported options. Dependency versions are locked in `rust/Cargo.lock`; generated binaries belong in `bin/` and must not be committed.

Each implementation owns its runtime configuration. Add or update the corresponding serde configuration type in `rust/crates/config`, keep `#[serde(deny_unknown_fields)]`, and register construction in `rust/crates/server`.

## Build, Test, and Development Commands

- `make build`: compile `bin/puppy-server` using vendored dependencies.
- `make run CONFIG=./config.toml`: build and run the local server.
- `make test`: run all unit and loopback integration tests.
- `make test-race`: compatibility alias for the Rust test suite.
- `make test-cover`: write coverage data with `cargo-llvm-cov`.
- `make check`: run the full test suite and Clippy with warnings denied.
- `make fmt`: format all Rust crates.
- `make clean`: remove binaries and coverage output.

## Coding Style & Naming Conventions

Use rustfmt with the checked-in `rust/rustfmt.toml`; run `make fmt` before submitting. Crate and module names are short and lowercase. Public items require concise rustdoc comments. Prefer typed errors with `thiserror`, add context at subsystem boundaries, and preserve cancellation through Tokio cancellation tokens or task shutdown channels.

## Testing Guidelines

Tests use Rust's built-in test framework and Tokio for async cases. Prefer focused unit tests and table-style case loops for validation. Keep network tests bound to `127.0.0.1:0`, ensure tasks and listeners are shut down, and use bounded timeouts. New configuration types, validation branches, protocol behavior, and connection lifecycles require tests. Run `make check` and `make cargo-fmt-check` before opening a pull request.

## Commit & Pull Request Guidelines

Use short, imperative commit subjects, optionally scoped, for example `server: add SOCKS backend config`. Keep commits focused. Pull requests should explain behavior and configuration changes, link relevant issues, list verification commands, and update `config.toml` plus `rust/Cargo.lock` when dependencies change. Screenshots are unnecessary for this CLI service; include logs or sample TOML when they clarify behavior.

## Security & Configuration Tips

Never commit real proxy credentials. Treat `0.0.0.0` listeners and empty authentication fields as deliberate security choices. Preserve strict rejection of unknown TOML fields so configuration mistakes fail at startup. TUN integration tests may require root and can modify host routes; prefer virtual-device tests unless a real-host test is explicitly intended.
