# Repository Guidelines

## Project Structure & Module Organization

This is a Go 1.24 HTTP CONNECT proxy. The executable entry point and Cobra/TOML configuration assembly live in `cmd/puppy-server/`. Reusable code is under `pkg/`: `httpproxy` provides the inbound frontend, `adapter/direct` and `adapter/httpproxy` provide outbound backends, `common` defines shared interfaces, and `shim` copies traffic between connections. Tests live beside their implementation as `*_test.go`. `config.toml` documents every supported option. Dependencies are committed under `vendor/`; generated binaries belong in `bin/` and must not be committed.

Each implementation owns its configuration. Add a `Type` constant, `Configuration` struct, and `Validate` method in the implementation package, then register its decoding and construction in `cmd/puppy-server/main.go`.

## Build, Test, and Development Commands

- `make build`: compile `bin/puppy-server` using vendored dependencies.
- `make run CONFIG=./config.toml`: build and run the local server.
- `make test`: run all unit and loopback integration tests.
- `make test-race`: run tests with the race detector.
- `make test-cover`: write coverage data to `coverage.out`.
- `make check`: run the standard test and vet checks.
- `make fmt`: format all Go packages.
- `make vendor`: resynchronize `vendor/` after module changes.
- `make clean`: remove binaries and coverage output.

## Coding Style & Naming Conventions

Use standard Go formatting and tabs; run `make fmt` before submitting. Package names are short and lowercase. Exported identifiers require concise GoDoc comments. Follow existing names such as `NewServer`, `NewBackend`, `ServerConfiguration`, and `TestConfigurationValidate`. Wrap errors with context using `%w`, and preserve cancellation through `context.Context`.

## Testing Guidelines

Tests use Go's standard `testing` package. Name tests `TestXxx_Behavior` or `TestXxx`; prefer table-driven cases for validation. Keep network tests bound to `127.0.0.1:0`, close listeners with `t.Cleanup`, and use bounded waits. There is no fixed coverage threshold, but new configuration types, validation branches, and connection behavior require tests. Run `make check` before opening a pull request.

## Commit & Pull Request Guidelines

Git history is unavailable in this checkout. Use short, imperative commit subjects, optionally scoped, for example `server: add SOCKS backend config`. Keep commits focused. Pull requests should explain behavior and configuration changes, link relevant issues, list verification commands, and update `config.toml` plus `vendor/` when applicable. Screenshots are unnecessary for this CLI service; include logs or sample TOML when they clarify behavior.

## Security & Configuration Tips

Never commit real proxy credentials. Treat `0.0.0.0` listeners and empty authentication fields as deliberate security choices. Preserve strict rejection of unknown TOML fields so configuration mistakes fail at startup.
