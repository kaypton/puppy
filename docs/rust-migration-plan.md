# Puppy Go-to-Rust Migration Plan (Historical Archive)

> This document records the original migration strategy. The migration is complete, the Go implementation has been removed, and the Electron/HTTP dashboard described by the early plan has been replaced by Ratatui and a read-only gRPC observability API. This is historical context, not an active implementation checklist.

## 1. Original objective

The migration replaced the Go proxy server with a Rust workspace while preserving the service's externally visible behavior:

1. Keep the `bin/puppy-server-<os>-<arch>` naming convention and the `--config` / `-c` CLI argument.
2. Preserve strict TOML decoding and reject unknown fields at startup.
3. Preserve HTTP CONNECT, SOCKS5, direct outbound, upstream proxy, and TUN behavior.
4. Retain authentication, TLS, camouflage, DNS-over-TCP, automatic route restoration, Linux DNS interception, protocol detection, and egress binding.
5. Port the important unit and loopback integration tests.

The desktop dashboard was initially out of scope. It was later retired entirely in favor of `puppy-tui` and gRPC observability.

## 2. Technology choices

| Purpose | Selected Rust technology |
|---|---|
| Async runtime | Tokio multi-threaded runtime |
| TOML | `toml` and Serde with `#[serde(deny_unknown_fields)]` |
| CLI | Clap derive |
| Logging | `tracing` and `tracing-subscriber` |
| TLS | Rustls, Tokio Rustls, and `rustls-pemfile` |
| HTTP parsing | `httparse` |
| Authentication helpers | `base64` and constant-time comparison |
| System calls | `nix` and `libc` |
| Socket control | `socket2` |
| Errors | `thiserror` in libraries and `anyhow` at application boundaries |

The workspace uses a pinned Rust toolchain, rustfmt with hard tabs, and Clippy with warnings denied.

## 3. Workspace architecture

The completed workspace lives under `rust/`:

```text
rust/
├── Cargo.toml
├── Cargo.lock
├── rust-toolchain.toml
├── rustfmt.toml
└── crates/
    ├── config/
    ├── puppy-core/
    ├── direct/
    ├── httpproxy-fe/
    ├── httpproxy-be/
    ├── socksproxy-fe/
    ├── socksproxy-be/
    ├── tun/
    ├── puppy-rpc/
    ├── puppy-tui/
    └── server/
```

The server assembles configuration, frontend, backend, tunnel, observability, and lifecycle components. Shared protocol abstractions, traffic copying, and statistics live in `puppy-core`.

## 4. Historical migration phases

### Phase 0: workspace and build pipeline

- Create the Cargo workspace and crate skeletons.
- Preserve Make target names while changing their implementation to Cargo.
- Preserve host OS/architecture mapping for generated binaries.
- Add the Clap server entry point and formatting/lint configuration.

### Phase 1: configuration

- Model every runtime configuration with Serde.
- Apply `deny_unknown_fields` to all configuration structures.
- Validate references, field combinations, addresses, ports, and credentials.
- Resolve relative paths from the configuration file's directory.
- Port validation tests and exact error cases.

### Phase 2: core abstractions and traffic shim

- Define targets, protocols, capabilities, backend traits, and dialer traits.
- Implement SOCKS5 address encoding and decoding.
- Implement byte-counted asynchronous streams.
- Implement shared statistics and connection tracking.
- Implement cancellation-aware bidirectional traffic copying.

### Phase 3: direct backend

- Resolve and connect directly to requested targets.
- Bind outbound sockets to the physical egress interface when required by TUN mode.
- Classify timeouts, DNS failures, refused connections, and interface binding failures.
- Cover success and failure behavior with loopback tests.

### Phase 4: upstream HTTP CONNECT backend

- Connect to an upstream HTTP proxy, optionally with TLS and authentication.
- Send and parse HTTP CONNECT handshakes.
- Reject non-successful upstream status responses.
- Hand established streams to the shared traffic shim.
- Test plaintext, TLS, credentials, status failures, and early disconnects.

### Phase 5: upstream SOCKS5 backend

- Negotiate SOCKS5 methods and optional RFC 1929 credentials.
- Encode target addresses and parse CONNECT replies.
- Support optional TLS to the upstream SOCKS5 endpoint.
- Test address variants, authentication, reply failures, and early disconnects.

### Phase 6: HTTP CONNECT frontend

- Accept plaintext or TLS client connections.
- Parse CONNECT requests with bounded header sizes.
- Enforce optional Basic Authentication and camouflage behavior.
- Resolve the selected backend and forward the accepted stream.
- Test authentication, methods, malformed requests, IPv6, and TLS.

### Phase 7: SOCKS5 frontend

- Negotiate no-authentication or RFC 1929 authentication.
- Parse CONNECT requests for IPv4, IPv6, and domain targets.
- Return protocol-correct failure replies for unsupported commands and malformed input.
- Support optional SOCKS5-over-TLS.
- Test all negotiation and address branches.

### Phase 8: server assembly

- Load and validate configuration.
- Initialize structured logging and shared statistics.
- Construct named backends and frontends.
- Run frontends as Tokio tasks and preserve cancellation during shutdown.
- Wait for connections within a bounded graceful-shutdown interval.

### Phase 9: TUN frontend

- Open macOS `utun` or Linux `/dev/net/tun` devices.
- Configure a userspace network stack and dispatch TCP/UDP traffic.
- Install split routes and restore them through lifecycle guards.
- Bind outbound sockets to the original physical egress.
- Redirect configured DNS traffic and convert UDP DNS to DNS-over-TCP.
- Install and remove Linux `nft` interception rules for `systemd-resolved` where needed.
- Separate unprivileged protocol tests from privileged host integration tests.

### Phase 10: integration and Go removal

- Exercise every frontend/backend combination with loopback tests.
- Verify route and firewall cleanup after TUN shutdown.
- Compare proxy throughput against the former implementation.
- Delete Go sources and dependencies only after Rust behavior is verified.
- Update repository documentation and build commands for the Rust-only workspace.

### Later observability work

The proposed Electron REST/SSE dashboard phase was not implemented as originally described. The current architecture instead provides:

- a read-only gRPC observability service in `puppy-server`;
- SQLite-backed connection history and structured log storage;
- live connection, traffic, and log streams;
- a Ratatui client in `rust/crates/puppy-tui`.

## 5. Cross-cutting constraints

- Keep configuration decoding strict.
- Keep binary names and CLI arguments stable.
- Bind network tests to `127.0.0.1:0` and shut down every listener and task.
- Preserve cancellation through Tokio cancellation tokens or task shutdown channels.
- Minimize `unsafe`; document the safety invariant at every unavoidable system-call boundary.
- Pin dependencies whose low-level APIs materially affect TUN behavior.
- Protect credentials and treat public listeners or empty authentication as explicit security choices.

## 6. Historical risks and mitigations

| Risk | Mitigation |
|---|---|
| Userspace network-stack behavior differs from the former implementation | Build packet and TCP loopback tests before privileged host tests |
| macOS TUN system calls lack high-level wrappers | Isolate and document minimal `libc` calls |
| Stale routes can disconnect the host | Use lifecycle guards, startup cleanup, and explicit shutdown verification |
| Linux DNS interception can leave firewall state | Use uniquely identified rules and test cleanup |
| Proxy throughput regresses | Benchmark representative large transfers and profile Tokio tasks |
| Configuration accepts misspelled fields | Require `deny_unknown_fields` and test injected unknown keys |
| Binary naming drifts | Keep mapping logic in the Makefile and assert expected artifact paths |

## 7. Completion record

The repository now uses Rust as its only server implementation. Current acceptance commands are:

```bash
make build
make test
make check
make cargo-fmt-check
```

For present-day architecture and configuration, use the root [README](../README.md), [TUI guide](TUI.md), and `config.toml` instead of this archive.
