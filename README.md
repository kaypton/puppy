# Puppy

Puppy is a proxy server written in Rust. It supports three operating modes:

- **HTTP CONNECT proxy**: listens on a local HTTP(S) proxy port for browsers, CLI tools, and other HTTP-proxy-aware applications.
- **SOCKS5 proxy**: listens on a local SOCKS5 proxy port, with optional TLS and username/password authentication.
- **System-wide TUN proxy**: creates a virtual network interface and captures host TCP/UDP traffic for applications that do not support proxy settings.

All modes are assembled from named **frontend**, **backend**, and **shim** components in one TOML configuration file.

## Features

- HTTP CONNECT proxy with optional TLS and Basic Authentication
- Camouflage mode that makes unauthenticated requests resemble an ordinary web endpoint
- SOCKS5 proxy with optional SOCKS5-over-TLS and RFC 1929 authentication
- Upstream HTTP CONNECT and SOCKS5 proxy chaining, with optional upstream TLS
- System-wide TUN mode with TCP/UDP support and automatic route installation and restoration
- DNS redirection, including UDP-to-DNS-over-TCP conversion
- Read-only gRPC observability API and a Ratatui terminal dashboard
- Strict TOML validation that rejects unknown fields

## Build and install

Puppy requires Rust 1.95 or later. `rust/rust-toolchain.toml` pins the toolchain and `rust/Cargo.lock` locks dependency versions.

### Build the server

```bash
make build
```

The output filename includes the host OS and architecture:

- Linux x86_64: `bin/puppy-server-linux-x64`
- Linux aarch64: `bin/puppy-server-linux-arm64`
- macOS x86_64: `bin/puppy-server-darwin-x64`
- macOS Apple Silicon: `bin/puppy-server-darwin-arm64`

### Cross-compile the server

Install the desired Rust target and build from the workspace:

```bash
# Linux x86_64
rustup target add x86_64-unknown-linux-gnu
cd rust && cargo build --release --bin puppy-server --target x86_64-unknown-linux-gnu

# Linux arm64
rustup target add aarch64-unknown-linux-gnu
cd rust && cargo build --release --bin puppy-server --target aarch64-unknown-linux-gnu

# macOS x86_64
rustup target add x86_64-apple-darwin
cd rust && cargo build --release --bin puppy-server --target x86_64-apple-darwin

# macOS arm64 (Apple Silicon)
rustup target add aarch64-apple-darwin
cd rust && cargo build --release --bin puppy-server --target aarch64-apple-darwin
```

Artifacts are written to `rust/target/<target>/release/puppy-server`. Cross-OS builds generally require a compatible linker and sysroot.

### Build and run the TUI

`puppy-tui` is an independent Ratatui client that connects to `puppy-server` over gRPC. TLS and Bearer token authentication are both optional:

```bash
make tui-build
PUPPY_TUI_TOKEN='the configured token' \
  make tui-run ARGS="--endpoint https://127.0.0.1:50051 --ca-cert ./certs/proxy-cert.pem"
```

When `PUPPY_TUI_TOKEN` is unset, the client sends no authentication header. Use an `http://` endpoint for plaintext gRPC and `https://` for TLS. Use `--ca-cert` to trust a private CA and `--server-name` when the certificate name differs from the endpoint host. See [docs/TUI.md](docs/TUI.md) for details.

### Common Make targets

| Target | Description |
|---|---|
| `make build` | Build the server for the host OS and architecture |
| `make tui-build` | Build the TUI for the host OS and architecture |
| `make run CONFIG=./config.toml` | Build and run the server |
| `make tui-run ARGS="..."` | Run the TUI in development mode |
| `make test` | Run all Rust workspace tests |
| `make test-race` | Compatibility alias for the Rust test suite |
| `make test-cover` | Generate `coverage.out` with `cargo-llvm-cov` |
| `make check` | Run tests and Clippy |
| `make fmt` | Format all Rust crates |
| `make vet` | Run Clippy for all targets with warnings denied |
| `make clean` | Remove binaries, coverage data, and Rust build artifacts |
| `make help` | List available targets |

## Quick start

The root `config.toml` is a complete example. It starts a local HTTP proxy on `127.0.0.1:8848` with username `test` and password `test12345`.

```bash
make run CONFIG=./config.toml
# Or:
bin/puppy-server --config ./config.toml
```

Configure a client to use `http://test:test12345@127.0.0.1:8848`, for example:

```bash
curl -x http://test:test12345@127.0.0.1:8848 https://example.com
```

## Operating modes

The top-level `frontend = "..."` value selects one named frontend group.

### Local HTTP proxy to a direct connection

This is the usual setup for browsers and tools such as `curl`, `git`, and `pip`.

```toml
frontend = "local_http_proxy"

[frontends.local_http_proxy]
type = "httpproxy"
listen_address = "127.0.0.1"
listen_port = 8848
username = "test"
password = "test12345"
backend = "direct_out"
shim = "default_tunnel"

[backends.direct_out]
type = "direct"
```

### Local HTTP proxy to an upstream HTTP proxy

This adds local authentication, TLS, or camouflage in front of an upstream HTTP CONNECT proxy.

```toml
frontend = "local_http_proxy"

[frontends.local_http_proxy]
type = "httpproxy"
listen_address = "127.0.0.1"
listen_port = 8848
backend = "upstream_http_proxy"
shim = "default_tunnel"

[backends.upstream_http_proxy]
type = "httpproxy"
proxy_address = "10.0.0.2:3128"
username = ""
password = ""
tls = false
```

### Local HTTP proxy to an upstream SOCKS5 proxy

This forwards TCP connections through an upstream SOCKS5 proxy.

```toml
frontend = "local_http_proxy"

[frontends.local_http_proxy]
type = "httpproxy"
listen_address = "127.0.0.1"
listen_port = 8848
backend = "upstream_socks_proxy"
shim = "default_tunnel"

[backends.upstream_socks_proxy]
type = "socksproxy"
proxy_address = "10.0.0.2:1080"
username = ""
password = ""
tls = false
```

### Local SOCKS5 proxy

The SOCKS5 frontend supports CONNECT (TCP) and can use either a direct, HTTP CONNECT, or SOCKS5 backend.

```toml
frontend = "local_socks_proxy"

[frontends.local_socks_proxy]
type = "socksproxy"
listen_address = "127.0.0.1"
listen_port = 1080
username = "test"
password = "test12345"
backend = "direct_out"
shim = "default_tunnel"

[backends.direct_out]
type = "direct"
```

### System-wide TUN proxy to a direct connection

TUN mode captures host traffic through a virtual interface. It requires root privileges and supports macOS and Linux.

```toml
frontend = "local_tun"

[frontends.local_tun]
type = "tun"
ipv4_address = "10.0.0.1/24"
mtu = 1500
auto_route = true
udp_idle_timeout = 30
backends = ["direct_out"]
fallback = "direct_out"
shim = "default_tunnel"

[backends.direct_out]
type = "direct"
```

Start it with:

```bash
sudo bin/puppy-server --config ./config.toml
```

### System-wide TUN proxy to an upstream HTTP proxy

HTTP CONNECT carries TCP only, so unsupported UDP traffic uses the configured fallback. `dns_server` can convert UDP DNS queries to DNS-over-TCP before forwarding.

```toml
frontend = "local_tun"

[frontends.local_tun]
type = "tun"
ipv4_address = "10.0.0.1/24"
auto_route = true
backends = ["upstream_http_proxy"]
fallback = "direct_out"
dns_server = "1.1.1.1:53"
shim = "default_tunnel"

[backends.upstream_http_proxy]
type = "httpproxy"
proxy_address = "10.0.0.2:3128"

[backends.direct_out]
type = "direct"
```

### Mode selection

| Requirement | Frontend | Backend |
|---|---|---|
| Browser or CLI proxy with direct outbound access | `httpproxy` | `direct` |
| HTTP proxy client through upstream HTTP CONNECT | `httpproxy` | `httpproxy` |
| HTTP proxy client through upstream SOCKS5 | `httpproxy` | `socksproxy` |
| SOCKS5 client with direct outbound access | `socksproxy` | `direct` |
| SOCKS5 client through upstream HTTP CONNECT | `socksproxy` | `httpproxy` |
| SOCKS5 client through upstream SOCKS5 | `socksproxy` | `socksproxy` |
| System-wide proxy with TCP and UDP | `tun` | `direct` |
| System-wide proxy through upstream HTTP CONNECT | `tun` | `httpproxy` plus a `direct` fallback |
| System-wide proxy through upstream SOCKS5 | `tun` | `socksproxy` plus a `direct` fallback |

## Configuration reference

A configuration selects one named frontend and defines named component groups:

```toml
frontend = "local_http_proxy"

[frontends.<name>]
[backends.<name>]
[shims.<name>]
```

Every reference must resolve to an existing group. Unknown fields are rejected.

### HTTP proxy frontend

`[frontends.<name>]` with `type = "httpproxy"` supports:

| Field | Required | Description |
|---|---|---|
| `type` | Yes | Must be `httpproxy` |
| `listen_address` | Yes | Listener IP; use a bare IPv6 address such as `::1` |
| `listen_port` | Yes | Listener port, 1–65535 |
| `tls_cert_file`, `tls_key_file` | No | Enable HTTPS proxy mode; both must be provided together |
| `username`, `password` | No | Basic Authentication credentials; both must be set or both empty |
| `camouflage` | No | Return ordinary-looking errors for unauthenticated requests |
| `camouflage_method` | No | Currently only `return-404` |
| `backend` | Yes | Referenced backend group |
| `shim` | Yes | Referenced shim group |

### SOCKS5 frontend

`[frontends.<name>]` with `type = "socksproxy"` supports CONNECT (TCP):

| Field | Required | Description |
|---|---|---|
| `type` | Yes | Must be `socksproxy` |
| `listen_address`, `listen_port` | Yes | Listener address and port |
| `tls_cert_file`, `tls_key_file` | No | Enable non-standard SOCKS5-over-TLS; both must be provided together |
| `username`, `password` | No | RFC 1929 credentials; both must be set or both empty |
| `backend` | Yes | Referenced backend group |
| `shim` | Yes | Referenced shim group |

### TUN frontend

`[frontends.<name>]` with `type = "tun"` supports:

| Field | Required | Description |
|---|---|---|
| `device_name` | No | Interface name; empty lets the OS assign one |
| `ipv4_address`, `ipv6_address` | At least one | Interface address in CIDR form |
| `mtu` | No | Defaults to 1500 |
| `auto_route` | No | Installs split `/1` routes and bypasses the backend; defaults to `true` |
| `udp_idle_timeout` | No | UDP session idle timeout in seconds; defaults to 30 |
| `dns_server` | No | Redirect port 53 DNS traffic to an `IP:port` resolver |
| `backends` | One form required | Ordered backend group list |
| `backend` | One form required | Legacy single backend; mutually exclusive with `backends` |
| `fallback` | No | Used when all candidates reject the traffic type; defaults to built-in direct |
| `protocol_detect_timeout` | No | TCP protocol detection timeout in seconds; defaults to 1 |
| `protocol_detect_max_bytes` | No | Detection buffer limit; defaults to 16384 |
| `shim` | Yes | Referenced shim group |

### Backends

- `type = "direct"` connects directly and supports TCP and UDP.
- `type = "httpproxy"` forwards TCP through an upstream HTTP CONNECT proxy.
- `type = "socksproxy"` forwards TCP through an upstream SOCKS5 proxy.

HTTP and SOCKS5 proxy backends accept `proxy_address`, optional `username`/`password`, `tls`, `tls_ca_file`, `tls_server_name`, and test-only `tls_insecure_skip_verify`. TLS-specific fields apply only when `tls = true`; `tls_ca_file` and `tls_insecure_skip_verify` are mutually exclusive.

### Shim

`[shims.<name>]` accepts `buffer_size`, the per-direction copy buffer size. Zero or omission uses 32768 bytes; negative values are invalid.

### gRPC observability

`[grpc]` controls the read-only observability API. `tls_cert_file` and `tls_key_file` are optional but must be supplied together. `token` is also optional; an empty token disables Bearer authentication. Prefer TLS and authentication when binding outside a trusted local interface.

`[observability]` controls SQLite connection history, structured log storage, checkpoint frequency, and retention limits. A retention value of zero means unlimited retention.

## Generate development certificates

The repository includes a script that creates a development CA and server certificate:

```bash
scripts/generate-proxy-certs.sh
scripts/generate-proxy-certs.sh --output-dir ./certs \
  --dns proxy.example.com --ip 192.168.1.10 --days 365 --force
```

- The default SAN includes `DNS:localhost` and `IP:127.0.0.1`.
- Clients must trust the generated `certs/ca-cert.pem`.
- An IP used to connect must appear in the server certificate SAN.

## Platform support and permissions

| Mode | macOS | Linux | Windows | Privileges |
|---|---|---|---|---|
| HTTP CONNECT proxy | Yes | Yes | Yes | Unprivileged, except ports below 1024 |
| SOCKS5 proxy | Yes | Yes | Yes | Unprivileged, except ports below 1024 |
| TUN system proxy | Yes (`utun`) | Yes (`/dev/net/tun`) | No | Root required |

TUN mode modifies routes and restores them on exit. If another VPN or TUN owns more specific public routes, startup fails; disable the other VPN or set `auto_route = false` and manage compatible routes yourself.

On Linux, enabling both `auto_route` and `ipv4_address` uses `nft` to intercept DNS requests sent to `systemd-resolved` at `127.0.0.53:53`; `nft` must be installed.

## Security notes

- Binding to `0.0.0.0` and leaving authentication empty are deliberate security choices; use them only on controlled networks.
- Restrict configuration file permissions when credentials are present.
- Never commit real proxy credentials.
- Unknown TOML fields fail fast to expose spelling mistakes.
