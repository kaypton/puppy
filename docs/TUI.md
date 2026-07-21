# Puppy TUI

`puppy-tui` is a read-only terminal observability client for `puppy-server`. The server exposes its overview, complete connection history, real-time traffic, and structured logs over gRPC. TLS and Bearer token authentication can be enabled or disabled independently.

## Server configuration

```toml
[grpc]
enabled = true
listen_address = "127.0.0.1"
listen_port = 50051
tls_cert_file = "./certs/server.pem"
tls_key_file = "./certs/server-key.pem"
token = "replace-with-a-long-random-token"

[observability]
database_path = "./data/puppy-observability.sqlite3"
log_directory = "./logs"
checkpoint_interval_ms = 1000
connection_retention_days = 0
connection_max_rows = 0
log_retention_days = 0
log_max_total_bytes = 0
```

Relative storage paths are resolved from the TOML file's directory. A retention value of `0` disables automatic deletion; the connection row limit removes only the oldest inactive connections.

`tls_cert_file` and `tls_key_file` must be supplied together. Omitting both enables plaintext gRPC. An empty `token` disables Bearer authentication. Disable both only on a trusted interface such as `127.0.0.1`.

## Start the server and TUI

```bash
make build tui-build
make run CONFIG=./config.toml

PUPPY_TUI_TOKEN='replace-with-a-long-random-token' \
  make tui-run ARGS="--endpoint https://127.0.0.1:50051 --ca-cert ./certs/server.pem"
```

When `PUPPY_TUI_TOKEN` is unset, the client sends no authentication header. Use an `http://` endpoint for plaintext gRPC and `https://` for TLS. Use `--server-name` when the certificate SAN does not match the endpoint host.

## Keyboard shortcuts

| Key | Action |
|---|---|
| `1`–`4` | Open Overview, Connections, Traffic, or Logs |
| `j`/`k`, arrow keys, PageUp/PageDown | Move or scroll |
| `/` | Search connections or logs |
| `f` / `s` | Filter connection status / change time sort order |
| `l` | Cycle the minimum log level |
| `Enter` / `Esc` | Open / close connection details |
| `Space` | Pause or resume log following |
| `?` / `q` | Open help / quit |
