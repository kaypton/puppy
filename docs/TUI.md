# Puppy TUI

`puppy-tui` 是 `puppy-server` 的只读终端观测客户端。服务端通过 TLS gRPC 提供系统概览、完整连接历史、实时流量和结构化日志。

## 服务端配置

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

相对存储路径以 TOML 文件目录为基准。保留字段为 `0` 时不自动删除；连接行数限制只清理最旧的非活跃连接。

## 启动

```bash
make build tui-build
make run CONFIG=./config.toml

PUPPY_TUI_TOKEN='replace-with-a-long-random-token' \
  make tui-run ARGS="--endpoint https://127.0.0.1:50051 --ca-cert ./certs/server.pem"
```

不设置 `PUPPY_TUI_TOKEN` 时，客户端会隐藏输入 token。证书 SAN 与 endpoint 主机名不同时使用 `--server-name` 指定证书名称。

## 快捷键

| 按键 | 功能 |
|---|---|
| `1`–`4` | 概览、连接、流量、日志 |
| `j`/`k`、方向键、PageUp/PageDown | 移动或滚动 |
| `/` | 搜索连接或日志 |
| `f` / `s` | 连接状态筛选 / 时间排序 |
| `l` | 循环切换日志最低级别 |
| `Enter` / `Esc` | 打开 / 关闭连接详情 |
| `Space` | 暂停或恢复日志跟随 |
| `?` / `q` | 帮助 / 退出 |
