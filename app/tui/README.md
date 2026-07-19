# puppy-tui

puppy-server 的终端 UI 仪表盘，通过 [docs/HTTP-API.md](../../docs/HTTP-API.md) 定义的 HTTP API 与运行中的 puppy-server 交互。

基于 [ratatui](https://ratatui.rs/) + crossterm + tokio + reqwest。

## 功能

| 页面 | 数据来源 | 说明 |
|------|----------|------|
| 系统概览 | `GET /system` | API/Go 版本、PID、启动时间、uptime、活跃连接、SSE 订阅者 |
| 统计 | `GET /stats` | 累计/活跃连接、拨号成功/失败、入/出字节、拨号成功率 |
| 连接 | `GET /connections` | 活跃连接表格（id/frontend/remote/target/proto/bytes/时长） |
| Frontends | `GET /frontends` | 已配置的 frontend 列表 |
| Backends | `GET /backends` | 已配置的 backend 及能力 |
| 配置 | `GET /config` | 脱敏后的运行时配置 JSON（可滚动） |
| 事件 | `GET /events` (SSE) | 实时生命周期事件流（connect/disconnect/dial_failed/config_reloaded/...） |

- 数据页每 5 秒自动轮询（对齐 Electron 桌面版）
- SSE 事件流实时推送，断线自动重连（指数退避）
- 全局连接状态指示（在线/离线），传输层错误自动标离线

## 构建

```bash
cd app/tui
make build       # cargo build --release → target/release/puppy-tui
```

## 运行

```bash
puppy-tui --server https://127.0.0.1:8443 --token <TOKEN> -k
```

参数：

| 参数 | 说明 |
|------|------|
| `--server <URL>` | Dashboard API 基础 URL，默认 `https://127.0.0.1:8443` |
| `--token <TOKEN>` | Bearer 认证 token；服务端未配置 token 时可省略 |
| `-k, --ignore-tls` | 跳过 TLS 证书校验（自签证书场景） |

示例（本机自签证书 + token）：

```bash
puppy-tui --server https://127.0.0.1:8443 --token puppy-dashboard-secret -k
```

## 按键

| 键 | 功能 |
|----|------|
| `q` / `Ctrl-C` | 退出 |
| `Tab` / `→` | 下一页 |
| `Shift-Tab` / `←` | 上一页 |
| `1`–`7` | 直接跳到对应页 |
| `r` | 立即刷新所有数据 |
| `R` | 触发服务端 `POST /config/reload`（结果通过事件流推送） |
| `j` / `↓` | 连接页下移选中；配置/事件页向下滚动 |
| `k` / `↑` | 连接页上移选中；配置/事件页向上滚动 |
| `PgUp` / `PgDn` | 配置/事件页翻页滚动 |
| `g` / `Home` | 配置/事件页回到顶部 |
| `G` / `End` | 事件页回到底部（恢复跟随最新事件） |

## 开发

```bash
make check       # cargo test + cargo clippy -- -D warnings + cargo fmt --check
make fmt         # cargo fmt
```

## 与 Electron 桌面版的关系

`app/desktop/puppy` 是 Electron 图形界面；本 crate 是它的终端等价物，面向 SSH/无图形环境下的运维场景。两者共享同一套 HTTP API，字段与展示逻辑保持一致（轮询间隔、成功率阈值、格式化规则等）。
