# Puppy

Puppy 是一个用 Rust 编写的代理服务，支持三种工作模式：

- **HTTP CONNECT 代理**：在本地监听一个 HTTP(S) 代理端口，供浏览器、CLI 或任意支持 HTTP 代理的应用使用。
- **SOCKS5 代理**：在本地监听一个 SOCKS5 代理端口（可选 TLS 与用户名/密码认证），供支持 SOCKS5 的应用使用。
- **TUN 全局代理**：创建虚拟网卡接管整机 TCP/UDP 流量，适合不识别代理设置的应用或全局转发场景。

三种模式都通过一份 TOML 配置文件组装，可自由组合**前端 (frontend)**、**后端 (backend)**、**隧道 (shim)** 三类组件。

## 特性

- HTTP CONNECT 代理，可选 TLS（HTTPS 代理）与 Basic Auth 认证
- 伪装模式：未认证请求返回 404，使代理端口看起来像普通 Web 服务
- SOCKS5 代理，可选 TLS（SOCKS5-over-TLS）与 RFC 1929 用户名/密码认证
- 上游 HTTP CONNECT 代理链式转发（可选 TLS 到上游）
- 上游 SOCKS5 代理链式转发（可选 TLS 到上游）
- TUN 模式整机接管，支持 TCP/UDP，自动安装/恢复路由
- DNS 重定向：将 53 端口流量改发到指定解析器，UDP 查询自动转为 DNS-over-TCP
- 严格的 TOML 校验，未知字段直接报错，避免配置失误

## 安装与构建

需要 Rust 1.95+。仓库通过 `rust/rust-toolchain.toml` 固定工具链版本，依赖版本由 `rust/Cargo.lock` 锁定。

### 编译服务端二进制

```bash
make build              # 生成 bin/puppy-server-<os>-<arch>
```

`make build` 会根据当前宿主操作系统和架构生成带 OS/arch 后缀的二进制，例如：

- Linux x86_64 → `bin/puppy-server-linux-x64`
- Linux aarch64 → `bin/puppy-server-linux-arm64`
- macOS x86_64 → `bin/puppy-server-darwin-x64`
- macOS Apple Silicon → `bin/puppy-server-darwin-arm64`

### 交叉编译服务端二进制

交叉编译使用 Rust target triple。先通过 `rustup target add` 安装目标，再从 `rust/` 工作区构建：

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

交叉编译产物位于 `rust/target/<target>/release/puppy-server`。跨操作系统构建通常还需要对应的 linker/sysroot。

### 编译和运行 TUI

`puppy-tui` 是独立的 Ratatui 客户端，通过 gRPC 连接 `puppy-server`。TLS 与 Bearer Token 均为可选能力：

```bash
make tui-build
PUPPY_TUI_TOKEN='配置中的 token' make tui-run ARGS="--endpoint https://127.0.0.1:50051 --ca-cert ./certs/proxy-cert.pem"
```

未设置 `PUPPY_TUI_TOKEN` 时客户端不发送认证头。明文服务使用 `http://`；TLS 服务使用 `https://`，自签名证书通过 `--ca-cert` 显式信任，证书名称不一致时可补充 `--server-name`。

### 常用 Make 目标速查

| 目标 | 说明 |
|------|------|
| `make build` | 编译当前宿主 OS/arch 的服务端二进制 |
| `make tui-build` | 编译当前宿主 OS/arch 的 TUI 二进制 |
| `make run CONFIG=./config.toml` | 编译并运行服务端 |
| `make tui-run ARGS="..."` | 开发模式运行 TUI |
| `make test` | 运行 Rust 工作区全部测试 |
| `make test-race` | 运行 Rust 工作区全部测试（兼容别名） |
| `make test-cover` | 使用 `cargo-llvm-cov` 生成 `coverage.out` |
| `make check` | 运行测试与 Clippy |
| `make fmt` | 格式化所有 Rust crate |
| `make vet` | 对所有 target 运行 Clippy 并拒绝警告 |
| `make clean` | 清理 `bin/`、`coverage.out` 和 Rust 构建产物 |
| `make help` | 列出所有可用目标 |

## 快速开始

仓库根目录的 `config.toml` 是一份完整示例，默认启用本地 HTTP 代理（`127.0.0.1:8848`，用户名 `test`，密码 `test12345`）。

```bash
make run CONFIG=./config.toml
# 或者
bin/puppy-server --config ./config.toml
```

然后让客户端使用 `http://test:test12345@127.0.0.1:8848` 作为 HTTP 代理即可。例如：

```bash
curl -x http://test:test12345@127.0.0.1:8848 https://example.com
```

## 运行模式与适用场景

配置文件顶部的 `frontend = "..."` 决定启动哪个前端组。下面列出四种典型组合。

### 1. 本地 HTTP 代理 → 直连

最常用。本机或局域网客户端把 puppy 当作普通 HTTP 代理，puppy 直接连接目标。

适用场景：

- 给浏览器、`curl`、`git`、`pip` 等支持 HTTP 代理的工具统一出口
- 在公司内网/家庭网络提供带认证的共享代理
- 对外开放时配合 TLS + 认证，避免明文暴露凭据

```toml
frontend = "local_http_proxy"

[frontends.local_http_proxy]
type            = "httpproxy"
listen_address  = "127.0.0.1"   # 对外开放改为 0.0.0.0
listen_port     = 8848
username        = "test"
password        = "test12345"
backend         = "direct_out"
shim            = "default_tunnel"

[backends.direct_out]
type = "direct"
```

### 2. 本地 HTTP 代理 → 上游 HTTP 代理

puppy 在客户端与上游 HTTP 代理之间再加一层，可在本地加 TLS、认证或伪装。

适用场景：

- 上游是公司/学校强制使用的 HTTP 代理，但你想在本地用不带认证的工具
- 想给上游代理连接套上 TLS（`https_proxy=https://...`）
- 用伪装模式隐藏上游代理的存在

```toml
frontend = "local_http_proxy"

[frontends.local_http_proxy]
type            = "httpproxy"
listen_address  = "127.0.0.1"
listen_port     = 8848
backend         = "upstream_http_proxy"
shim            = "default_tunnel"

[backends.upstream_http_proxy]
type          = "httpproxy"
proxy_address = "10.0.0.2:3128"
username      = ""        # 上游如需认证再填
password      = ""
tls           = false     # 上游支持 HTTPS 时设为 true
```

### 3. 本地 HTTP 代理 → 上游 SOCKS5 代理

puppy 在客户端与上游 SOCKS5 代理之间再加一层，可在本地加 TLS、认证或伪装。仅支持 TCP（SOCKS5 CONNECT）。

适用场景：

- 上游是公司/学校提供的 SOCKS5 代理，但你想在本地用不带认证的工具
- 想给上游 SOCKS5 连接套上 TLS（自建上游时）
- 用伪装模式隐藏上游代理的存在

```toml
frontend = "local_http_proxy"

[frontends.local_http_proxy]
type            = "httpproxy"
listen_address  = "127.0.0.1"
listen_port     = 8848
backend         = "upstream_socks_proxy"
shim            = "default_tunnel"

[backends.upstream_socks_proxy]
type          = "socksproxy"
proxy_address = "10.0.0.2:1080"
username      = ""        # 上游如需认证再填
password      = ""
tls           = false     # 上游为 TLS 端口时设为 true
```

### 4. 本地 SOCKS5 代理 → 直连

本机或局域网客户端把 puppy 当作普通 SOCKS5 代理，puppy 直接连接目标。仅支持 TCP（CONNECT）。

适用场景：

- 给支持 SOCKS5 的浏览器、CLI（`curl --socks5`）、IM 等工具统一出口
- 部分应用只支持 SOCKS5 而不支持 HTTP 代理
- 对外开放时配合 TLS + 认证，避免明文暴露凭据

```toml
frontend = "local_socks_proxy"

[frontends.local_socks_proxy]
type            = "socksproxy"
listen_address  = "127.0.0.1"   # 对外开放改为 0.0.0.0
listen_port     = 1080
username        = "test"
password        = "test12345"
backend         = "direct_out"
shim            = "default_tunnel"

[backends.direct_out]
type = "direct"
```

### 5. 本地 SOCKS5 代理 → 上游代理

puppy 在客户端与上游代理之间再加一层，可在本地加 TLS、认证。上游可以是 HTTP CONNECT 代理或 SOCKS5 代理；仅支持 TCP。

适用场景：

- 上游是公司/学校强制使用的代理，但你想在本地用不带认证的工具
- 想给上游代理连接套上 TLS
- 客户端只支持 SOCKS5，但上游只提供 HTTP 代理（或反之），由 puppy 做协议转换

```toml
frontend = "local_socks_proxy"

[frontends.local_socks_proxy]
type            = "socksproxy"
listen_address  = "127.0.0.1"
listen_port     = 1080
backend         = "upstream_http_proxy"   # 或 "upstream_socks_proxy"
shim            = "default_tunnel"

[backends.upstream_http_proxy]
type          = "httpproxy"
proxy_address = "10.0.0.2:3128"
```

### 6. TUN 全局代理 → 直连

puppy 创建虚拟网卡接管整机流量，按系统默认路由表直连目标。**需要 root 权限**，仅支持 macOS 与 Linux。

适用场景：

- 不识别 HTTP 代理的应用（某些游戏、命令行工具、移动模拟器）
- 整机透明代理，无需逐个应用配置
- 需要 UDP 转发（HTTP CONNECT 代理只支持 TCP）

```toml
frontend = "local_tun"

[frontends.local_tun]
type             = "tun"
ipv4_address     = "10.0.0.1/24"
mtu              = 1500
auto_route       = true
udp_idle_timeout = 30
backends         = ["direct_out"]
fallback         = "direct_out"
shim             = "default_tunnel"

[backends.direct_out]
type = "direct"
```

启动：

```bash
sudo bin/puppy-server --config ./config.toml
```

### 7. TUN 全局代理 → 上游 HTTP 代理

整机流量经上游 HTTP 代理转发。注意：HTTP CONNECT 只能承载 TCP，UDP 会落到 `fallback`（通常配置为 `direct` 直连）。

适用场景：

- 上游仅提供 HTTP 代理，但希望整机 TCP 流量都走它
- 配合 `dns_server` 把 UDP DNS 转为 DNS-over-TCP 后通过上游代理转发

```toml
frontend = "local_tun"

[frontends.local_tun]
type         = "tun"
ipv4_address = "10.0.0.1/24"
auto_route   = true
backends     = ["upstream_http_proxy"]   # TCP 走上游
fallback     = "direct_out"              # UDP 与不支持流量直连
dns_server   = "1.1.1.1:53"              # 可选：重定向 DNS 到 1.1.1.1
shim         = "default_tunnel"

[backends.upstream_http_proxy]
type          = "httpproxy"
proxy_address = "10.0.0.2:3128"

[backends.direct_out]
type = "direct"
```

### 模式选择速查

| 需求 | frontend | backend |
|------|----------|---------|
| 浏览器/curl 等使用，直连目标 | `httpproxy` | `direct` |
| 浏览器/curl 等使用，走上游 HTTP 代理 | `httpproxy` | `httpproxy` |
| 浏览器/curl 等使用，走上游 SOCKS5 代理 | `httpproxy` | `socksproxy` |
| 支持 SOCKS5 的应用使用，直连目标 | `socksproxy` | `direct` |
| 支持 SOCKS5 的应用使用，走上游 HTTP 代理 | `socksproxy` | `httpproxy` |
| 支持 SOCKS5 的应用使用，走上游 SOCKS5 代理 | `socksproxy` | `socksproxy` |
| 整机透明代理，直连目标（含 UDP） | `tun` | `direct` |
| 整机透明代理，走上游 HTTP 代理（仅 TCP） | `tun` | `httpproxy` + `direct` fallback |
| 整机透明代理，走上游 SOCKS5 代理（仅 TCP） | `tun` | `socksproxy` + `direct` fallback |

## 配置说明

配置文件由顶层选择项和三组命名块组成：

```toml
frontend = "local_http_proxy"      # 必填：选择启动哪个前端组

[frontends.<名称>]                  # 前端：决定如何接收客户端流量
[backends.<名称>]                   # 后端：决定如何连接最终目标
[shims.<名称>]                      # 隧道：前后端之间的双向字节流参数
```

前端和后端通过 `type` 字段选择实现，通过名称互相引用。所有引用必须存在，未知字段会被拒绝。

### 顶层

| 字段 | 说明 |
|------|------|
| `frontend` | 必填。要启动的前端组名称，必须出现在 `[frontends.*]` 中。 |

### `[frontends.<名称>]` —— `type = "httpproxy"`

| 字段 | 必填 | 说明 |
|------|------|------|
| `type` | 是 | 固定为 `httpproxy` |
| `listen_address` | 是 | 监听 IP。`127.0.0.1` 仅本机；`0.0.0.0` 接受外部连接。IPv6 写裸地址，如 `::1` 或 `2001:db8::1` |
| `listen_port` | 是 | 监听端口，1–65535 |
| `tls_cert_file` | 否 | 启用 HTTPS 代理时填证书文件路径，需与 `tls_key_file` 同时配置 |
| `tls_key_file` | 否 | 启用 HTTPS 代理时填私钥文件路径 |
| `username` | 否 | Basic Auth 用户名，必须与 `password` 同时填写或同时留空 |
| `password` | 否 | Basic Auth 密码 |
| `camouflage` | 否 | `true` 时启用伪装，未认证的普通请求返回 404，未认证的 CONNECT 返回 405 |
| `camouflage_method` | 否 | 伪装方式，目前仅支持 `return-404`（默认） |
| `backend` | 是 | 引用的后端组名称 |
| `shim` | 是 | 引用的隧道组名称 |

### `[frontends.<名称>]` —— `type = "socksproxy"`

SOCKS5 代理前端，仅支持 CONNECT 命令（TCP）。认证方式为 RFC 1929 用户名/密码或无认证。

| 字段 | 必填 | 说明 |
|------|------|------|
| `type` | 是 | 固定为 `socksproxy` |
| `listen_address` | 是 | 监听 IP。`127.0.0.1` 仅本机；`0.0.0.0` 接受外部连接。IPv6 写裸地址，如 `::1` 或 `2001:db8::1` |
| `listen_port` | 是 | 监听端口，1–65535 |
| `tls_cert_file` | 否 | 启用 SOCKS5-over-TLS 时填证书文件路径，需与 `tls_key_file` 同时配置 |
| `tls_key_file` | 否 | 启用 SOCKS5-over-TLS 时填私钥文件路径 |
| `username` | 否 | RFC 1929 用户名，必须与 `password` 同时填写或同时留空 |
| `password` | 否 | RFC 1929 密码 |
| `backend` | 是 | 引用的后端组名称 |
| `shim` | 是 | 引用的隧道组名称 |

### `[frontends.<名称>]` —— `type = "tun"`

| 字段 | 必填 | 说明 |
|------|------|------|
| `type` | 是 | 固定为 `tun` |
| `device_name` | 否 | 虚拟网卡名。留空由系统分配（macOS `utunN`，Linux `tunN`） |
| `ipv4_address` | 二选一 | TUN 网卡 IPv4 地址，CIDR 格式，如 `10.0.0.1/24` |
| `ipv6_address` | 二选一 | TUN 网卡 IPv6 地址，CIDR 格式 |
| `mtu` | 否 | MTU，留空或 0 使用 1500 |
| `auto_route` | 否 | `true`（默认）自动安装 `/1` 分流路由并绕行 backend；`false` 时需自行管理路由 |
| `udp_idle_timeout` | 否 | UDP 会话空闲超时秒数，默认 30 |
| `dns_server` | 否 | 重定向 53 端口 DNS 到此解析器（`IP:port` 格式，不接受主机名） |
| `backends` | 是* | 候选后端组名称列表，按优先级匹配 |
| `backend` | 是* | 旧式单后端，与 `backends` 互斥 |
| `fallback` | 否 | 所有候选后端都不支持当前流量时使用，默认内置 direct |
| `protocol_detect_timeout` | 否 | TCP 协议探测最长等待秒数，默认 1 |
| `protocol_detect_max_bytes` | 否 | TCP 协议探测最大缓存字节数，默认 16384 |
| `shim` | 是 | 引用的隧道组名称 |

`backends` 与 `backend` 必须二选一。

### `[backends.<名称>]` —— `type = "direct"`

直连目标，无额外配置。支持 TCP 与 UDP。

```toml
[backends.direct_out]
type = "direct"
```

### `[backends.<名称>]` —— `type = "httpproxy"`

通过上游 HTTP CONNECT 代理转发。仅支持 TCP。

| 字段 | 必填 | 说明 |
|------|------|------|
| `type` | 是 | 固定为 `httpproxy` |
| `proxy_address` | 是 | 上游代理地址，`host:port` 格式（IPv6 用 `[::1]:3128`） |
| `username` | 否 | 上游 Basic Auth 用户名，必须与 `password` 同时填写或同时留空 |
| `password` | 否 | 上游 Basic Auth 密码 |
| `tls` | 否 | `true` 时通过 TLS 连接上游（即 `https_proxy=https://...`） |
| `tls_ca_file` | 否 | 校验上游证书的 CA 文件（PEM），默认系统根证书；与 `tls_insecure_skip_verify` 互斥 |
| `tls_server_name` | 否 | 覆盖 TLS SNI 与证书校验名 |
| `tls_insecure_skip_verify` | 否 | `true` 跳过证书校验，仅用于测试；与 `tls_ca_file` 互斥 |

`tls_*` 字段仅在 `tls = true` 时有效。

### `[backends.<名称>]` —— `type = "socksproxy"`

通过上游 SOCKS5 代理转发（CONNECT）。仅支持 TCP；认证方式为 RFC 1929 用户名/密码或无认证。

| 字段 | 必填 | 说明 |
|------|------|------|
| `type` | 是 | 固定为 `socksproxy` |
| `proxy_address` | 是 | 上游代理地址，`host:port` 格式（IPv6 用 `[::1]:1080`） |
| `username` | 否 | 上游 SOCKS5 用户名，必须与 `password` 同时填写或同时留空 |
| `password` | 否 | 上游 SOCKS5 密码 |
| `tls` | 否 | `true` 时通过 TLS 连接上游 SOCKS5 代理 |
| `tls_ca_file` | 否 | 校验上游证书的 CA 文件（PEM），默认系统根证书；与 `tls_insecure_skip_verify` 互斥 |
| `tls_server_name` | 否 | 覆盖 TLS SNI 与证书校验名 |
| `tls_insecure_skip_verify` | 否 | `true` 跳过证书校验，仅用于测试；与 `tls_ca_file` 互斥 |

`tls_*` 字段仅在 `tls = true` 时有效。

### `[shims.<名称>]`

隧道可被多个前端复用。

| 字段 | 必填 | 说明 |
|------|------|------|
| `buffer_size` | 否 | 隧道双向复制的每方向缓冲区字节数，0 或留空使用默认 32768，负数无效 |

## 生成 HTTPS 代理证书

启用 `tls_cert_file` / `tls_key_file` 时需要一对 PEM 证书与私钥。仓库自带脚本可生成本地开发用 CA 与服务器证书：

```bash
scripts/generate-proxy-certs.sh                    # 默认输出到 ./certs
scripts/generate-proxy-certs.sh --output-dir ./certs \
    --dns proxy.example.com --ip 192.168.1.10 --days 365 --force
```

- 默认 SAN 包含 `DNS:localhost` 与 `IP:127.0.0.1`
- 客户端需信任生成的 `certs/ca-cert.pem`
- 通过 IP 连接时，该 IP 必须在服务器证书 SAN 中

然后配置：

```toml
[frontends.local_http_proxy]
tls_cert_file = "./certs/proxy-cert.pem"
tls_key_file  = "./certs/proxy-key.pem"
```

## 命令参考

```bash
bin/puppy-server --config ./config.toml     # 启动（-c 是 --config 的简写）
```

开发与测试：

```bash
make build           # 编译当前宿主 OS/arch 的 bin/puppy-server-<os>-<arch>
make tui-build       # 编译 bin/puppy-tui-<os>-<arch>
make run CONFIG=./config.toml   # 编译并运行
make tui-run ARGS="--endpoint https://127.0.0.1:50051 --ca-cert ./certs/proxy-cert.pem"
make test            # 单元测试与回环集成测试
make test-race       # 全工作区测试（兼容别名）
make test-cover      # 通过 cargo-llvm-cov 输出 coverage.out
make check           # 测试 + Clippy
make fmt             # rustfmt 格式化
make clean           # 清理 bin/、coverage.out 和 Rust 构建产物
```


## 平台支持与权限

| 模式 | macOS | Linux | Windows | 权限 |
|------|-------|-------|---------|------|
| HTTP CONNECT 代理 | ✅ | ✅ | ✅ | 普通用户（绑定 <1024 端口需 root） |
| TUN 全局代理 | ✅ (`utun`) | ✅ (`/dev/net/tun`) | ❌ | **必须 root** |

TUN 模式启动会修改系统路由，**退出时会自动恢复**。若机器已有其他 VPN/TUN 通过更具体路由接管公网，启动会失败，请先关闭或设置 `auto_route = false` 自行管理兼容路由。

Linux 上同时启用 `auto_route` 与 `ipv4_address` 时，会使用 `nft` 拦截发往 `systemd-resolved`（`127.0.0.53:53`）的 DNS 查询，需要系统已安装 `nft`。

## 注意事项

- `0.0.0.0` 监听与空认证字段是**有意为之的安全选择**，请仅在受控网络使用
- 启用认证时，请限制配置文件读取权限，避免凭据泄露
- **不要提交真实代理凭据**到版本库
- 配置文件中的未知字段会直接报错，方便排查拼写错误
