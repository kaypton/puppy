# Puppy Go → Rust 重构执行计划（历史归档）

> 说明：本文记录初始迁移阶段，Electron 与 HTTP dashboard 相关内容已被 Ratatui + gRPC 可观测性实现取代，不再代表当前架构。

> 本文仅供理解历史迁移决策，不应作为当前实现任务清单。

## 0. 背景与目标

Puppy 当前是一个 Go 1.26 编写的 HTTP CONNECT / SOCKS5 / TUN 代理服务。本计划要求在不改动 `app/`（Electron 桌面应用）的前提下，把 `cmd/`、`pkg/`、`vendor/`、`go.mod`、`go.sum` 全部用 Rust 重写并最终删除。

**重构后必须保留的行为契约**：

1. `bin/puppy-server-<os>-<arch>` 二进制命名与启动参数（`--config / -c`）不变，因为 `app/desktop/puppy/src/main/server/manager.ts` 通过 `process.resourcesPath` + Node 风格的 `<os>-<arch>` 后缀定位二进制。
2. `config.toml` 的所有字段、语义、错误信息措辞不变；未知字段必须在启动时报错。
3. HTTP CONNECT frontend、SOCKS5 frontend、上游 HTTP/SOCKS5 backend、Direct backend、TUN frontend 的运行时行为（认证、TLS、伪装、UDP DNS-over-TCP 转换、auto_route 路由安装与恢复、nft DNS 拦截、协议探测、egress 接口绑定）必须与 Go 版完全对齐。
4. 桌面应用 `make desktop-package-mac` / `make desktop-package-linux` 仍能成功打包并运行。
5. 测试覆盖不得低于 Go 版关键场景（每个 `_test.go` 的 case 都要在 Rust 侧有对应覆盖）。

**显式排除范围**：

- `app/` 下的 Electron 代码不动。
- Dashboard（`pkg/dashboard/` + `cmd/puppy-server/providers.go` + `main.go` 中的 `frontendManager` / `handleControlRequest` / 控制通道）**一期不移植**。Rust 版启动后不监听 dashboard 端口，`config.toml` 中的 `[dashboard]` 段保留解析但忽略（或直接报"dashboard 暂未实现"），后续二期再用 `axum` 单独补齐。

## 1. 现有代码盘点（执行前必读）

仓库根目录运行 `find . -type f -name '*.go' -not -path './vendor/*' -not -path './app/*' | xargs wc -l`，总计约 **16,000 行**，其中约 50% 是测试。各模块行数与职责：

| Go 路径 | 行数（含测试） | 职责 | Rust 对应 |
|---|---|---|---|
| `pkg/common/backend.go` | 125 | `Target` / `Protocol` / `Capability` / `Backend` interface / `Dialer` interface | `puppy-core::backend` |
| `pkg/common/socks5.go` | 113+128 | SOCKS5 常量 + `ReadSOCKS5Address` | `puppy-core::socks5` |
| `pkg/common/counting/conn.go` | 70+168 | 字节计数 wrapper | `puppy-core::counting` |
| `pkg/common/stats/` | 138+155+151+445 | 全局计数器 / 连接注册表 / 事件总线 | `puppy-core::stats` |
| `pkg/shim/` | 16+100+74 | 双向字节流复制 | `puppy-core::shim` |
| `cmd/puppy-server/main.go` | 640+793 | 入口、配置加载、frontend 工厂（去 dashboard 后约 250 行） | `puppy-server` bin |
| `cmd/puppy-server/providers.go` | 138 | dashboard 数据 provider | **不移植** |
| `pkg/httpproxy/` | 79+104+292+163+413+774 | HTTP CONNECT frontend | `puppy-httpproxy-fe` |
| `pkg/socksproxy/` | 82+82+292+148+462+623 | SOCKS5 frontend | `puppy-socksproxy-fe` |
| `pkg/tunproxy/` | 32 文件，约 5,000 行 | TUN frontend（gVisor + 平台代码） | `puppy-tun` |
| `pkg/adapter/direct/` | 35+119 | direct backend | `puppy-direct` |
| `pkg/adapter/httpproxy/` | 199+596+… | 上游 HTTP CONNECT backend | `puppy-httpproxy-be` |
| `pkg/adapter/socksproxy/` | 309+887+… | 上游 SOCKS5 backend | `puppy-socksproxy-be` |
| `pkg/dashboard/` | 14 文件 | REST + SSE 管理 API | **一期不移植** |

**Go 版关键依赖**：`github.com/BurntSushi/toml`、`github.com/spf13/cobra`、`github.com/sagernet/gvisor`（仅 TUN 用）、`golang.org/x/sys`、`crypto/tls`、`net/http`。

## 2. 技术选型（强制）

| 用途 | Go | Rust（必须使用） | 备注 |
|---|---|---|---|
| 异步运行时 | goroutine + context | `tokio`（`rt-multi-thread`） | 不要用 async-std |
| TOML | `BurntSushi/toml` | `toml` + `serde`（`#[serde(deny_unknown_fields)]`） | 保留未知字段拒绝 |
| CLI | `spf13/cobra` | `clap`（derive） | `--config / -c` 必填 |
| 日志 | `log/slog` | `tracing` + `tracing-subscriber` | 保持结构化字段名一致 |
| TLS | `crypto/tls` | `rustls` + `tokio-rustls` + `rustls-pemfile` | 不要用 native-tls |
| HTTP 解析 | `net/http` | `httparse`（手动） | 仅用于 CONNECT 请求/响应行解析 |
| Base64 | `encoding/base64` | `base64` | |
| 常量时间比较 | `crypto/subtle` | `subtle` | Basic Auth / Bearer token / RFC 1929 |
| 随机 ID | `crypto/rand` | `rand` + `getrandom` | 连接 ID 生成 |
| 用户态 netstack | `sagernet/gvisor` | `smoltcp` | TUN 模式专用，无等价替代 |
| 系统 syscall | `golang.org/x/sys/unix` | `nix` + `libc` | macOS utun 需要 `libc` 裸调 |
| Socket 控制 | `net.Dialer.ControlContext` | `socket2` | egress 接口绑定 |
| 同步原语 | `sync` / `sync/atomic` | `parking_lot` + `std::sync::atomic` | |
| 错误 | `errors.Is/As` + `%w` | `thiserror`（库内）+ `anyhow`（bin 内） | |

**Rust 版本**：使用 stable 最新版，`rust-toolchain.toml` 锁定具体版本。Edition 2021。

**代码风格**：tab 缩进（与现有 Go 风格一致），`rustfmt.toml` + `clippy.toml` 配置为 `cargo clippy -- -D warnings` 必须通过。

## 3. 仓库结构

在仓库根新建 `rust/`，最终交付时 `cmd/`、`pkg/`、`vendor/`、`go.mod`、`go.sum` 删除，`rust/` 成为唯一的后端实现位置。`app/`、`scripts/`、`config.toml`、`docs/`、`Makefile` 保留并按需更新。

```
puppy/
├── app/                      # 不动
├── docs/
│   ├── HTTP-API.md           # 保留，二期实现
│   └── rust-migration-plan.md # 本文件
├── scripts/
│   └── generate-proxy-certs.sh # 不动
├── config.toml               # 保留，[dashboard] 段保留但被 Rust 版忽略
├── Makefile                  # 改写：build/run/test 默认走 cargo
└── rust/
    ├── Cargo.toml            # workspace
    ├── rust-toolchain.toml
    ├── rustfmt.toml
    ├── clippy.toml
    └── crates/
        ├── puppy-core/       # Target/Protocol/Capability/Backend trait/Dialer trait
        │                     # socks5 常量与 ReadSOCKS5Address
        │                     # stats（StatsRegistry/ConnectionRegistry/EventBus）
        │                     # counting::CountingConn
        │                     # shim::ShimServer
        ├── puppy-config/     # TOML 解析 + 校验 + frontend/backend 工厂枚举
        ├── puppy-direct/     # direct backend
        ├── puppy-httpproxy-fe/
        ├── puppy-socksproxy-fe/
        ├── puppy-httpproxy-be/
        ├── puppy-socksproxy-be/
        ├── puppy-tun/        # smoltcp + device_darwin/device_linux + route + egress + dispatch
        └── puppy-server/     # main bin
```

**crate 依赖方向**：`puppy-server` → `puppy-config` → 各 frontend/backend crate → `puppy-core`。`puppy-core` 不依赖任何业务 crate。

## 4. 阶段拆解

共 11 个阶段，前 10 个为一期必交付，Phase 11 为二期可选。每个阶段都给出：对应 Go 源码、实现要点、测试要求、验收标准。阶段之间允许并行验证，但 **Phase 编号代表交付顺序**，不得跳序。

### Phase 0 — 脚手架与构建链路

**对应 Go 源码**：`Makefile`、`go.mod`、`cmd/puppy-server/main.go`（仅入口骨架）。

**实现要点**：

1. 在 `rust/` 下创建 Cargo workspace，`Cargo.toml` 声明上述 9 个成员 crate（先建空 lib/bin）。
2. 写 `rust-toolchain.toml` 锁定 stable 版本。
3. 写 `rustfmt.toml`（`hard_tabs = true`，`edition = "2021"`）与 `clippy.toml`。
4. 改写 `Makefile`：新增 `cargo-build`、`cargo-test`、`cargo-run`、`cargo-clippy`、`cargo-fmt-check` 目标；保留 `build`、`run`、`test`、`test-race`、`test-cover`、`check`、`fmt`、`clean` 目标名，内部改为调用 cargo。`HOST_OS` / `HOST_ARCH` → `x64`/`arm64` 的映射保留，cargo 输出按 `bin/puppy-server-<os>-<arch>` 复制到对应路径。
   - 注意 Makefile 现有逻辑把 `x86_64` 映射成 `x64`、`aarch64` 映射成 `arm64`，Rust `std::env::consts::ARCH` 返回 `x86_64` / `aarch64`，映射表必须照搬。
5. `puppy-server` bin 用 `clap` 定义 `--config / -c` 必填参数，main 先只打印 "puppy-server (rust) starting" 后退出。
6. 验证 `make build` 产出 `bin/puppy-server-<os>-<arch>`，并在 macOS 上 `make run CONFIG=./config.toml` 能启动（即便立即报 "no frontends configured" 也可）。

**测试要求**：`cargo test` 全绿（哪怕还没有实质测试）；`cargo clippy -- -D warnings` 通过；`cargo fmt --check` 通过。

**验收标准**：`make build && ls bin/` 显示当前平台的二进制；`git status` 显示新增 `rust/`、改写的 `Makefile`，未触碰 `app/`。

### Phase 1 — 配置层（`puppy-config`）

**对应 Go 源码**：`cmd/puppy-server/main.go` 第 1–640 行的 `Configuration` / `FrontendConfiguration` / `BackendConfiguration` / `Validate` 系列、`config.toml`、`pkg/tunproxy/config.go` 中嵌套结构。

**实现要点**：

1. 用 `serde` + `toml` 定义与 Go 完全同名的结构（Rust 风格改 PascalCase）：
   - `Configuration { log, frontends: Vec<FrontendConfiguration>, backends: Vec<BackendConfiguration>, dashboard: Option<DashboardConfiguration> }`
   - `FrontendConfiguration` 为 tagged enum（`[frontends.type]` 区分 `http` / `socks` / `tun`），每个 variant 字段对应 Go 的 `HTTPProxyFrontendConfiguration` / `SOCKSProxyFrontendConfiguration` / `TUNFrontendConfiguration`。
   - `BackendConfiguration` 同理（`direct` / `http` / `socks`）。
   - **每个 struct 都加 `#[serde(deny_unknown_fields)]`**，这是 Go 版用 `toml.Strict` 达成的行为，必须在 Rust 侧复刻，否则配置错误会静默通过。
2. `Validate()` 方法逐字段校验，错误信息**逐字照抄** Go 版（包括 `[dashboard] is not supported in this build` 这类一期要新增的提示）。
3. `DashboardConfiguration` 保留解析字段但 `Validate` 直接返回 `dashboard is not yet implemented in rust port (phase 2)`；若 `config.toml` 中没有 `[dashboard]` 段则不报错。
4. `puppy-config` 暴露 `load(path: &Path) -> Result<Configuration>` 与 `Configuration::validate(&self) -> Result<()>`。
5. `puppy-server` main 改为：clap 解析 → `puppy_config::load` → `validate` → 打印 frontend/backend 列表 → 退出。

**测试要求**：把 `cmd/puppy-server/main_test.go` 中所有 `TestConfigurationValidate*` 用例翻译成 Rust 表驱动测试，错误信息用 `assert_eq!` 逐字比对。新增一个用 `config.toml` 本体做 round-trip 的测试。未知字段必须触发 `denied field` 类错误。

**验收标准**：`cargo test -p puppy-config` 全绿；`make run CONFIG=./config.toml` 在不删除 `[dashboard]` 段时报指定的 dashboard 错误，删除后能正常打印配置摘要。

### Phase 2 — 核心抽象与 shim（`puppy-core`）

**对应 Go 源码**：`pkg/common/backend.go`、`pkg/common/socks5.go`、`pkg/common/socks5_test.go`、`pkg/common/counting/`、`pkg/shim/`、`pkg/shim/shim_test.go`。

**实现要点**：

1. `Target { host: String, port: u16, addr_type: AddressType }` + `AddressType { Domain, IPv4, IPv6 }`，对应 Go `pkg/common/backend.go:Target`。
2. `Protocol` enum（`HttpConnect` / `Socks5` / `Tun`），`Capability` bitflags（`PeerInfo` / `UDP` / `FullPipeline`），对应 Go 接口。
3. `Backend` trait：`async fn handle(&self, target: Target, inbound: TcpStream) -> Result<()>` + `fn protocol(&self) -> Protocol` + `fn capabilities(&self) -> Capability`。Go 用 interface，Rust 用 `#[async_trait]`。
4. `Dialer` trait：`async fn dial(&self, target: &Target) -> Result<TcpStream>`。
5. `socks5` 模块：常量 `VER = 0x05`、方法枚举、回复码、`read_socks5_address(reader: &mut impl AsyncRead) -> Result<Target>`，逐行翻译 `pkg/common/socks5.go:ReadSOCKS5Address`。
6. `counting::CountingConn<T>`：包装 `TcpStream`，`AsyncRead` / `AsyncWrite` 实现里把字节数加到 `Arc<AtomicU64>`；对应 `pkg/common/counting/conn.go`。
7. `stats` 模块：`StatsRegistry`（全局计数）、`ConnectionRegistry`（活跃连接表，支持按 id 查询/关闭）、`EventBus`（SSE 用，一期可只建空 API）。用 `parking_lot::RwLock` + `Arc`。对应 `pkg/common/stats/` 三个文件。
8. `shim::ShimServer`：`async fn serve(left: TcpStream, right: TcpStream, on_done: impl Fn())`，内部 spawn 两个 task 各自 `io::copy`，任一方向结束就关闭两端。对应 `pkg/shim/shim.go`。

**测试要求**：

- `TestReadSOCKS5Address*` 全部翻译，覆盖 IPv4/IPv6/Domain 三种 atyp + 各种畸形输入（长度截断、保留 atyp）。
- `CountingConn` 用 `tokio::io::duplex` 做读写计数测试。
- `ShimServer` 用 `duplex` 双向通道验证：一端写、另一端收到、关闭一端另一端也被关闭、字节计数正确。
- `stats` 注册表用并发 task 验证计数原子性。

**验收标准**：`cargo test -p puppy-core` 全绿；clippy 无警告；`puppy-core` 不依赖任何业务 crate（在 `Cargo.toml` 里只有 `tokio` / `parking_lot` / `thiserror` / `tracing` / `async-trait` / `bytes`）。

### Phase 3 — Direct backend 与 outbound 工厂（`puppy-direct`）

**对应 Go 源码**：`pkg/adapter/direct/direct.go`（35 行）、`pkg/adapter/direct/direct_test.go`（119 行）、`cmd/puppy-server/main.go` 中 `createBackend` / `createDirectBackend` 工厂函数。

**实现要点**：

1. `DirectBackend` 结构持有：`egress_iface: Option<String>`、`timeout: Duration`、`stats: Arc<StatsRegistry>`、`dialer_id: String`。
2. 实现 `Backend` trait。`handle` 方法：用 `socket2::Socket` 新建 socket，若 `egress_iface` 非空则 `bindToDevice` / `SO_BINDTODEVICE`（Linux）或 `IP_BOUND_IF`（macOS），再 `connect` 到 `target`，转成 `tokio::net::TcpStream`。
3. 错误分类：连接拒绝 / 超时 / DNS 解析失败 / 接口绑定失败，每类对应 Go 版的 error 字符串。
4. `puppy-config` 中 `BackendConfiguration::Direct` variant 直接 `new_direct_backend(cfg) -> Arc<dyn Backend>`，工厂逻辑放在 `puppy-direct`，`puppy-config` 只做转发。

**测试要求**：

- 用 `tokio::net::TcpListener` bind `127.0.0.1:0` 做 loopback 连接测试：成功连接 + 计数正确 + egress_iface 为 None 时不绑定。
- egress_iface 设为不存在的接口名时必须返回明确错误。
- `TestDirectBackend_*` 用例逐个翻译。
- 连接超时用 `tokio::time::timeout` 包装一个不可路由地址验证。

**验收标准**：`cargo test -p puppy-direct` 全绿；`puppy-server` 能在配置只含 direct backend 时启动并打印 backend 列表。

### Phase 4 — HTTP CONNECT backend（`puppy-httpproxy-be`）

**对应 Go 源码**：`pkg/adapter/httpproxy/` 全部文件（`backend.go` 199 行、`backend_test.go` 596 行、`tls.go`、`auth.go`、`dialer.go` 等）。

**实现要点**：

1. `HTTPProxyBackend` 持有：上游 `host:port`、`tls_config`（`rustls::ClientConfig` + SNI）、`auth`（Basic 或 Bearer，用 `subtle::ConstantTimeEq` 比较 challenge）、`user_agent`、`capabilities`（声明 `PeerInfo`）、`stats`。
2. `handle` 流程（严格对应 Go `pkg/adapter/httpproxy/backend.go:Handle`）：
   a. 用 `socket2` + egress 绑定 dial 上游（若配置了 egress）。
   b. 若启用 TLS：`tokio-rustls::TlsConnector::connect` 握手，SNI 从配置取，证书校验默认 strict，`insecure_skip_verify` 时用 `NoCertificateVerification`（仅在 feature flag 后）。
   c. 发送 `CONNECT host:port HTTP/1.1\r\nHost: ...\r\nProxy-Authorization: Basic ...\r\n\r\n`，用 `httparse` 解析响应行 + headers。
   d. 校验状态码 200，否则按 Go 版错误信息报 `proxy returned status: <code> <text>`。
   e. 把握手后的连接交给 `shim::ShimServer` 与 inbound 互通。
3. `PeerInfo` capability：从上游 `200` 响应的 `X-Proxy-Connection-Id` / 自定义 header 中读取远端真实地址（若 Go 版有此逻辑，照搬）。
4. `auth` 子模块：`Basic` 构造 `Authorization: Basic base64(user:pass)`，`Bearer` 构造 `Proxy-Authorization: Bearer <token>`，challenge 比较用常量时间。
5. `tls` 子模块：`build_tls_config` 处理 `insecure_skip_verify` / 自定义 CA / ALPN（HTTP/1.1 无 ALPN）。

**测试要求**：

- 用 `tokio::net::TcpListener` 起一个 mock 上游，分别测试：
  - 200 响应 + 成功双向 copy。
  - 407 响应触发认证错误。
  - 502 响应触发 status 错误，错误信息逐字比对。
  - 上游先关闭连接 → shim 正确退出。
  - TLS 上游：用自签证书起 `tokio-rustls` server，验证 `insecure_skip_verify=true` 能连、`false` 握手失败。
  - Basic auth：上游校验 `Proxy-Authorization` 值正确才返回 200。
- `TestHTTPProxyBackend_*` 全部翻译（596 行测试用例）。
- 错误信息用 `assert_eq!(err.to_string(), "...")` 逐字比对 Go 版。

**验收标准**：`cargo test -p puppy-httpproxy-be` 全绿；本 crate 的 `Cargo.toml` 依赖含 `httparse`、`tokio-rustls`、`rustls-pemfile`、`base64`、`subtle`、`socket2`。

### Phase 5 — SOCKS5 backend（`puppy-socksproxy-be`）

**对应 Go 源码**：`pkg/adapter/socksproxy/` 全部文件（`backend.go` 309 行、`backend_test.go` 887 行、`tls.go`、`auth.go`、`dialer.go`）。

**实现要点**：

1. `SOCKSProxyBackend` 持有：上游 `host:port`、`tls_config`、`auth`（UserPass 或 Bearer）、`user_agent`、`stats`。
2. `handle` 流程（对应 Go `pkg/adapter/socksproxy/backend.go:Handle`）：
   a. dial 上游（含 egress 绑定）。
   b. 可选 TLS 握手。
   c. 发送 method selection：`05 02 00 02`（无认证 + UserPass）或 `05 01 00`（无认证）或 `05 01 02`（仅 UserPass）。
   d. 若服务端选 UserPass：发送 `01 <ulen> <user> <plen> <pass>`，验证 `01 00` 成功响应。
   e. 发送 CONNECT 请求：`05 01 00 <atyp> <addr> <port>`，atyp/addr 用 `puppy_core::socks5::encode_address(&target)`。
   f. 解析 reply，非 `00` 按 Go 版错误表（`socks5: reply 0x05` 等）报错。
   g. shim 双向 copy。
3. `PeerInfo` capability：SOCKS5 reply 的 BND.ADDR/BND.PORT 可作为远端绑定地址，照搬 Go 逻辑。
4. `auth` 子模块：UserPass 按 RFC 1929，Bearer 是 puppy 自定义扩展（如果 Go 版有），照搬。
5. `tls` 子模块：与 Phase 4 共享代码，可考虑提到 `puppy-core` 一个 `puppy-tls` 模块，或两个 backend 各自依赖 `tokio-rustls` 直接实现。

**测试要求**：

- mock SOCKS5 上游（用 `tokio::net::TcpListener` 手写协议帧）：
  - 完整 happy path：method=00 → CONNECT → reply 00 → copy。
  - method=02 UserPass → 成功 → CONNECT。
  - UserPass 失败（reply 01）→ 错误。
  - CONNECT reply 04（Host unreachable）→ 错误信息比对。
  - TLS 上游：自签证书 + `insecure_skip_verify` 双分支。
  - 上游早关闭 → shim 退出。
- `TestSOCKSProxyBackend_*` 全部翻译（887 行测试）。

**验收标准**：`cargo test -p puppy-socksproxy-be` 全绿；本 crate 依赖含 `tokio-rustls`、`subtle`、`socket2`、`puppy-core`。

### Phase 6 — HTTP CONNECT frontend（`puppy-httpproxy-fe`）

**对应 Go 源码**：`pkg/httpproxy/` 全部文件（`server.go` 413 行、`server_test.go` 774 行、`auth.go`、`auth_test.go`、`tls.go`、`listener.go`、`request.go`）。

**实现要点**：

1. `HTTPProxyFrontend` 持有：`listener: TcpListener`、`tls_config: Option<ServerConfig>`、`auth: Option<Auth>`（Basic/Bearer/None）、`backend: Arc<dyn Backend>`、`stats: Arc<StatsRegistry>`、`idle_timeout: Duration`。
2. `serve` 主循环：`listener.accept()` → spawn `handle_connection`。
3. `handle_connection`：
   a. 若启用 TLS：先做 TLS 握手（`tokio-rustls::TlsAcceptor`），失败按 Go 日志格式记录后关闭。
   b. 用 `httparse` 解析请求行 + headers（缓冲区上限照搬 Go 版 `MaxHeaderBytes`，默认 64KiB）。
   c. 仅接受 `CONNECT host:port HTTP/1.1`，其他方法返回 `405 Method Not Allowed`，错误信息比对 Go 版。
   d. 认证：`Proxy-Authorization` 头，Basic 用 `subtle::ConstantTimeEq` 比对 user/pass，Bearer 同样常量时间比对 token。失败返回 `407 Proxy Authentication Required` + `Proxy-Authenticate: Basic realm="..."` 头。
   e. 解析 `host:port`（支持 IPv6 `[::1]:443`、缺省端口 80/443 处理与 Go 一致）。
   f. 构造 `Target`，调用 `backend.handle(target, inbound)`。Backend 自己负责 shim。
4. `TLS` 子模块：`build_acceptor` 处理 cert/key 加载（`rustls-pemfile`）、ALPN（HTTP/1.1 无）、客户端证书校验（若 Go 版有）。
5. `auth` 子模块：Basic/Bearer challenge 比较，错误日志格式与 Go 一致。

**测试要求**：

- `tokio::net::TcpListener` 起一个 mock backend（接收任意 target，回 `200 OK` 后双向 copy）。
- 用例：
  - 完整 CONNECT：client 发 `CONNECT example.com:443`，server 接受、转 backend、client 与 backend 互发数据。
  - 非 CONNECT 方法 → 405。
  - 缺认证 → 407 + `Proxy-Authenticate` 头。
  - 错误凭证 → 407。
  - 正确 Basic 凭证 → 200。
  - 正确 Bearer 凭证 → 200。
  - TLS frontend：自签证书 + `tokio-rustls` client 验证握手成功/失败。
  - 超长 header → 连接关闭 + 错误日志。
  - IPv6 target `[::1]:443`。
  - 缺省端口 `CONNECT example.com HTTP/1.1` → 解析为 80。
- `TestHTTPProxyServer*` 全部翻译（774 行）。
- 错误日志用 `tracing::warn!` 输出，关键字段（client addr、target、error）与 Go `slog` 字段名一致。

**验收标准**：`cargo test -p puppy-httpproxy-fe` 全绿；端到端在 `config.toml` 配一个 http frontend + direct backend，`curl -x http://127.0.0.1:PORT https://example.com` 能成功。

### Phase 7 — SOCKS5 frontend（`puppy-socksproxy-fe`）

**对应 Go 源码**：`pkg/socksproxy/` 全部文件（`server.go` 462 行、`server_test.go` 623 行、`auth.go`、`tls.go`、`listener.go`）。

**实现要点**：

1. `SOCKSProxyFrontend` 持有同 Phase 6 类似配置 + `auth: Option<SocksAuth>`（None / UserPass / Bearer 自定义）。
2. `handle_connection`：
   a. 可选 TLS 握手。
   b. 读 ver/method：`05 <nmethods> <methods...>`，校验 ver=5，methods 中选第一个 frontend 支持的（无认证=00 优先于 UserPass=02）。
   c. 回 `05 <method>`。若 method=02 且 frontend 未启用 UserPass → 回 `05 ff` 关闭。
   d. UserPass 子协商：`01 <ulen> <user> <plen> <pass>` → `01 00` 成功 / `01 01` 失败关闭。用户名密码用常量时间比较。
   e. 读请求 `05 01 00 <atyp> <addr> <port>`，仅 CMD=01（CONNECT）支持；UDP ASSOCIATE 一期可返回 `07 command not supported`（与 Go 版一致则照搬，否则二期补）。
   f. 用 `puppy_core::socks5::read_socks5_address` 解析 addr。
   g. 回 `05 00 00 01 0.0.0.0 0`（BND 假值，与 Go 版一致）。
   h. 调 `backend.handle(target, inbound)`。
3. `TLS` 子模块与 Phase 6 共享思路。

**测试要求**：

- mock backend 同 Phase 6。
- 用例：
  - 无认证 CONNECT IPv4 / IPv6 / Domain → 成功 copy。
  - UserPass 成功 / 失败。
  - method 协商失败（client 只支持 02，frontend 只支持 00）→ `05 ff`。
  - CMD=02 UDP ASSOCIATE → `07`。
  - 畸形 ver / method 长度 / atyp → 关闭。
  - TLS frontend 握手。
- `TestSOCKSProxyServer*` 全部翻译（623 行）。

**验收标准**：`cargo test -p puppy-socksproxy-fe` 全绿；端到端 `curl --socks5 127.0.0.1:PORT https://example.com` 成功。

### Phase 8 — 入口集成（`puppy-server` bin）

**对应 Go 源码**：`cmd/puppy-server/main.go` 第 640 行起的 `run` 函数 + frontend 工厂（去 dashboard 后约 250 行）。

**实现要点**：

1. `main`：
   a. `clap` 解析 `--config`。
   b. `puppy_config::load` + `validate`。
   c. 初始化 `tracing_subscriber`（与 Go `slog` 字段名一致：`time` / `level` / `msg` / `target` / `client` / `backend` / `error`）。
   d. 为每个 `BackendConfiguration` 调对应工厂构造 `Arc<dyn Backend>`，注册到 `StatsRegistry`。
   e. 为每个 `FrontendConfiguration` 构造 frontend，spawn tokio task 跑 `serve`。
   f. 主线程 `tokio::signal::ctrl_c` 等待退出，收到后 graceful shutdown：关闭所有 listener，等所有活跃连接结束或超时（与 Go 版 timeout 一致）。
2. frontend 工厂在 `puppy-config` 暴露 `build_frontend(cfg, backend, stats) -> Arc<dyn Frontend>`，具体实现由各 frontend crate 提供。
3. `Backend` 的 `egress_iface` 在工厂阶段解析为接口索引并缓存（避免每条连接查）。
4. 启动日志格式：`listening on <addr> (frontend=<type>, backend=<type>)`，与 Go 一致。

**测试要求**：

- 用 `assert_cmd` 跑 `puppy-server --config <tmp>` 启动 + `tokio::time::sleep` + 用 curl 验证能代理 + 发 SIGTERM 验证优雅退出。
- 配置错误时退出码与 Go 版一致（非零 + stderr 错误信息比对）。
- 多 frontend + 多 backend 配置启动后日志正确。

**验收标准**：`make run CONFIG=./config.toml`（删除 `[dashboard]` 段后）能启动，HTTP/SOCKS frontend 都能正常代理；`make test` 全绿；`bin/puppy-server-<os>-<arch>` 二进制名正确。

### Phase 9 — TUN frontend（`puppy-tun`，最复杂，预估 3–4 周）

**对应 Go 源码**：`pkg/tunproxy/` 全部 32 个文件约 5,000 行。子模块：

- `config.go`：`TUNFrontendConfiguration`（已在 Phase 1 解析，此处消费）
- `tun.go` / `tun_darwin.go` / `tun_linux.go`：TUN 设备打开与读写
- `device.go`：设备抽象
- `netstack.go`：gVisor netstack 适配
- `stack.go`：协议栈初始化
- `tcp.go` / `udp.go`：L4 协议处理
- `dispatch.go`：包分发到 backend
- `route_darwin.go` / `route_linux.go`：路由安装与恢复
- `egress.go`：egress 接口绑定（与 direct backend 共享逻辑）
- `dns.go` / `dns_test.go`：DNS-over-TCP 转换
- `nft.go` / `nft_test.go`：Linux nftables DNS 拦截
- `auto_route.go`：auto_route 编排
- `*_test.go` 各类

**核心改动**：Go 版用 `sagernet/gvisor` 提供用户态 TCP/IP 协议栈。Rust 版**必须用 `smoltcp`** 替换，因为没有其他成熟的纯 Rust 用户态 netstack。smoltcp 与 gVisor API 差异大，本阶段是整个项目的最大风险点。

**实现要点**：

1. **设备层**（`device_darwin` / `device_linux`）：
   - macOS：用 `libc::socket(AF_SYSTEM, ...)` + `ioctl SIIFTUNDEL`（或 `utun`），照搬 `pkg/tunproxy/tun_darwin.go` 中的 syscall 序列。Rust 侧用 `nix` + 必要时 `libc` 裸调。
   - Linux：`/dev/net/tun` + `ioctl TUNSETIFF`，照搬 `tun_linux.go`。
   - 设备暴露 `async fn read(&self, buf: &mut [u8]) -> Result<usize>` 与 `async fn write(&self, buf: &[u8]) -> Result<usize>`。TUN fd 不是天然 async，用 `tokio::io::unix::AsyncFd` 包裹。
2. **smoltcp 协议栈**：
   - `smoltcp::iface::Interface` 配置：本机 IP（TUN CIDR）、MTU。
   - 一个 tokio task 从 TUN device `read` 包 → `interface.inject`。
   - 另一个 task 轮询 `interface.poll` → 把发出的包写回 TUN device。
   - TCP：实现 `TcpListener` 类似抽象，accept 后拿到 `(remote_ip, remote_port, local_port)`，构造 `Target` 交给 backend。
   - UDP：DNS-over-TCP 转换逻辑——收到 UDP 包到 53 端口时，把 DNS query 在 TCP 上重发到配置的上游 DNS（DoT 或 plain TCP 53），响应再封装回 UDP。**严格照搬 `pkg/tunproxy/dns.go` 的封装格式**（长度前缀 + DNS payload）。
   - 注意 smoltcp 0.11+ 的 API 与 0.10 有差异，锁版本前先验证。
3. **dispatch**：`tcp_accept` 拿到连接后，根据 `Target { host, port }` 选择 backend。auto_route 模式下需要根据路由表判断哪些目标走 TUN、哪些直连——这部分逻辑在 `dispatch.go`，照搬。
4. **route 安装**（`route_darwin` / `route_linux`）：
   - macOS：`route -n add -net ...` 或 `RTM_ADD` syscall，照搬 `route_darwin.go`。**必须实现 route 恢复**：进程退出时（含 panic）用 `ctrlc` / `drop` guard 删路由，否则会留下脏路由。
   - Linux：`ip route add` 或 netlink `RTM_NEWROUTE`。
   - 用 RAII guard：`RouteInstall { .. }` 在 `Drop` 里卸载，配合 tokio shutdown 信号。
5. **nftables DNS 拦截**（Linux only）：`pkg/tunproxy/nft.go` 用 `nft` 命令插入规则把 53 端口 UDP 流量重定向到 TUN。Rust 侧用 `nix` 调 `nft` 命令（不直接调 netlink，与 Go 版一致），规则字符串逐字比对。`nft_test.go` 用例翻译。
6. **egress**：TUN 模式下 backend dial 出去的连接要绑定到物理 egress 接口，逻辑与 Phase 3 direct backend 的 `bindToDevice` 共享，提到 `puppy-core::egress` 模块统一实现。
7. **auto_route**：`auto_route.go` 编排：检测默认路由 → 计算需要劫持的 CIDR → 安装路由 → 启动 DNS 拦截 → 启动 netstack。Rust 侧用 `auto_route::AutoRoute` struct，`start` / `stop` 方法，`stop` 在 shutdown guard 里调用。

**测试要求**（TUN 测试是最难的，分三层）：

1. **单元测试**（不需 root）：
   - `dns` 模块：UDP→TCP 封装 / TCP→UDP 解封装，`dns_test.go` 全部翻译。
   - `nft` 规则字符串生成：snapshot 比对，`nft_test.go` 全部翻译。
   - `route` 规则计算：给定默认路由 + CIDR，生成的 `route add` 命令字符串与 Go 版一致。
   - smoltcp 接口配置：构造 `Interface` 后 IP / MTU / routes 正确。
2. **loopback 测试**（不需 root）：
   - 用 `tokio::io::duplex` 模拟 TUN fd，构造一组预编排的 IP 包喂给 smoltcp，验证 TCP 三次握手 + 数据传输 + 关闭。
   - mock backend（直接 echo）验证 dispatch 把 `Target` 正确传给 backend。
3. **集成测试**（需 root，CI 跳过，本地手动跑）：
   - 起一个真实 TUN 设备，从主命名空间 `curl` 一个测试域名，验证流量经过 TUN → smoltcp → backend → 真实出口。
   - macOS 和 Linux 各跑一遍，验证路由安装与退出恢复。
   - 退出后 `netstat -rn` / `ip route` 确认无残留路由。

**验收标准**：

- `cargo test -p puppy-tun` 单元 + loopback 全绿。
- 在 macOS 上 `sudo make run CONFIG=./config.toml`（配置 TUN frontend）能正常上网，关闭后路由恢复。
- Linux 同上，且 `nft list ruleset` 退出后无 puppy 残留规则。
- TUN 启动日志字段与 Go 版一致：`tun device opened: <name>`、`route installed: <cidr> via <if>`、`dns intercept enabled`。

**风险与缓解**：

- **smoltcp 与 gVisor 行为差异**：gVisor 自带完整 BSD socket 语义，smoltcp 是裸 stack，需要自己实现 accept 队列、连接超时。缓解：先实现最小 TCP echo 验证 smoltcp 可用，再逐步加 DNS / UDP。
- **macOS utun syscall**：`socket(AF_SYSTEM, ...)` 在 Rust 中没有封装，需要 `libc::socket` 裸调 + 手动 `sockaddr` 构造。参考 `tun_darwin.go` 字节序。
- **route 恢复**：若进程 panic 或被 `kill -9`，Drop guard 不执行。缓解：在 `/tmp/puppy-routes.<pid>` 持久化已安装路由，启动时检查并清理孤儿路由（Go 版有此机制则照搬，无则新增并测试）。
- **smoltcp 版本锁定**：在 `Cargo.toml` 用 `=0.11.0` 精确锁版本，避免 API 漂移。

### Phase 10 — 集成验证与清理

**对应 Go 源码**：无新增实现，全量回归。

**实现要点**：

1. 跑全量 `make test`、`make test-race`（`cargo test` + `cargo miri` 对 unsafe 块）、`make test-cover`，覆盖率不低于 Go 版关键路径。
2. 用 `config.toml` 完整配置（删除 `[dashboard]` 段）跑 `make run`，验证 HTTP frontend + SOCKS frontend + 各 backend 组合：
   - http-fe → direct-be
   - http-fe → http-be（指向另一个 puppy 实例做上游）
   - http-fe → socks-be
   - socks-fe → direct-be
   - socks-fe → http-be
   - socks-fe → socks-be
   - tun-fe → direct-be（手动 + sudo）
3. 用 `app/desktop/puppy` 的开发模式启动 Electron，验证 `manager.ts` 能正确定位 `bin/puppy-server-<os>-<arch>` 并拉起进程，代理流量成功。
4. `make desktop-package-mac` 与 `make desktop-package-linux` 各跑一次，产出 `.app` / `.deb` / `.AppImage`，安装后实测代理。
5. 性能基准：用 `apache-bench` 通过 HTTP frontend 拉 100MB 文件，吞吐与 Go 版差距不超过 20%。若显著落后，用 `tokio-console` 定位瓶颈。
6. **删除 Go 代码**：确认上述全部通过后，`git rm -r cmd/ pkg/ vendor/ go.mod go.sum`，更新 `AGENTS.md`（移除 Go 相关构建说明，替换为 cargo 命令）。
7. 更新 `Makefile` 移除 `vendor` 目标，保留 `build` / `run` / `test` / `clean`。
8. 更新 `config.toml` 顶部注释，注明 `[dashboard]` 段一期被忽略，错误信息指引到 issue。

**验收标准**：

- `git status` 显示 Go 文件全部删除，`rust/` 为唯一后端实现。
- `make build && make test` 全绿。
- `make desktop-package-mac` 产出可运行的 `.app`。
- `config.toml` 含 `[dashboard]` 段时启动报指定的 phase 2 错误，不含时正常启动。
- README / AGENTS.md 无残留 Go 指令。

### Phase 11（二期可选）— Dashboard

**对应 Go 源码**：`pkg/dashboard/` 14 个文件、`cmd/puppy-server/providers.go` 138 行、`main.go` 中 `frontendManager` / `handleControlRequest` / 控制通道。

**实现要点**：

1. 用 `axum` 实现 REST API，路由按 `docs/HTTP-API.md` 逐个对应。
2. SSE 用 `axum::response::sse::Sse` + `EventBus`（Phase 2 已建空 API，本阶段填充）。
3. 静态资源服务：`tower-http::services::ServeDir` 提供 `app/dist` 产物。
4. `puppy-config` 的 `DashboardConfiguration::validate` 改为真正校验（端口、CORS、TLS 证书路径）。
5. `puppy-server` 在配置含 `[dashboard]` 时 spawn dashboard 任务。

**测试要求**：把 `pkg/dashboard/*_test.go` 全部翻译，错误信息比对。

**验收标准**：浏览器打开 `http://127.0.0.1:<port>` 看到 dashboard UI，SSE 实时推送连接事件，REST API 行为与 Go 版一致。

## 5. 跨阶段约束

1. **错误信息逐字比对**：每个 `Validate` 分支、每个连接错误、每个日志字段的字符串必须与 Go 版一致。Go 版用 `fmt.Errorf("proxy returned status: %d %s", ...)`，Rust 版用 `format!("proxy returned status: {} {}", ...)`，最终字符串相等。测试用 `assert_eq!(err.to_string(), "...")` 锁定。
2. **日志字段名一致**：Go `slog` 的 `slog.String("client", addr)` → Rust `tracing::field::display(addr)` + span attribute `client = %addr`。`tracing-subscriber` 输出格式选 JSON 与 Go 版 JSON handler 对齐，便于 Electron 端解析不变形。
3. **二进制命名**：`bin/puppy-server-<os>-<arch>`，`<os>` ∈ {`darwin`, `linux`, `windows`}，`<arch>` ∈ {`x64`, `arm64`}（注意是 `x64` 不是 `x86_64`）。Makefile 中映射逻辑保留。
4. **config.toml 不动**：字段、类型、默认值、错误信息全部不变。新增字段只能加在 `[dashboard]` 段一期忽略的子表里。
5. **不引入新依赖**：除上表列出的 crate 外，任何新依赖必须在 PR 说明里给出理由并经人类 owner 批准。
6. **测试并行性**：所有网络测试 bind `127.0.0.1:0`，`t.Cleanup` 对应 Rust 的 `Drop` guard 或 `tokio::test` 中显式 drop listener。
7. **unsafe 最小化**：syscall 必然需要 unsafe，但每处 unsafe 必须有注释说明为何安全。`cargo miri` 在 CI 可选，但本地必须能跑过 device 层 unsafe 测试。

## 6. 风险与缓解

| 风险 | 影响 | 缓解 |
|---|---|---|
| smoltcp 与 gVisor 行为差异导致 TUN 模式不可用 | 项目阻塞 | Phase 9 第一个里程碑：纯 smoltcp TCP echo 跑通；若两周内无法跑通，escalate 评估改用 `lwIP` binding 或保留 Go 版 TUN 模块 |
| macOS utun syscall 在 Rust 中无现成封装 | TUN 无法在 macOS 工作 | 参考 `tun_darwin.go` 字节级翻译；备选用 `tun` crate（需评估是否支持 AF_SYSTEM） |
| route 残留导致宿主机断网 | 严重 | RAII guard + 持久化路由记录 + 启动清理孤儿 + 信号处理覆盖 SIGTERM/SIGINT/SIGHUP |
| 性能回退 > 20% | 体验下降 | Phase 10 基准对比；定位瓶颈用 `tokio-console` + `pprof-rs` |
| 测试覆盖遗漏导致行为回归 | 隐蔽 bug | 每个 Go `*_test.go` 在 PR 中列出对应 Rust 测试文件路径；review 时逐文件核对 |
| `config.toml` 未知字段静默通过 | 配置错误隐患 | 每个 serde struct 强制 `#[serde(deny_unknown_fields)]`，CI 加一个 fuzz 测试随机插入未知字段验证报错 |
| 二进制命名/启动参数漂移 | Electron 桌面应用无法启动 | Phase 0 起 `make desktop-package-mac` 即验证 manager.ts 能拉起进程，每个阶段都跑一次冒烟 |
| smoltcp 版本升级 API 漂移 | 编译失败 | `Cargo.toml` 用 `=` 精确锁版本，升级单独 PR |

## 7. 总验收标准

项目视为完成，当且仅当：

1. `rust/` 是仓库唯一后端实现，`cmd/` / `pkg/` / `vendor/` / `go.mod` / `go.sum` 已删除。
2. `make build` 产出 `bin/puppy-server-<os>-<arch>`，命名与 Go 版一致。
3. `make test` 全绿，覆盖率不低于 Go 版关键路径（每个 Go 测试函数有对应 Rust 测试）。
4. `make run CONFIG=./config.toml`（删 `[dashboard]` 段）能启动 HTTP + SOCKS + TUN frontend，行为与 Go 版一致。
5. `make desktop-package-mac` 与 `make desktop-package-linux` 产出可运行的桌面应用，代理功能正常。
6. `config.toml` 含 `[dashboard]` 段时报 `dashboard is not yet implemented in rust port (phase 2)` 并退出非零。
7. TUN 模式在 macOS 与 Linux 上各手动跑一次，路由安装与恢复正确，nftables 规则退出后清理干净。
8. 错误信息、日志字段、二进制命名、启动参数全部与 Go 版对齐（有测试锁定）。
9. `cargo clippy -- -D warnings` 与 `cargo fmt --check` 通过。
10. `AGENTS.md` 与 `Makefile` 已更新为 Rust 工作流，无残留 Go 指令。

## 8. 执行前 checklist（给下一个 Agent）

- [ ] 通读本文件全文。
- [ ] 在仓库根跑 `find . -type f -name '*.go' -not -path './vendor/*' -not -path './app/*' | xargs wc -l` 复核代码规模。
- [ ] 读 `config.toml` 全文，列出每个字段，确认 Phase 1 的 serde struct 覆盖完整。
- [ ] 读 `cmd/puppy-server/main.go` 全文，画出 frontend/backend 工厂调用图。
- [ ] 读 `pkg/tunproxy/tun_darwin.go` 与 `tun_linux.go`，确认 syscall 列表。
- [ ] 读 `Makefile` 的 `HOST_OS` / `HOST_ARCH` 映射，确认二进制命名规则。
- [ ] 读 `app/desktop/puppy/src/main/server/manager.ts`，确认 Electron 端对二进制的期望。
- [ ] 在 `rust/` 下 `cargo init --workspace` 后立即 commit "phase 0: scaffold"，作为后续 PR 的基线。
- [ ] 每个 Phase 完成后回到本文件对应小节，逐条勾选"实现要点"与"验收标准"，未达标的回炉。
