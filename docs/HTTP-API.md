# Puppy Dashboard HTTP API

## 版本

- API 版本: `v1`
- Base URL: `https://<host>:<port>/api/v1`

## 认证

当服务器配置了 `token` 时，所有请求必须在 `Authorization` 头中携带 Bearer token：

```
Authorization: Bearer <your-token>
```

token 校验使用常量时间比较以防止计时攻击。未配置 token 时认证关闭（仅建议本地监听 `127.0.0.1` 时使用）。

### 认证失败响应

```json
HTTP/1.1 401 Unauthorized
Content-Type: application/json

{"error": "unauthorized"}
```

## 通用约定

| 约定 | 说明 |
|------|------|
| 请求/响应 Content-Type | `application/json; charset=utf-8`（SSE 端点除外） |
| 错误响应格式 | `{"error": "..."}` |
| 时间格式 | RFC 3339（如 `2026-07-15T19:30:00+08:00`） |
| 异步操作 | 返回 `202 Accepted` + `{"job_id": "...", "message": "..."}`，结果通过 SSE 事件流推送 |
| CORS | 所有响应包含 `Access-Control-Allow-Origin: *`，支持 OPTIONS 预检 |

## 端点

### 系统

#### GET /system

返回系统信息。

**响应 200 OK:**

```json
{
  "version": "v1",
  "rust_version": "rustc 1.95.0",
  "started_at": "2026-07-15T19:00:00+08:00",
  "uptime_seconds": 1800.5,
  "pid": 12345,
  "active_connections": 3,
  "sse_subscribers": 1
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| version | string | API 版本 |
| rust_version | string | Rust 编译器版本 |
| started_at | string | 服务器启动时间 (RFC 3339) |
| uptime_seconds | float | 运行时长（秒） |
| pid | int | 进程 ID |
| active_connections | int | 当前活跃连接数 |
| sse_subscribers | int | 当前 SSE 订阅者数 |

**curl 示例:**
```bash
curl -k -H "Authorization: Bearer <token>" https://127.0.0.1:8443/api/v1/system
```

---

#### POST /system/shutdown

请求服务器优雅关闭。发送请求到主控制任务，返回 `202 Accepted`。关闭结果通过 SSE 事件流推送（`shutdown` 事件）。

**响应 202 Accepted:**

```json
{
  "job_id": "shutdown",
  "message": "shutdown request submitted"
}
```

**响应 501 Not Implemented:** 控制通道未配置。

**curl 示例:**
```bash
curl -k -X POST -H "Authorization: Bearer <token>" https://127.0.0.1:8443/api/v1/system/shutdown
```

---

### 统计

#### GET /stats

返回全局统计快照。

**响应 200 OK:**

```json
{
  "total_connections": 150,
  "active_connections": 3,
  "dial_successes": 147,
  "dial_failures": 3,
  "bytes_in": 1048576,
  "bytes_out": 2097152,
  "started_at": "2026-07-15T19:00:00+08:00",
  "uptime_seconds": 1800.5
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| total_connections | uint64 | 启动至今累计接受的连接数 |
| active_connections | uint64 | 当前活跃连接数 |
| dial_successes | uint64 | 累计后端拨号成功数 |
| dial_failures | uint64 | 累计后端拨号失败数 |
| bytes_in | uint64 | 累计从客户端读取的字节数 |
| bytes_out | uint64 | 累计向客户端写入的字节数 |
| started_at | string | 服务器启动时间 (RFC 3339) |
| uptime_seconds | float | 运行时长（秒） |

---

#### GET /stats/frontends/{name}

返回指定 frontend 的统计信息和活跃连接列表。

**路径参数:**

| 参数 | 说明 |
|------|------|
| name | frontend 名称 |

**响应 200 OK:**

```json
{
  "frontend": "local_http_proxy",
  "active_connections": 2,
  "bytes_in": 524288,
  "bytes_out": 1048576,
  "connections": [
    {
      "id": "conn-a1b2c3d4-1",
      "frontend": "local_http_proxy",
      "remote_addr": "192.168.1.10:54321",
      "target": "example.com:443",
      "protocol": "tls",
      "network": "tcp",
      "started_at": "2026-07-15T19:25:00+08:00",
      "bytes_in": 2048,
      "bytes_out": 8192
    }
  ]
}
```

---

### 连接

#### GET /connections

返回所有活跃连接列表，支持按 frontend 过滤。

**查询参数:**

| 参数 | 说明 |
|------|------|
| frontend | （可选）按 frontend 名称过滤 |

**响应 200 OK:**

```json
{
  "count": 3,
  "connections": [
    {
      "id": "conn-a1b2c3d4-1",
      "frontend": "local_http_proxy",
      "remote_addr": "192.168.1.10:54321",
      "target": "example.com:443",
      "protocol": "tls",
      "network": "tcp",
      "started_at": "2026-07-15T19:25:00+08:00",
      "bytes_in": 2048,
      "bytes_out": 8192
    }
  ]
}
```

---

#### GET /connections/{id}

返回单个活跃连接的详情。

**路径参数:**

| 参数 | 说明 |
|------|------|
| id | 连接 ID |

**响应 200 OK:**

```json
{
  "id": "conn-a1b2c3d4-1",
  "frontend": "local_http_proxy",
  "remote_addr": "192.168.1.10:54321",
  "target": "example.com:443",
  "protocol": "tls",
  "network": "tcp",
  "started_at": "2026-07-15T19:25:00+08:00",
  "bytes_in": 2048,
  "bytes_out": 8192
}
```

**响应 404 Not Found:**

```json
{"error": "connection not found"}
```

---

#### DELETE /connections/{id}

关闭指定的活跃连接。

**响应 501 Not Implemented:** 连接关闭功能暂未实现。

---

### 配置

#### GET /config

返回当前生效的配置（已脱敏，password 等敏感字段被隐藏）。

**响应 200 OK:**

```json
{
  "frontend": "local_http_proxy",
  "frontends": {
    "local_http_proxy": {
      "type": "httpproxy",
      "listen_address": "127.0.0.1"
    }
  }
}
```

**响应 501 Not Implemented:** 配置端点未配置。

---

#### POST /config/reload

触发热重载配置文件。发送控制请求到主 goroutine，返回 `202 Accepted`。重载结果通过 SSE 事件流推送（`config_reloaded` 或 `config_reload_failed` 事件）。

**响应 202 Accepted:**

```json
{
  "job_id": "reload",
  "message": "reload request submitted"
}
```

**响应 501 Not Implemented:** 控制通道未配置。

---

### Frontends

#### GET /frontends

返回所有已配置的 frontend。

**响应 200 OK:**

```json
{
  "count": 2,
  "frontends": [
    {"name": "local_http_proxy", "type": "httpproxy"},
    {"name": "local_socks_proxy", "type": "socksproxy"}
  ]
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| name | string | frontend 名称 |
| type | string | frontend 类型 (httpproxy/socksproxy/tun) |

---

### Backends

#### GET /backends

返回所有已配置的 backend 及其能力。

**响应 200 OK:**

```json
{
  "count": 3,
  "backends": [
    {
      "name": "direct_out",
      "type": "direct",
      "capabilities": [
        {"network": "tcp", "protocol": "*"},
        {"network": "udp", "protocol": "*"}
      ]
    }
  ]
}
```

| 字段 | 类型 | 说明 |
|------|------|------|
| name | string | backend 名称 |
| type | string | backend 类型 (direct/httpproxy/socksproxy) |
| capabilities | array | 支持的网络/协议组合 |

---

### 事件流

#### GET /events

通过 Server-Sent Events (SSE) 推送实时生命周期事件。

**查询参数:**

| 参数 | 说明 |
|------|------|
| topics | （可选）按事件类型过滤，逗号分隔。如 `?topics=connect,disconnect`。未指定时接收所有事件 |

**响应头:**

```
Content-Type: text/event-stream
Cache-Control: no-cache
Connection: keep-alive
```

**消息格式:**

```
data: {"type":"connect","time":"2026-07-15T19:25:00+08:00","frontend":"local_http_proxy","connection_id":"conn-a1b2c3d4-1","target":"example.com:443","remote_addr":"192.168.1.10:54321"}

data: {"type":"disconnect","time":"2026-07-15T19:26:00+08:00","frontend":"local_http_proxy","connection_id":"conn-a1b2c3d4-1","target":"example.com:443"}

data: {"type":"dial_failed","time":"2026-07-15T19:27:00+08:00","frontend":"local_http_proxy","target":"unreachable.com:443","remote_addr":"192.168.1.10:54322","message":"connection refused"}

data: {"type":"config_reloaded","time":"2026-07-15T19:28:00+08:00"}

```

**事件类型:**

| 类型 | 说明 | 特有字段 |
|------|------|----------|
| `connect` | 隧道建立 | frontend, connection_id, target, remote_addr |
| `disconnect` | 隧道关闭 | frontend, connection_id, target |
| `dial_failed` | 后端拨号失败 | frontend, target, remote_addr, message |
| `config_reloaded` | 配置热重载成功 | — |
| `config_reload_failed` | 配置热重载失败 | message |
| `shutdown` | 服务器正在关闭 | — |

**心跳:** 服务器每 15 秒发送一个 SSE 注释 `: ping\n\n` 以保持连接活跃。

**SSE 消息字段:**

| 字段 | 类型 | 说明 |
|------|------|------|
| type | string | 事件类型 |
| time | string | 事件时间 (RFC 3339) |
| frontend | string | 关联的 frontend 名称（如有） |
| connection_id | string | 关联的连接 ID（如有） |
| target | string | 目标地址（如有） |
| remote_addr | string | 客户端地址（如有） |
| message | string | 人类可读的详情（如有） |

**JavaScript 示例:**

```javascript
// 接收所有事件
const es = new EventSource("https://127.0.0.1:8443/api/v1/events", {
  withCredentials: true,
});
// 注意: EventSource 不支持自定义 header，需通过其他方式传递 token
// 建议使用 fetch + ReadableStream 实现带认证的 SSE 客户端

// 只接收连接事件
const es = new EventSource("https://127.0.0.1:8443/api/v1/events?topics=connect,disconnect", {
  withCredentials: true,
});

es.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log(data.type, data);
};
```

**curl 示例:**

```bash
# 接收所有事件
curl -k -N -H "Authorization: Bearer <token>" https://127.0.0.1:8443/api/v1/events

# 只接收连接和断开事件
curl -k -N -H "Authorization: Bearer <token>" "https://127.0.0.1:8443/api/v1/events?topics=connect,disconnect"
```

---

## 错误码汇总

| 状态码 | 含义 |
|--------|------|
| 200 OK | 请求成功 |
| 202 Accepted | 异步操作已接受 |
| 204 No Content | CORS 预检成功 |
| 400 Bad Request | 请求参数错误 |
| 401 Unauthorized | 认证失败 |
| 404 Not Found | 资源不存在 |
| 405 Method Not Allowed | HTTP 方法不被允许 |
| 500 Internal Server Error | 服务器内部错误 |
| 501 Not Implemented | 功能未配置/未实现 |
| 503 Service Unavailable | 控制通道繁忙 |
