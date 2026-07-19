//! Data transfer objects matching docs/HTTP-API.md (API v1).

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// 系统 / 统计
// ---------------------------------------------------------------------------

/// GET /system 响应。
#[derive(Debug, Clone, Deserialize)]
pub struct SystemInfo {
    pub version: String,
    pub go_version: String,
    pub started_at: String,
    pub uptime_seconds: f64,
    pub pid: u64,
    pub active_connections: u64,
    pub sse_subscribers: u64,
}

/// GET /stats 响应。
#[derive(Debug, Clone, Deserialize)]
pub struct Stats {
    pub total_connections: u64,
    pub active_connections: u64,
    pub dial_successes: u64,
    pub dial_failures: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub started_at: String,
    pub uptime_seconds: f64,
}

// ---------------------------------------------------------------------------
// 连接
// ---------------------------------------------------------------------------

/// 单条活跃连接（/connections、/stats/frontends/{name} 内嵌）。
#[derive(Debug, Clone, Deserialize)]
pub struct Connection {
    pub id: String,
    pub frontend: String,
    pub remote_addr: String,
    pub target: String,
    pub protocol: String,
    pub network: String,
    pub started_at: String,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

/// GET /connections 响应。
#[derive(Debug, Clone, Deserialize)]
pub struct ConnectionsResponse {
    pub count: u64,
    #[serde(default)]
    pub connections: Vec<Connection>,
}

// ---------------------------------------------------------------------------
// Frontends / Backends
// ---------------------------------------------------------------------------

/// 单个 frontend 摘要。
#[derive(Debug, Clone, Deserialize)]
pub struct FrontendSummary {
    pub name: String,
    #[serde(rename = "type")]
    pub frontend_type: String,
}

/// GET /frontends 响应。
#[derive(Debug, Clone, Deserialize)]
pub struct FrontendsResponse {
    pub count: u64,
    #[serde(default)]
    pub frontends: Vec<FrontendSummary>,
}

/// backend 支持的一组 network/protocol 能力。
#[derive(Debug, Clone, Deserialize)]
pub struct BackendCapability {
    pub network: String,
    pub protocol: String,
}

/// 单个 backend 摘要。
#[derive(Debug, Clone, Deserialize)]
pub struct BackendSummary {
    pub name: String,
    #[serde(rename = "type")]
    pub backend_type: String,
    #[serde(default)]
    pub capabilities: Vec<BackendCapability>,
}

/// GET /backends 响应。
#[derive(Debug, Clone, Deserialize)]
pub struct BackendsResponse {
    pub count: u64,
    #[serde(default)]
    pub backends: Vec<BackendSummary>,
}

// ---------------------------------------------------------------------------
// 配置
// ---------------------------------------------------------------------------

/// GET /config 返回脱敏后的运行时配置，结构松散，保留原始 JSON。
pub type ConfigResponse = serde_json::Value;

// ---------------------------------------------------------------------------
// 异步操作 (202 Accepted)
// ---------------------------------------------------------------------------

/// POST /config/reload、POST /system/shutdown 的 202 响应。
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)] // message 是 API 契约的一部分，UI 只展示 job_id
pub struct JobAccepted {
    pub job_id: String,
    pub message: String,
}

// ---------------------------------------------------------------------------
// 错误
// ---------------------------------------------------------------------------

/// 非 2xx 响应的错误体 `{"error": "..."}`。
#[derive(Debug, Clone, Deserialize)]
pub struct ApiErrorBody {
    pub error: String,
}

// ---------------------------------------------------------------------------
// SSE 事件流
// ---------------------------------------------------------------------------

/// GET /events 推送的生命周期事件。特有字段视事件类型可能缺省。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SseEvent {
    #[serde(rename = "type")]
    pub event_type: String,
    pub time: String,
    #[serde(default)]
    pub frontend: Option<String>,
    #[serde(default)]
    pub connection_id: Option<String>,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub remote_addr: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_info_deserializes_doc_example() {
        let json = r#"{
            "version": "v1",
            "go_version": "go1.26.3",
            "started_at": "2026-07-15T19:00:00+08:00",
            "uptime_seconds": 1800.5,
            "pid": 12345,
            "active_connections": 3,
            "sse_subscribers": 1
        }"#;
        let info: SystemInfo = serde_json::from_str(json).unwrap();
        assert_eq!(info.version, "v1");
        assert_eq!(info.pid, 12345);
        assert!((info.uptime_seconds - 1800.5).abs() < f64::EPSILON);
    }

    #[test]
    fn stats_deserializes_doc_example() {
        let json = r#"{
            "total_connections": 150,
            "active_connections": 3,
            "dial_successes": 147,
            "dial_failures": 3,
            "bytes_in": 1048576,
            "bytes_out": 2097152,
            "started_at": "2026-07-15T19:00:00+08:00",
            "uptime_seconds": 1800.5
        }"#;
        let stats: Stats = serde_json::from_str(json).unwrap();
        assert_eq!(stats.total_connections, 150);
        assert_eq!(stats.bytes_out, 2_097_152);
    }

    #[test]
    fn connection_deserializes_doc_example() {
        let json = r#"{
            "id": "conn-a1b2c3d4-1",
            "frontend": "local_http_proxy",
            "remote_addr": "192.168.1.10:54321",
            "target": "example.com:443",
            "protocol": "tls",
            "network": "tcp",
            "started_at": "2026-07-15T19:25:00+08:00",
            "bytes_in": 2048,
            "bytes_out": 8192
        }"#;
        let conn: Connection = serde_json::from_str(json).unwrap();
        assert_eq!(conn.id, "conn-a1b2c3d4-1");
        assert_eq!(conn.protocol, "tls");
    }

    #[test]
    fn frontends_deserializes_doc_example() {
        let json = r#"{
            "count": 2,
            "frontends": [
                {"name": "local_http_proxy", "type": "httpproxy"},
                {"name": "local_socks_proxy", "type": "socksproxy"}
            ]
        }"#;
        let resp: FrontendsResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.count, 2);
        assert_eq!(resp.frontends[1].frontend_type, "socksproxy");
    }

    #[test]
    fn backends_deserializes_doc_example() {
        let json = r#"{
            "count": 1,
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
        }"#;
        let resp: BackendsResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.backends[0].capabilities.len(), 2);
        assert_eq!(resp.backends[0].backend_type, "direct");
    }

    #[test]
    fn sse_event_deserializes_variants() {
        let connect = r#"{"type":"connect","time":"2026-07-15T19:25:00+08:00","frontend":"local_http_proxy","connection_id":"conn-a1b2c3d4-1","target":"example.com:443","remote_addr":"192.168.1.10:54321"}"#;
        let ev: SseEvent = serde_json::from_str(connect).unwrap();
        assert_eq!(ev.event_type, "connect");
        assert_eq!(ev.target.as_deref(), Some("example.com:443"));
        assert!(ev.message.is_none());

        let reload_failed = r#"{"type":"config_reload_failed","time":"2026-07-15T19:28:00+08:00","message":"bad toml"}"#;
        let ev: SseEvent = serde_json::from_str(reload_failed).unwrap();
        assert_eq!(ev.event_type, "config_reload_failed");
        assert_eq!(ev.message.as_deref(), Some("bad toml"));
        assert!(ev.frontend.is_none());
    }

    #[test]
    fn api_error_body_deserializes() {
        let body: ApiErrorBody = serde_json::from_str(r#"{"error":"unauthorized"}"#).unwrap();
        assert_eq!(body.error, "unauthorized");
    }

    #[test]
    fn job_accepted_deserializes() {
        let job: JobAccepted =
            serde_json::from_str(r#"{"job_id":"reload","message":"reload request submitted"}"#)
                .unwrap();
        assert_eq!(job.job_id, "reload");
    }
}
