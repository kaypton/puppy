//! Server-Sent Events subscriber for GET /events.
//!
//! Parses the `text/event-stream` line protocol: `data: {...}` payloads are
//! decoded into [`SseEvent`]; `: ping` heartbeat comments and blank lines are
//! ignored. Reconnects with exponential backoff when the stream drops.

use std::time::Duration;

use futures_util::StreamExt;
use tokio::sync::mpsc;

use super::types::SseEvent;
use super::ApiClient;

/// Notifications produced by the SSE subscription task.
#[derive(Debug)]
pub enum SseMsg {
    /// A decoded lifecycle event.
    Event(SseEvent),
    /// Stream state changed (connected / disconnected with reason).
    Connected,
    Disconnected(String),
}

const INITIAL_BACKOFF: Duration = Duration::from_secs(3);
const MAX_BACKOFF: Duration = Duration::from_secs(30);

/// Subscribes to `/events` and forwards decoded events until `shutdown` fires.
///
/// `topics` optionally filters event types (comma-separated, see API docs).
pub async fn subscribe(
    client: ApiClient,
    topics: Option<String>,
    tx: mpsc::Sender<SseMsg>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let mut backoff = INITIAL_BACKOFF;
    loop {
        if *shutdown.borrow() {
            return;
        }
        match run_once(&client, topics.as_deref(), &tx, &mut shutdown).await {
            Ok(()) => return, // clean shutdown requested
            Err(reason) => {
                if tx.send(SseMsg::Disconnected(reason)).await.is_err() {
                    return;
                }
                tokio::select! {
                    _ = tokio::time::sleep(backoff) => {},
                    _ = shutdown.changed() => return,
                }
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
        }
    }
}

/// One subscription attempt. `Ok(())` means shutdown was requested; `Err`
/// carries a human-readable disconnect reason and the caller should retry.
async fn run_once(
    client: &ApiClient,
    topics: Option<&str>,
    tx: &mpsc::Sender<SseMsg>,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
) -> Result<(), String> {
    let mut url = client.url("/events");
    if let Some(t) = topics.filter(|t| !t.is_empty()) {
        url.push_str("?topics=");
        url.push_str(t);
    }

    let resp = client
        .raw()
        .get(&url)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !resp.status().is_success() {
        return Err(format!("events: HTTP {}", resp.status()));
    }
    if tx.send(SseMsg::Connected).await.is_err() {
        return Ok(());
    }

    let mut stream = resp.bytes_stream();
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let mut data_lines: Vec<String> = Vec::new();

    loop {
        tokio::select! {
            _ = shutdown.changed() => return Ok(()),
            chunk = stream.next() => {
                match chunk {
                    None => return Err("events stream closed".into()),
                    Some(Err(e)) => return Err(e.to_string()),
                    Some(Ok(bytes)) => {
                        buf.extend_from_slice(&bytes);
                        while let Some(pos) = buf.iter().position(|&b| b == b'\n') {
                            let line: Vec<u8> = buf.drain(..=pos).collect();
                            let line = String::from_utf8_lossy(&line);
                            let line = line.trim_end_matches(['\r', '\n']);
                            if line.is_empty() {
                                // 空行 = 事件边界，派发已收集的 data。
                                if !data_lines.is_empty() {
                                    let payload = data_lines.join("\n");
                                    data_lines.clear();
                                    match serde_json::from_str::<SseEvent>(&payload) {
                                        Ok(ev) => {
                                            if tx.send(SseMsg::Event(ev)).await.is_err() {
                                                return Ok(());
                                            }
                                        }
                                        Err(e) => {
                                            tracing_warn(&format!("bad event payload: {e}"));
                                        }
                                    }
                                }
                            } else if let Some(rest) = line.strip_prefix("data:") {
                                data_lines.push(rest.trim_start().to_string());
                            }
                            // `: ping` 注释与其他字段（event:/id:/retry:）忽略。
                        }
                    }
                }
            }
        }
    }
}

/// SSE 解析错误不致命，打到 stderr 供调试（TUI 原始模式下会看不到，
/// 但启动前的早期错误仍可见）。
fn tracing_warn(msg: &str) {
    eprintln!("puppy-tui: {msg}");
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 模拟服务端逐块喂字节，验证解析逻辑。直接内联一份微型解析器驱动
    /// run_once 的核心片段不可行（需要 HTTP），这里改为对解析行为做
    /// 集成式冒烟：拼一段流式文本，按行拆分逻辑与 run_once 保持一致。
    #[test]
    fn parses_data_frames() {
        let stream_text = ": ping\n\ndata: {\"type\":\"connect\",\"time\":\"2026-07-15T19:25:00+08:00\",\"frontend\":\"f1\",\"connection_id\":\"c1\",\"target\":\"example.com:443\",\"remote_addr\":\"10.0.0.1:1\"}\n\ndata: {\"type\":\"shutdown\",\"time\":\"2026-07-15T19:30:00+08:00\"}\n\n";
        let mut events = Vec::new();
        let mut data_lines: Vec<String> = Vec::new();
        for line in stream_text.split_inclusive('\n') {
            let line = line.trim_end_matches(['\r', '\n']);
            if line.is_empty() {
                if !data_lines.is_empty() {
                    let payload = data_lines.join("\n");
                    data_lines.clear();
                    events.push(serde_json::from_str::<SseEvent>(&payload).unwrap());
                }
            } else if let Some(rest) = line.strip_prefix("data:") {
                data_lines.push(rest.trim_start().to_string());
            }
        }
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event_type, "connect");
        assert_eq!(events[1].event_type, "shutdown");
    }
}
