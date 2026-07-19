//! Application state machine.

use std::collections::VecDeque;
use std::time::Instant;

use crate::api::types::{
    BackendsResponse, ConfigResponse, ConnectionsResponse, FrontendsResponse, SseEvent, Stats,
    SystemInfo,
};

/// Top-level pages, switchable via Tab / Shift-Tab / number keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Page {
    Overview,
    Stats,
    Connections,
    Frontends,
    Backends,
    Config,
    Events,
}

impl Page {
    /// All pages in display order (number key = index + 1).
    pub const ALL: [Page; 7] = [
        Page::Overview,
        Page::Stats,
        Page::Connections,
        Page::Frontends,
        Page::Backends,
        Page::Config,
        Page::Events,
    ];

    /// Chinese title shown in the header, mirroring the Electron sidebar labels.
    pub fn title(self) -> &'static str {
        match self {
            Page::Overview => "系统概览",
            Page::Stats => "统计",
            Page::Connections => "连接",
            Page::Frontends => "Frontends",
            Page::Backends => "Backends",
            Page::Config => "配置",
            Page::Events => "事件",
        }
    }

    /// API endpoint hint shown in the header, mirroring PageHeader subtitles.
    pub fn subtitle(self) -> &'static str {
        match self {
            Page::Overview => "GET /system — 服务器运行信息",
            Page::Stats => "GET /stats — 全局统计快照",
            Page::Connections => "GET /connections — 活跃连接列表",
            Page::Frontends => "GET /frontends — 已配置的 frontend 列表",
            Page::Backends => "GET /backends — 已配置的 backend 及能力",
            Page::Config => "GET /config — 当前生效的脱敏配置",
            Page::Events => "GET /events — SSE 实时事件流",
        }
    }

    pub fn next(self) -> Page {
        let idx = Self::ALL.iter().position(|p| *p == self).unwrap_or(0);
        Self::ALL[(idx + 1) % Self::ALL.len()]
    }

    pub fn prev(self) -> Page {
        let idx = Self::ALL.iter().position(|p| *p == self).unwrap_or(0);
        Self::ALL[(idx + Self::ALL.len() - 1) % Self::ALL.len()]
    }

    /// Page for 1-based number key, if any.
    pub fn from_digit(d: u8) -> Option<Page> {
        if d == 0 {
            return None;
        }
        Self::ALL.get(usize::from(d) - 1).copied()
    }
}

/// Connectivity state shown in the header.
#[derive(Debug, Clone)]
pub enum ConnStatus {
    Checking,
    Online,
    Offline(String),
}

/// Per-endpoint fetch result cache: data + error + when it completed.
#[derive(Debug, Clone)]
pub struct FetchState<T> {
    pub data: Option<T>,
    pub error: Option<String>,
    /// HTTP status for special handling (e.g. 501 on /config).
    pub status: Option<u16>,
    pub updated: Option<Instant>,
    pub loading: bool,
}

impl<T> Default for FetchState<T> {
    fn default() -> Self {
        Self {
            data: None,
            error: None,
            status: None,
            updated: None,
            loading: false,
        }
    }
}

impl<T> FetchState<T> {
    pub fn set_ok(&mut self, data: T) {
        self.data = Some(data);
        self.error = None;
        self.status = None;
        self.updated = Some(Instant::now());
        self.loading = false;
    }

    pub fn set_err(&mut self, msg: String, status: Option<u16>) {
        self.error = Some(msg);
        self.status = status;
        self.updated = Some(Instant::now());
        self.loading = false;
    }
}

/// Maximum events kept in the ring buffer.
pub const EVENT_BUFFER: usize = 500;

/// Root application state.
#[derive(Debug)]
pub struct App {
    pub page: Page,
    pub conn: ConnStatus,
    pub should_quit: bool,

    pub system: FetchState<SystemInfo>,
    pub stats: FetchState<Stats>,
    pub connections: FetchState<ConnectionsResponse>,
    pub frontends: FetchState<FrontendsResponse>,
    pub backends: FetchState<BackendsResponse>,
    pub config: FetchState<ConfigResponse>,

    pub events: VecDeque<SseEvent>,
    /// Selected row index in the connections table.
    pub conn_selected: usize,
    /// Vertical scroll offset (lines) of the config JSON view.
    pub config_scroll: u16,
    /// Vertical scroll offset (events from bottom: 0 = follow tail).
    pub events_scroll: u16,

    /// One-shot status-bar notice (e.g. reload accepted), with timestamp.
    pub notice: Option<(String, Instant)>,
}

impl App {
    pub fn new() -> Self {
        Self {
            page: Page::Overview,
            conn: ConnStatus::Checking,
            should_quit: false,
            system: FetchState::default(),
            stats: FetchState::default(),
            connections: FetchState::default(),
            frontends: FetchState::default(),
            backends: FetchState::default(),
            config: FetchState::default(),
            events: VecDeque::with_capacity(EVENT_BUFFER),
            conn_selected: 0,
            config_scroll: 0,
            events_scroll: 0,
            notice: None,
        }
    }

    /// Appends an SSE event to the ring buffer, dropping the oldest at capacity.
    pub fn push_event(&mut self, ev: SseEvent) {
        if self.events.len() >= EVENT_BUFFER {
            self.events.pop_front();
        }
        self.events.push_back(ev);
    }

    /// Sets a transient status-bar notice.
    pub fn set_notice(&mut self, msg: impl Into<String>) {
        self.notice = Some((msg.into(), Instant::now()));
    }

    /// Clears notices older than 8 seconds (called on each tick).
    pub fn expire_notice(&mut self) {
        let expired = match &self.notice {
            Some((_, at)) => at.elapsed().as_secs() >= 8,
            None => false,
        };
        if expired {
            self.notice = None;
        }
    }

    /// Moves the connections-table selection by `delta` (clamped).
    pub fn move_connection_selection(&mut self, delta: i64) {
        let len = self
            .connections
            .data
            .as_ref()
            .map(|c| c.connections.len())
            .unwrap_or(0);
        if len == 0 {
            self.conn_selected = 0;
            return;
        }
        let cur = self.conn_selected as i64 + delta;
        self.conn_selected = cur.clamp(0, len as i64 - 1) as usize;
    }

    /// Scrolls the config view by `delta` lines.
    pub fn scroll_config(&mut self, delta: i64) {
        let cur = self.config_scroll as i64 + delta;
        self.config_scroll = cur.max(0) as u16;
    }

    /// Scrolls the events view away from the tail (positive = up).
    pub fn scroll_events(&mut self, delta: i64) {
        let cur = self.events_scroll as i64 + delta;
        let max = self.events.len().saturating_sub(1) as i64;
        self.events_scroll = cur.clamp(0, max) as u16;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_navigation_cycles() {
        let mut p = Page::Overview;
        for _ in 0..Page::ALL.len() {
            p = p.next();
        }
        assert_eq!(p, Page::Overview);
        assert_eq!(Page::Overview.prev(), Page::Events);
    }

    #[test]
    fn page_from_digit() {
        assert_eq!(Page::from_digit(1), Some(Page::Overview));
        assert_eq!(Page::from_digit(7), Some(Page::Events));
        assert_eq!(Page::from_digit(8), None);
        assert_eq!(Page::from_digit(0), None);
    }

    #[test]
    fn event_ring_buffer_caps_at_limit() {
        let mut app = App::new();
        for i in 0..EVENT_BUFFER + 50 {
            app.push_event(SseEvent {
                event_type: "connect".into(),
                time: format!("t{i}"),
                frontend: None,
                connection_id: None,
                target: None,
                remote_addr: None,
                message: None,
            });
        }
        assert_eq!(app.events.len(), EVENT_BUFFER);
        assert_eq!(app.events.front().unwrap().time, "t50");
    }

    #[test]
    fn connection_selection_clamped() {
        let mut app = App::new();
        app.move_connection_selection(-1);
        assert_eq!(app.conn_selected, 0);
        app.set_ok_connections_fixture();
        app.move_connection_selection(99);
        assert_eq!(app.conn_selected, 2);
        app.move_connection_selection(-99);
        assert_eq!(app.conn_selected, 0);
    }

    impl App {
        fn set_ok_connections_fixture(&mut self) {
            use crate::api::types::Connection;
            let mk = |id: &str| Connection {
                id: id.into(),
                frontend: "f".into(),
                remote_addr: "r".into(),
                target: "t".into(),
                protocol: "tls".into(),
                network: "tcp".into(),
                started_at: "s".into(),
                bytes_in: 0,
                bytes_out: 0,
            };
            self.connections.set_ok(ConnectionsResponse {
                count: 3,
                connections: vec![mk("a"), mk("b"), mk("c")],
            });
        }
    }
}
