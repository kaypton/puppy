//! puppy-tui: terminal UI dashboard for puppy-server.
//!
//! Talks to the puppy dashboard HTTP API (docs/HTTP-API.md) and renders
//! system info, stats, connections, frontends, backends, config and the
//! live event stream in the terminal.

mod api;
mod app;
mod config;
mod ui;

use std::time::Duration;

use clap::Parser;
use crossterm::event::{Event, EventStream, KeyCode, KeyEventKind, KeyModifiers};
use futures_util::StreamExt;
use tokio::sync::{mpsc, watch};

use api::ApiClient;
use app::{App, ConnStatus, Page};
use config::ConnectionConfig;

/// Polling interval, matching the Electron dashboard's 5s refresh.
const POLL_INTERVAL: Duration = Duration::from_secs(5);
/// UI tick / redraw cadence.
const TICK: Duration = Duration::from_millis(100);

/// Messages from background tasks into the UI loop.
enum AppMsg {
    System(Result<api::types::SystemInfo, api::ApiError>),
    Stats(Result<api::types::Stats, api::ApiError>),
    Connections(Result<api::types::ConnectionsResponse, api::ApiError>),
    Frontends(Result<api::types::FrontendsResponse, api::ApiError>),
    Backends(Result<api::types::BackendsResponse, api::ApiError>),
    Config(Result<api::types::ConfigResponse, api::ApiError>),
    Reload(Result<api::types::JobAccepted, api::ApiError>),
    Sse(api::sse::SseMsg),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cfg = ConnectionConfig::parse();
    let client = ApiClient::new(&cfg)?;

    let (tx, mut rx) = mpsc::channel::<AppMsg>(256);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // SSE 订阅（事件流 + 连接状态判定）。
    {
        let client = client.clone();
        let tx = tx.clone();
        let shutdown = shutdown_rx.clone();
        tokio::spawn(async move {
            let (sse_tx, mut sse_rx) = mpsc::channel::<api::sse::SseMsg>(256);
            let forward = tokio::spawn(async move {
                while let Some(m) = sse_rx.recv().await {
                    if tx.send(AppMsg::Sse(m)).await.is_err() {
                        break;
                    }
                }
            });
            api::sse::subscribe(client, None, sse_tx, shutdown).await;
            forward.abort();
        });
    }

    // 周期轮询任务：每 POLL_INTERVAL 请求所有端点。
    {
        let client = client.clone();
        let tx = tx.clone();
        let mut shutdown = shutdown_rx.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(POLL_INTERVAL);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = ticker.tick() => {
                        poll_once(&client, &tx);
                    }
                    _ = shutdown.changed() => return,
                }
            }
        });
    }

    // 终端初始化（guard 保证退出时恢复）。
    let mut terminal = ratatui::init();
    let mut app = App::new();
    let mut keys = EventStream::new();
    let mut ticker = tokio::time::interval(TICK);

    let result = loop {
        terminal.draw(|f| ui::draw(f, &app))?;
        app.expire_notice();

        tokio::select! {
            _ = ticker.tick() => {}
            maybe_key = keys.next() => {
                if let Some(Ok(Event::Key(key))) = maybe_key {
                    if key.kind == KeyEventKind::Press {
                        handle_key(&mut app, key.code, key.modifiers, &client, &tx);
                    }
                }
            }
            maybe_msg = rx.recv() => {
                match maybe_msg {
                    Some(msg) => apply_msg(&mut app, msg),
                    None => break Ok(()), // 所有后台任务退出
                }
            }
        }

        if app.should_quit {
            break Ok(());
        }
    };

    ratatui::restore();
    let _ = shutdown_tx.send(true);
    result
}

/// 立即发起一轮轮询（r 键手动刷新 / 定时轮询）。
fn poll_once(client: &ApiClient, tx: &mpsc::Sender<AppMsg>) {
    macro_rules! fetch {
        ($variant:ident, $method:ident) => {{
            let c = client.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                let _ = tx.send(AppMsg::$variant(c.$method().await)).await;
            });
        }};
    }
    fetch!(System, system);
    fetch!(Stats, stats);
    fetch!(Frontends, frontends);
    fetch!(Backends, backends);
    fetch!(Config, config);
    {
        let c = client.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            let _ = tx
                .send(AppMsg::Connections(c.connections(None).await))
                .await;
        });
    }
}

fn handle_key(
    app: &mut App,
    code: KeyCode,
    modifiers: KeyModifiers,
    client: &ApiClient,
    tx: &mpsc::Sender<AppMsg>,
) {
    match code {
        KeyCode::Char('c') if modifiers.contains(KeyModifiers::CONTROL) => app.should_quit = true,
        KeyCode::Char('q') => app.should_quit = true,
        KeyCode::Tab | KeyCode::Right => app.page = app.page.next(),
        KeyCode::BackTab | KeyCode::Left => app.page = app.page.prev(),
        KeyCode::Char(c @ '1'..='7') => {
            if let Some(p) = Page::from_digit(c as u8 - b'0') {
                app.page = p;
            }
        }
        KeyCode::Char('r') => poll_once(client, tx),
        KeyCode::Char('R') => {
            let c = client.clone();
            let tx = tx.clone();
            tokio::spawn(async move {
                let _ = tx.send(AppMsg::Reload(c.reload().await)).await;
            });
        }
        KeyCode::Char('j') | KeyCode::Down => match app.page {
            Page::Connections => app.move_connection_selection(1),
            Page::Config => app.scroll_config(1),
            Page::Events => app.scroll_events(-1),
            _ => {}
        },
        KeyCode::Char('k') | KeyCode::Up => match app.page {
            Page::Connections => app.move_connection_selection(-1),
            Page::Config => app.scroll_config(-1),
            Page::Events => app.scroll_events(1),
            _ => {}
        },
        KeyCode::PageDown => match app.page {
            Page::Config => app.scroll_config(20),
            Page::Events => app.scroll_events(-20),
            _ => {}
        },
        KeyCode::PageUp => match app.page {
            Page::Config => app.scroll_config(-20),
            Page::Events => app.scroll_events(20),
            _ => {}
        },
        KeyCode::Char('g') | KeyCode::Home => match app.page {
            Page::Config => app.config_scroll = 0,
            Page::Events => app.events_scroll = u16::MAX,
            _ => {}
        },
        KeyCode::Char('G') | KeyCode::End => match app.page {
            Page::Events => app.events_scroll = 0,
            Page::Config => app.config_scroll = u16::MAX / 2, // 交给渲染层截断
            _ => {}
        },
        _ => {}
    }
}

fn apply_msg(app: &mut App, msg: AppMsg) {
    match msg {
        AppMsg::System(res) => apply(&mut app.system, res, &mut app.conn),
        AppMsg::Stats(res) => apply(&mut app.stats, res, &mut app.conn),
        AppMsg::Connections(res) => apply(&mut app.connections, res, &mut app.conn),
        AppMsg::Frontends(res) => apply(&mut app.frontends, res, &mut app.conn),
        AppMsg::Backends(res) => apply(&mut app.backends, res, &mut app.conn),
        AppMsg::Config(res) => apply(&mut app.config, res, &mut app.conn),
        AppMsg::Reload(Ok(job)) => app.set_notice(format!("reload 已提交 (job={})", job.job_id)),
        AppMsg::Reload(Err(e)) => app.set_notice(format!("reload 失败：{e}")),
        AppMsg::Sse(api::sse::SseMsg::Event(ev)) => app.push_event(ev),
        AppMsg::Sse(api::sse::SseMsg::Connected) => app.conn = ConnStatus::Online,
        AppMsg::Sse(api::sse::SseMsg::Disconnected(reason)) => {
            // 轮询可能仍在成功（如 events 端点单独故障），但通常意味着离线。
            if !matches!(app.conn, ConnStatus::Online) {
                app.conn = ConnStatus::Offline(reason);
            }
        }
    }
}

fn apply<T>(slot: &mut app::FetchState<T>, res: Result<T, api::ApiError>, conn: &mut ConnStatus) {
    match res {
        Ok(data) => {
            slot.set_ok(data);
            *conn = ConnStatus::Online;
        }
        Err(e) => {
            let status = e.status();
            slot.set_err(e.to_string(), status);
            // 传输层错误才翻转全局连接状态；4xx/5xx 只影响对应面板。
            if status.is_none() {
                *conn = ConnStatus::Offline(e.to_string());
            }
        }
    }
}
