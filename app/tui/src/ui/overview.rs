//! Overview page: GET /system — 服务器运行信息.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::Frame;

use super::fmt::{fmt_time, fmt_uptime};
use super::widgets::{card, error_block, kv, loading_block};
use crate::app::App;

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    match (&app.system.data, &app.system.error) {
        (Some(info), _) => {
            let runtime = vec![
                kv("API 版本", info.version.clone()),
                kv("Go 版本", info.go_version.clone()),
                kv("PID", info.pid.to_string()),
                kv("启动时间", fmt_time(&info.started_at)),
                kv("运行时长", fmt_uptime(info.uptime_seconds)),
            ];
            let conns = vec![
                kv("活跃连接", info.active_connections.to_string()),
                kv("SSE 订阅者", info.sse_subscribers.to_string()),
            ];
            f.render_widget(card("运行时", runtime), chunks[0]);
            f.render_widget(card("连接", conns), chunks[1]);
        }
        (None, Some(err)) => f.render_widget(error_block(err), area),
        (None, None) => f.render_widget(loading_block(), area),
    }
}
