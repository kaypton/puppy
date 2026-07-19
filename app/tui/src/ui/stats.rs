//! Stats page: GET /stats — 全局统计快照.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::widgets::{Block, Borders, Gauge, Paragraph};
use ratatui::Frame;

use super::fmt::{fmt_bytes, fmt_time, fmt_uptime};
use super::widgets::{error_block, loading_block};
use crate::app::App;

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    match (&app.stats.data, &app.stats.error) {
        (Some(stats), _) => draw_stats(f, stats, area),
        (None, Some(err)) => f.render_widget(error_block(err), area),
        (None, None) => f.render_widget(loading_block(), area),
    }
}

fn draw_stats(f: &mut Frame, stats: &crate::api::types::Stats, area: Rect) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(4),
            Constraint::Length(4),
            Constraint::Min(3),
        ])
        .split(area);

    let metrics: [(&str, String); 8] = [
        ("累计连接", stats.total_connections.to_string()),
        ("活跃连接", stats.active_connections.to_string()),
        ("拨号成功", stats.dial_successes.to_string()),
        ("拨号失败", stats.dial_failures.to_string()),
        ("入站字节", fmt_bytes(stats.bytes_in)),
        ("出站字节", fmt_bytes(stats.bytes_out)),
        ("启动时间", fmt_time(&stats.started_at)),
        ("运行时长", fmt_uptime(stats.uptime_seconds)),
    ];
    for (row, chunk) in rows[..2].iter().enumerate() {
        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Ratio(1, 4); 4])
            .split(*chunk);
        for (col, cell) in cols.iter().enumerate() {
            let (label, value) = &metrics[row * 4 + col];
            f.render_widget(
                Paragraph::new(vec![
                    ratatui::text::Line::from(ratatui::text::Span::styled(
                        label.to_string(),
                        Style::default().fg(Color::DarkGray),
                    )),
                    ratatui::text::Line::from(ratatui::text::Span::styled(
                        value.clone(),
                        Style::default().add_modifier(ratatui::style::Modifier::BOLD),
                    )),
                ])
                .block(Block::default().borders(Borders::ALL)),
                *cell,
            );
        }
    }

    // 拨号成功率（阈值与 Electron 版一致：>=95 绿，>=80 黄，否则红）。
    let total = stats.dial_successes + stats.dial_failures;
    let (ratio, label) = if total > 0 {
        let r = stats.dial_successes as f64 / total as f64;
        (
            r,
            format!("{:.2}% ({}/{})", r * 100.0, stats.dial_successes, total),
        )
    } else {
        (0.0, "暂无拨号数据".to_string())
    };
    let color = if total == 0 {
        Color::DarkGray
    } else if ratio >= 0.95 {
        Color::Green
    } else if ratio >= 0.80 {
        Color::Yellow
    } else {
        Color::Red
    };
    f.render_widget(
        Gauge::default()
            .block(Block::default().title("拨号成功率").borders(Borders::ALL))
            .gauge_style(Style::default().fg(color))
            .ratio(ratio)
            .label(label),
        rows[2],
    );
}
