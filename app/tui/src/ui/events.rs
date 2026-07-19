//! Events page: GET /events — SSE 实时事件流.

use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use crate::api::types::SseEvent;
use crate::app::App;

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    let height = area.height.saturating_sub(2) as usize; // 边框
    let total = app.events.len();
    let scroll = app.events_scroll as usize;

    // events_scroll = 距底部偏移；计算可见窗口的起点。
    let end = total.saturating_sub(scroll);
    let start = end.saturating_sub(height);

    let lines: Vec<Line> = app
        .events
        .iter()
        .skip(start)
        .take(end - start)
        .map(render_event)
        .collect();

    let title = if scroll > 0 {
        format!("事件 ({total}) — 向上滚动 {scroll} 条，G 回到底部")
    } else {
        format!("事件 ({total})")
    };

    f.render_widget(
        Paragraph::new(lines).block(Block::default().title(title).borders(Borders::ALL)),
        area,
    );
}

fn render_event(ev: &SseEvent) -> Line<'static> {
    let (tag, color) = match ev.event_type.as_str() {
        "connect" => ("CONNECT ", Color::Green),
        "disconnect" => ("DISCONN ", Color::DarkGray),
        "dial_failed" => ("DIALFAIL", Color::Red),
        "config_reloaded" => ("RELOADED", Color::Yellow),
        "config_reload_failed" => ("RELOADERR", Color::Red),
        "shutdown" => ("SHUTDOWN", Color::Magenta),
        other => (other, Color::Cyan),
    };
    let mut spans = vec![
        Span::styled(
            format!("[{}] ", short_time(&ev.time)),
            Style::default().fg(Color::DarkGray),
        ),
        Span::styled(
            format!("{tag:<9}"),
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        ),
    ];
    if let Some(fe) = &ev.frontend {
        spans.push(Span::raw(format!(" {fe}")));
    }
    if let Some(t) = &ev.target {
        spans.push(Span::styled(
            format!(" → {t}"),
            Style::default().fg(Color::Cyan),
        ));
    }
    if let Some(m) = &ev.message {
        spans.push(Span::styled(
            format!(" ({m})"),
            Style::default().fg(Color::Red),
        ));
    }
    Line::from(spans)
}

/// "2026-07-15T19:30:00+08:00" -> "19:30:00"
fn short_time(iso: &str) -> String {
    if iso.len() >= 19 && iso.as_bytes()[10] == b'T' {
        iso[11..19].to_string()
    } else {
        iso.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_time_extracts_hms() {
        assert_eq!(short_time("2026-07-15T19:30:00+08:00"), "19:30:00");
        assert_eq!(short_time("bad"), "bad");
    }
}
