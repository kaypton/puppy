//! Shared UI widgets.

use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

/// 标签-值行（标签灰色定宽）。
pub fn kv<'a>(label: &'a str, value: String) -> Line<'a> {
    Line::from(vec![
        Span::styled(format!("{label:<12}"), Style::default().fg(Color::DarkGray)),
        Span::raw(value),
    ])
}

/// 带边框的分组卡片。
pub fn card<'a>(title: &'a str, lines: Vec<Line<'a>>) -> Paragraph<'a> {
    Paragraph::new(lines).block(Block::default().title(title).borders(Borders::ALL))
}

/// 加载占位。
pub fn loading_block() -> Paragraph<'static> {
    Paragraph::new("加载中…").block(Block::default().borders(Borders::ALL))
}

/// 错误展示。
pub fn error_block(err: &str) -> Paragraph<'_> {
    Paragraph::new(Line::from(vec![
        Span::styled("获取失败：", Style::default().fg(Color::Red)),
        Span::raw(err.to_string()),
    ]))
    .block(Block::default().borders(Borders::ALL))
}

/// 空数据展示。
pub fn empty_block(msg: &str) -> Paragraph<'_> {
    Paragraph::new(msg.to_string()).block(Block::default().borders(Borders::ALL))
}

/// 状态徽章样式（连接状态用）。
pub fn conn_badge(online: bool) -> Span<'static> {
    if online {
        Span::styled(
            "● 已连接",
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(
            "● 离线",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )
    }
}
