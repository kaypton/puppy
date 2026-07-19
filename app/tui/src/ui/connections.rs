//! Connections page: GET /connections — 活跃连接表格.

use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Borders, Row, Table, TableState};
use ratatui::Frame;

use super::fmt::{fmt_bytes, fmt_elapsed_since};
use super::widgets::{empty_block, error_block, loading_block};
use crate::app::App;

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    match (&app.connections.data, &app.connections.error) {
        (Some(resp), _) if resp.connections.is_empty() => {
            f.render_widget(empty_block("当前没有活跃连接"), area);
        }
        (Some(resp), _) => {
            let header = Row::new([
                "ID", "FRONTEND", "REMOTE", "TARGET", "协议", "入站", "出站", "时长",
            ])
            .style(
                Style::default()
                    .fg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            );
            let rows = resp.connections.iter().map(|c| {
                Row::new(vec![
                    c.id.clone(),
                    c.frontend.clone(),
                    c.remote_addr.clone(),
                    c.target.clone(),
                    format!("{}/{}", c.network, c.protocol),
                    fmt_bytes(c.bytes_in),
                    fmt_bytes(c.bytes_out),
                    fmt_elapsed_since(&c.started_at),
                ])
            });
            let table = Table::new(
                rows,
                [
                    Constraint::Length(18),
                    Constraint::Length(16),
                    Constraint::Length(22),
                    Constraint::Min(24),
                    Constraint::Length(9),
                    Constraint::Length(10),
                    Constraint::Length(10),
                    Constraint::Length(10),
                ],
            )
            .header(header)
            .block(
                Block::default()
                    .title(format!("活跃连接 ({})", resp.count))
                    .borders(Borders::ALL),
            )
            .row_highlight_style(Style::default().bg(Color::DarkGray))
            .highlight_symbol("▶ ");
            let mut state = TableState::default().with_selected(app.conn_selected);
            f.render_stateful_widget(table, area, &mut state);
        }
        (None, Some(err)) => f.render_widget(error_block(err), area),
        (None, None) => f.render_widget(loading_block(), area),
    }
}
