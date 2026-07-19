//! Backends page: GET /backends.

use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Borders, Row, Table};
use ratatui::Frame;

use super::widgets::{empty_block, error_block, loading_block};
use crate::app::App;

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    match (&app.backends.data, &app.backends.error) {
        (Some(resp), _) if resp.backends.is_empty() => {
            f.render_widget(empty_block("未配置任何 backend"), area);
        }
        (Some(resp), _) => {
            let header = Row::new(["名称", "类型", "能力 (network/protocol)"]).style(
                Style::default()
                    .fg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            );
            let rows = resp.backends.iter().map(|b| {
                let caps = b
                    .capabilities
                    .iter()
                    .map(|c| format!("{}/{}", c.network, c.protocol))
                    .collect::<Vec<_>>()
                    .join("  ");
                Row::new(vec![b.name.clone(), b.backend_type.clone(), caps])
            });
            let table = Table::new(
                rows,
                [
                    Constraint::Percentage(30),
                    Constraint::Percentage(20),
                    Constraint::Percentage(50),
                ],
            )
            .header(header)
            .block(
                Block::default()
                    .title(format!("Backends ({})", resp.count))
                    .borders(Borders::ALL),
            );
            f.render_widget(table, area);
        }
        (None, Some(err)) => f.render_widget(error_block(err), area),
        (None, None) => f.render_widget(loading_block(), area),
    }
}
