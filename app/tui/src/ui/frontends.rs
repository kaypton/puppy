//! Frontends page: GET /frontends.

use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, Borders, Row, Table};
use ratatui::Frame;

use super::widgets::{empty_block, error_block, loading_block};
use crate::app::App;

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    match (&app.frontends.data, &app.frontends.error) {
        (Some(resp), _) if resp.frontends.is_empty() => {
            f.render_widget(empty_block("未配置任何 frontend"), area);
        }
        (Some(resp), _) => {
            let header = Row::new(["名称", "类型"]).style(
                Style::default()
                    .fg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            );
            let rows = resp
                .frontends
                .iter()
                .map(|fe| Row::new(vec![fe.name.clone(), fe.frontend_type.clone()]));
            let table = Table::new(
                rows,
                [Constraint::Percentage(60), Constraint::Percentage(40)],
            )
            .header(header)
            .block(
                Block::default()
                    .title(format!("Frontends ({})", resp.count))
                    .borders(Borders::ALL),
            );
            f.render_widget(table, area);
        }
        (None, Some(err)) => f.render_widget(error_block(err), area),
        (None, None) => f.render_widget(loading_block(), area),
    }
}
