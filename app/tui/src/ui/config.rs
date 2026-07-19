//! Config page: GET /config — 脱敏配置 JSON 视图.

use ratatui::layout::Rect;
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use super::widgets::{empty_block, error_block, loading_block};
use crate::app::App;

pub fn draw(f: &mut Frame, app: &App, area: Rect) {
    // 501 = 配置端点未配置（对齐 Electron 版的提示）。
    if app.config.status == Some(501) {
        f.render_widget(empty_block("配置端点未配置 (501 Not Implemented)"), area);
        return;
    }
    match (&app.config.data, &app.config.error) {
        (Some(cfg), _) => {
            let text = serde_json::to_string_pretty(cfg).unwrap_or_else(|_| cfg.to_string());
            f.render_widget(
                Paragraph::new(text)
                    .block(
                        Block::default()
                            .title("当前配置（脱敏）")
                            .borders(Borders::ALL),
                    )
                    .scroll((app.config_scroll, 0)),
                area,
            );
        }
        (None, Some(err)) => f.render_widget(error_block(err), area),
        (None, None) => f.render_widget(loading_block(), area),
    }
}
