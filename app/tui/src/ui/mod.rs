//! Root layout: header / page body / footer help bar.

use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph};
use ratatui::Frame;

use crate::app::{App, ConnStatus, Page};

pub mod backends;
pub mod config;
pub mod connections;
pub mod events;
pub mod fmt;
pub mod frontends;
pub mod overview;
pub mod stats;
pub mod widgets;

pub fn draw(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2), // header
            Constraint::Min(3),    // body
            Constraint::Length(1), // footer
        ])
        .split(f.area());

    draw_header(f, app, chunks[0]);
    draw_body(f, app, chunks[1]);
    draw_footer(f, app, chunks[2]);
}

fn draw_header(f: &mut Frame, app: &App, area: Rect) {
    let tabs: Vec<Span> = Page::ALL
        .iter()
        .enumerate()
        .flat_map(|(i, p)| {
            let style = if *p == app.page {
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
            } else {
                Style::default().fg(Color::DarkGray)
            };
            vec![
                Span::styled(format!("{}:{}", i + 1, p.title()), style),
                Span::raw("  "),
            ]
        })
        .collect();

    let status = match &app.conn {
        ConnStatus::Online => widgets::conn_badge(true),
        ConnStatus::Offline(_) => widgets::conn_badge(false),
        ConnStatus::Checking => Span::styled("… 检测中", Style::default().fg(Color::Yellow)),
    };

    let mut right = vec![Span::raw(format!("{}  ", app.page.subtitle())), status];
    if let ConnStatus::Offline(err) = &app.conn {
        right.push(Span::styled(
            format!("  ({err})"),
            Style::default().fg(Color::DarkGray),
        ));
    }

    let top = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Min(40), Constraint::Min(30)])
        .split(area);
    f.render_widget(Paragraph::new(Line::from(tabs)), top[0]);
    f.render_widget(
        Paragraph::new(Line::from(right)).alignment(ratatui::layout::Alignment::Right),
        top[1],
    );
}

fn draw_body(f: &mut Frame, app: &App, area: Rect) {
    match app.page {
        Page::Overview => overview::draw(f, app, area),
        Page::Stats => stats::draw(f, app, area),
        Page::Connections => connections::draw(f, app, area),
        Page::Frontends => frontends::draw(f, app, area),
        Page::Backends => backends::draw(f, app, area),
        Page::Config => config::draw(f, app, area),
        Page::Events => events::draw(f, app, area),
    }
}

fn draw_footer(f: &mut Frame, app: &App, area: Rect) {
    let mut spans = vec![
        Span::styled(" q", Style::default().fg(Color::Cyan)),
        Span::raw(" 退出  "),
        Span::styled("Tab/1-7", Style::default().fg(Color::Cyan)),
        Span::raw(" 切页  "),
        Span::styled("r", Style::default().fg(Color::Cyan)),
        Span::raw(" 刷新  "),
        Span::styled("R", Style::default().fg(Color::Cyan)),
        Span::raw(" 重载配置  "),
        Span::styled("j/k/↑/↓", Style::default().fg(Color::Cyan)),
        Span::raw(" 移动/滚动  "),
        Span::styled("g/G", Style::default().fg(Color::Cyan)),
        Span::raw(" 顶/底"),
    ];
    if let Some((notice, _)) = &app.notice {
        spans.push(Span::raw("   "));
        spans.push(Span::styled(
            notice.clone(),
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ));
    }
    f.render_widget(
        Paragraph::new(Line::from(spans)).block(Block::default()),
        area,
    );
}
