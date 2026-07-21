use std::collections::{HashMap, VecDeque};
use std::io;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use crossterm::event::{Event, EventStream, KeyCode, KeyEventKind};
use crossterm::execute;
use crossterm::terminal::{
	disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use futures_util::StreamExt;
use puppy_rpc::v1::observability_client::ObservabilityClient;
use puppy_rpc::v1::{
	Connection, ConnectionStatus, ConnectionUpdate, ListConnectionsRequest, ListLogsRequest,
	LogEntry, Overview, TrafficSample, WatchConnectionsRequest, WatchLogsRequest,
	WatchTrafficRequest,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
	Block, Borders, Cell, Clear, List, ListItem, Paragraph, Row, Sparkline, Table, Tabs, Wrap,
};
use ratatui::{Frame, Terminal};
use tokio::sync::mpsc;
use tonic::metadata::MetadataValue;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint};
use tonic::Request;

#[derive(Parser, Debug, Clone)]
#[command(
	name = "puppy-tui",
	version,
	about = "Puppy gRPC observability terminal UI"
)]
struct Cli {
	#[arg(long, default_value = "http://127.0.0.1:50051")]
	endpoint: String,
	#[arg(long, value_name = "PEM")]
	ca_cert: Option<PathBuf>,
	#[arg(long)]
	server_name: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Page {
	Overview,
	Connections,
	Traffic,
	Logs,
}

impl Page {
	fn index(self) -> usize {
		match self {
			Self::Overview => 0,
			Self::Connections => 1,
			Self::Traffic => 2,
			Self::Logs => 3,
		}
	}
}

enum NetworkEvent {
	Connected,
	Disconnected(String),
	Overview(Overview),
	Connections(Vec<Connection>),
	Connection(ConnectionUpdate),
	Logs(Vec<LogEntry>),
	Log(LogEntry),
	Traffic(TrafficSample),
}

struct App {
	page: Page,
	connected: bool,
	status: String,
	overview: Option<Overview>,
	connections: HashMap<String, Connection>,
	logs: VecDeque<LogEntry>,
	traffic: VecDeque<TrafficSample>,
	selected: usize,
	searching: bool,
	query: String,
	log_query: String,
	min_log_level: String,
	status_filter: i32,
	descending: bool,
	follow_logs: bool,
	help: bool,
	detail: bool,
}

impl Default for App {
	fn default() -> Self {
		Self {
			page: Page::Overview,
			connected: false,
			status: "Connecting...".to_string(),
			overview: None,
			connections: HashMap::new(),
			logs: VecDeque::new(),
			traffic: VecDeque::new(),
			selected: 0,
			searching: false,
			query: String::new(),
			log_query: String::new(),
			min_log_level: "TRACE".to_string(),
			status_filter: ConnectionStatus::Unspecified as i32,
			descending: true,
			follow_logs: true,
			help: false,
			detail: false,
		}
	}
}

impl App {
	fn apply(&mut self, event: NetworkEvent) {
		match event {
			NetworkEvent::Connected => {
				self.connected = true;
				self.status = "Connected".to_string();
			}
			NetworkEvent::Disconnected(error) => {
				self.connected = false;
				self.status = format!("Disconnected: {error} (reconnecting)");
			}
			NetworkEvent::Overview(value) => self.overview = Some(value),
			NetworkEvent::Connections(values) => {
				for value in values {
					self.connections.insert(value.id.clone(), value);
				}
			}
			NetworkEvent::Connection(update) => {
				if let Some(value) = update.connection {
					self.connections.insert(value.id.clone(), value);
				}
			}
			NetworkEvent::Logs(values) => {
				for value in values {
					self.push_log(value);
				}
			}
			NetworkEvent::Log(value) => self.push_log(value),
			NetworkEvent::Traffic(value) => {
				self.traffic.push_back(value);
				while self.traffic.len() > 120 {
					self.traffic.pop_front();
				}
			}
		}
	}

	fn push_log(&mut self, value: LogEntry) {
		if self
			.logs
			.back()
			.is_none_or(|last| last.cursor != value.cursor)
		{
			self.logs.push_back(value);
		}
		while self.logs.len() > 2_000 {
			self.logs.pop_front();
		}
	}

	fn visible_connections(&self) -> Vec<&Connection> {
		let query = self.query.to_lowercase();
		let mut values: Vec<_> = self
			.connections
			.values()
			.filter(|connection| {
				(self.status_filter == ConnectionStatus::Unspecified as i32
					|| connection.status == self.status_filter)
					&& (query.is_empty()
						|| connection.id.to_lowercase().contains(&query)
						|| connection.remote_addr.to_lowercase().contains(&query)
						|| connection.target_host.to_lowercase().contains(&query))
			})
			.collect();
		values.sort_by_key(|connection| {
			connection
				.started_at
				.as_ref()
				.map_or(0, |time| time.seconds)
		});
		if self.descending {
			values.reverse();
		}
		values
	}

	fn visible_logs(&self) -> Vec<&LogEntry> {
		let query = self.log_query.to_lowercase();
		self.logs
			.iter()
			.filter(|entry| {
				level_rank(&entry.level) >= level_rank(&self.min_log_level)
					&& (query.is_empty()
						|| entry.message.to_lowercase().contains(&query)
						|| entry.target.to_lowercase().contains(&query))
			})
			.collect()
	}
}

#[tokio::main]
async fn main() -> Result<()> {
	let cli = Cli::parse();
	let token = std::env::var("PUPPY_TUI_TOKEN")
		.ok()
		.filter(|value| !value.is_empty());
	let (tx, mut rx) = mpsc::channel(1_024);
	tokio::spawn(connection_loop(cli, token, tx));

	let mut terminal = setup_terminal()?;
	install_panic_restore();
	let mut events = EventStream::new();
	let mut app = App::default();
	let mut tick = tokio::time::interval(Duration::from_millis(100));
	let result = loop {
		if let Err(error) = terminal.draw(|frame| draw(frame, &app)) {
			break Err(error.into());
		}
		tokio::select! {
			_ = tick.tick() => {}
			Some(network) = rx.recv() => app.apply(network),
			input = events.next() => {
				match input {
					Some(Ok(Event::Key(key)))
						if key.kind == KeyEventKind::Press && handle_key(&mut app, key.code) =>
					{
						break Ok(());
					}
					Some(Err(error)) => break Err(error.into()),
					_ => {}
				}
			}
		}
	};
	restore_terminal(&mut terminal)?;
	result
}

async fn connection_loop(cli: Cli, token: Option<String>, tx: mpsc::Sender<NetworkEvent>) {
	let mut delay = Duration::from_millis(500);
	loop {
		match connect_client(&cli, &token).await {
			Ok(mut client) => {
				let _ = tx.send(NetworkEvent::Connected).await;
				match run_connected(&mut client, &tx).await {
					Ok(()) => {
						let _ = tx
							.send(NetworkEvent::Disconnected(
								"The server closed an event stream".to_string(),
							))
							.await;
					}
					Err(error) => {
						let _ = tx.send(NetworkEvent::Disconnected(error.to_string())).await;
					}
				}
				delay = Duration::from_millis(500);
			}
			Err(error) => {
				let _ = tx.send(NetworkEvent::Disconnected(error.to_string())).await;
			}
		}
		tokio::time::sleep(delay).await;
		delay = (delay * 2).min(Duration::from_secs(30));
	}
}

#[derive(Clone)]
struct AuthClient {
	inner: ObservabilityClient<Channel>,
	token: Option<MetadataValue<tonic::metadata::Ascii>>,
}

impl AuthClient {
	fn request<T>(&self, value: T) -> Request<T> {
		let mut request = Request::new(value);
		if let Some(token) = &self.token {
			request
				.metadata_mut()
				.insert("authorization", token.clone());
		}
		request
	}
}

async fn connect_client(cli: &Cli, token: &Option<String>) -> Result<AuthClient> {
	let mut endpoint = Endpoint::from_shared(cli.endpoint.clone())?;
	if cli.endpoint.starts_with("https://") {
		let mut tls = ClientTlsConfig::new();
		if let Some(path) = &cli.ca_cert {
			tls = tls.ca_certificate(Certificate::from_pem(
				tokio::fs::read(path).await.context("read CA certificate")?,
			));
		}
		if let Some(name) = &cli.server_name {
			tls = tls.domain_name(name);
		}
		endpoint = endpoint.tls_config(tls)?;
	} else if cli.ca_cert.is_some() || cli.server_name.is_some() {
		anyhow::bail!("--ca-cert/--server-name require an https:// endpoint");
	}
	let channel = endpoint.connect().await?;
	let token = token
		.as_ref()
		.map(|token| format!("Bearer {token}").parse())
		.transpose()
		.context("token is not valid gRPC metadata")?;
	Ok(AuthClient {
		inner: ObservabilityClient::new(channel),
		token,
	})
}

async fn run_connected(client: &mut AuthClient, tx: &mpsc::Sender<NetworkEvent>) -> Result<()> {
	let overview = client
		.inner
		.get_overview(client.request(()))
		.await?
		.into_inner();
	tx.send(NetworkEvent::Overview(overview)).await?;
	let mut page_token = String::new();
	loop {
		let request = client.request(ListConnectionsRequest {
			status: ConnectionStatus::Unspecified as i32,
			frontend: String::new(),
			network: String::new(),
			protocol: String::new(),
			query: String::new(),
			page_size: 500,
			page_token,
			sort_by: "started_at".to_string(),
			descending: true,
		});
		let page = client.inner.list_connections(request).await?.into_inner();
		tx.send(NetworkEvent::Connections(page.connections)).await?;
		if page.next_page_token.is_empty() {
			break;
		}
		page_token = page.next_page_token;
	}
	let logs = client
		.inner
		.list_logs(client.request(ListLogsRequest {
			filter: None,
			limit: 500,
			before_cursor: String::new(),
		}))
		.await?
		.into_inner()
		.entries;
	let last_cursor = logs
		.last()
		.map(|entry| entry.cursor.clone())
		.unwrap_or_default();
	tx.send(NetworkEvent::Logs(logs)).await?;

	let mut connection_client = client.clone();
	let mut log_client = client.clone();
	let mut traffic_client = client.clone();
	let mut overview_client = client.clone();
	let connection_request = connection_client.request(WatchConnectionsRequest {
		include_initial: true,
	});
	let log_request = log_client.request(WatchLogsRequest {
		filter: None,
		after_cursor: last_cursor,
	});
	let traffic_request = traffic_client.request(WatchTrafficRequest { interval_ms: 1_000 });
	let mut connections = connection_client
		.inner
		.watch_connections(connection_request)
		.await?
		.into_inner();
	let mut logs = log_client.inner.watch_logs(log_request).await?.into_inner();
	let mut traffic = traffic_client
		.inner
		.watch_traffic(traffic_request)
		.await?
		.into_inner();
	let mut overview_tick = tokio::time::interval(Duration::from_secs(1));
	overview_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
	overview_tick.tick().await;
	loop {
		tokio::select! {
			_ = overview_tick.tick() => {
				let request = overview_client.request(());
				let overview = overview_client.inner.get_overview(request).await?.into_inner();
				tx.send(NetworkEvent::Overview(overview)).await?;
			}
			value = connections.message() => match value? { Some(value) => tx.send(NetworkEvent::Connection(value)).await?, None => return Ok(()) },
			value = logs.message() => match value? { Some(value) => tx.send(NetworkEvent::Log(value)).await?, None => return Ok(()) },
			value = traffic.message() => match value? { Some(value) => tx.send(NetworkEvent::Traffic(value)).await?, None => return Ok(()) },
		}
	}
}

fn handle_key(app: &mut App, code: KeyCode) -> bool {
	if app.searching {
		match code {
			KeyCode::Esc | KeyCode::Enter => app.searching = false,
			KeyCode::Backspace => {
				if app.page == Page::Logs {
					app.log_query.pop();
				} else {
					app.query.pop();
				}
			}
			KeyCode::Char(value) => {
				if app.page == Page::Logs {
					app.log_query.push(value);
				} else {
					app.query.push(value);
				}
			}
			_ => {}
		}
		return false;
	}
	if app.help {
		if matches!(code, KeyCode::Esc | KeyCode::Char('?')) {
			app.help = false;
		}
		return false;
	}
	if app.detail {
		if matches!(code, KeyCode::Esc | KeyCode::Enter) {
			app.detail = false;
		}
		return false;
	}
	match code {
		KeyCode::Char('q') => return true,
		KeyCode::Char('1') => app.page = Page::Overview,
		KeyCode::Char('2') => app.page = Page::Connections,
		KeyCode::Char('3') => app.page = Page::Traffic,
		KeyCode::Char('4') => app.page = Page::Logs,
		KeyCode::Char('?') => app.help = true,
		KeyCode::Char('/') if matches!(app.page, Page::Connections | Page::Logs) => {
			app.searching = true
		}
		KeyCode::Char('f') if app.page == Page::Connections => {
			app.status_filter = match app.status_filter {
				x if x == ConnectionStatus::Unspecified as i32 => ConnectionStatus::Active as i32,
				x if x == ConnectionStatus::Active as i32 => ConnectionStatus::Closed as i32,
				_ => ConnectionStatus::Unspecified as i32,
			};
			app.selected = 0;
		}
		KeyCode::Char('s') if app.page == Page::Connections => app.descending = !app.descending,
		KeyCode::Char(' ') if app.page == Page::Logs => {
			app.follow_logs = !app.follow_logs;
			if !app.follow_logs {
				app.selected = app.logs.len().saturating_sub(1);
			}
		}
		KeyCode::Char('l') if app.page == Page::Logs => {
			app.min_log_level = match app.min_log_level.as_str() {
				"TRACE" => "DEBUG",
				"DEBUG" => "INFO",
				"INFO" => "WARN",
				"WARN" => "ERROR",
				_ => "TRACE",
			}
			.to_string();
		}
		KeyCode::Down | KeyCode::Char('j') => app.selected = app.selected.saturating_add(1),
		KeyCode::Up | KeyCode::Char('k') => app.selected = app.selected.saturating_sub(1),
		KeyCode::PageDown => app.selected = app.selected.saturating_add(10),
		KeyCode::PageUp => app.selected = app.selected.saturating_sub(10),
		KeyCode::Enter
			if app.page == Page::Connections && !app.visible_connections().is_empty() =>
		{
			app.detail = true
		}
		_ => {}
	}
	false
}

fn draw(frame: &mut Frame<'_>, app: &App) {
	let size = frame.area();
	if size.width < 80 || size.height < 24 {
		frame.render_widget(
			Paragraph::new("Terminal is too small; minimum size is 80x24")
				.alignment(Alignment::Center)
				.block(Block::default().borders(Borders::ALL)),
			size,
		);
		return;
	}
	let layout = Layout::default()
		.direction(Direction::Vertical)
		.constraints([
			Constraint::Length(3),
			Constraint::Min(1),
			Constraint::Length(1),
		])
		.split(size);
	let titles = ["1 Overview", "2 Connections", "3 Traffic", "4 Logs"]
		.into_iter()
		.map(Line::from)
		.collect::<Vec<_>>();
	frame.render_widget(
		Tabs::new(titles)
			.select(app.page.index())
			.highlight_style(
				Style::default()
					.fg(Color::Cyan)
					.add_modifier(Modifier::BOLD),
			)
			.block(Block::default().title(" Puppy ").borders(Borders::ALL)),
		layout[0],
	);
	match app.page {
		Page::Overview => draw_overview(frame, layout[1], app),
		Page::Connections => draw_connections(frame, layout[1], app),
		Page::Traffic => draw_traffic(frame, layout[1], app),
		Page::Logs => draw_logs(frame, layout[1], app),
	}
	let color = if app.connected {
		Color::Green
	} else {
		Color::Yellow
	};
	frame.render_widget(
		Paragraph::new(Line::from(vec![
			Span::styled(&app.status, Style::default().fg(color)),
			Span::raw("   ? Help   q Quit"),
		])),
		layout[2],
	);
	if app.help {
		draw_help(frame, centered(60, 60, size));
	}
	if app.detail {
		draw_detail(frame, centered(76, 76, size), app);
	}
}

fn draw_overview(frame: &mut Frame<'_>, area: Rect, app: &App) {
	let Some(value) = &app.overview else {
		frame.render_widget(
			Paragraph::new("Waiting for server overview...")
				.block(Block::default().borders(Borders::ALL)),
			area,
		);
		return;
	};
	let rows = Layout::default()
		.direction(Direction::Vertical)
		.constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
		.split(area);
	let top = Layout::default()
		.direction(Direction::Horizontal)
		.constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
		.split(rows[0]);
	let bottom = Layout::default()
		.direction(Direction::Horizontal)
		.constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
		.split(rows[1]);
	let status = if value.degraded {
		format!("Degraded: {}", value.degraded_reason)
	} else {
		"Healthy".to_string()
	};
	metric(
		frame,
		top[0],
		"Server",
		format!(
			"Status: {status}\nVersion: {} / API {}\nInstance: {}\nPID: {}\nUptime: {}",
			value.server_version,
			value.api_version,
			short(&value.server_instance_id),
			value.pid,
			format_duration(value.uptime_seconds as u64)
		),
	);
	metric(
		frame,
		top[1],
		"Connections",
		format!(
			"Active: {}\nProcess total: {}\nAll-time total: {}\nDial success/failure: {}/{}",
			value.active_connections,
			value.process_total_connections,
			value.all_time_connections,
			value.dial_successes,
			value.dial_failures
		),
	);
	metric(
		frame,
		bottom[0],
		"Process traffic",
		format!(
			"Inbound: {}\nOutbound: {}",
			bytes(value.process_bytes_in),
			bytes(value.process_bytes_out)
		),
	);
	metric(
		frame,
		bottom[1],
		"All-time traffic",
		format!(
			"Inbound: {}\nOutbound: {}",
			bytes(value.all_time_bytes_in),
			bytes(value.all_time_bytes_out)
		),
	);
}

fn metric(frame: &mut Frame<'_>, area: Rect, title: &str, text: String) {
	frame.render_widget(
		Paragraph::new(text)
			.block(Block::default().title(title).borders(Borders::ALL))
			.wrap(Wrap { trim: true }),
		area,
	);
}

fn draw_connections(frame: &mut Frame<'_>, area: Rect, app: &App) {
	let values = app.visible_connections();
	let selected = app.selected.min(values.len().saturating_sub(1));
	let filter = match app.status_filter {
		x if x == ConnectionStatus::Active as i32 => "Active",
		x if x == ConnectionStatus::Closed as i32 => "Closed",
		_ => "All",
	};
	let title = if app.searching {
		format!(" Connections  Search: {}_ ", app.query)
	} else {
		format!(
			" Connections {}  Filter:{filter}  / Search  f Filter  s Sort  Enter Details ",
			values.len()
		)
	};
	let rows = values.iter().enumerate().map(|(index, value)| {
		Row::new(vec![
			Cell::from(if index == selected { ">" } else { "" }),
			Cell::from(short(&value.id)),
			Cell::from(status_name(value.status)),
			Cell::from(value.frontend.clone()),
			Cell::from(value.remote_addr.clone()),
			Cell::from(format!("{}:{}", value.target_host, value.target_port)),
			Cell::from(value.protocol.clone()),
			Cell::from(bytes(value.bytes_in)),
			Cell::from(bytes(value.bytes_out)),
		])
	});
	let widths = [
		Constraint::Length(1),
		Constraint::Length(14),
		Constraint::Length(8),
		Constraint::Length(14),
		Constraint::Length(22),
		Constraint::Min(22),
		Constraint::Length(8),
		Constraint::Length(10),
		Constraint::Length(10),
	];
	let header = Row::new([
		"", "ID", "Status", "Frontend", "Client", "Target", "Protocol", "Inbound", "Outbound",
	])
	.style(
		Style::default()
			.fg(Color::Cyan)
			.add_modifier(Modifier::BOLD),
	);
	frame.render_widget(
		Table::new(rows, widths)
			.header(header)
			.row_highlight_style(Style::default().bg(Color::DarkGray))
			.block(Block::default().title(title).borders(Borders::ALL)),
		area,
	);
}

fn draw_traffic(frame: &mut Frame<'_>, area: Rect, app: &App) {
	let rows = Layout::default()
		.direction(Direction::Vertical)
		.constraints([
			Constraint::Length(5),
			Constraint::Percentage(50),
			Constraint::Percentage(50),
		])
		.split(area);
	let latest = app.traffic.back();
	let inbound = latest.map_or(0, |v| v.bytes_in_per_second);
	let outbound = latest.map_or(0, |v| v.bytes_out_per_second);
	let max = app
		.traffic
		.iter()
		.flat_map(|v| [v.bytes_in_per_second, v.bytes_out_per_second])
		.max()
		.unwrap_or(1)
		.max(1);
	frame.render_widget(
		Paragraph::new(format!(
			"Current inbound {}/s    Current outbound {}/s    Active connections {}\nProcess total ↓{} ↑{}    All-time total ↓{} ↑{}",
			bytes(inbound),
			bytes(outbound),
			latest.map_or(0, |v| v.active_connections),
			bytes(latest.map_or(0, |v| v.process_bytes_in)),
			bytes(latest.map_or(0, |v| v.process_bytes_out)),
			bytes(latest.map_or(0, |v| v.all_time_bytes_in)),
			bytes(latest.map_or(0, |v| v.all_time_bytes_out))
		))
		.block(Block::default().title(" Traffic ").borders(Borders::ALL)),
		rows[0],
	);
	let in_data: Vec<u64> = app.traffic.iter().map(|v| v.bytes_in_per_second).collect();
	let out_data: Vec<u64> = app.traffic.iter().map(|v| v.bytes_out_per_second).collect();
	frame.render_widget(
		Sparkline::default()
			.block(
				Block::default()
					.title(" Inbound rate (last 120 seconds) ")
					.borders(Borders::ALL),
			)
			.data(&in_data)
			.max(max)
			.style(Style::default().fg(Color::Cyan)),
		rows[1],
	);
	frame.render_widget(
		Sparkline::default()
			.block(
				Block::default()
					.title(" Outbound rate (last 120 seconds) ")
					.borders(Borders::ALL),
			)
			.data(&out_data)
			.max(max)
			.style(Style::default().fg(Color::Magenta)),
		rows[2],
	);
}

fn draw_logs(frame: &mut Frame<'_>, area: Rect, app: &App) {
	let visible = app.visible_logs();
	let height = area.height.saturating_sub(2) as usize;
	let start = if app.follow_logs {
		visible.len().saturating_sub(height)
	} else {
		app.selected
			.min(visible.len())
			.saturating_sub(height.saturating_sub(1))
	};
	let items = visible.into_iter().skip(start).take(height).map(|entry| {
		let color = match entry.level.as_str() {
			"ERROR" => Color::Red,
			"WARN" => Color::Yellow,
			"DEBUG" | "TRACE" => Color::DarkGray,
			_ => Color::Green,
		};
		ListItem::new(Line::from(vec![
			Span::styled(format!("{:5}", entry.level), Style::default().fg(color)),
			Span::raw(format!(" {:20} {}", short(&entry.target), entry.message)),
		]))
	});
	let mode = if app.follow_logs {
		"Following"
	} else {
		"Paused"
	};
	let title = if app.searching {
		format!(" Logs  Search: {}_ ", app.log_query)
	} else {
		format!(
			" Logs {mode}  Minimum level:{}  / Search  l Level  Space Pause/Resume ",
			app.min_log_level
		)
	};
	frame.render_widget(
		List::new(items).block(Block::default().title(title).borders(Borders::ALL)),
		area,
	);
}

fn draw_help(frame: &mut Frame<'_>, area: Rect) {
	frame.render_widget(Clear, area);
	frame.render_widget(
		Paragraph::new(
			"1–4 Switch pages\nj/k or arrow keys Move\n/ Search connections or logs\nf Filter connection status   s Sort connections\nl Set minimum log level   Enter View details\nSpace Pause/resume log following\nEsc Close dialog   q Quit",
		)
		.block(Block::default().title(" Help ").borders(Borders::ALL))
		.wrap(Wrap { trim: false }),
		area,
	);
}

fn draw_detail(frame: &mut Frame<'_>, area: Rect, app: &App) {
	let values = app.visible_connections();
	let Some(value) = values.get(app.selected.min(values.len().saturating_sub(1))) else {
		return;
	};
	frame.render_widget(Clear, area);
	let text = format!("ID: {}\nStatus: {}\nServer instance: {}\nFrontend: {}\nBackend: {}\nClient: {}\nTarget: {}:{}\nNetwork/Protocol: {}/{}\nStarted: {}\nClosed: {}\nDuration: {}\nInbound/Outbound: {} / {}\nClose reason: {}", value.id, status_name(value.status), value.server_instance_id, value.frontend, dash(&value.backend), value.remote_addr, value.target_host, value.target_port, value.network, value.protocol, timestamp_text(value.started_at.as_ref()), timestamp_text(value.closed_at.as_ref()), format_duration(value.duration_ms / 1_000), bytes(value.bytes_in), bytes(value.bytes_out), dash(&value.close_reason));
	frame.render_widget(
		Paragraph::new(text)
			.block(
				Block::default()
					.title(" Connection details  Enter/Esc Close ")
					.borders(Borders::ALL),
			)
			.wrap(Wrap { trim: false }),
		area,
	);
}

fn centered(width: u16, height: u16, area: Rect) -> Rect {
	let vertical = Layout::default()
		.direction(Direction::Vertical)
		.constraints([
			Constraint::Percentage((100 - height) / 2),
			Constraint::Percentage(height),
			Constraint::Percentage((100 - height) / 2),
		])
		.split(area);
	Layout::default()
		.direction(Direction::Horizontal)
		.constraints([
			Constraint::Percentage((100 - width) / 2),
			Constraint::Percentage(width),
			Constraint::Percentage((100 - width) / 2),
		])
		.split(vertical[1])[1]
}

fn setup_terminal() -> Result<Terminal<CrosstermBackend<io::Stdout>>> {
	enable_raw_mode()?;
	let mut stdout = io::stdout();
	execute!(stdout, EnterAlternateScreen)?;
	Ok(Terminal::new(CrosstermBackend::new(stdout))?)
}

fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> Result<()> {
	disable_raw_mode()?;
	execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
	terminal.show_cursor()?;
	Ok(())
}

fn install_panic_restore() {
	let previous = std::panic::take_hook();
	std::panic::set_hook(Box::new(move |info| {
		let _ = disable_raw_mode();
		let _ = execute!(io::stdout(), LeaveAlternateScreen);
		previous(info);
	}));
}

fn short(value: &str) -> String {
	if value.chars().count() > 18 {
		format!("{}…", value.chars().take(17).collect::<String>())
	} else {
		value.to_string()
	}
}
fn dash(value: &str) -> &str {
	if value.is_empty() {
		"—"
	} else {
		value
	}
}
fn status_name(value: i32) -> &'static str {
	match ConnectionStatus::try_from(value).unwrap_or_default() {
		ConnectionStatus::Active => "Active",
		ConnectionStatus::Closed => "Closed",
		ConnectionStatus::Interrupted => "Interrupted",
		_ => "Unknown",
	}
}
fn bytes(value: u64) -> String {
	const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
	let mut n = value as f64;
	let mut unit = 0;
	while n >= 1024.0 && unit < UNITS.len() - 1 {
		n /= 1024.0;
		unit += 1;
	}
	if unit == 0 {
		format!("{value} B")
	} else {
		format!("{n:.1} {}", UNITS[unit])
	}
}
fn format_duration(seconds: u64) -> String {
	format!(
		"{}d {:02}:{:02}:{:02}",
		seconds / 86_400,
		seconds / 3_600 % 24,
		seconds / 60 % 60,
		seconds % 60
	)
}
fn timestamp_text(value: Option<&prost_types::Timestamp>) -> String {
	value.map_or_else(
		|| "—".to_string(),
		|time| format!("{}.{:03} Unix", time.seconds, time.nanos / 1_000_000),
	)
}

fn level_rank(level: &str) -> u8 {
	match level {
		"TRACE" => 0,
		"DEBUG" => 1,
		"INFO" => 2,
		"WARN" => 3,
		"ERROR" => 4,
		_ => 0,
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn formats_bytes() {
		assert_eq!(bytes(999), "999 B");
		assert_eq!(bytes(1_536), "1.5 KiB");
	}

	#[test]
	fn keyboard_navigation_and_filters() {
		let mut app = App::default();
		assert!(!handle_key(&mut app, KeyCode::Char('2')));
		assert!(app.page == Page::Connections);
		handle_key(&mut app, KeyCode::Char('f'));
		assert_eq!(app.status_filter, ConnectionStatus::Active as i32);
		handle_key(&mut app, KeyCode::Char('/'));
		handle_key(&mut app, KeyCode::Char('x'));
		assert_eq!(app.query, "x");
	}
}
