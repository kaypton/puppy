use std::cmp::Ordering;
use std::collections::{HashMap, HashSet, VecDeque};
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
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::symbols::Marker;
use ratatui::text::{Line, Span};
use ratatui::widgets::{
	Axis, Block, BorderType, Borders, Cell, Chart, Clear, Dataset, GraphType, List, ListItem,
	Padding, Paragraph, Row, Table, Tabs, Wrap,
};
use ratatui::{Frame, Terminal};
use tokio::sync::mpsc;
use tonic::metadata::MetadataValue;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint};
use tonic::Request;

const BACKGROUND: Color = Color::Rgb(7, 11, 19);
const SURFACE: Color = Color::Rgb(13, 20, 32);
const SURFACE_ALT: Color = Color::Rgb(20, 30, 47);
const BORDER: Color = Color::Rgb(48, 65, 86);
const TEXT: Color = Color::Rgb(224, 231, 239);
const MUTED: Color = Color::Rgb(126, 143, 166);
const CYAN: Color = Color::Rgb(70, 211, 220);
const BLUE: Color = Color::Rgb(89, 142, 247);
const GREEN: Color = Color::Rgb(89, 214, 124);
const YELLOW: Color = Color::Rgb(244, 190, 76);
const RED: Color = Color::Rgb(255, 105, 120);
const MAGENTA: Color = Color::Rgb(194, 126, 242);

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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConnectionSort {
	Newest,
	Oldest,
	Status,
	Traffic,
}

impl ConnectionSort {
	const ALL: [Self; 4] = [Self::Newest, Self::Oldest, Self::Status, Self::Traffic];

	fn label(self) -> &'static str {
		match self {
			Self::Newest => "Newest",
			Self::Oldest => "Oldest",
			Self::Status => "Status",
			Self::Traffic => "Total Traffic",
		}
	}

	fn toolbar_label(self) -> &'static str {
		match self {
			Self::Traffic => "Traffic",
			_ => self.label(),
		}
	}

	fn index(self) -> usize {
		Self::ALL
			.iter()
			.position(|value| *value == self)
			.unwrap_or(0)
	}
}

#[derive(Debug)]
struct ConnectionGroup {
	target_url: String,
	total: usize,
	active: usize,
	interrupted: usize,
	clients: HashSet<String>,
	bytes_in: u64,
	bytes_out: u64,
	first_started: i64,
	last_started: i64,
}

impl ConnectionGroup {
	fn status(&self) -> i32 {
		if self.active > 0 {
			ConnectionStatus::Active as i32
		} else if self.interrupted > 0 {
			ConnectionStatus::Interrupted as i32
		} else {
			ConnectionStatus::Closed as i32
		}
	}

	fn traffic(&self) -> u64 {
		self.bytes_in.saturating_add(self.bytes_out)
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
	connection_offset: usize,
	searching: bool,
	query: String,
	log_query: String,
	min_log_level: String,
	status_filter: i32,
	connection_sort: ConnectionSort,
	group_connections: bool,
	sort_menu: bool,
	sort_menu_selected: usize,
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
			connection_offset: 0,
			searching: false,
			query: String::new(),
			log_query: String::new(),
			min_log_level: "TRACE".to_string(),
			status_filter: ConnectionStatus::Unspecified as i32,
			connection_sort: ConnectionSort::Newest,
			group_connections: false,
			sort_menu: false,
			sort_menu_selected: 0,
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

	fn filtered_connections(&self) -> Vec<&Connection> {
		let query = self.query.to_lowercase();
		self.connections
			.values()
			.filter(|connection| {
				(self.status_filter == ConnectionStatus::Unspecified as i32
					|| connection.status == self.status_filter)
					&& (query.is_empty()
						|| connection.id.to_lowercase().contains(&query)
						|| connection.remote_addr.to_lowercase().contains(&query)
						|| connection.target_host.to_lowercase().contains(&query)
						|| connection.protocol.to_lowercase().contains(&query))
			})
			.collect()
	}

	fn visible_connections(&self) -> Vec<&Connection> {
		let mut values = self.filtered_connections();
		values.sort_by(|left, right| compare_connections(left, right, self.connection_sort));
		values
	}

	fn visible_connection_groups(&self) -> Vec<ConnectionGroup> {
		let mut grouped: HashMap<String, ConnectionGroup> = HashMap::new();
		for connection in self.filtered_connections() {
			let target_url = connection_target_url(connection);
			let started = connection_started(connection);
			let group = grouped
				.entry(target_url.clone())
				.or_insert_with(|| ConnectionGroup {
					target_url,
					total: 0,
					active: 0,
					interrupted: 0,
					clients: HashSet::new(),
					bytes_in: 0,
					bytes_out: 0,
					first_started: started,
					last_started: started,
				});
			group.total = group.total.saturating_add(1);
			match ConnectionStatus::try_from(connection.status).unwrap_or_default() {
				ConnectionStatus::Active => group.active = group.active.saturating_add(1),
				ConnectionStatus::Interrupted => {
					group.interrupted = group.interrupted.saturating_add(1)
				}
				_ => {}
			}
			group.clients.insert(connection.remote_addr.clone());
			group.bytes_in = group.bytes_in.saturating_add(connection.bytes_in);
			group.bytes_out = group.bytes_out.saturating_add(connection.bytes_out);
			group.first_started = group.first_started.min(started);
			group.last_started = group.last_started.max(started);
		}
		let mut groups: Vec<_> = grouped.into_values().collect();
		groups.sort_by(|left, right| compare_connection_groups(left, right, self.connection_sort));
		groups
	}

	fn connection_row_count(&self) -> usize {
		if self.group_connections {
			self.visible_connection_groups().len()
		} else {
			self.visible_connections().len()
		}
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
		if let Err(error) = terminal.draw(|frame| draw(frame, &mut app)) {
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
	if app.sort_menu {
		match code {
			KeyCode::Esc | KeyCode::Char('s') => app.sort_menu = false,
			KeyCode::Up | KeyCode::Char('k') => {
				app.sort_menu_selected = app.sort_menu_selected.saturating_sub(1)
			}
			KeyCode::Down | KeyCode::Char('j') => {
				app.sort_menu_selected = app
					.sort_menu_selected
					.saturating_add(1)
					.min(ConnectionSort::ALL.len() - 1)
			}
			KeyCode::Char(value @ '1'..='4') => {
				app.sort_menu_selected = value as usize - '1' as usize;
				apply_connection_sort(app);
			}
			KeyCode::Enter => apply_connection_sort(app),
			_ => {}
		}
		return false;
	}
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
			app.connection_offset = 0;
		}
		KeyCode::Char('s') if app.page == Page::Connections => {
			app.sort_menu_selected = app.connection_sort.index();
			app.sort_menu = true;
		}
		KeyCode::Char('g') if app.page == Page::Connections => {
			app.group_connections = !app.group_connections;
			app.selected = 0;
			app.connection_offset = 0;
		}
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
		KeyCode::Down | KeyCode::Char('j') => {
			let last = match app.page {
				Page::Connections => app.connection_row_count().saturating_sub(1),
				Page::Logs => app.visible_logs().len().saturating_sub(1),
				_ => app.selected,
			};
			app.selected = app.selected.saturating_add(1).min(last);
		}
		KeyCode::Up | KeyCode::Char('k') => app.selected = app.selected.saturating_sub(1),
		KeyCode::PageDown => app.selected = app.selected.saturating_add(10),
		KeyCode::PageUp => app.selected = app.selected.saturating_sub(10),
		KeyCode::Enter if app.page == Page::Connections && app.connection_row_count() > 0 => {
			app.detail = true
		}
		_ => {}
	}
	false
}

fn apply_connection_sort(app: &mut App) {
	app.connection_sort = ConnectionSort::ALL[app.sort_menu_selected];
	app.sort_menu = false;
	app.selected = 0;
	app.connection_offset = 0;
}

fn draw(frame: &mut Frame<'_>, app: &mut App) {
	let size = frame.area();
	frame.render_widget(
		Block::default().style(Style::default().bg(BACKGROUND)),
		size,
	);
	if size.width < 80 || size.height < 24 {
		frame.render_widget(
			Paragraph::new("Terminal is too small; minimum size is 80x24")
				.alignment(Alignment::Center)
				.style(Style::default().fg(RED).bg(SURFACE).bold())
				.block(panel("RESIZE TERMINAL", RED)),
			size,
		);
		return;
	}
	let layout = Layout::default()
		.direction(Direction::Vertical)
		.constraints([
			Constraint::Length(4),
			Constraint::Min(1),
			Constraint::Length(2),
		])
		.split(size);
	draw_header(frame, layout[0], app);
	let content = inset(layout[1], 1, 0);
	match app.page {
		Page::Overview => draw_overview(frame, content, app),
		Page::Connections => draw_connections(frame, content, app),
		Page::Traffic => draw_traffic(frame, content, app),
		Page::Logs => draw_logs(frame, content, app),
	}
	draw_footer(frame, layout[2], app);
	if app.help {
		draw_help(frame, centered(72, 82, size));
	}
	if app.detail {
		draw_detail(frame, centered(76, 76, size), app);
	}
	if app.sort_menu {
		draw_sort_menu(frame, centered(44, 54, size), app);
	}
}

fn draw_header(frame: &mut Frame<'_>, area: Rect, app: &App) {
	let block = Block::default()
		.borders(Borders::BOTTOM)
		.border_style(Style::default().fg(BORDER))
		.style(Style::default().bg(SURFACE));
	let inner = block.inner(area);
	frame.render_widget(block, area);
	let columns = Layout::default()
		.direction(Direction::Horizontal)
		.constraints([
			Constraint::Length(19),
			Constraint::Min(44),
			Constraint::Length(14),
		])
		.split(inner);
	frame.render_widget(
		Paragraph::new(vec![
			Line::from(vec![
				Span::styled(" PUPPY", Style::default().fg(CYAN).bold()),
				Span::styled(" /", Style::default().fg(BORDER)),
			]),
			Line::styled(
				" NETWORK OBSERVER",
				Style::default().fg(MUTED).add_modifier(Modifier::BOLD),
			),
		])
		.style(Style::default().bg(SURFACE)),
		columns[0],
	);
	let tabs_area = centered_row(columns[1]);
	let titles = [
		("1", "Overview"),
		("2", "Connections"),
		("3", "Traffic"),
		("4", "Logs"),
	]
	.into_iter()
	.map(|(key, label)| {
		Line::from(vec![
			Span::styled(format!(" {key} "), Style::default().fg(MUTED)),
			Span::styled(format!("{label} "), Style::default().fg(TEXT)),
		])
	})
	.collect::<Vec<_>>();
	frame.render_widget(
		Tabs::new(titles)
			.select(app.page.index())
			.highlight_style(
				Style::default()
					.fg(BACKGROUND)
					.bg(CYAN)
					.add_modifier(Modifier::BOLD),
			)
			.style(Style::default().bg(SURFACE))
			.divider(Span::raw(" ")),
		tabs_area,
	);
	let (indicator, label, color) = if app.connected {
		("●", "LIVE", GREEN)
	} else {
		("◌", "RETRYING", YELLOW)
	};
	frame.render_widget(
		Paragraph::new(vec![
			Line::from(vec![
				Span::styled(format!("{indicator} "), Style::default().fg(color).bold()),
				Span::styled(label, Style::default().fg(color).bold()),
			]),
			Line::styled("gRPC", Style::default().fg(MUTED)),
		])
		.alignment(Alignment::Right)
		.style(Style::default().bg(SURFACE)),
		columns[2],
	);
}

fn draw_footer(frame: &mut Frame<'_>, area: Rect, app: &App) {
	let block = Block::default()
		.borders(Borders::TOP)
		.border_style(Style::default().fg(BORDER))
		.style(Style::default().bg(SURFACE));
	let inner = block.inner(area);
	frame.render_widget(block, area);
	let columns = Layout::default()
		.direction(Direction::Horizontal)
		.constraints([Constraint::Min(20), Constraint::Length(58)])
		.split(inner);
	let status_color = if app.connected { MUTED } else { YELLOW };
	frame.render_widget(
		Paragraph::new(Line::from(vec![
			Span::raw(" "),
			Span::styled(&app.status, Style::default().fg(status_color)),
		]))
		.style(Style::default().bg(SURFACE)),
		columns[0],
	);
	let mut hints = vec![];
	match app.page {
		Page::Connections => {
			hints.extend(key_hint("/", "Search"));
			hints.extend(key_hint("s", "Sort"));
			hints.extend(key_hint("g", "Group"));
		}
		Page::Logs => {
			hints.extend(key_hint("/", "Search"));
			hints.extend(key_hint("l", "Level"));
			hints.extend(key_hint("space", "Follow"));
		}
		_ => hints.extend(key_hint("1–4", "Navigate")),
	}
	hints.extend(key_hint("?", "Help"));
	hints.extend(key_hint("q", "Quit"));
	frame.render_widget(
		Paragraph::new(Line::from(hints))
			.alignment(Alignment::Right)
			.style(Style::default().bg(SURFACE)),
		columns[1],
	);
}

fn draw_overview(frame: &mut Frame<'_>, area: Rect, app: &App) {
	let Some(value) = &app.overview else {
		frame.render_widget(
			Paragraph::new("Waiting for server overview...")
				.alignment(Alignment::Center)
				.style(Style::default().fg(MUTED).bg(SURFACE))
				.block(panel("OVERVIEW", CYAN)),
			area,
		);
		return;
	};
	let rows = Layout::default()
		.direction(Direction::Vertical)
		.constraints([
			Constraint::Length(5),
			Constraint::Length(1),
			Constraint::Min(10),
		])
		.split(area);
	let server_color = if value.degraded { YELLOW } else { GREEN };
	let server_status = if value.degraded {
		format!("DEGRADED · {}", value.degraded_reason)
	} else {
		"HEALTHY".to_string()
	};
	frame.render_widget(
		Paragraph::new(vec![
			Line::from(vec![
				Span::styled(" ● ", Style::default().fg(server_color).bold()),
				Span::styled(server_status, Style::default().fg(server_color).bold()),
				Span::styled("   Puppy server ", Style::default().fg(TEXT)),
				Span::styled(
					format!("v{}", value.server_version),
					Style::default().fg(CYAN).bold(),
				),
				Span::styled(
					format!("  ·  API {}", value.api_version),
					Style::default().fg(MUTED),
				),
			]),
			Line::from(vec![
				Span::styled(" Instance ", Style::default().fg(MUTED)),
				Span::styled(short(&value.server_instance_id), Style::default().fg(TEXT)),
				Span::styled("   PID ", Style::default().fg(MUTED)),
				Span::styled(value.pid.to_string(), Style::default().fg(TEXT)),
				Span::styled("   Uptime ", Style::default().fg(MUTED)),
				Span::styled(
					format_duration(value.uptime_seconds as u64),
					Style::default().fg(TEXT),
				),
			]),
		])
		.style(Style::default().fg(TEXT).bg(SURFACE))
		.block(panel("SERVER STATUS", server_color)),
		rows[0],
	);
	let card_rows = Layout::default()
		.direction(Direction::Vertical)
		.constraints([
			Constraint::Percentage(50),
			Constraint::Length(1),
			Constraint::Percentage(50),
		])
		.split(rows[2]);
	let top = Layout::default()
		.direction(Direction::Horizontal)
		.constraints([
			Constraint::Percentage(50),
			Constraint::Length(1),
			Constraint::Percentage(50),
		])
		.split(card_rows[0]);
	let bottom = Layout::default()
		.direction(Direction::Horizontal)
		.constraints([
			Constraint::Percentage(50),
			Constraint::Length(1),
			Constraint::Percentage(50),
		])
		.split(card_rows[2]);
	metric_card(
		frame,
		top[0],
		"ACTIVE CONNECTIONS",
		CYAN,
		value.active_connections.to_string(),
		format!(
			"{} this run  ·  {} all time",
			value.process_total_connections, value.all_time_connections
		),
	);
	let dial_total = value.dial_successes.saturating_add(value.dial_failures);
	let dial_rate = if dial_total == 0 {
		100.0
	} else {
		value.dial_successes as f64 * 100.0 / dial_total as f64
	};
	metric_card(
		frame,
		top[2],
		"DIAL HEALTH",
		GREEN,
		format!("{dial_rate:.1}%"),
		format!(
			"{} succeeded  ·  {} failed",
			value.dial_successes, value.dial_failures
		),
	);
	metric_card(
		frame,
		bottom[0],
		"SESSION TRAFFIC",
		BLUE,
		format!(
			"↓ {}   ↑ {}",
			bytes(value.process_bytes_in),
			bytes(value.process_bytes_out)
		),
		"Inbound / Outbound".to_string(),
	);
	metric_card(
		frame,
		bottom[2],
		"ALL-TIME TRAFFIC",
		MAGENTA,
		format!(
			"↓ {}   ↑ {}",
			bytes(value.all_time_bytes_in),
			bytes(value.all_time_bytes_out)
		),
		"Inbound / Outbound".to_string(),
	);
}

fn metric_card(
	frame: &mut Frame<'_>,
	area: Rect,
	title: &str,
	accent: Color,
	primary: String,
	secondary: String,
) {
	frame.render_widget(
		Paragraph::new(vec![
			Line::styled(primary, Style::default().fg(accent).bold()),
			Line::styled(secondary, Style::default().fg(MUTED)),
		])
		.style(Style::default().bg(SURFACE))
		.block(panel(title, accent))
		.wrap(Wrap { trim: true }),
		area,
	);
}

fn draw_connections(frame: &mut Frame<'_>, area: Rect, app: &mut App) {
	let raw_count = app.filtered_connections().len();
	let value_count = app.connection_row_count();
	app.selected = app.selected.min(value_count.saturating_sub(1));
	let selected = app.selected;
	let filter = match app.status_filter {
		x if x == ConnectionStatus::Active as i32 => "Active",
		x if x == ConnectionStatus::Closed as i32 => "Closed",
		_ => "All",
	};
	let layout = Layout::default()
		.direction(Direction::Vertical)
		.constraints([
			Constraint::Length(3),
			Constraint::Length(1),
			Constraint::Min(1),
		])
		.split(area);
	let visible_rows = layout[2].height.saturating_sub(3) as usize;
	app.connection_offset =
		connection_viewport_offset(app.connection_offset, selected, value_count, visible_rows);
	let connection_offset = app.connection_offset;
	let search = if app.searching {
		format!("{}▌", app.query)
	} else if app.query.is_empty() {
		"Press / to search".to_string()
	} else {
		app.query.clone()
	};
	let toolbar_color = if app.searching { YELLOW } else { BORDER };
	frame.render_widget(
		Paragraph::new(Line::from(vec![
			Span::styled(" FIND ", Style::default().fg(MUTED).bold()),
			Span::styled(search, Style::default().fg(TEXT)),
			Span::styled("  STATUS ", Style::default().fg(MUTED).bold()),
			Span::styled(format!(" {filter} "), chip_style(CYAN)),
			Span::styled("  SORT ", Style::default().fg(MUTED).bold()),
			Span::styled(
				format!(" {} ", app.connection_sort.toolbar_label()),
				chip_style(BLUE),
			),
			Span::styled("  VIEW ", Style::default().fg(MUTED).bold()),
			Span::styled(
				if app.group_connections {
					" Targets "
				} else {
					" Individual "
				},
				chip_style(MAGENTA),
			),
		]))
		.style(Style::default().bg(SURFACE))
		.block(panel("CONNECTION EXPLORER", toolbar_color)),
		layout[0],
	);
	if app.group_connections {
		let groups = app.visible_connection_groups();
		draw_connection_groups(
			frame,
			layout[2],
			&groups,
			selected,
			connection_offset,
			visible_rows,
			raw_count,
		);
		return;
	}
	let values = app.visible_connections();
	let compact = layout[2].width < 110;
	let rows = values
		.iter()
		.enumerate()
		.skip(connection_offset)
		.take(visible_rows)
		.map(|(index, value)| {
			let cells = if compact {
				vec![
					Cell::from(if index == selected { "▌" } else { "" })
						.style(Style::default().fg(CYAN)),
					Cell::from(status_name(value.status))
						.style(connection_status_style(value.status)),
					Cell::from(value.remote_addr.clone()),
					Cell::from(format!("{}:{}", value.target_host, value.target_port)),
					Cell::from(bytes(value.bytes_in)).style(Style::default().fg(CYAN)),
					Cell::from(bytes(value.bytes_out)).style(Style::default().fg(MAGENTA)),
				]
			} else {
				vec![
					Cell::from(if index == selected { "▌" } else { "" })
						.style(Style::default().fg(CYAN)),
					Cell::from(short(&value.id)),
					Cell::from(status_name(value.status))
						.style(connection_status_style(value.status)),
					Cell::from(value.frontend.clone()),
					Cell::from(value.remote_addr.clone()),
					Cell::from(format!("{}:{}", value.target_host, value.target_port)),
					Cell::from(value.protocol.clone()).style(Style::default().fg(BLUE)),
					Cell::from(bytes(value.bytes_in)).style(Style::default().fg(CYAN)),
					Cell::from(bytes(value.bytes_out)).style(Style::default().fg(MAGENTA)),
				]
			};
			let row = Row::new(cells);
			if index == selected {
				row.style(Style::default().fg(TEXT).bg(SURFACE_ALT).bold())
			} else if index % 2 == 1 {
				row.style(Style::default().fg(TEXT).bg(SURFACE))
			} else {
				row.style(Style::default().fg(TEXT).bg(BACKGROUND))
			}
		});
	let (widths, labels) = if compact {
		(
			vec![
				Constraint::Length(1),
				Constraint::Length(8),
				Constraint::Length(18),
				Constraint::Min(18),
				Constraint::Length(9),
				Constraint::Length(9),
			],
			vec!["", "Status", "Client", "Target", "Inbound", "Outbound"],
		)
	} else {
		(
			vec![
				Constraint::Length(1),
				Constraint::Length(14),
				Constraint::Length(8),
				Constraint::Length(14),
				Constraint::Length(22),
				Constraint::Min(22),
				Constraint::Length(8),
				Constraint::Length(10),
				Constraint::Length(10),
			],
			vec![
				"", "ID", "Status", "Frontend", "Client", "Target", "Protocol", "Inbound",
				"Outbound",
			],
		)
	};
	let header = Row::new(labels).style(
		Style::default()
			.fg(MUTED)
			.bg(SURFACE_ALT)
			.add_modifier(Modifier::BOLD),
	);
	frame.render_widget(
		Table::new(rows, widths)
			.header(header)
			.column_spacing(1)
			.block(panel(&format!("CONNECTIONS  {value_count}"), CYAN)),
		layout[2],
	);
}

fn draw_connection_groups(
	frame: &mut Frame<'_>,
	area: Rect,
	groups: &[ConnectionGroup],
	selected: usize,
	offset: usize,
	visible_rows: usize,
	raw_count: usize,
) {
	let compact = area.width < 110;
	let rows = groups
		.iter()
		.enumerate()
		.skip(offset)
		.take(visible_rows)
		.map(|(index, group)| {
			let mut cells = vec![
				Cell::from(if index == selected { "▌" } else { "" })
					.style(Style::default().fg(CYAN)),
				Cell::from(group.target_url.clone()),
				Cell::from(status_name(group.status()))
					.style(connection_status_style(group.status())),
				Cell::from(group.total.to_string()),
				Cell::from(group.active.to_string()).style(Style::default().fg(GREEN)),
			];
			if !compact {
				cells.push(Cell::from(group.clients.len().to_string()));
			}
			cells.extend([
				Cell::from(bytes(group.bytes_in)).style(Style::default().fg(CYAN)),
				Cell::from(bytes(group.bytes_out)).style(Style::default().fg(MAGENTA)),
			]);
			let row = Row::new(cells);
			if index == selected {
				row.style(Style::default().fg(TEXT).bg(SURFACE_ALT).bold())
			} else if index % 2 == 1 {
				row.style(Style::default().fg(TEXT).bg(SURFACE))
			} else {
				row.style(Style::default().fg(TEXT).bg(BACKGROUND))
			}
		});
	let (widths, labels) = if compact {
		(
			vec![
				Constraint::Length(1),
				Constraint::Min(20),
				Constraint::Length(10),
				Constraint::Length(6),
				Constraint::Length(6),
				Constraint::Length(9),
				Constraint::Length(9),
			],
			vec![
				"",
				"Target URL",
				"Status",
				"Total",
				"Active",
				"Inbound",
				"Outbound",
			],
		)
	} else {
		(
			vec![
				Constraint::Length(1),
				Constraint::Min(28),
				Constraint::Length(10),
				Constraint::Length(7),
				Constraint::Length(7),
				Constraint::Length(8),
				Constraint::Length(11),
				Constraint::Length(11),
			],
			vec![
				"",
				"Target URL",
				"Status",
				"Total",
				"Active",
				"Clients",
				"Inbound",
				"Outbound",
			],
		)
	};
	let header = Row::new(labels).style(
		Style::default()
			.fg(MUTED)
			.bg(SURFACE_ALT)
			.add_modifier(Modifier::BOLD),
	);
	frame.render_widget(
		Table::new(rows, widths)
			.header(header)
			.column_spacing(1)
			.block(panel(
				&format!(
					"TARGET GROUPS  {}  ·  {raw_count} CONNECTIONS",
					groups.len()
				),
				MAGENTA,
			)),
		area,
	);
}

fn draw_traffic(frame: &mut Frame<'_>, area: Rect, app: &App) {
	let rows = Layout::default()
		.direction(Direction::Vertical)
		.constraints([
			Constraint::Length(4),
			Constraint::Length(1),
			Constraint::Min(8),
			Constraint::Length(1),
			Constraint::Length(4),
		])
		.split(area);
	let latest = app.traffic.back();
	let inbound = latest.map_or(0, |v| v.bytes_in_per_second);
	let outbound = latest.map_or(0, |v| v.bytes_out_per_second);
	let summary = Layout::default()
		.direction(Direction::Horizontal)
		.constraints([
			Constraint::Percentage(33),
			Constraint::Length(1),
			Constraint::Percentage(34),
			Constraint::Length(1),
			Constraint::Percentage(33),
		])
		.split(rows[0]);
	metric_card(
		frame,
		summary[0],
		"INBOUND RATE",
		CYAN,
		format!("{}/s", bytes(inbound)),
		"Live throughput".to_string(),
	);
	metric_card(
		frame,
		summary[2],
		"OUTBOUND RATE",
		MAGENTA,
		format!("{}/s", bytes(outbound)),
		"Live throughput".to_string(),
	);
	metric_card(
		frame,
		summary[4],
		"ACTIVE FLOWS",
		GREEN,
		latest.map_or(0, |v| v.active_connections).to_string(),
		"Open connections".to_string(),
	);
	let charts = Layout::default()
		.direction(Direction::Horizontal)
		.constraints([
			Constraint::Percentage(50),
			Constraint::Length(1),
			Constraint::Percentage(50),
		])
		.split(rows[2]);
	draw_rate_chart(
		frame,
		charts[0],
		"INBOUND RATE HISTORY",
		CYAN,
		&app.traffic,
		|sample| sample.bytes_in_per_second,
	);
	draw_rate_chart(
		frame,
		charts[2],
		"OUTBOUND RATE HISTORY",
		MAGENTA,
		&app.traffic,
		|sample| sample.bytes_out_per_second,
	);
	let totals = Layout::default()
		.direction(Direction::Horizontal)
		.constraints([
			Constraint::Percentage(50),
			Constraint::Length(1),
			Constraint::Percentage(50),
		])
		.split(rows[4]);
	metric_card(
		frame,
		totals[0],
		"SESSION TOTAL",
		BLUE,
		format!(
			"↓ {}   ↑ {}",
			bytes(latest.map_or(0, |v| v.process_bytes_in)),
			bytes(latest.map_or(0, |v| v.process_bytes_out))
		),
		"Inbound / Outbound".to_string(),
	);
	metric_card(
		frame,
		totals[2],
		"ALL-TIME TOTAL",
		YELLOW,
		format!(
			"↓ {}   ↑ {}",
			bytes(latest.map_or(0, |v| v.all_time_bytes_in)),
			bytes(latest.map_or(0, |v| v.all_time_bytes_out))
		),
		"Inbound / Outbound".to_string(),
	);
}

fn draw_rate_chart(
	frame: &mut Frame<'_>,
	area: Rect,
	title: &str,
	accent: Color,
	samples: &VecDeque<TrafficSample>,
	value: fn(&TrafficSample) -> u64,
) {
	let interval_seconds = samples
		.back()
		.map_or(1.0, |sample| sample.interval_ms.max(1) as f64 / 1_000.0);
	let history_seconds = if samples.len() > 1 {
		(samples.len() - 1) as f64 * interval_seconds
	} else {
		interval_seconds
	};
	let point_capacity = area.width.saturating_sub(14).max(2) as usize;
	let data = resample_traffic(samples, point_capacity, value);
	let peak = data.iter().map(|(_, rate)| *rate as u64).max().unwrap_or(1);
	let ceiling = rate_axis_ceiling(peak);
	let x_labels = vec![
		Line::styled(
			format!("-{}", axis_duration(history_seconds)),
			Style::default().fg(MUTED),
		),
		Line::styled(
			format!("-{}", axis_duration(history_seconds / 2.0)),
			Style::default().fg(MUTED),
		),
		Line::styled("now", Style::default().fg(MUTED)),
	];
	let y_labels = vec![
		Line::styled("0 B/s", Style::default().fg(MUTED)),
		Line::styled(
			format!("{}/s", bytes(ceiling / 2)),
			Style::default().fg(MUTED),
		),
		Line::styled(format!("{}/s", bytes(ceiling)), Style::default().fg(MUTED)),
	];
	let dataset = Dataset::default()
		.marker(Marker::HalfBlock)
		.graph_type(GraphType::Bar)
		.style(Style::default().fg(accent))
		.data(&data);
	let chart = Chart::new(vec![dataset])
		.style(Style::default().bg(SURFACE))
		.block(panel(title, accent))
		.x_axis(
			Axis::default()
				.title(Line::styled("time", Style::default().fg(MUTED)))
				.style(Style::default().fg(BORDER))
				.bounds([-history_seconds, 0.0])
				.labels(x_labels),
		)
		.y_axis(
			Axis::default()
				.title(Line::styled("rate", Style::default().fg(MUTED)))
				.style(Style::default().fg(BORDER))
				.bounds([0.0, ceiling as f64])
				.labels(y_labels),
		);
	frame.render_widget(chart, area);
}

fn resample_traffic(
	samples: &VecDeque<TrafficSample>,
	capacity: usize,
	value: fn(&TrafficSample) -> u64,
) -> Vec<(f64, f64)> {
	if samples.is_empty() || capacity == 0 {
		return Vec::new();
	}
	let bucket_count = capacity.min(samples.len()).max(1);
	let interval_seconds = samples
		.back()
		.map_or(1.0, |sample| sample.interval_ms.max(1) as f64 / 1_000.0);
	let history_seconds = samples.len().saturating_sub(1) as f64 * interval_seconds;
	(0..bucket_count)
		.map(|bucket| {
			let start = bucket * samples.len() / bucket_count;
			let end = ((bucket + 1) * samples.len() / bucket_count).max(start + 1);
			let peak = samples
				.iter()
				.skip(start)
				.take(end.saturating_sub(start))
				.map(value)
				.max()
				.unwrap_or(0);
			let x = if bucket_count == 1 {
				0.0
			} else {
				-history_seconds + history_seconds * bucket as f64 / (bucket_count - 1) as f64
			};
			(x, peak as f64)
		})
		.collect()
}

fn rate_axis_ceiling(value: u64) -> u64 {
	value.max(1).checked_next_power_of_two().unwrap_or(u64::MAX)
}

fn axis_duration(seconds: f64) -> String {
	let seconds = seconds.max(0.0).round() as u64;
	if seconds >= 60 {
		format!("{}m{:02}s", seconds / 60, seconds % 60)
	} else {
		format!("{seconds}s")
	}
}

fn draw_logs(frame: &mut Frame<'_>, area: Rect, app: &App) {
	let visible = app.visible_logs();
	let layout = Layout::default()
		.direction(Direction::Vertical)
		.constraints([
			Constraint::Length(3),
			Constraint::Length(1),
			Constraint::Min(1),
		])
		.split(area);
	let height = layout[2].height.saturating_sub(2) as usize;
	let start = if app.follow_logs {
		visible.len().saturating_sub(height)
	} else {
		app.selected
			.min(visible.len())
			.saturating_sub(height.saturating_sub(1))
	};
	let displayed_count = visible.len();
	let items = visible
		.into_iter()
		.skip(start)
		.take(height)
		.enumerate()
		.map(|(index, entry)| {
			let color = log_level_color(&entry.level);
			ListItem::new(Line::from(vec![
				Span::styled(format!(" {:5} ", entry.level), chip_style(color)),
				Span::styled(
					format!(" {:18} ", short(&entry.target)),
					Style::default().fg(MUTED),
				),
				Span::styled(entry.message.as_str(), Style::default().fg(TEXT)),
			]))
			.style(if index % 2 == 1 {
				Style::default().bg(SURFACE)
			} else {
				Style::default().bg(BACKGROUND)
			})
		});
	let mode = if app.follow_logs {
		"Following"
	} else {
		"Paused"
	};
	let search = if app.searching {
		format!("{}▌", app.log_query)
	} else if app.log_query.is_empty() {
		"Press / to search".to_string()
	} else {
		app.log_query.clone()
	};
	let toolbar_color = if app.searching { YELLOW } else { BORDER };
	frame.render_widget(
		Paragraph::new(Line::from(vec![
			Span::styled(" SEARCH ", Style::default().fg(MUTED).bold()),
			Span::styled(search, Style::default().fg(TEXT)),
			Span::styled("    LEVEL ", Style::default().fg(MUTED).bold()),
			Span::styled(
				format!(" {} ", app.min_log_level),
				chip_style(log_level_color(&app.min_log_level)),
			),
			Span::styled("    MODE ", Style::default().fg(MUTED).bold()),
			Span::styled(
				format!(" {mode} "),
				chip_style(if app.follow_logs { GREEN } else { YELLOW }),
			),
		]))
		.style(Style::default().bg(SURFACE))
		.block(panel("LOG STREAM", toolbar_color)),
		layout[0],
	);
	frame.render_widget(
		List::new(items)
			.style(Style::default().bg(BACKGROUND))
			.block(panel(&format!("EVENTS  {displayed_count}"), BLUE)),
		layout[2],
	);
}

fn draw_help(frame: &mut Frame<'_>, area: Rect) {
	frame.render_widget(Clear, area);
	frame.render_widget(
		Paragraph::new(vec![
			help_line("1–4", "Switch dashboard pages"),
			help_line("j / k", "Move through connections and logs"),
			help_line("↑ / ↓", "Move through connections and logs"),
			help_line("PgUp / PgDn", "Move ten rows at a time"),
			help_line("/", "Search connections or logs"),
			help_line("f", "Cycle the connection status filter"),
			help_line("s", "Choose the connection sort order"),
			help_line("g", "Group connections by target URL"),
			help_line("l", "Cycle the minimum log level"),
			help_line("Space", "Pause or resume log following"),
			help_line("Enter", "Open connection details"),
			help_line("Esc", "Close a dialog or finish searching"),
			help_line("q", "Quit Puppy TUI"),
		])
		.style(Style::default().fg(TEXT).bg(SURFACE))
		.block(panel("KEYBOARD SHORTCUTS", CYAN).padding(Padding::new(2, 2, 1, 1)))
		.wrap(Wrap { trim: false }),
		area,
	);
}

fn draw_detail(frame: &mut Frame<'_>, area: Rect, app: &App) {
	if app.group_connections {
		draw_connection_group_detail(frame, area, app);
		return;
	}
	let values = app.visible_connections();
	let Some(value) = values.get(app.selected.min(values.len().saturating_sub(1))) else {
		return;
	};
	frame.render_widget(Clear, area);
	frame.render_widget(
		Paragraph::new(vec![
			detail_line("ID", value.id.clone()),
			detail_line("Status", status_name(value.status).to_string()),
			detail_line("Server instance", value.server_instance_id.clone()),
			detail_line("Frontend", value.frontend.clone()),
			detail_line("Backend", dash(&value.backend).to_string()),
			detail_line("Client", value.remote_addr.clone()),
			detail_line(
				"Target",
				format!("{}:{}", value.target_host, value.target_port),
			),
			detail_line(
				"Network / Protocol",
				format!("{} / {}", value.network, value.protocol),
			),
			detail_line("Started", timestamp_text(value.started_at.as_ref())),
			detail_line("Closed", timestamp_text(value.closed_at.as_ref())),
			detail_line("Duration", format_duration(value.duration_ms / 1_000)),
			detail_line(
				"Inbound / Outbound",
				format!("{} / {}", bytes(value.bytes_in), bytes(value.bytes_out)),
			),
			detail_line("Close reason", dash(&value.close_reason).to_string()),
		])
		.style(Style::default().fg(TEXT).bg(SURFACE))
		.block(
			panel("CONNECTION DETAILS", CYAN)
				.title_bottom(Line::styled(
					" Enter / Esc to close ",
					Style::default().fg(MUTED),
				))
				.padding(Padding::horizontal(2)),
		)
		.wrap(Wrap { trim: false }),
		area,
	);
}

fn draw_connection_group_detail(frame: &mut Frame<'_>, area: Rect, app: &App) {
	let groups = app.visible_connection_groups();
	let Some(group) = groups.get(app.selected.min(groups.len().saturating_sub(1))) else {
		return;
	};
	frame.render_widget(Clear, area);
	frame.render_widget(
		Paragraph::new(vec![
			detail_line("Target URL", group.target_url.clone()),
			detail_line("Status", status_name(group.status()).to_string()),
			detail_line("Connections", group.total.to_string()),
			detail_line("Active", group.active.to_string()),
			detail_line(
				"Closed / Interrupted",
				format!(
					"{} / {}",
					group
						.total
						.saturating_sub(group.active)
						.saturating_sub(group.interrupted),
					group.interrupted
				),
			),
			detail_line("Unique clients", group.clients.len().to_string()),
			detail_line(
				"Inbound / Outbound",
				format!("{} / {}", bytes(group.bytes_in), bytes(group.bytes_out)),
			),
			detail_line("Total traffic", bytes(group.traffic())),
			detail_line("First seen", timestamp_seconds_text(group.first_started)),
			detail_line("Last seen", timestamp_seconds_text(group.last_started)),
		])
		.style(Style::default().fg(TEXT).bg(SURFACE))
		.block(
			panel("TARGET GROUP DETAILS", MAGENTA)
				.title_bottom(Line::styled(
					" Enter / Esc to close ",
					Style::default().fg(MUTED),
				))
				.padding(Padding::horizontal(2)),
		)
		.wrap(Wrap { trim: false }),
		area,
	);
}

fn draw_sort_menu(frame: &mut Frame<'_>, area: Rect, app: &App) {
	frame.render_widget(Clear, area);
	let items = ConnectionSort::ALL.iter().enumerate().map(|(index, sort)| {
		let selected = index == app.sort_menu_selected;
		let active = *sort == app.connection_sort;
		ListItem::new(Line::from(vec![
			Span::styled(
				if selected { " ▌ " } else { "   " },
				Style::default().fg(CYAN),
			),
			Span::styled(format!("{}  ", index + 1), Style::default().fg(MUTED)),
			Span::styled(
				sort.label(),
				if selected {
					Style::default().fg(TEXT).bold()
				} else {
					Style::default().fg(MUTED)
				},
			),
			Span::styled(
				if active { "  ✓" } else { "" },
				Style::default().fg(GREEN).bold(),
			),
		]))
		.style(if selected {
			Style::default().bg(SURFACE_ALT)
		} else {
			Style::default().bg(SURFACE)
		})
	});
	frame.render_widget(
		List::new(items).block(
			panel("SORT CONNECTIONS", BLUE)
				.title_bottom(Line::styled(
					" Enter Apply  ·  Esc Cancel ",
					Style::default().fg(MUTED),
				))
				.padding(Padding::new(1, 1, 1, 1)),
		),
		area,
	);
}

fn panel(title: &str, accent: Color) -> Block<'static> {
	Block::default()
		.borders(Borders::ALL)
		.border_type(BorderType::Rounded)
		.border_style(Style::default().fg(BORDER))
		.style(Style::default().bg(SURFACE))
		.title(Line::from(Span::styled(
			format!(" {title} "),
			Style::default().fg(accent).bold(),
		)))
}

fn chip_style(color: Color) -> Style {
	Style::default().fg(BACKGROUND).bg(color).bold()
}

fn key_hint(key: &str, label: &str) -> Vec<Span<'static>> {
	vec![
		Span::styled(format!(" {key} "), chip_style(BORDER)),
		Span::styled(format!(" {label}  "), Style::default().fg(MUTED)),
	]
}

fn help_line(key: &str, description: &str) -> Line<'static> {
	Line::from(vec![
		Span::styled(format!(" {key:<12}"), Style::default().fg(CYAN).bold()),
		Span::styled(description.to_string(), Style::default().fg(TEXT)),
	])
}

fn detail_line(label: &str, value: String) -> Line<'static> {
	Line::from(vec![
		Span::styled(format!("{label:<20}"), Style::default().fg(MUTED)),
		Span::styled(value, Style::default().fg(TEXT).bold()),
	])
}

fn connection_started(connection: &Connection) -> i64 {
	connection
		.started_at
		.as_ref()
		.map_or(0, |timestamp| timestamp.seconds)
}

fn connection_traffic(connection: &Connection) -> u64 {
	connection.bytes_in.saturating_add(connection.bytes_out)
}

fn status_sort_rank(status: i32) -> u8 {
	match ConnectionStatus::try_from(status).unwrap_or_default() {
		ConnectionStatus::Active => 0,
		ConnectionStatus::Interrupted => 1,
		ConnectionStatus::Closed => 2,
		_ => 3,
	}
}

fn compare_connections(left: &Connection, right: &Connection, sort: ConnectionSort) -> Ordering {
	let order = match sort {
		ConnectionSort::Newest => connection_started(right).cmp(&connection_started(left)),
		ConnectionSort::Oldest => connection_started(left).cmp(&connection_started(right)),
		ConnectionSort::Status => status_sort_rank(left.status)
			.cmp(&status_sort_rank(right.status))
			.then_with(|| connection_started(right).cmp(&connection_started(left))),
		ConnectionSort::Traffic => connection_traffic(right)
			.cmp(&connection_traffic(left))
			.then_with(|| connection_started(right).cmp(&connection_started(left))),
	};
	order.then_with(|| left.id.cmp(&right.id))
}

fn compare_connection_groups(
	left: &ConnectionGroup,
	right: &ConnectionGroup,
	sort: ConnectionSort,
) -> Ordering {
	let order = match sort {
		ConnectionSort::Newest => right.last_started.cmp(&left.last_started),
		ConnectionSort::Oldest => left.first_started.cmp(&right.first_started),
		ConnectionSort::Status => status_sort_rank(left.status())
			.cmp(&status_sort_rank(right.status()))
			.then_with(|| right.last_started.cmp(&left.last_started)),
		ConnectionSort::Traffic => right
			.traffic()
			.cmp(&left.traffic())
			.then_with(|| right.last_started.cmp(&left.last_started)),
	};
	order.then_with(|| left.target_url.cmp(&right.target_url))
}

fn connection_target_url(connection: &Connection) -> String {
	let host = if connection.target_host.contains(':') && !connection.target_host.starts_with('[') {
		format!("[{}]", connection.target_host)
	} else {
		connection.target_host.clone()
	};
	let authority = format!("{host}:{}", connection.target_port);
	if connection.protocol.is_empty() {
		authority
	} else {
		format!("{}://{authority}", connection.protocol.to_lowercase())
	}
}

fn timestamp_seconds_text(seconds: i64) -> String {
	if seconds == 0 {
		"—".to_string()
	} else {
		format!("{seconds} Unix")
	}
}

fn connection_viewport_offset(
	current: usize,
	selected: usize,
	total: usize,
	capacity: usize,
) -> usize {
	if total == 0 || capacity == 0 || total <= capacity {
		return 0;
	}
	let capacity = capacity.min(total);
	let max_offset = total.saturating_sub(capacity);
	let current = current.min(max_offset);
	let margin = 2.min(capacity.saturating_sub(1) / 2);
	let upper_guard = current.saturating_add(margin);
	let lower_guard = current
		.saturating_add(capacity.saturating_sub(1))
		.saturating_sub(margin);
	if selected < upper_guard {
		selected.saturating_sub(margin).min(max_offset)
	} else if selected > lower_guard {
		selected
			.saturating_add(margin)
			.saturating_add(1)
			.saturating_sub(capacity)
			.min(max_offset)
	} else {
		current
	}
}

fn connection_status_style(value: i32) -> Style {
	match ConnectionStatus::try_from(value).unwrap_or_default() {
		ConnectionStatus::Active => Style::default().fg(GREEN).bold(),
		ConnectionStatus::Closed => Style::default().fg(MUTED),
		ConnectionStatus::Interrupted => Style::default().fg(RED),
		_ => Style::default().fg(YELLOW),
	}
}

fn log_level_color(level: &str) -> Color {
	match level {
		"ERROR" => RED,
		"WARN" => YELLOW,
		"INFO" => GREEN,
		"DEBUG" => BLUE,
		"TRACE" => MUTED,
		_ => MUTED,
	}
}

fn inset(area: Rect, horizontal: u16, vertical: u16) -> Rect {
	Rect {
		x: area.x.saturating_add(horizontal),
		y: area.y.saturating_add(vertical),
		width: area.width.saturating_sub(horizontal.saturating_mul(2)),
		height: area.height.saturating_sub(vertical.saturating_mul(2)),
	}
}

fn centered_row(area: Rect) -> Rect {
	Rect {
		x: area.x,
		y: area.y.saturating_add(area.height.saturating_sub(1) / 2),
		width: area.width,
		height: area.height.min(1),
	}
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
	use ratatui::backend::TestBackend;

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

	#[test]
	fn dashboard_pages_render_at_minimum_size() {
		let mut app = populated_app();
		for (page, expected) in [
			(Page::Overview, "SERVER STATUS"),
			(Page::Connections, "CONNECTION EXPLORER"),
			(Page::Traffic, "INBOUND RATE"),
			(Page::Logs, "LOG STREAM"),
		] {
			app.page = page;
			let rendered = render_text(&mut app, 80, 24);
			assert!(rendered.contains("PUPPY"));
			assert!(rendered.contains(expected), "missing {expected}");
		}
	}

	#[test]
	fn overlays_render_with_dashboard_theme() {
		let mut app = populated_app();
		app.help = true;
		assert!(render_text(&mut app, 100, 32).contains("KEYBOARD SHORTCUTS"));
		app.help = false;
		app.page = Page::Connections;
		app.detail = true;
		assert!(render_text(&mut app, 100, 32).contains("CONNECTION DETAILS"));
		app.group_connections = true;
		assert!(render_text(&mut app, 100, 32).contains("TARGET GROUP DETAILS"));
	}

	#[test]
	fn connections_table_adapts_to_terminal_width() {
		let mut app = populated_app();
		app.page = Page::Connections;
		let compact = render_text(&mut app, 80, 24);
		assert!(compact.contains("Outbound"));
		assert!(!compact.contains("Frontend"));
		let wide = render_text(&mut app, 140, 32);
		assert!(wide.contains("Frontend"));
		assert!(wide.contains("Protocol"));
	}

	#[test]
	fn connection_viewport_tracks_selection_in_both_directions() {
		let offset = connection_viewport_offset(0, 7, 30, 10);
		assert_eq!(offset, 0);
		let offset = connection_viewport_offset(offset, 8, 30, 10);
		assert_eq!(offset, 1);
		let offset = connection_viewport_offset(10, 12, 30, 10);
		assert_eq!(offset, 10);
		let offset = connection_viewport_offset(offset, 11, 30, 10);
		assert_eq!(offset, 9);
		assert_eq!(connection_viewport_offset(9, 0, 5, 10), 0);
	}

	#[test]
	fn connections_render_scrolls_selected_row_into_view() {
		let mut app = populated_app();
		app.page = Page::Connections;
		for index in 0..24 {
			let connection = Connection {
				id: format!("connection-{index:04}"),
				status: ConnectionStatus::Active as i32,
				remote_addr: format!("127.0.0.1:{}", 20_000 + index),
				target_host: format!("target-{index}.example"),
				target_port: 443,
				started_at: Some(prost_types::Timestamp {
					seconds: index as i64,
					nanos: 0,
				}),
				..Connection::default()
			};
			app.connections.insert(connection.id.clone(), connection);
		}
		app.selected = 18;
		let rendered = render_text(&mut app, 80, 24);
		assert!(app.connection_offset > 0);
		assert!(rendered.contains('▌'));
		app.selected = 0;
		render_text(&mut app, 80, 24);
		assert_eq!(app.connection_offset, 0);
	}

	#[test]
	fn connections_support_all_sort_orders() {
		let mut app = App::default();
		for connection in [
			connection_fixture("old-active", "a.example", ConnectionStatus::Active, 100, 10),
			connection_fixture("new-closed", "b.example", ConnectionStatus::Closed, 500, 30),
			connection_fixture(
				"mid-interrupted",
				"c.example",
				ConnectionStatus::Interrupted,
				300,
				20,
			),
		] {
			app.connections.insert(connection.id.clone(), connection);
		}
		app.connection_sort = ConnectionSort::Newest;
		assert_eq!(
			connection_ids(&app),
			["new-closed", "mid-interrupted", "old-active"]
		);
		app.connection_sort = ConnectionSort::Oldest;
		assert_eq!(
			connection_ids(&app),
			["old-active", "mid-interrupted", "new-closed"]
		);
		app.connection_sort = ConnectionSort::Status;
		assert_eq!(
			connection_ids(&app),
			["old-active", "mid-interrupted", "new-closed"]
		);
		app.connection_sort = ConnectionSort::Traffic;
		assert_eq!(
			connection_ids(&app),
			["new-closed", "mid-interrupted", "old-active"]
		);
	}

	#[test]
	fn connections_group_by_target_url() {
		let mut app = App::default();
		let mut first =
			connection_fixture("first", "example.com", ConnectionStatus::Active, 100, 10);
		first.protocol = "https".to_string();
		first.remote_addr = "127.0.0.1:1001".to_string();
		let mut second =
			connection_fixture("second", "example.com", ConnectionStatus::Closed, 250, 20);
		second.protocol = "https".to_string();
		second.remote_addr = "127.0.0.1:1002".to_string();
		let other = connection_fixture("other", "other.example", ConnectionStatus::Closed, 50, 30);
		for connection in [first, second, other] {
			app.connections.insert(connection.id.clone(), connection);
		}
		let groups = app.visible_connection_groups();
		assert_eq!(groups.len(), 2);
		let group = groups
			.iter()
			.find(|group| group.target_url == "https://example.com:443")
			.expect("grouped target");
		assert_eq!(group.total, 2);
		assert_eq!(group.active, 1);
		assert_eq!(group.clients.len(), 2);
		assert_eq!(group.traffic(), 350);
		assert_eq!(group.status(), ConnectionStatus::Active as i32);
	}

	#[test]
	fn sort_picker_and_group_toggle_use_keyboard_controls() {
		let mut app = populated_app();
		app.page = Page::Connections;
		handle_key(&mut app, KeyCode::Char('s'));
		assert!(app.sort_menu);
		assert!(render_text(&mut app, 80, 24).contains("SORT CONNECTIONS"));
		handle_key(&mut app, KeyCode::Down);
		handle_key(&mut app, KeyCode::Down);
		handle_key(&mut app, KeyCode::Enter);
		assert_eq!(app.connection_sort, ConnectionSort::Status);
		assert!(!app.sort_menu);
		handle_key(&mut app, KeyCode::Char('g'));
		assert!(app.group_connections);
		let rendered = render_text(&mut app, 80, 24);
		assert!(rendered.contains("TARGET GROUPS"));
		assert!(rendered.contains("https://example.com:443"));
	}

	#[test]
	fn traffic_history_resamples_to_available_width() {
		let samples: VecDeque<_> = (0..120)
			.map(|index| TrafficSample {
				interval_ms: 1_000,
				bytes_in_per_second: index,
				..TrafficSample::default()
			})
			.collect();
		let narrow = resample_traffic(&samples, 10, |sample| sample.bytes_in_per_second);
		assert_eq!(narrow.len(), 10);
		assert_eq!(narrow.first(), Some(&(-119.0, 11.0)));
		assert_eq!(narrow.last(), Some(&(0.0, 119.0)));
		let wide = resample_traffic(&samples, 200, |sample| sample.bytes_in_per_second);
		assert_eq!(wide.len(), 120);
		assert_eq!(wide.first(), Some(&(-119.0, 0.0)));
		assert_eq!(wide.last(), Some(&(0.0, 119.0)));
	}

	#[test]
	fn traffic_charts_render_time_and_rate_axes() {
		let mut app = populated_app();
		app.page = Page::Traffic;
		for index in 1..120 {
			app.traffic.push_back(TrafficSample {
				interval_ms: 1_000,
				bytes_in_per_second: index * 1_024,
				bytes_out_per_second: index * 512,
				..TrafficSample::default()
			});
		}
		let rendered = render_text(&mut app, 80, 24);
		assert!(rendered.contains("now"));
		assert!(rendered.contains("0 B/s"));
		assert!(rendered.contains("1m59s"));
		assert_eq!(rate_axis_ceiling(9_000), 16_384);
	}

	fn populated_app() -> App {
		let mut app = App {
			connected: true,
			status: "Connected".to_string(),
			overview: Some(Overview {
				api_version: "v1".to_string(),
				server_version: "0.1.0".to_string(),
				server_instance_id: "puppy-test-instance".to_string(),
				uptime_seconds: 3_661.0,
				pid: 1_234,
				process_total_connections: 42,
				active_connections: 3,
				dial_successes: 40,
				dial_failures: 2,
				process_bytes_in: 1_048_576,
				process_bytes_out: 2_097_152,
				all_time_connections: 420,
				all_time_bytes_in: 10_485_760,
				all_time_bytes_out: 20_971_520,
				..Overview::default()
			}),
			..App::default()
		};
		let connection = Connection {
			id: "connection-0001".to_string(),
			status: ConnectionStatus::Active as i32,
			frontend: "local_http_proxy".to_string(),
			remote_addr: "127.0.0.1:54321".to_string(),
			target_host: "example.com".to_string(),
			target_port: 443,
			protocol: "https".to_string(),
			bytes_in: 4_096,
			bytes_out: 8_192,
			..Connection::default()
		};
		app.connections.insert(connection.id.clone(), connection);
		app.traffic.push_back(TrafficSample {
			bytes_in_per_second: 12_000,
			bytes_out_per_second: 8_000,
			active_connections: 3,
			process_bytes_in: 1_048_576,
			process_bytes_out: 2_097_152,
			all_time_bytes_in: 10_485_760,
			all_time_bytes_out: 20_971_520,
			..TrafficSample::default()
		});
		app.logs.push_back(LogEntry {
			level: "INFO".to_string(),
			target: "puppy::server".to_string(),
			message: "proxy server is ready".to_string(),
			..LogEntry::default()
		});
		app
	}

	fn connection_fixture(
		id: &str,
		target: &str,
		status: ConnectionStatus,
		traffic: u64,
		started: i64,
	) -> Connection {
		Connection {
			id: id.to_string(),
			status: status as i32,
			target_host: target.to_string(),
			target_port: 443,
			bytes_in: traffic,
			started_at: Some(prost_types::Timestamp {
				seconds: started,
				nanos: 0,
			}),
			..Connection::default()
		}
	}

	fn connection_ids(app: &App) -> Vec<&str> {
		app.visible_connections()
			.into_iter()
			.map(|connection| connection.id.as_str())
			.collect()
	}

	fn render_text(app: &mut App, width: u16, height: u16) -> String {
		let backend = TestBackend::new(width, height);
		let mut terminal = Terminal::new(backend).expect("test terminal");
		terminal
			.draw(|frame| draw(frame, app))
			.expect("dashboard render");
		terminal
			.backend()
			.buffer()
			.content()
			.chunks(width as usize)
			.map(|row| row.iter().map(|cell| cell.symbol()).collect::<String>())
			.collect::<Vec<_>>()
			.join("\n")
	}
}
