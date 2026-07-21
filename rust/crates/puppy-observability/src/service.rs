use std::collections::HashMap;
use std::pin::Pin;
use std::time::{Duration, Instant};

use puppy_core::stats::{ConnectionRegistry, StatsRegistry};
use puppy_rpc::v1::observability_server::Observability;
use puppy_rpc::v1::{
	Connection, ConnectionStatus, ConnectionUpdate, ConnectionUpdateKind, GetConnectionRequest,
	ListConnectionsRequest, ListConnectionsResponse, ListLogsRequest, ListLogsResponse, LogEntry,
	Overview, TrafficSample, WatchConnectionsRequest, WatchLogsRequest, WatchTrafficRequest,
};
use tokio::sync::mpsc;
use tokio_stream::{wrappers::ReceiverStream, Stream};
use tonic::{Request, Response, Status};

use crate::database::connection_from_info;
use crate::logging::matches_filter;
use crate::{Database, LogHub};

type ResponseStream<T> = Pin<Box<dyn Stream<Item = Result<T, Status>> + Send + 'static>>;

#[derive(Clone)]
pub struct ObservabilityService {
	database: Database,
	stats: StatsRegistry,
	connections: ConnectionRegistry,
	logs: LogHub,
	instance_id: String,
	started_at_ms: i64,
	started: Instant,
}

impl ObservabilityService {
	pub fn new(
		database: Database,
		stats: StatsRegistry,
		connections: ConnectionRegistry,
		logs: LogHub,
		instance_id: String,
		started_at_ms: i64,
	) -> Self {
		Self {
			database,
			stats,
			connections,
			logs,
			instance_id,
			started_at_ms,
			started: Instant::now(),
		}
	}
}

#[tonic::async_trait]
impl Observability for ObservabilityService {
	async fn get_overview(&self, _request: Request<()>) -> Result<Response<Overview>, Status> {
		let snapshot = self.stats.snapshot();
		let totals = self.database.totals().map_err(internal)?;
		Ok(Response::new(Overview {
			api_version: "v1".to_string(),
			server_version: env!("CARGO_PKG_VERSION").to_string(),
			server_instance_id: self.instance_id.clone(),
			started_at: Some(timestamp(self.started_at_ms)),
			uptime_seconds: self.started.elapsed().as_secs_f64(),
			pid: std::process::id(),
			degraded: false,
			degraded_reason: String::new(),
			process_total_connections: snapshot.total_connections,
			active_connections: snapshot.active_connections,
			dial_successes: snapshot.dial_successes,
			dial_failures: snapshot.dial_failures,
			process_bytes_in: snapshot.bytes_in,
			process_bytes_out: snapshot.bytes_out,
			all_time_connections: totals.connections,
			all_time_bytes_in: totals.bytes_in,
			all_time_bytes_out: totals.bytes_out,
		}))
	}

	async fn list_connections(
		&self,
		request: Request<ListConnectionsRequest>,
	) -> Result<Response<ListConnectionsResponse>, Status> {
		let (connections, total, next_page_token) =
			self.database.list(request.get_ref()).map_err(internal)?;
		Ok(Response::new(ListConnectionsResponse {
			connections,
			next_page_token,
			total,
		}))
	}

	async fn get_connection(
		&self,
		request: Request<GetConnectionRequest>,
	) -> Result<Response<Connection>, Status> {
		let id = &request.get_ref().id;
		if let Some(info) = self.connections.get(id) {
			return Ok(Response::new(connection_from_info(
				&self.instance_id,
				&info,
			)));
		}
		self.database
			.get(id)
			.map_err(internal)?
			.map(Response::new)
			.ok_or_else(|| Status::not_found("connection not found"))
	}

	type WatchConnectionsStream = ResponseStream<ConnectionUpdate>;

	async fn watch_connections(
		&self,
		request: Request<WatchConnectionsRequest>,
	) -> Result<Response<Self::WatchConnectionsStream>, Status> {
		let registry = self.connections.clone();
		let instance_id = self.instance_id.clone();
		let include_initial = request.get_ref().include_initial;
		let (tx, rx) = mpsc::channel(256);
		tokio::spawn(async move {
			let mut previous: HashMap<String, Connection> = HashMap::new();
			let mut ticker = tokio::time::interval(Duration::from_secs(1));
			loop {
				ticker.tick().await;
				let current: HashMap<String, Connection> = registry
					.active()
					.into_iter()
					.map(|info| {
						let connection = connection_from_info(&instance_id, &info);
						(connection.id.clone(), connection)
					})
					.collect();
				for (id, connection) in &current {
					let changed = previous.get(id).is_none_or(|old| {
						old.bytes_in != connection.bytes_in || old.bytes_out != connection.bytes_out
					});
					if (include_initial && previous.is_empty()) || changed {
						let kind = if previous.contains_key(id) {
							ConnectionUpdateKind::Upsert
						} else {
							ConnectionUpdateKind::Snapshot
						};
						if tx
							.send(Ok(ConnectionUpdate {
								kind: kind as i32,
								connection: Some(connection.clone()),
							}))
							.await
							.is_err()
						{
							return;
						}
					}
				}
				for (id, old) in &previous {
					if !current.contains_key(id) {
						let mut closed = old.clone();
						closed.status = ConnectionStatus::Closed as i32;
						closed.close_reason = "completed".to_string();
						if tx
							.send(Ok(ConnectionUpdate {
								kind: ConnectionUpdateKind::Closed as i32,
								connection: Some(closed),
							}))
							.await
							.is_err()
						{
							return;
						}
					}
				}
				previous = current;
			}
		});
		Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
	}

	async fn list_logs(
		&self,
		request: Request<ListLogsRequest>,
	) -> Result<Response<ListLogsResponse>, Status> {
		let req = request.get_ref();
		let (entries, next_cursor) = self
			.logs
			.list(
				req.filter.as_ref(),
				req.limit.max(1) as usize,
				&req.before_cursor,
			)
			.map_err(internal)?;
		Ok(Response::new(ListLogsResponse {
			entries,
			next_cursor,
		}))
	}

	type WatchLogsStream = ResponseStream<LogEntry>;

	async fn watch_logs(
		&self,
		request: Request<WatchLogsRequest>,
	) -> Result<Response<Self::WatchLogsStream>, Status> {
		let req = request.into_inner();
		let history = self
			.logs
			.after(&req.after_cursor, req.filter.as_ref())
			.map_err(internal)?;
		let mut live = self.logs.subscribe();
		let (tx, rx) = mpsc::channel(512);
		tokio::spawn(async move {
			for record in history {
				if tx.send(Ok(record.into_proto())).await.is_err() {
					return;
				}
			}
			loop {
				match live.recv().await {
					Ok(record) if matches_filter(&record, req.filter.as_ref()) => {
						if tx.send(Ok(record.into_proto())).await.is_err() {
							return;
						}
					}
					Ok(_) => {}
					Err(tokio::sync::broadcast::error::RecvError::Lagged(count)) => {
						if tx
							.send(Err(Status::data_loss(format!(
								"log subscriber lagged by {count} records"
							))))
							.await
							.is_err()
						{
							return;
						}
					}
					Err(tokio::sync::broadcast::error::RecvError::Closed) => return,
				}
			}
		});
		Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
	}

	type WatchTrafficStream = ResponseStream<TrafficSample>;

	async fn watch_traffic(
		&self,
		request: Request<WatchTrafficRequest>,
	) -> Result<Response<Self::WatchTrafficStream>, Status> {
		let interval_ms = request.get_ref().interval_ms.clamp(250, 5_000).max(250) as u64;
		let stats = self.stats.clone();
		let database = self.database.clone();
		let (tx, rx) = mpsc::channel(32);
		tokio::spawn(async move {
			let mut ticker = tokio::time::interval(Duration::from_millis(interval_ms));
			let mut previous = stats.snapshot();
			loop {
				ticker.tick().await;
				let current = stats.snapshot();
				let totals = match database.totals() {
					Ok(v) => v,
					Err(error) => {
						let _ = tx.send(Err(internal(error))).await;
						return;
					}
				};
				let factor = 1_000.0 / interval_ms as f64;
				let sample = TrafficSample {
					time: Some(timestamp(now_ms())),
					interval_ms,
					bytes_in_per_second: (current.bytes_in.saturating_sub(previous.bytes_in) as f64
						* factor) as u64,
					bytes_out_per_second: (current.bytes_out.saturating_sub(previous.bytes_out)
						as f64 * factor) as u64,
					process_bytes_in: current.bytes_in,
					process_bytes_out: current.bytes_out,
					all_time_bytes_in: totals.bytes_in,
					all_time_bytes_out: totals.bytes_out,
					active_connections: current.active_connections,
				};
				previous = current;
				if tx.send(Ok(sample)).await.is_err() {
					return;
				}
			}
		});
		Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
	}
}

fn internal(error: impl std::fmt::Display) -> Status {
	Status::internal(error.to_string())
}

fn timestamp(ms: i64) -> prost_types::Timestamp {
	prost_types::Timestamp {
		seconds: ms.div_euclid(1000),
		nanos: (ms.rem_euclid(1000) * 1_000_000) as i32,
	}
}

fn now_ms() -> i64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.unwrap_or_default()
		.as_millis() as i64
}
