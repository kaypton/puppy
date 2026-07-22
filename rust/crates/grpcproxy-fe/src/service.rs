//! gRPC tunnel service: implements the `puppy.tunnel.v1.Tunnel` server.
//!
//! Each `Connect` RPC is one tunnel: the handler authenticates the client,
//! decodes the initial connect frame, dials the upstream through the backend,
//! and then spawns a task that pipes bytes between the gRPC stream and the
//! backend-dialed stream via a `ShimServer`. The response stream is fed by the
//! shim through a forwarding pump so the handler can return immediately while
//! the copy loop keeps running.

use std::sync::Arc;

use grpc_tunnel::tunnel_server::Tunnel;
use grpc_tunnel::{parse_connect, server_stream, Frame, CHANNEL_CAPACITY};
use puppy_core::backend::{Backend, BoxedStream, Dialer, Protocol, Target};
use puppy_core::counting::CountingConn;
use puppy_core::shim::{ShimServer, ShimServerConfiguration};
use puppy_core::stats::{generate_connection_id, ConnectionInfo, EventType};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use crate::config::ServerConfiguration;

/// gRPC tunnel service handed to `tonic::transport::Server`.
///
/// Cheap to clone: all state lives behind `Arc`s.
pub struct TunnelService {
	config: Arc<ServerConfiguration>,
	backend: Arc<dyn Backend>,
	dialer: Arc<dyn Dialer>,
}

impl TunnelService {
	/// Creates a service from the shared runtime configuration, the backend,
	/// and the egress dialer selected by `Server::new`.
	pub fn new(
		config: Arc<ServerConfiguration>,
		backend: Arc<dyn Backend>,
		dialer: Arc<dyn Dialer>,
	) -> Self {
		Self {
			config,
			backend,
			dialer,
		}
	}
}

#[tonic::async_trait]
impl Tunnel for TunnelService {
	type ConnectStream = ReceiverStream<Result<Frame, Status>>;

	async fn connect(
		&self,
		request: Request<tonic::Streaming<Frame>>,
	) -> Result<Response<Self::ConnectStream>, Status> {
		let config = &*self.config;

		// Bearer token authentication, enabled only when a token is configured.
		if !config.token.is_empty() {
			let expected = format!("Bearer {}", config.token);
			let authenticated = request
				.metadata()
				.get("authorization")
				.and_then(|v| v.to_str().ok())
				.map(|v| v == expected)
				.unwrap_or(false);
			if !authenticated {
				return Err(Status::unauthenticated(
					"grpcproxy: invalid or missing bearer token",
				));
			}
		}

		let remote_addr = request
			.remote_addr()
			.map(|a| a.to_string())
			.unwrap_or_default();
		let mut requests = request.into_inner();

		// The first frame must be a connect frame describing the target.
		let first = match requests.message().await {
			Ok(Some(frame)) => frame,
			Ok(None) => return Err(Status::invalid_argument("missing connect frame")),
			Err(status) => return Err(status),
		};
		let (network, host, port) = parse_connect(first)?;
		let target = Target {
			network,
			protocol: Protocol::Unknown,
			host,
			port,
		};

		if let Some(stats) = &config.stats {
			stats.inc_total();
		}

		// Dial the upstream backend.
		let upstream = match self
			.backend
			.dial(target.clone(), self.dialer.as_ref())
			.await
		{
			Ok(s) => s,
			Err(e) => {
				if let Some(stats) = &config.stats {
					stats.inc_dial_failure();
				}
				if let Some(bus) = &config.bus {
					bus.publish(puppy_core::stats::Event {
						event_type: EventType::DialFailed,
						time: std::time::Instant::now(),
						frontend: config.name.clone(),
						connection_id: String::new(),
						target: target.address(),
						remote_addr: remote_addr.clone(),
						message: e.to_string(),
					});
				}
				tracing::info!(target = %target.address(), err = %e, "backend dial failed");
				return Err(Status::unavailable(format!("backend dial failed: {e}")));
			}
		};
		if let Some(stats) = &config.stats {
			stats.inc_dial_success();
		}

		// Register the connection for stats tracking and wrap the frontend side
		// with a counting connection so per-connection and global byte counters
		// stay in sync.
		let conn_info: Option<Arc<ConnectionInfo>> =
			if config.conn_reg.is_some() || config.stats.is_some() {
				let info = Arc::new(ConnectionInfo::with_backend(
					generate_connection_id(),
					config.name.clone(),
					remote_addr.clone(),
					target.clone(),
					target.protocol,
					target.net(),
					config.backend_name.clone(),
				));
				let registered = config
					.conn_reg
					.as_ref()
					.map(|r| r.register(info.clone()))
					.unwrap_or(info.clone());
				if let Some(stats) = &config.stats {
					stats.inc_active();
				}
				if let Some(bus) = &config.bus {
					bus.publish(puppy_core::stats::Event {
						event_type: EventType::Connect,
						time: std::time::Instant::now(),
						frontend: config.name.clone(),
						connection_id: registered.id.clone(),
						target: target.address(),
						remote_addr: remote_addr.clone(),
						message: String::new(),
					});
				}
				Some(registered)
			} else {
				None
			};

		let (grpc_stream, response_rx) = server_stream(requests);
		let wrapped_frontend: BoxedStream = if config.conn_reg.is_some() || config.stats.is_some() {
			Box::new(CountingConn::new(
				grpc_stream,
				conn_info.clone(),
				config.stats.clone(),
			))
		} else {
			Box::new(grpc_stream)
		};

		let shim_server = match ShimServer::new(ShimServerConfiguration {
			frontend: Some(wrapped_frontend),
			backend: Some(upstream),
			buffer_size: config.shim_buffer_size,
		}) {
			Ok(s) => s,
			Err(e) => {
				tracing::error!("shim: {e}");
				cleanup_conn(config, &conn_info);
				return Err(Status::internal("shim setup failed"));
			}
		};

		// The handler must return the response stream now, while the copy loop
		// runs for the lifetime of the tunnel. Frames produced by the shim
		// (writes into the `GrpcStream`) land in `response_rx`; a pump task
		// forwards them as `Ok(frame)` items into the returned stream. When the
		// client disconnects, tonic drops the response stream, the request
		// stream ends (read-side EOF in the `GrpcStream`), and the shim's write
		// side eventually sees `BrokenPipe`; either way the shim task exits and
		// runs the cleanup.
		let (out_tx, out_rx) = mpsc::channel(CHANNEL_CAPACITY);
		let config = self.config.clone();
		let target_address = target.address();
		tokio::spawn(async move {
			let forward = async move {
				let mut response_rx = response_rx;
				while let Some(frame) = response_rx.recv().await {
					if out_tx.send(Ok(frame)).await.is_err() {
						break;
					}
				}
			};
			let _ = tokio::join!(shim_server.run(), forward);
			tracing::info!(target = %target_address, "tunnel closed");
			cleanup_conn(&config, &conn_info);
		});

		tracing::info!(target = %target.address(), remote = %remote_addr, "tunnel established");
		Ok(Response::new(ReceiverStream::new(out_rx)))
	}
}

/// Removes the connection from the registry, decrements the active counter,
/// and publishes a disconnect event.
fn cleanup_conn(config: &ServerConfiguration, conn_info: &Option<Arc<ConnectionInfo>>) {
	if let Some(info) = conn_info {
		if let Some(reg) = &config.conn_reg {
			reg.remove(&info.id);
		}
		if let Some(stats) = &config.stats {
			stats.dec_active();
		}
		if let Some(bus) = &config.bus {
			bus.publish(puppy_core::stats::Event {
				event_type: EventType::Disconnect,
				time: std::time::Instant::now(),
				frontend: config.name.clone(),
				connection_id: info.id.clone(),
				target: String::new(),
				remote_addr: String::new(),
				message: String::new(),
			});
		}
	}
}
