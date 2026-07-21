//! HTTP CONNECT proxy server: listener, accept loop, per-connection handling.
//!
//! Each accepted connection goes through the optional TLS handshake, the HTTP
//! CONNECT handshake, and then a `ShimServer` pipes bytes between the client
//! and the backend-dialed upstream.

use std::sync::Arc;

use puppy_core::backend::{Backend, BoxedStream, Dialer, SystemDialer};
use puppy_core::counting::CountingConn;
use puppy_core::shim::{ShimError, ShimServer, ShimServerConfiguration};
use puppy_core::stats::{
	generate_connection_id, ConnectionInfo, EventBus, EventType, StatsRegistry,
};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio_rustls::rustls;

use crate::config::ServerConfiguration;
use crate::handshake::handshake;

/// HTTP CONNECT proxy server.
pub struct Server {
	config: ServerConfiguration,
	backend: Arc<dyn Backend>,
	dialer: Arc<dyn Dialer>,
	tls_config: Option<Arc<rustls::ServerConfig>>,
}

impl Server {
	/// Applies defaults and returns a ready-to-run proxy. Configuration
	/// validation must be performed via `validate()` (typically through
	/// [`ServerConfiguration::from_file_config`]) before calling `new`.
	pub fn new(config: ServerConfiguration) -> Result<Self, crate::ConfigError> {
		let dialer: Arc<dyn Dialer> = config
			.egress_dialer
			.clone()
			.unwrap_or_else(|| Arc::new(SystemDialer));

		let backend = config.backend.clone();
		let tls_config = if !config.tls_cert_file.is_empty() {
			Some(build_server_tls_config(
				&config.tls_cert_file,
				&config.tls_key_file,
			)?)
		} else {
			None
		};

		Ok(Self {
			config,
			backend,
			dialer,
			tls_config,
		})
	}

	/// Returns a reference to the runtime configuration. Used by tests to
	/// inspect defaults applied by `new`.
	pub fn config(&self) -> &ServerConfiguration {
		&self.config
	}

	/// Listens and accepts connections until `shutdown` resolves. Returns
	/// `Ok(())` on graceful shutdown.
	pub async fn run<F: std::future::Future<Output = ()> + Send + 'static>(
		self,
		shutdown: F,
	) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
		let addr = format!("{}:{}", self.config.listen_address, self.config.listen_port);
		let ln = TcpListener::bind(&addr)
			.await
			.map_err(|e| format!("httpproxy: listen: {e}"))?;

		let transport = if self.tls_config.is_some() {
			"https"
		} else {
			"http"
		};
		tracing::info!(
			addr = ln
				.local_addr()
				.ok()
				.map(|a| a.to_string())
				.unwrap_or_default(),
			transport,
			"httpproxy listening"
		);

		let backend = self.backend.clone();
		let dialer = self.dialer.clone();
		let tls_config = self.tls_config.clone();
		let config = Arc::new(self.config);

		tokio::pin!(shutdown);

		loop {
			tokio::select! {
				_ = &mut shutdown => {
					return Ok(());
				}
				accept = ln.accept() => {
					let (conn, peer) = match accept {
						Ok((c, p)) => (c, p),
						Err(e) => {
							tracing::warn!("httpproxy: accept: {e}");
							return Err(format!("httpproxy: accept: {e}").into());
						}
					};
					let backend = backend.clone();
					let dialer = dialer.clone();
					let tls_config = tls_config.clone();
					let config = config.clone();
					tokio::spawn(async move {
						if let Err(e) = handle_conn(config, conn, peer, backend, dialer, tls_config).await {
							tracing::debug!("httpproxy: connection error: {e}");
						}
					});
				}
			}
		}
	}
}

/// Builds a `rustls::ServerConfig` from PEM-encoded cert/key files.
///
/// Errors are wrapped as `ConfigError::TlsLoad` so callers see the
/// `"httpproxy: load TLS certificate and key: ..."` prefix.
fn build_server_tls_config(
	cert_file: &str,
	key_file: &str,
) -> Result<Arc<rustls::ServerConfig>, crate::ConfigError> {
	let cert_pem =
		std::fs::read(cert_file).map_err(|e| crate::ConfigError::TlsLoad(e.to_string()))?;
	let key_pem =
		std::fs::read(key_file).map_err(|e| crate::ConfigError::TlsLoad(e.to_string()))?;

	let mut cert_chain = Vec::new();
	let mut cert_reader = std::io::Cursor::new(&cert_pem);
	for cert in rustls_pemfile::certs(&mut cert_reader) {
		let cert = cert.map_err(|e| crate::ConfigError::TlsLoad(e.to_string()))?;
		cert_chain.push(rustls::pki_types::CertificateDer::from(cert.to_vec()));
	}
	if cert_chain.is_empty() {
		return Err(crate::ConfigError::TlsLoad(
			"no certificates parsed from tls_cert_file".to_string(),
		));
	}
	let mut key_reader = std::io::Cursor::new(&key_pem);
	let key = rustls_pemfile::private_key(&mut key_reader)
		.map_err(|e| crate::ConfigError::TlsLoad(e.to_string()))?
		.ok_or_else(|| {
			crate::ConfigError::TlsLoad("no private key parsed from tls_key_file".to_string())
		})?;

	let mut server_config = rustls::ServerConfig::builder()
		.with_no_client_auth()
		.with_single_cert(cert_chain, key)
		.map_err(|e| crate::ConfigError::TlsLoad(e.to_string()))?;
	// Configure ALPN to advertise `http/1.1`. rustls always enforces TLS 1.2+
	// as its minimum, so the minimum-version setting from other TLS stacks is
	// already satisfied.
	server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
	Ok(Arc::new(server_config))
}

/// Handles a single accepted connection: handshake, dial upstream, then run a
/// ShimServer to pipe bytes between client and upstream.
async fn handle_conn(
	config: Arc<ServerConfiguration>,
	conn: tokio::net::TcpStream,
	peer: std::net::SocketAddr,
	backend: Arc<dyn Backend>,
	dialer: Arc<dyn Dialer>,
	tls_config: Option<Arc<rustls::ServerConfig>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
	// Optional TLS handshake, bounded so a stalled client cannot hold a task
	// forever (30-second deadline before `prepare_frontend_conn` + `handshake`).
	let conn: BoxedStream = match tokio::time::timeout(
		std::time::Duration::from_secs(30),
		prepare_frontend_conn(conn, tls_config.as_ref()),
	)
	.await
	{
		Ok(Ok(c)) => c,
		Ok(Err(e)) => {
			tracing::debug!(remote = %peer, err = %e, "TLS handshake failed");
			return Ok(());
		}
		Err(_) => {
			tracing::debug!(remote = %peer, "handshake timed out");
			return Ok(());
		}
	};

	if let Some(stats) = &config.stats {
		stats.inc_total();
	}

	// HTTP CONNECT handshake.
	let (target, mut frontend) = match handshake(conn, &config).await {
		Ok(v) => v,
		Err(e) => {
			tracing::error!(remote = %peer, err = %e, "handshake failed");
			return Ok(());
		}
	};

	// Dial the upstream backend.
	let upstream = match backend.dial(target.clone(), dialer.as_ref()).await {
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
					remote_addr: peer.to_string(),
					message: e.to_string(),
				});
			}
			// Tell the client the dial failed (502 Bad Gateway). The body is
			// the canonical status text plus a newline.
			let body = "Bad Gateway\n";
			let resp = format!(
				"HTTP/1.1 502 Bad Gateway\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
				body.len(),
				body
			);
			let _ = frontend.write_all(resp.as_bytes()).await;
			tracing::info!(target = %target.address(), err = %e, "backend dial failed");
			return Ok(());
		}
	};
	if let Some(stats) = &config.stats {
		stats.inc_dial_success();
	}

	// Tell the client the tunnel is up. Per RFC 7231 the 2xx response has no
	// body and the connection becomes a raw tunnel.
	if frontend
		.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
		.await
		.is_err()
	{
		return Ok(());
	}

	// Register the connection for stats tracking and wrap the frontend side
	// with a counting connection so per-connection and global byte counters
	// stay in sync.
	let conn_info: Option<Arc<ConnectionInfo>> =
		if config.conn_reg.is_some() || config.stats.is_some() {
			let info = Arc::new(ConnectionInfo::with_backend(
				generate_connection_id(),
				config.name.clone(),
				peer.to_string(),
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
					remote_addr: peer.to_string(),
					message: String::new(),
				});
			}
			Some(registered)
		} else {
			None
		};

	let wrapped_frontend: BoxedStream = if config.conn_reg.is_some() || config.stats.is_some() {
		Box::new(CountingConn::new(
			frontend,
			conn_info.clone(),
			config.stats.clone(),
		))
	} else {
		frontend
	};

	let shim_cfg = ShimServerConfiguration {
		frontend: Some(wrapped_frontend),
		backend: Some(upstream),
		buffer_size: config.shim_buffer_size,
	};
	let shim_server = match ShimServer::new(shim_cfg) {
		Ok(s) => s,
		Err(ShimError::FrontendNil) => {
			tracing::error!("shim: frontend is nil");
			cleanup_conn(&config, &conn_info);
			return Ok(());
		}
		Err(ShimError::BackendNil) => {
			tracing::error!("shim: backend is nil");
			cleanup_conn(&config, &conn_info);
			return Ok(());
		}
	};

	tracing::info!(target = %target.address(), remote = %peer, "tunnel established");
	let _ = shim_server.run().await;
	tracing::info!(target = %target.address(), "tunnel closed");

	cleanup_conn(&config, &conn_info);
	Ok(())
}

/// Completes the optional TLS transport handshake before the HTTP CONNECT
/// handshake starts.
async fn prepare_frontend_conn(
	conn: tokio::net::TcpStream,
	tls_config: Option<&Arc<rustls::ServerConfig>>,
) -> Result<BoxedStream, Box<dyn std::error::Error + Send + Sync>> {
	match tls_config {
		Some(tc) => {
			let acceptor = tokio_rustls::TlsAcceptor::from(tc.clone());
			let tls = acceptor.accept(conn).await.map_err(|e| {
				let err: Box<dyn std::error::Error + Send + Sync> =
					format!("TLS handshake: {e}").into();
				err
			})?;
			Ok(Box::new(tls))
		}
		None => Ok(Box::new(conn)),
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

// `EventBus` is referenced via the `config.bus` field; silence unused-import
// warning when the crate is built without stats wiring exercised.
#[allow(dead_code)]
fn _ensure_event_bus_import(_: &EventBus) {}

// `StatsRegistry` is referenced via `config.stats`; same as above.
#[allow(dead_code)]
fn _ensure_stats_registry_import(_: &StatsRegistry) {}
