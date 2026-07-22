//! gRPC tunnel server: tonic transport setup with optional TLS.
//!
//! The server exposes a single `puppy.tunnel.v1.Tunnel` service; per-request
//! handling (authentication, connect frame parsing, dialing, and the copy
//! loop) lives in [`crate::service`].

use std::net::SocketAddr;
use std::sync::Arc;

use grpc_tunnel::tunnel_server::TunnelServer;
use puppy_core::backend::{Backend, Dialer, SystemDialer};
use tonic::transport::{Identity, Server as TonicServer, ServerTlsConfig};

use crate::config::ServerConfiguration;
use crate::service::TunnelService;

/// gRPC tunnel proxy server.
pub struct Server {
	config: ServerConfiguration,
	backend: Arc<dyn Backend>,
	dialer: Arc<dyn Dialer>,
	tls_identity: Option<Identity>,
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
		let tls_identity = if !config.tls_cert_file.is_empty() {
			Some(load_tls_identity(
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
			tls_identity,
		})
	}

	/// Returns a reference to the runtime configuration. Used by tests to
	/// inspect defaults applied by `new`.
	pub fn config(&self) -> &ServerConfiguration {
		&self.config
	}

	/// Serves the tunnel endpoint until `shutdown` resolves. Returns `Ok(())`
	/// on graceful shutdown.
	pub async fn run<F: std::future::Future<Output = ()> + Send + 'static>(
		self,
		shutdown: F,
	) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
		let addr: SocketAddr =
			format!("{}:{}", self.config.listen_address, self.config.listen_port)
				.parse()
				.map_err(|e| format!("grpcproxy: listen address: {e}"))?;

		let transport = if self.tls_identity.is_some() {
			"https"
		} else {
			"http"
		};
		tracing::info!(addr = %addr, transport, "grpcproxy listening");

		let service = TunnelService::new(Arc::new(self.config), self.backend, self.dialer);

		let mut builder = TonicServer::builder();
		if let Some(identity) = self.tls_identity {
			builder = builder
				.tls_config(ServerTlsConfig::new().identity(identity))
				.map_err(|e| format!("grpcproxy: TLS config: {e}"))?;
		}
		builder
			.add_service(TunnelServer::new(service))
			.serve_with_shutdown(addr, shutdown)
			.await?;
		Ok(())
	}
}

/// Loads a PEM-encoded certificate chain and private key into a tonic
/// [`Identity`].
///
/// Errors are wrapped as `ConfigError::TlsLoad` so callers see the
/// `"grpcproxy: load TLS certificate and key: ..."` prefix.
fn load_tls_identity(cert_file: &str, key_file: &str) -> Result<Identity, crate::ConfigError> {
	let cert = std::fs::read(cert_file).map_err(|e| crate::ConfigError::TlsLoad(e.to_string()))?;
	let key = std::fs::read(key_file).map_err(|e| crate::ConfigError::TlsLoad(e.to_string()))?;
	Ok(Identity::from_pem(cert, key))
}
