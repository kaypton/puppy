//! Runtime configuration for the SOCKS5 frontend.
//!
//! The TOML-decoded file configuration lives in the `config` crate as
//! `SocksFrontendConfiguration`; this crate owns the runtime form
//! (`ServerConfiguration`) which adds the backend, dialer, stats, and TLS
//! material.

use std::sync::Arc;

use puppy_core::backend::{supports, Backend, Dialer, Protocol, Target};
use puppy_core::stats::{ConnectionRegistry, Deps, EventBus, StatsRegistry};

pub use config::SocksFrontendConfiguration;

/// Discriminant identifying the SOCKS5 proxy frontend in a named configuration
/// group.
pub const TYPE: &str = "socksproxy";

/// Runtime configuration for the SOCKS5 proxy frontend.
///
/// The TOML-decoded [`SocksFrontendConfiguration`] is converted into this
/// runtime form via [`ServerConfiguration::from_file_config`].
#[derive(Clone)]
pub struct ServerConfiguration {
	pub listen_address: String,
	pub listen_port: u16,
	/// PEM-encoded certificate file. When both `tls_cert_file` and
	/// `tls_key_file` are non-empty, the listener wraps each accepted
	/// connection in TLS (SOCKS5-over-TLS).
	pub tls_cert_file: String,
	pub tls_key_file: String,
	/// RFC 1929 username. When both `username` and `password` are non-empty,
	/// the proxy requires username/password authentication (method 0x02).
	/// When both are empty the proxy runs open (method 0x00).
	pub username: String,
	pub password: String,
	/// Backend that dials the upstream connection for each CONNECT target.
	pub backend: Arc<dyn Backend>,
	/// Egress dialer for backend transport connections. When `None`, the
	/// system default (`SystemDialer`) is used.
	pub egress_dialer: Option<Arc<dyn Dialer>>,
	/// Per-direction copy buffer used by each tunnel. When zero, the shim
	/// package default is used.
	pub shim_buffer_size: usize,
	/// Frontend name used for stats attribution and event publishing.
	pub name: String,
	/// Global counter registry. `None` disables global counting.
	pub stats: Option<Arc<StatsRegistry>>,
	/// Active connection registry. `None` disables per-connection tracking.
	pub conn_reg: Option<Arc<ConnectionRegistry>>,
	/// Lifecycle event bus. `None` disables event publishing.
	pub bus: Option<Arc<EventBus>>,
}

impl ServerConfiguration {
	/// Validates the runtime configuration fields.
	///
	/// Error strings are prefixed with `"socksproxy: "`.
	pub fn validate(&self) -> Result<(), ConfigError> {
		if self.listen_address.is_empty() {
			return Err(ConfigError::Validation(
				"socksproxy: listen address is required".to_string(),
			));
		}
		if self.listen_port == 0 {
			return Err(ConfigError::Validation(
				"socksproxy: listen port is required".to_string(),
			));
		}
		if (self.tls_cert_file.is_empty()) != (self.tls_key_file.is_empty()) {
			return Err(ConfigError::Validation(
				"socksproxy: TLS certificate and key files must both be set or both be empty"
					.to_string(),
			));
		}
		if !supports(
			&self.backend.capabilities(),
			&Target {
				network: "tcp".to_string(),
				protocol: Protocol::Unknown,
				host: String::new(),
				port: 0,
			},
		) {
			return Err(ConfigError::Validation(
				"socksproxy: backend must support tcp with unknown application protocol"
					.to_string(),
			));
		}
		if (self.username.is_empty()) != (self.password.is_empty()) {
			return Err(ConfigError::Validation(
				"socksproxy: username and password must both be set or both be empty".to_string(),
			));
		}
		Ok(())
	}

	/// Adds runtime dependencies to the frontend's file configuration and
	/// validates the resulting runtime configuration.
	///
	/// The file config is the TOML-decoded [`SocksFrontendConfiguration`].
	pub fn from_file_config(
		file: &SocksFrontendConfiguration,
		backend: Arc<dyn Backend>,
		shim_buffer_size: usize,
		stats_deps: Deps,
	) -> Result<Self, ConfigError> {
		let sc = ServerConfiguration {
			listen_address: file.listen_address.clone(),
			listen_port: file.listen_port,
			tls_cert_file: file.tls_cert_file.clone(),
			tls_key_file: file.tls_key_file.clone(),
			username: file.username.clone(),
			password: file.password.clone(),
			backend,
			egress_dialer: None,
			shim_buffer_size,
			name: stats_deps.name,
			stats: stats_deps.stats.map(Arc::new),
			conn_reg: stats_deps.conn_reg.map(Arc::new),
			bus: stats_deps.bus.map(Arc::new),
		};
		sc.validate()?;
		Ok(sc)
	}
}

/// Errors returned by configuration validation and TLS material loading.
#[derive(thiserror::Error, Debug)]
pub enum ConfigError {
	#[error("{0}")]
	Validation(String),
	#[error("socksproxy: load TLS certificate and key: {0}")]
	TlsLoad(String),
}
