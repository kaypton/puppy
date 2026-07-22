//! Runtime configuration for the gRPC tunnel frontend.
//!
//! The TOML-decoded file configuration lives in the `config` crate as
//! `GrpcFrontendConfiguration`; this crate owns the runtime form
//! (`ServerConfiguration`) which adds the backend, dialer, stats, and TLS
//! material.

use std::sync::Arc;

use puppy_core::backend::{supports, Backend, Dialer, Protocol, Target};
use puppy_core::stats::{ConnectionRegistry, Deps, EventBus, StatsRegistry};

pub use config::GrpcFrontendConfiguration;

/// Discriminant identifying the gRPC tunnel frontend in a named configuration
/// group.
pub const TYPE: &str = "grpcproxy";

/// Runtime configuration for the gRPC tunnel proxy frontend.
///
/// The TOML-decoded [`GrpcFrontendConfiguration`] is converted into this
/// runtime form via [`ServerConfiguration::from_file_config`].
#[derive(Clone)]
pub struct ServerConfiguration {
	pub listen_address: String,
	pub listen_port: u16,
	pub tls_cert_file: String,
	pub tls_key_file: String,
	pub token: String,
	pub backend: Arc<dyn Backend>,
	pub egress_dialer: Option<Arc<dyn Dialer>>,
	pub shim_buffer_size: usize,
	pub name: String,
	pub backend_name: String,
	pub stats: Option<Arc<StatsRegistry>>,
	pub conn_reg: Option<Arc<ConnectionRegistry>>,
	pub bus: Option<Arc<EventBus>>,
}

impl ServerConfiguration {
	/// Validates the runtime configuration fields.
	///
	/// Error strings are prefixed with `"grpcproxy: "` so callers see a
	/// consistent, machine-greppable prefix.
	pub fn validate(&self) -> Result<(), ConfigError> {
		if self.listen_address.is_empty() {
			return Err(ConfigError::Validation(
				"grpcproxy: listen address is required".to_string(),
			));
		}
		if self.listen_port == 0 {
			return Err(ConfigError::Validation(
				"grpcproxy: listen port is required".to_string(),
			));
		}
		if (self.tls_cert_file.is_empty()) != (self.tls_key_file.is_empty()) {
			return Err(ConfigError::Validation(
				"grpcproxy: TLS certificate and key files must both be set or both be empty"
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
				"grpcproxy: backend must support tcp with unknown application protocol".to_string(),
			));
		}
		Ok(())
	}

	/// Adds runtime dependencies to the frontend's file configuration and
	/// validates the resulting runtime configuration.
	///
	/// The file config is the TOML-decoded [`GrpcFrontendConfiguration`].
	pub fn from_file_config(
		file: &GrpcFrontendConfiguration,
		backend: Arc<dyn Backend>,
		shim_buffer_size: usize,
		stats_deps: Deps,
	) -> Result<Self, ConfigError> {
		let sc = ServerConfiguration {
			listen_address: file.listen_address.clone(),
			listen_port: file.listen_port,
			tls_cert_file: file.tls_cert_file.clone(),
			tls_key_file: file.tls_key_file.clone(),
			token: file.token.clone(),
			backend,
			egress_dialer: None,
			shim_buffer_size,
			name: stats_deps.name,
			backend_name: stats_deps.backend,
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
	#[error("grpcproxy: load TLS certificate and key: {0}")]
	TlsLoad(String),
}
