//! Runtime configuration for the HTTP CONNECT frontend.
//!
//! The TOML-decoded file configuration lives in the `config` crate as
//! `HttpFrontendConfiguration`; this crate owns the runtime form
//! (`ServerConfiguration`) which adds the backend, dialer, stats, and TLS
//! material.

use std::sync::Arc;

use puppy_core::backend::{supports, Backend, Dialer, Protocol, Target};
use puppy_core::stats::{ConnectionRegistry, Deps, EventBus, StatsRegistry};

pub use config::HttpFrontendConfiguration;

/// Discriminant identifying the HTTP proxy frontend in a named configuration
/// group.
pub const TYPE: &str = "httpproxy";

/// Camouflage method selector.
///
/// Only `Return404` is supported; an empty string normalizes to `Return404`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CamouflageMethod {
	/// Make rejected requests resemble a 404 from a generic nginx server.
	#[default]
	Return404,
}

impl CamouflageMethod {
	/// Returns the string form used in TOML configuration and log messages.
	pub fn as_str(self) -> &'static str {
		match self {
			CamouflageMethod::Return404 => "return-404",
		}
	}
}

/// Returns `Return404` for an empty string, or `Return404` if already that
/// value. Any other value returns `None` and is rejected by
/// [`ServerConfiguration::validate`].
pub(crate) fn normalize_camouflage_method(method: &str) -> Option<CamouflageMethod> {
	if method.is_empty() || method == CamouflageMethod::Return404.as_str() {
		Some(CamouflageMethod::Return404)
	} else {
		None
	}
}

/// Runtime configuration for the HTTP CONNECT proxy frontend.
///
/// The TOML-decoded [`HttpFrontendConfiguration`] is converted into this
/// runtime form via [`ServerConfiguration::from_file_config`].
#[derive(Clone)]
pub struct ServerConfiguration {
	pub listen_address: String,
	pub listen_port: u16,
	pub tls_cert_file: String,
	pub tls_key_file: String,
	pub username: String,
	pub password: String,
	pub camouflage: bool,
	pub camouflage_method: CamouflageMethod,
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
	/// Error strings are prefixed with `"httpproxy: "` so callers see a
	/// consistent, machine-greppable prefix.
	pub fn validate(&self) -> Result<(), ConfigError> {
		if self.listen_address.is_empty() {
			return Err(ConfigError::Validation(
				"httpproxy: listen address is required".to_string(),
			));
		}
		if self.listen_port == 0 {
			return Err(ConfigError::Validation(
				"httpproxy: listen port is required".to_string(),
			));
		}
		if (self.tls_cert_file.is_empty()) != (self.tls_key_file.is_empty()) {
			return Err(ConfigError::Validation(
				"httpproxy: TLS certificate and key files must both be set or both be empty"
					.to_string(),
			));
		}
		if (self.username.is_empty()) != (self.password.is_empty()) {
			return Err(ConfigError::Validation(
				"httpproxy: username and password must both be set or both be empty".to_string(),
			));
		}
		if normalize_camouflage_method(self.camouflage_method.as_str()).is_none() {
			return Err(ConfigError::Validation(format!(
				"httpproxy: unsupported camouflage method {:?}",
				self.camouflage_method.as_str()
			)));
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
				"httpproxy: backend must support tcp with unknown application protocol".to_string(),
			));
		}
		Ok(())
	}

	/// Adds runtime dependencies to the frontend's file configuration and
	/// validates the resulting runtime configuration.
	///
	/// The file config is the TOML-decoded [`HttpFrontendConfiguration`].
	pub fn from_file_config(
		file: &HttpFrontendConfiguration,
		backend: Arc<dyn Backend>,
		shim_buffer_size: usize,
		stats_deps: Deps,
	) -> Result<Self, ConfigError> {
		let camouflage_method =
			normalize_camouflage_method(&file.camouflage_method).ok_or_else(|| {
				ConfigError::Validation("camouflage_method must be return-404 or empty".to_string())
			})?;
		let sc = ServerConfiguration {
			listen_address: file.listen_address.clone(),
			listen_port: file.listen_port,
			tls_cert_file: file.tls_cert_file.clone(),
			tls_key_file: file.tls_key_file.clone(),
			username: file.username.clone(),
			password: file.password.clone(),
			camouflage: file.camouflage,
			camouflage_method,
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
	#[error("httpproxy: load TLS certificate and key: {0}")]
	TlsLoad(String),
}
