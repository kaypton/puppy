//! puppy-server assembly: build backends and frontends from a loaded
//! `Configuration`, then run the selected frontend until shutdown.

use std::sync::Arc;

use anyhow::anyhow;
use puppy_core::backend::Backend;
use puppy_core::stats::Deps;
use tracing_subscriber::EnvFilter;

use config::{
	BackendConfiguration, Configuration, FrontendConfiguration, HttpBackendConfiguration,
	HttpFrontendConfiguration, SocksBackendConfiguration, SocksFrontendConfiguration,
	TunFrontendConfiguration,
};

pub use config::ConfigError;

/// Errors returned by [`build_backend`] or [`build_frontend`].
///
/// Error strings follow the `build backend "<name>": ...` and
/// `build frontend "<name>": ...` wrapping shape so callers can match on
/// substrings.
#[derive(thiserror::Error, Debug)]
pub enum BuildError {
	#[error(r#"build backend {name:?}: {source}"#)]
	Backend {
		name: String,
		#[source]
		source: anyhow::Error,
	},
	#[error(r#"build fallback backend {name:?}: {source}"#)]
	FallbackBackend {
		name: String,
		#[source]
		source: anyhow::Error,
	},
	#[error(r#"build frontend {name:?}: {source}"#)]
	Frontend {
		name: String,
		#[source]
		source: anyhow::Error,
	},
	#[error(r#"build frontend {name:?}: unsupported type {type_name:?}"#)]
	FrontendUnsupported { name: String, type_name: String },
}

/// Constructs a `Backend` from a decoded `BackendConfiguration` group.
///
/// The caller supplies the backend's `name` so error messages can reproduce
/// the `build backend "<name>": ...` wrapping.
pub fn build_backend(
	name: &str,
	group: &BackendConfiguration,
) -> Result<Arc<dyn Backend>, BuildError> {
	match group {
		BackendConfiguration::Direct(_cfg) => {
			// `direct::DirectBackend` is a unit struct with no configuration.
			Ok(Arc::new(direct::DirectBackend::new()))
		}
		BackendConfiguration::Http(cfg) => build_http_backend(name, cfg),
		BackendConfiguration::Socks(cfg) => build_socks_backend(name, cfg),
	}
}

fn build_http_backend(
	name: &str,
	file: &HttpBackendConfiguration,
) -> Result<Arc<dyn Backend>, BuildError> {
	let runtime = httpproxy_be::Configuration {
		proxy_address: file.proxy_address.clone(),
		username: file.username.clone(),
		password: file.password.clone(),
		tls: file.tls,
		tls_ca_file: file.tls_ca_file.clone(),
		tls_server_name: file.tls_server_name.clone(),
		tls_insecure_skip_verify: file.tls_insecure_skip_verify,
	}
	.backend_config()
	.map_err(|e| BuildError::Backend {
		name: name.to_string(),
		source: anyhow!(e),
	})?;
	let backend =
		httpproxy_be::HttpProxyBackend::new(runtime).map_err(|e| BuildError::Backend {
			name: name.to_string(),
			source: anyhow!(e),
		})?;
	Ok(Arc::new(backend))
}

fn build_socks_backend(
	name: &str,
	file: &SocksBackendConfiguration,
) -> Result<Arc<dyn Backend>, BuildError> {
	let runtime = socksproxy_be::Configuration {
		proxy_address: file.proxy_address.clone(),
		username: file.username.clone(),
		password: file.password.clone(),
		tls: file.tls,
		tls_ca_file: file.tls_ca_file.clone(),
		tls_server_name: file.tls_server_name.clone(),
		tls_insecure_skip_verify: file.tls_insecure_skip_verify,
	}
	.backend_config()
	.map_err(|e| BuildError::Backend {
		name: name.to_string(),
		source: anyhow!(e),
	})?;
	let backend =
		socksproxy_be::SocksProxyBackend::new(runtime).map_err(|e| BuildError::Backend {
			name: name.to_string(),
			source: anyhow!(e),
		})?;
	Ok(Arc::new(backend))
}

/// A constructed frontend ready to run.
///
/// Each variant wraps the typed `Server` from the corresponding frontend crate.
/// `run` consumes the frontend and drives it until `shutdown` resolves.
pub enum Frontend {
	Http(httpproxy_fe::Server),
	Socks(socksproxy_fe::Server),
	Tun(tun::server::Server),
}

impl Frontend {
	/// Runs the frontend until `shutdown` resolves (Ctrl-C, SIGTERM, etc.).
	pub async fn run<F>(self, shutdown: F) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
	where
		F: std::future::Future<Output = ()> + Send + 'static,
	{
		match self {
			Frontend::Http(s) => s.run(shutdown).await,
			Frontend::Socks(s) => s.run(shutdown).await,
			Frontend::Tun(s) => s.run(shutdown).await,
		}
	}
}

/// Constructs the selected frontend from a loaded `Configuration`.
///
/// Resolves the backend reference, looks up the shim buffer size, and delegates
/// to the frontend's `from_file_config` + `Server::new` constructor.
pub fn build_frontend(config: &Configuration, stats_deps: Deps) -> Result<Frontend, BuildError> {
	let frontend_name = config.frontend.as_str();
	let group = &config.frontends[frontend_name];
	match group {
		FrontendConfiguration::Http(file) => {
			build_http_frontend(frontend_name, file, config, stats_deps)
		}
		FrontendConfiguration::Socks(file) => {
			build_socks_frontend(frontend_name, file, config, stats_deps)
		}
		FrontendConfiguration::Tun(file) => {
			build_tun_frontend(frontend_name, file, config, stats_deps)
		}
	}
}

fn build_http_frontend(
	name: &str,
	file: &HttpFrontendConfiguration,
	config: &Configuration,
	stats_deps: Deps,
) -> Result<Frontend, BuildError> {
	let backend = build_backend(&file.backend, &config.backends[&file.backend])
		.map_err(|e| wrap_frontend_err(name, e))?;
	let shim_buffer_size = shim_buffer_size(config, &file.shim, name)?;
	let runtime = httpproxy_fe::ServerConfiguration::from_file_config(
		file,
		backend,
		shim_buffer_size,
		stats_deps,
	)
	.map_err(|e| BuildError::Frontend {
		name: name.to_string(),
		source: anyhow!(e),
	})?;
	let server = httpproxy_fe::Server::new(runtime).map_err(|e| BuildError::Frontend {
		name: name.to_string(),
		source: anyhow!(e),
	})?;
	Ok(Frontend::Http(server))
}

fn build_socks_frontend(
	name: &str,
	file: &SocksFrontendConfiguration,
	config: &Configuration,
	stats_deps: Deps,
) -> Result<Frontend, BuildError> {
	let backend = build_backend(&file.backend, &config.backends[&file.backend])
		.map_err(|e| wrap_frontend_err(name, e))?;
	let shim_buffer_size = shim_buffer_size(config, &file.shim, name)?;
	let runtime = socksproxy_fe::ServerConfiguration::from_file_config(
		file,
		backend,
		shim_buffer_size,
		stats_deps,
	)
	.map_err(|e| BuildError::Frontend {
		name: name.to_string(),
		source: anyhow!(e),
	})?;
	let server = socksproxy_fe::Server::new(runtime).map_err(|e| BuildError::Frontend {
		name: name.to_string(),
		source: anyhow!(e),
	})?;
	Ok(Frontend::Socks(server))
}

/// Builds the TUN frontend by resolving all candidate backends and the
/// fallback, then constructing the runtime `ServerConfiguration`.
///
/// Mirrors Go `buildFrontend` case `frontendtunproxy.Type` (cmd/puppy-server/main.go:573).
fn build_tun_frontend(
	name: &str,
	file: &TunFrontendConfiguration,
	config: &Configuration,
	stats_deps: Deps,
) -> Result<Frontend, BuildError> {
	let mut backends: Vec<Arc<dyn Backend>> = Vec::new();
	for backend_name in file.backend_references() {
		let backend = build_backend(&backend_name, &config.backends[&backend_name])
			.map_err(|e| wrap_frontend_err(name, e))?;
		backends.push(backend);
	}
	// Fallback defaults to a fresh direct backend when not configured.
	let fallback: Arc<dyn Backend> = if file.fallback.is_empty() {
		Arc::new(direct::DirectBackend::new())
	} else {
		build_backend(&file.fallback, &config.backends[&file.fallback])
			.map_err(|e| BuildError::FallbackBackend {
				name: file.fallback.clone(),
				source: anyhow!(e),
			})
			.map_err(|e| wrap_frontend_err(name, e))?
	};
	let shim_buffer_size = shim_buffer_size(config, &file.shim, name)?;
	let runtime = tun::config::ServerConfiguration::from_file_config(
		file,
		backends,
		fallback,
		None,
		shim_buffer_size,
		stats_deps,
	)
	.map_err(|e| BuildError::Frontend {
		name: name.to_string(),
		source: anyhow!(e),
	})?;
	let server = tun::server::Server::new(runtime).map_err(|e| BuildError::Frontend {
		name: name.to_string(),
		source: anyhow!(e),
	})?;
	Ok(Frontend::Tun(server))
}

/// Re-wraps a `BuildError::Backend` so the frontend's name appears in the
/// outermost error message: `build frontend "<name>": ...`.
fn wrap_frontend_err(name: &str, e: BuildError) -> BuildError {
	BuildError::Frontend {
		name: name.to_string(),
		source: anyhow!(e),
	}
}

/// Resolves the shim buffer size for a frontend's shim reference.
///
/// The `buffer_size` field is stored as `i64` in TOML; we convert to `usize`
/// here, falling back to `puppy_core::shim::DEFAULT_BUFFER_SIZE` when zero.
fn shim_buffer_size(
	config: &Configuration,
	shim_name: &str,
	frontend_name: &str,
) -> Result<usize, BuildError> {
	let shim = &config.shims[shim_name];
	let raw = shim.buffer_size;
	if raw < 0 {
		return Err(BuildError::Frontend {
			name: frontend_name.to_string(),
			source: anyhow!("shim {shim_name:?}: buffer_size must not be negative"),
		});
	}
	if raw == 0 {
		Ok(puppy_core::shim::DEFAULT_BUFFER_SIZE)
	} else {
		Ok(raw as usize)
	}
}

/// Initializes the global `tracing` subscriber with a JSON formatter using
/// field names `time`, `level`, `msg`, `target`, `client`, `backend`, `error`.
///
/// Output goes to stderr. The filter defaults to `info` and can be overridden
/// via `RUST_LOG`.
pub fn init_tracing() {
	use tracing_subscriber::fmt::format::FmtSpan;
	tracing_subscriber::fmt()
		.with_env_filter(
			EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
		)
		.with_writer(std::io::stderr)
		.with_span_events(FmtSpan::NONE)
		.json()
		.init();
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn build_error_messages_match_documented_format() {
		let e = BuildError::Backend {
			name: "direct_out".to_string(),
			source: anyhow!("oops"),
		};
		assert_eq!(e.to_string(), r#"build backend "direct_out": oops"#);

		let e = BuildError::Frontend {
			name: "fe".to_string(),
			source: anyhow!("boom"),
		};
		assert_eq!(e.to_string(), r#"build frontend "fe": boom"#);

		let e = BuildError::FrontendUnsupported {
			name: "fe".to_string(),
			type_name: "tun".to_string(),
		};
		assert_eq!(
			e.to_string(),
			r#"build frontend "fe": unsupported type "tun""#
		);
	}
}
