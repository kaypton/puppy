//! Configuration tests for the HTTP CONNECT frontend.
//!
//! Test groups:
//! - `configuration_server_config_*`: cover the
//!   `ServerConfiguration::from_file_config` conversion that adds runtime
//!   dependencies to the file config (defaults and full-field cases).
//! - `server_configuration_validate_*`: cover the runtime `validate()`.

use std::sync::Arc;

use async_trait::async_trait;
use puppy_core::backend::{
	Backend, BackendError, BoxedStream, Capability, Dialer, Protocol, Target,
};
use puppy_core::stats::{ConnectionRegistry, Deps, EventBus, StatsRegistry};

use direct::DirectBackend;
use httpproxy_fe::{CamouflageMethod, ConfigError, HttpFrontendConfiguration, ServerConfiguration};

// ---------------------------------------------------------------------------
// Test backends.
// ---------------------------------------------------------------------------

/// Backend that only declares UDP support. Used to verify the frontend
/// rejects backends that cannot serve TCP-unknown targets.
struct UdpOnlyBackend;

#[async_trait]
impl Backend for UdpOnlyBackend {
	fn capabilities(&self) -> Vec<Capability> {
		vec![Capability {
			network: "udp".to_string(),
			protocol: Protocol::Any,
		}]
	}

	async fn dial(
		&self,
		_target: Target,
		_dialer: &dyn Dialer,
	) -> Result<BoxedStream, BackendError> {
		Err(BackendError::Other("udp-only backend".to_string()))
	}
}

/// Builds a valid baseline file configuration.
fn base_file_config() -> HttpFrontendConfiguration {
	HttpFrontendConfiguration {
		listen_address: "127.0.0.1".to_string(),
		listen_port: 8080,
		tls_cert_file: "proxy-cert.pem".to_string(),
		tls_key_file: "proxy-key.pem".to_string(),
		username: "alice".to_string(),
		password: "secret".to_string(),
		camouflage: true,
		camouflage_method: "return-404".to_string(),
		backend: "out".to_string(),
		shim: "tunnel".to_string(),
	}
}

// ---------------------------------------------------------------------------
// ServerConfiguration::from_file_config
// ---------------------------------------------------------------------------

/// Verifies `ServerConfiguration::from_file_config` copies every file-config
/// field, applies the default camouflage method, attaches the provided
/// backend, propagates the shim buffer size, and wires the runtime
/// stats/conn-reg/event-bus dependencies.
#[test]
fn configuration_server_config_copies_fields_and_runtime_deps() {
	let file = base_file_config();
	let backend: Arc<dyn Backend> = Arc::new(DirectBackend::new());

	let stats = StatsRegistry::new();
	let conn_reg = ConnectionRegistry::new();
	let bus = EventBus::new();
	let deps = Deps {
		name: "test".to_string(),
		backend: String::new(),
		stats: Some(stats),
		conn_reg: Some(conn_reg),
		bus: Some(bus),
	};

	let sc = ServerConfiguration::from_file_config(&file, backend.clone(), 65536, deps)
		.expect("ServerConfiguration::from_file_config");

	assert_eq!(sc.listen_address, file.listen_address);
	assert_eq!(sc.listen_port, file.listen_port);
	assert_eq!(sc.tls_cert_file, file.tls_cert_file);
	assert_eq!(sc.tls_key_file, file.tls_key_file);
	assert_eq!(sc.username, file.username);
	assert_eq!(sc.password, file.password);
	assert!(sc.camouflage);
	assert_eq!(sc.camouflage_method, CamouflageMethod::Return404);
	assert!(Arc::ptr_eq(&sc.backend, &backend));
	assert_eq!(sc.shim_buffer_size, 65536);
	assert_eq!(sc.name, "test");
	assert!(sc.stats.is_some());
	assert!(sc.conn_reg.is_some());
	assert!(sc.bus.is_some());
}

// ---------------------------------------------------------------------------
// DefaultsCamouflageMethod
// ---------------------------------------------------------------------------

/// Verifies a file config with `camouflage_method` left empty defaults to
/// `CamouflageMethod::Return404` after conversion.
#[test]
fn configuration_server_config_defaults_camouflage_method() {
	let file = HttpFrontendConfiguration {
		listen_address: "127.0.0.1".to_string(),
		listen_port: 8080,
		backend: "out".to_string(),
		shim: "tunnel".to_string(),
		..Default::default()
	};
	let sc = ServerConfiguration::from_file_config(
		&file,
		Arc::new(DirectBackend::new()),
		0,
		Deps::default(),
	)
	.expect("ServerConfiguration::from_file_config");
	assert_eq!(sc.camouflage_method, CamouflageMethod::Return404);
}

// ---------------------------------------------------------------------------
// ServerConfiguration::validate
// ---------------------------------------------------------------------------

/// Returns a `ServerConfiguration` baseline with `listen_address`,
/// `listen_port`, and a `DirectBackend`.
fn base_runtime_config() -> ServerConfiguration {
	ServerConfiguration {
		listen_address: "127.0.0.1".to_string(),
		listen_port: 1,
		tls_cert_file: String::new(),
		tls_key_file: String::new(),
		username: String::new(),
		password: String::new(),
		camouflage: false,
		camouflage_method: CamouflageMethod::Return404,
		backend: Arc::new(DirectBackend::new()),
		egress_dialer: None,
		shim_buffer_size: 0,
		name: String::new(),
		backend_name: String::new(),
		stats: None,
		conn_reg: None,
		bus: None,
	}
}

/// Table-driven validation of `ServerConfiguration::validate`: each case
/// mutates a baseline config and checks that the resulting error message
/// contains a substring (or that the config validates cleanly). Covers
/// missing address/port, TCP-unsupported backend, half-set TLS credentials,
/// half-set auth credentials, and two valid baselines (open and authed).
#[test]
fn server_configuration_validate_table() {
	let valid_backend: Arc<dyn Backend> = Arc::new(DirectBackend::new());
	type Case = (
		&'static str,
		fn(&mut ServerConfiguration),
		Option<&'static str>,
	);
	let cases: &[Case] = &[
		(
			"missing address",
			|c| c.listen_address.clear(),
			Some("listen address"),
		),
		("missing port", |c| c.listen_port = 0, Some("listen port")),
		(
			"missing backend",
			|c| {
				// Replace with a backend that has no capabilities. Easiest is
				// to swap with a UDP-only backend.
				c.backend = Arc::new(UdpOnlyBackend);
			},
			Some("backend must support tcp"),
		),
		(
			"certificate only",
			|c| c.tls_cert_file = "proxy-cert.pem".to_string(),
			Some("certificate and key files"),
		),
		(
			"key only",
			|c| c.tls_key_file = "proxy-key.pem".to_string(),
			Some("certificate and key files"),
		),
		(
			"username only",
			|c| c.username = "u".to_string(),
			Some("username and password"),
		),
		(
			"password only",
			|c| c.password = "p".to_string(),
			Some("username and password"),
		),
		(
			"unknown camouflage method",
			|c| c.camouflage_method = CamouflageMethod::Return404, // cannot represent "unknown" via enum
			None,                                                  // treated as valid (Return404)
		),
		("valid open", |_| {}, None),
		(
			"valid authed",
			|c| {
				c.username = "u".to_string();
				c.password = "p".to_string();
			},
			None,
		),
	];
	for (name, change, want_err) in cases {
		let mut cfg = base_runtime_config();
		cfg.backend = valid_backend.clone();
		change(&mut cfg);
		let result = cfg.validate();
		match want_err {
			Some(sub) => match result {
				Err(ConfigError::Validation(msg)) => {
					assert!(
						msg.contains(sub),
						"{name}: error = {msg}, want substring {sub:?}"
					);
				}
				Err(e) => panic!("{name}: unexpected error variant: {e}"),
				Ok(_) => panic!("{name}: expected error containing {sub:?}, got Ok"),
			},
			None => match result {
				Ok(()) => {}
				Err(e) => panic!("{name}: unexpected error: {e}"),
			},
		}
	}
}

/// Verifies `validate` rejects a backend whose capabilities omit TCP with an
/// error mentioning "backend must support tcp".
#[test]
fn server_configuration_validate_supports_check_rejects_udp_only() {
	let mut cfg = base_runtime_config();
	cfg.backend = Arc::new(UdpOnlyBackend);
	let err = cfg.validate().expect_err("expected validation error");
	assert!(
		err.to_string().contains("backend must support tcp"),
		"error = {err}"
	);
}

/// Verifies the file-config conversion path rejects an unrecognized
/// `camouflage_method` string (e.g. "unknown") with an error containing
/// "camouflage_method must be return-404 or empty". The `CamouflageMethod`
/// enum cannot represent an invalid value, so this is exercised through
/// `from_file_config` rather than `validate` directly.
#[test]
fn server_configuration_validate_rejects_unsupported_camouflage_method() {
	// The `CamouflageMethod` enum only has `Return404`, so we cannot directly
	// test an unsupported value through the public API. We verify that the
	// `normalize_camouflage_method` helper (via the file config path) rejects
	// unknown strings.
	let file = HttpFrontendConfiguration {
		listen_address: "127.0.0.1".to_string(),
		listen_port: 8080,
		camouflage_method: "unknown".to_string(),
		backend: "out".to_string(),
		shim: "tunnel".to_string(),
		..Default::default()
	};
	let result = ServerConfiguration::from_file_config(
		&file,
		Arc::new(DirectBackend::new()),
		0,
		Deps::default(),
	);
	let err = match result {
		Err(e) => e,
		Ok(_) => panic!("expected validation error, got Ok"),
	};
	assert!(
		err.to_string()
			.contains("camouflage_method must be return-404 or empty"),
		"error = {err}"
	);
}
