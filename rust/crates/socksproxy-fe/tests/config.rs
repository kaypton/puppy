//! Configuration tests for the SOCKS5 frontend.
//!
//! Test groups:
//! - `configuration_validate_*`: cover the file config `validate()`.
//! - `configuration_server_config_*`: cover the
//!   `ServerConfiguration::from_file_config` conversion that adds runtime
//!   dependencies to the file config.
//! - `server_configuration_validate_*`: cover the runtime `validate()`.

use std::sync::Arc;

use async_trait::async_trait;
use puppy_core::backend::{
	Backend, BackendError, BoxedStream, Capability, Dialer, Protocol, Target,
};
use puppy_core::stats::{ConnectionRegistry, Deps, EventBus, StatsRegistry};

use direct::DirectBackend;
use socksproxy_fe::{ConfigError, ServerConfiguration, SocksFrontendConfiguration};

// ---------------------------------------------------------------------------
// Test backends (udpOnlyBackend).
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

/// Builds a valid file configuration baseline.
fn base_file_config() -> SocksFrontendConfiguration {
	SocksFrontendConfiguration {
		listen_address: "127.0.0.1".to_string(),
		listen_port: 1080,
		tls_cert_file: String::new(),
		tls_key_file: String::new(),
		username: String::new(),
		password: String::new(),
		backend: "out".to_string(),
		shim: "tunnel".to_string(),
	}
}

// ---------------------------------------------------------------------------
// TestConfigurationValidate
// ---------------------------------------------------------------------------

#[test]
fn configuration_validate_accepts_valid() {
	let cfg = base_file_config();
	cfg.validate()
		.expect("Validate valid configuration should succeed");
}

#[test]
fn configuration_validate_table() {
	type Case = (
		&'static str,
		fn(&mut SocksFrontendConfiguration),
		Option<&'static str>,
	);
	let cases: &[Case] = &[
		(
			"missing address",
			|c| c.listen_address.clear(),
			Some("listen_address"),
		),
		("missing port", |c| c.listen_port = 0, Some("listen_port")),
		(
			"certificate only",
			|c| c.tls_cert_file = "proxy-cert.pem".to_string(),
			Some("tls_cert_file and tls_key_file"),
		),
		(
			"key only",
			|c| c.tls_key_file = "proxy-key.pem".to_string(),
			Some("tls_cert_file and tls_key_file"),
		),
		(
			"unpaired credentials",
			|c| c.username = "alice".to_string(),
			Some("username and password"),
		),
		(
			"missing backend",
			|c| c.backend.clear(),
			Some("backend reference"),
		),
		("missing shim", |c| c.shim.clear(), Some("shim reference")),
	];
	for (name, change, want_err) in cases {
		let mut cfg = base_file_config();
		change(&mut cfg);
		let result = cfg.validate();
		match want_err {
			Some(sub) => match result {
				Err(msg) => {
					assert!(
						msg.contains(sub),
						"{name}: error = {msg}, want substring {sub:?}"
					);
				}
				Ok(_) => panic!("{name}: expected error containing {sub:?}, got Ok"),
			},
			None => match result {
				Ok(()) => {}
				Err(msg) => panic!("{name}: unexpected error: {msg}"),
			},
		}
	}
}

// ---------------------------------------------------------------------------
// TestConfigurationServerConfig
// ---------------------------------------------------------------------------

#[test]
fn configuration_server_config_copies_fields_and_runtime_deps() {
	let mut file = base_file_config();
	file.tls_cert_file = "proxy-cert.pem".to_string();
	file.tls_key_file = "proxy-key.pem".to_string();
	file.username = "alice".to_string();
	file.password = "secret".to_string();

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
	assert!(Arc::ptr_eq(&sc.backend, &backend));
	assert_eq!(sc.shim_buffer_size, 65536);
	assert_eq!(sc.name, "test");
	assert!(sc.stats.is_some());
	assert!(sc.conn_reg.is_some());
	assert!(sc.bus.is_some());
}

// ---------------------------------------------------------------------------
// TestServerConfiguration_Validate
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
			"backend lacks tcp unknown",
			|c| c.backend = Arc::new(UdpOnlyBackend),
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
		match want_err {
			Some(sub) => match cfg.validate() {
				Err(ConfigError::Validation(msg)) => {
					assert!(
						msg.contains(sub),
						"{name}: error = {msg}, want substring {sub:?}"
					);
				}
				Err(e) => panic!("{name}: unexpected error variant: {e}"),
				Ok(_) => panic!("{name}: expected error containing {sub:?}, got Ok"),
			},
			None => match cfg.validate() {
				Ok(()) => {}
				Err(e) => panic!("{name}: unexpected error: {e}"),
			},
		}
	}
}

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
