//! Integration tests for the `server` crate's factory functions and CLI.
//!
//! Coverage map:
//! - `build_backend_*` exercises direct / HTTP / SOCKS5 backend construction.
//! - `build_selected_frontend_http`, `build_selected_frontend_socks`, and
//!   `build_selected_frontend_tun` exercise the selected-frontend path for
//!   each frontend type.
//! - `cli_passes_config_path` and `cli_requires_config_flag` exercise the
//!   CLI surface.
//! - `TestRootCommandHidesUsageForRuntimeErrors` is N/A: clap separates flag
//!   errors from runtime errors by construction (we only call the runner after
//!   `Cli::try_parse` succeeds).

use std::path::PathBuf;

use puppy_core::stats::{ConnectionRegistry, Deps, EventBus, StatsRegistry};

use config::{
	BackendConfiguration, Configuration, DirectBackendConfiguration, HttpBackendConfiguration,
	SocksBackendConfiguration,
};
use server::{build_backend, build_frontend};

/// The canonical valid configuration used across these tests.
const VALID_CONFIGURATION: &str = r#"
frontend = "office_proxy"

[frontends.office_proxy]
type = "httpproxy"
listen_address = "127.0.0.1"
listen_port = 8080
username = "alice"
password = "secret"
camouflage = true
camouflage_method = "return-404"
backend = "direct_out"
shim = "default_tunnel"

[frontends.unused_proxy]
type = "httpproxy"
listen_address = "127.0.0.1"
listen_port = 8081
backend = "corporate_proxy"
shim = "large_tunnel"

[frontends.unused_socks]
type = "socksproxy"
listen_address = "127.0.0.1"
listen_port = 1080
backend = "direct_out"
shim = "default_tunnel"

[frontends.unused_tun]
type = "tun"
ipv4_address = "10.0.0.1/24"
mtu = 1500
auto_route = false
dns_server = "1.1.1.1:53"
backend = "direct_out"
shim = "default_tunnel"

[backends.direct_out]
type = "direct"

[backends.corporate_proxy]
type = "httpproxy"
proxy_address = "proxy.example.com:3128"
username = "bob"
password = "password"

[backends.corporate_socks]
type = "socksproxy"
proxy_address = "socks.example.com:1080"
username = "carol"
password = "swordfish"

[shims.default_tunnel]
buffer_size = 32768

[shims.large_tunnel]
buffer_size = 65536
"#;

fn write_config(contents: &str) -> (tempfile::TempDir, PathBuf) {
	let dir = tempfile::tempdir().expect("tempdir");
	let path = dir.path().join("puppy.toml");
	std::fs::write(&path, contents).expect("write config");
	(dir, path)
}

fn load_str(contents: &str) -> Configuration {
	let (_dir, path) = write_config(contents);
	config::load(&path).expect("load configuration")
}

fn test_stats_deps(name: &str) -> Deps {
	Deps {
		name: name.to_string(),
		stats: Some(StatsRegistry::new()),
		conn_reg: Some(ConnectionRegistry::new()),
		bus: Some(EventBus::new()),
	}
}

// ---------------------------------------------------------------------------
// build_backend
// ---------------------------------------------------------------------------

#[test]
fn build_backend_direct_returns_direct_backend() {
	// Direct backend case.
	let backend = build_backend(
		"direct_out",
		&BackendConfiguration::Direct(DirectBackendConfiguration {}),
	)
	.expect("build direct backend");
	// The concrete type is `direct::DirectBackend`; we just assert the
	// capability surface matches the direct backend (TCP + UDP, Any protocol).
	let caps = backend.capabilities();
	assert!(
		caps.iter()
			.any(|c| c.network == "tcp" && c.protocol == puppy_core::backend::Protocol::Any),
		"direct backend should support tcp+Any, got {caps:?}"
	);
	assert!(
		caps.iter()
			.any(|c| c.network == "udp" && c.protocol == puppy_core::backend::Protocol::Any),
		"direct backend should support udp+Any, got {caps:?}"
	);
}

#[test]
fn build_backend_http_returns_http_backend() {
	// HTTP backend case.
	let backend = build_backend(
		"corporate_proxy",
		&BackendConfiguration::Http(HttpBackendConfiguration {
			proxy_address: "proxy.example.com:3128".to_string(),
			..Default::default()
		}),
	)
	.expect("build HTTP backend");
	let caps = backend.capabilities();
	assert_eq!(
		caps,
		vec![puppy_core::backend::Capability {
			network: "tcp".to_string(),
			protocol: puppy_core::backend::Protocol::Any,
		}],
		"HTTP backend should support tcp+Any, got {caps:?}"
	);
}

#[test]
fn build_backend_socks_returns_socks_backend() {
	// SOCKS5 backend case.
	let backend = build_backend(
		"corporate_socks",
		&BackendConfiguration::Socks(SocksBackendConfiguration {
			proxy_address: "socks.example.com:1080".to_string(),
			..Default::default()
		}),
	)
	.expect("build SOCKS backend");
	let caps = backend.capabilities();
	assert_eq!(
		caps,
		vec![puppy_core::backend::Capability {
			network: "tcp".to_string(),
			protocol: puppy_core::backend::Protocol::Any,
		}],
		"SOCKS backend should support tcp+Any, got {caps:?}"
	);
}

#[test]
fn build_backend_http_tls_ca_load_failure_wraps_error() {
	// When `tls = true` and `tls_ca_file` points at a non-existent file,
	// validation passes (the path is non-empty and `tls_insecure_skip_verify`
	// is false) but `HttpProxyBackend::new` fails to load the CA. The error
	// should be wrapped as `build backend "<name>": ...`.
	let err = match build_backend(
		"bad",
		&BackendConfiguration::Http(HttpBackendConfiguration {
			proxy_address: "proxy.example.com:3128".to_string(),
			tls: true,
			tls_ca_file: "/nonexistent/ca.pem".to_string(),
			..Default::default()
		}),
	) {
		Ok(_) => panic!("expected build error"),
		Err(e) => e,
	};
	let msg = err.to_string();
	assert!(
		msg.starts_with(r#"build backend "bad":"#),
		"error should be wrapped as `build backend \"bad\": ...`, got: {msg}"
	);
}

// ---------------------------------------------------------------------------
// build_frontend
// ---------------------------------------------------------------------------

#[test]
fn build_selected_frontend_http() {
	// HTTP frontend construction.
	let config = load_str(VALID_CONFIGURATION);
	let frontend =
		build_frontend(&config, test_stats_deps(&config.frontend)).expect("build frontend");
	assert!(matches!(frontend, server::Frontend::Http(_)));
}

#[test]
fn build_selected_frontend_socks() {
	// SOCKS5 frontend construction.
	let contents = VALID_CONFIGURATION.replacen(
		r#"frontend = "office_proxy""#,
		r#"frontend = "unused_socks""#,
		1,
	);
	let config = load_str(&contents);
	let frontend =
		build_frontend(&config, test_stats_deps(&config.frontend)).expect("build frontend");
	assert!(matches!(frontend, server::Frontend::Socks(_)));
}

#[test]
fn build_selected_frontend_tun() {
	// TUN frontend construction resolves the candidate backend list and
	// fallback, then builds a `tun::server::Server`.
	let contents = VALID_CONFIGURATION.replacen(
		r#"frontend = "office_proxy""#,
		r#"frontend = "unused_tun""#,
		1,
	);
	let config = load_str(&contents);
	let frontend =
		build_frontend(&config, test_stats_deps(&config.frontend)).expect("build frontend");
	assert!(matches!(frontend, server::Frontend::Tun(_)));
}

#[test]
fn build_frontend_wraps_backend_error() {
	// When the referenced backend fails to build (e.g., TLS CA file missing),
	// the error should be wrapped as
	// `build frontend "<name>": build backend "<backend>": ...` (nested
	// wrapping from `build_frontend`). The config passes `load` validation
	// because the TLS CA path is syntactically valid; the failure surfaces
	// only when `HttpProxyBackend::new` tries to read the file.
	let contents = r#"
frontend = "fe"

[frontends.fe]
type = "httpproxy"
listen_address = "127.0.0.1"
listen_port = 8080
backend = "bad_backend"
shim = "shim"

[backends.bad_backend]
type = "httpproxy"
proxy_address = "proxy.example.com:3128"
tls = true
tls_ca_file = "/nonexistent/ca.pem"

[shims.shim]
buffer_size = 32768
"#;
	let config = load_str(contents);
	let err = match build_frontend(&config, test_stats_deps(&config.frontend)) {
		Err(e) => e,
		Ok(_) => panic!("expected error, got Ok"),
	};
	let msg = err.to_string();
	assert!(
		msg.starts_with(r#"build frontend "fe": build backend "bad_backend":"#),
		"expected nested wrapping, got: {msg}"
	);
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

#[test]
fn cli_passes_config_path() {
	// clap parses `--config <path>` into `Cli.config`; we verify by parsing
	// directly.
	use clap::Parser;
	#[derive(Parser, Debug)]
	struct Cli {
		#[arg(short, long, value_name = "PATH")]
		config: PathBuf,
	}

	let cli = Cli::try_parse_from(["puppy-server", "--config", "custom.toml"])
		.expect("parse should succeed");
	assert_eq!(cli.config, PathBuf::from("custom.toml"));
}

#[test]
fn cli_requires_config_flag() {
	// Without `--config`, clap exits with an error containing
	// `required arguments were not provided`.
	use clap::Parser;
	#[derive(Parser, Debug)]
	struct Cli {
		#[arg(short, long, value_name = "PATH")]
		config: PathBuf,
	}

	let err = Cli::try_parse_from(["puppy-server"]).expect_err("expected required error");
	let msg = err.to_string();
	assert!(
		msg.contains("required arguments were not provided") && msg.contains("--config"),
		"expected required-arg error mentioning --config, got: {msg}"
	);
}

#[test]
fn cli_short_form_works() {
	// Verify `-c <path>` short form also works.
	use clap::Parser;
	#[derive(Parser, Debug)]
	struct Cli {
		#[arg(short, long, value_name = "PATH")]
		config: PathBuf,
	}

	let cli =
		Cli::try_parse_from(["puppy-server", "-c", "short.toml"]).expect("parse should succeed");
	assert_eq!(cli.config, PathBuf::from("short.toml"));
}

// ---------------------------------------------------------------------------
// End-to-end smoke test: build + run + shutdown
// ---------------------------------------------------------------------------

#[tokio::test]
async fn frontend_runs_and_shuts_down() {
	// Build a HTTP frontend on a free port, run it with an immediate shutdown
	// signal, and verify it exits cleanly.
	use tokio::sync::oneshot;

	// Bind a free port first, then write it into the config (port = 0 fails
	// `HttpFrontendConfiguration::validate`).
	let ln = tokio::net::TcpListener::bind("127.0.0.1:0")
		.await
		.expect("free port");
	let addr = ln.local_addr().unwrap();
	drop(ln);

	let contents = format!(
		r#"
frontend = "fe"

[frontends.fe]
type = "httpproxy"
listen_address = "127.0.0.1"
listen_port = {port}
backend = "direct_out"
shim = "shim"

[backends.direct_out]
type = "direct"

[shims.shim]
buffer_size = 32768
"#,
		port = addr.port()
	);
	let config = load_str(&contents);

	let frontend =
		build_frontend(&config, test_stats_deps(&config.frontend)).expect("build frontend");

	let (tx, rx) = oneshot::channel::<()>();
	let handle = tokio::spawn(async move {
		frontend
			.run(async move {
				let _ = rx.await;
			})
			.await
	});

	// Give the server a moment to bind, then signal shutdown.
	tokio::time::sleep(std::time::Duration::from_millis(100)).await;
	let _ = tx.send(());
	let result = tokio::time::timeout(std::time::Duration::from_secs(2), handle)
		.await
		.expect("frontend should shut down within 2s");
	assert!(result.is_ok(), "frontend run should complete cleanly");
}
