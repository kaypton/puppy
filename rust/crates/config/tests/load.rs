//! Tests for `config` crate.
//!
//! Error assertions use `contains` so that wrapping prefixes like
//! `validate configuration "...": ` don't break tests.

use std::fs;
use std::path::PathBuf;

use config::{Configuration, FrontendConfiguration};

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
	fs::write(&path, contents).expect("write config");
	(dir, path)
}

fn load_str(contents: &str) -> Result<Configuration, config::ConfigError> {
	let (_dir, path) = write_config(contents);
	config::load(&path)
}

#[test]
fn load_configuration_decodes_valid() {
	let cfg = load_str(VALID_CONFIGURATION).expect("load valid configuration");
	assert_eq!(cfg.frontend, "office_proxy");
	assert_eq!(cfg.frontends.len(), 4);
	assert_eq!(cfg.backends.len(), 3);
	assert_eq!(cfg.shims.len(), 2);

	let office = cfg.frontends.get("office_proxy").expect("office_proxy");
	let FrontendConfiguration::Http(http) = office else {
		panic!("office_proxy is not http: {office:?}");
	};
	assert_eq!(http.backend, "direct_out");
	assert_eq!(http.shim, "default_tunnel");
	assert!(http.camouflage);
	assert_eq!(http.camouflage_method, "return-404");

	let corp = cfg
		.backends
		.get("corporate_proxy")
		.expect("corporate_proxy");
	let config::BackendConfiguration::Http(http_be) = corp else {
		panic!("corporate_proxy is not http: {corp:?}");
	};
	assert_eq!(http_be.proxy_address, "proxy.example.com:3128");
	assert_eq!(http_be.username, "bob");

	let corp_socks = cfg
		.backends
		.get("corporate_socks")
		.expect("corporate_socks");
	let config::BackendConfiguration::Socks(socks_be) = corp_socks else {
		panic!("corporate_socks is not socks: {corp_socks:?}");
	};
	assert_eq!(socks_be.proxy_address, "socks.example.com:1080");
	assert_eq!(socks_be.username, "carol");
	assert_eq!(socks_be.password, "swordfish");

	let unused_socks = cfg.frontends.get("unused_socks").expect("unused_socks");
	let FrontendConfiguration::Socks(s) = unused_socks else {
		panic!("unused_socks is not socks: {unused_socks:?}");
	};
	assert_eq!(s.listen_address, "127.0.0.1");
	assert_eq!(s.listen_port, 1080);
	assert_eq!(s.backend, "direct_out");
	assert_eq!(s.shim, "default_tunnel");

	assert_eq!(cfg.shims.get("large_tunnel").unwrap().buffer_size, 65536);

	let unused_tun = cfg.frontends.get("unused_tun").expect("unused_tun");
	let FrontendConfiguration::Tun(tun) = unused_tun else {
		panic!("unused_tun is not tun: {unused_tun:?}");
	};
	assert_eq!(tun.ipv4_address, "10.0.0.1/24");
	assert_eq!(tun.mtu, 1500);
	assert_eq!(tun.backend, "direct_out");
	assert_eq!(tun.shim, "default_tunnel");
	assert_eq!(tun.auto_route, Some(false));
	assert_eq!(tun.dns_server, "1.1.1.1:53");
}

#[test]
fn load_configuration_tun_frontend_errors() {
	let cases = [
		(
			"tun missing address",
			r#"
frontend = "t"
[frontends.t]
type = "tun"
backend = "out"
shim = "s"
[backends.out]
type = "direct"
[shims.s]
"#,
			r#"frontend "t": ipv4_address or ipv6_address is required"#,
		),
		(
			"tun invalid cidr",
			r#"
frontend = "t"
[frontends.t]
type = "tun"
ipv4_address = "10.0.0.1"
backend = "out"
shim = "s"
[backends.out]
type = "direct"
[shims.s]
"#,
			r#"frontend "t": ipv4_address must be in CIDR form"#,
		),
		(
			"tun missing backend reference",
			r#"
frontend = "t"
[frontends.t]
type = "tun"
ipv4_address = "10.0.0.1/24"
backend = "missing"
shim = "s"
[backends.out]
type = "direct"
[shims.s]
"#,
			r#"frontend "t": backend "missing" does not exist"#,
		),
	];
	for (name, config, want_err) in cases {
		let err = load_str(config).unwrap_err().to_string();
		assert!(
			err.contains(want_err),
			"[{name}] error = {err:?}, want substring {want_err:?}"
		);
	}
}

#[test]
fn load_configuration_tls_frontend() {
	let contents = VALID_CONFIGURATION.replace(
		"listen_port = 8081",
		"listen_port = 8081\ntls_cert_file = \"proxy-cert.pem\"\ntls_key_file = \"proxy-key.pem\"",
	);
	let cfg = load_str(&contents).expect("load");
	let FrontendConfiguration::Http(fe) = cfg.frontends.get("unused_proxy").unwrap() else {
		panic!("unused_proxy is not http");
	};
	assert_eq!(fe.tls_cert_file, "proxy-cert.pem");
	assert_eq!(fe.tls_key_file, "proxy-key.pem");
}

#[test]
fn load_configuration_tls_backend() {
	let contents = VALID_CONFIGURATION.replace(
		r#"proxy_address = "proxy.example.com:3128""#,
		r#"proxy_address = "proxy.example.com:3128"
tls = true
tls_ca_file = "./certs/ca-cert.pem"
tls_server_name = "proxy.internal""#,
	);
	let cfg = load_str(&contents).expect("load");
	let config::BackendConfiguration::Http(be) = cfg.backends.get("corporate_proxy").unwrap()
	else {
		panic!("corporate_proxy is not http");
	};
	assert!(be.tls);
	assert_eq!(be.tls_ca_file, "./certs/ca-cert.pem");
	assert_eq!(be.tls_server_name, "proxy.internal");
}

#[test]
fn load_configuration_tun_ordered_backends() {
	let contents = VALID_CONFIGURATION.replace(
		r#"backend = "direct_out"
shim = "default_tunnel"

[backends.direct_out]"#,
		r#"backends = ["corporate_proxy", "direct_out"]
fallback = "direct_out"
protocol_detect_timeout = 2
protocol_detect_max_bytes = 8192
shim = "default_tunnel"

[backends.direct_out]"#,
	);
	let cfg = load_str(&contents).expect("load");
	let FrontendConfiguration::Tun(tun) = cfg.frontends.get("unused_tun").unwrap() else {
		panic!("unused_tun is not tun");
	};
	assert_eq!(
		tun.backend_references(),
		vec!["corporate_proxy", "direct_out"]
	);
	assert_eq!(tun.fallback, "direct_out");
	assert_eq!(tun.protocol_detect_timeout, 2);
	assert_eq!(tun.protocol_detect_max_bytes, 8192);
}

#[test]
fn load_configuration_errors() {
	let cases: &[(&str, &str, &str)] = &[
		("invalid TOML", "frontend = [", "load configuration"),
		(
			"missing selection",
			r#"
[frontends.proxy]
type = "httpproxy"
listen_address = "127.0.0.1"
listen_port = 8080
backend = "out"
shim = "tunnel"
[backends.out]
type = "direct"
[shims.tunnel]
"#,
			"frontend selection is required",
		),
		(
			"selected frontend missing",
			r#"frontend = "missing""#,
			r#"selected frontend "missing" does not exist"#,
		),
		(
			"unknown top-level field",
			&VALID_CONFIGURATION.replace(
				r#"frontend = "office_proxy""#,
				r#"frontend = "office_proxy"
debug = true"#,
			),
			"configuration contains unknown field",
		),
		(
			"unknown frontend field",
			&VALID_CONFIGURATION.replace("listen_port = 8081", "listen_port = 8081\nextra = true"),
			"unused_proxy.extra",
		),
		(
			"unknown direct backend field",
			&VALID_CONFIGURATION.replace(
				r#"[backends.direct_out]
type = "direct""#,
				r#"[backends.direct_out]
type = "direct"
proxy_address = "should-not-be-accepted:1""#,
			),
			"backends.direct_out.proxy_address",
		),
		(
			"unknown unused frontend type",
			&VALID_CONFIGURATION.replace(
				r#"type = "httpproxy"
listen_address = "127.0.0.1"
listen_port = 8081"#,
				r#"type = "socks5"
listen_address = "127.0.0.1"
listen_port = 8081"#,
			),
			r#"frontend "unused_proxy": unknown type "socks5""#,
		),
		(
			"unknown unused backend type",
			&VALID_CONFIGURATION.replace(
				r#"type = "httpproxy"
proxy_address = "proxy.example.com:3128""#,
				r#"type = "socks5"
proxy_address = "proxy.example.com:3128""#,
			),
			r#"backend "corporate_proxy": unknown type "socks5""#,
		),
		(
			"missing backend reference",
			&VALID_CONFIGURATION
				.replace(r#"backend = "corporate_proxy""#, r#"backend = "missing""#),
			r#"frontend "unused_proxy": backend "missing" does not exist"#,
		),
		(
			"socks frontend missing address",
			&VALID_CONFIGURATION.replace(
				r#"[frontends.unused_socks]
type = "socksproxy"
listen_address = "127.0.0.1"
listen_port = 1080"#,
				r#"[frontends.unused_socks]
type = "socksproxy"
listen_port = 1080"#,
			),
			r#"frontend "unused_socks": listen_address"#,
		),
		(
			"socks frontend unpaired credentials",
			&VALID_CONFIGURATION.replace(
				r#"[frontends.unused_socks]
type = "socksproxy"
listen_address = "127.0.0.1"
listen_port = 1080
backend = "direct_out""#,
				r#"[frontends.unused_socks]
type = "socksproxy"
listen_address = "127.0.0.1"
listen_port = 1080
username = "alice"
backend = "direct_out""#,
			),
			r#"frontend "unused_socks": username and password"#,
		),
		(
			"socks frontend missing backend reference",
			&VALID_CONFIGURATION.replace(
				r#"[frontends.unused_socks]
type = "socksproxy"
listen_address = "127.0.0.1"
listen_port = 1080
backend = "direct_out""#,
				r#"[frontends.unused_socks]
type = "socksproxy"
listen_address = "127.0.0.1"
listen_port = 1080
backend = "missing_socks""#,
			),
			r#"frontend "unused_socks": backend "missing_socks" does not exist"#,
		),
		(
			"socks frontend unpaired tls cert",
			&VALID_CONFIGURATION.replace(
				r#"[frontends.unused_socks]
type = "socksproxy"
listen_address = "127.0.0.1"
listen_port = 1080
backend = "direct_out""#,
				r#"[frontends.unused_socks]
type = "socksproxy"
listen_address = "127.0.0.1"
listen_port = 1080
tls_cert_file = "proxy-cert.pem"
backend = "direct_out""#,
			),
			r#"frontend "unused_socks": tls_cert_file and tls_key_file"#,
		),
		(
			"missing shim reference",
			&VALID_CONFIGURATION.replace(r#"shim = "large_tunnel""#, r#"shim = "missing""#),
			r#"frontend "unused_proxy": shim "missing" does not exist"#,
		),
		(
			"unpaired frontend credentials",
			&VALID_CONFIGURATION.replace(r#"password = "secret""#, r#"password = """#),
			r#"frontend "office_proxy": username and password"#,
		),
		(
			"unknown camouflage method",
			&VALID_CONFIGURATION.replace(
				r#"camouflage_method = "return-404""#,
				r#"camouflage_method = "unknown""#,
			),
			r#"frontend "office_proxy": camouflage_method"#,
		),
		(
			"invalid unused proxy address",
			&VALID_CONFIGURATION.replace(
				r#"proxy_address = "proxy.example.com:3128""#,
				r#"proxy_address = "proxy.example.com""#,
			),
			r#"backend "corporate_proxy": proxy_address must be in host:port form"#,
		),
		(
			"negative unused shim buffer",
			&VALID_CONFIGURATION.replace("buffer_size = 65536", "buffer_size = -1"),
			r#"shim "large_tunnel": buffer_size must not be negative"#,
		),
	];

	for (name, config, want_err) in cases {
		let err = load_str(config).unwrap_err().to_string();
		assert!(
			err.contains(want_err),
			"[{name}] error = {err:?}, want substring {want_err:?}"
		);
	}
}

#[test]
fn load_configuration_missing_file() {
	let dir = tempfile::tempdir().unwrap();
	let missing = dir.path().join("missing.toml");
	let err = config::load(&missing).unwrap_err().to_string();
	assert!(
		err.contains("load configuration"),
		"error = {err:?}, want 'load configuration' substring"
	);
}

#[test]
fn example_configuration_loads() {
	// config.toml ships with the gRPC observability service enabled.
	// CARGO_MANIFEST_DIR is crates/config, so config.toml is ../../../config.toml.
	let manifest_dir = env!("CARGO_MANIFEST_DIR");
	let path = std::path::Path::new(manifest_dir).join("../../../config.toml");
	let cfg = config::load(&path).expect("load example configuration");
	assert_eq!(cfg.frontend, "local_http_proxy");
}

#[test]
fn load_configuration_with_grpc() {
	let contents = format!(
		"{VALID_CONFIGURATION}\n[grpc]\nenabled = true\nlisten_address = \"127.0.0.1\"\nlisten_port = 8443\ntls_cert_file = \"cert.pem\"\ntls_key_file = \"key.pem\"\ntoken = \"test-token\"\n[observability]\ndatabase_path = \"puppy.db\"\nlog_directory = \"logs\"\n"
	);
	let cfg = load_str(&contents).expect("load");
	let dash = cfg.grpc.expect("grpc present");
	assert!(dash.enabled);
	assert_eq!(dash.listen_port, 8443);
	assert_eq!(dash.token, "test-token");
}

#[test]
fn load_configuration_allows_plaintext_grpc_without_token() {
	let contents = format!(
		"{VALID_CONFIGURATION}\n[grpc]\nenabled = true\nlisten_address = \"127.0.0.1\"\nlisten_port = 50051\n[observability]\ndatabase_path = \"puppy.db\"\nlog_directory = \"logs\"\n"
	);
	let cfg = load_str(&contents).expect("load optional gRPC security");
	let grpc = cfg.grpc.expect("grpc present");
	assert!(grpc.tls_cert_file.is_empty());
	assert!(grpc.token.is_empty());
}

#[test]
fn load_configuration_rejects_half_configured_grpc_tls() {
	let contents = format!(
		"{VALID_CONFIGURATION}\n[grpc]\nenabled = true\nlisten_address = \"127.0.0.1\"\nlisten_port = 50051\ntls_cert_file = \"server.pem\"\n[observability]\ndatabase_path = \"puppy.db\"\nlog_directory = \"logs\"\n"
	);
	let error = load_str(&contents).unwrap_err().to_string();
	assert!(error.contains("must both be set or both be empty"));
}

#[test]
fn load_configuration_rejects_unknown_grpc_field() {
	let contents =
		format!("{VALID_CONFIGURATION}\n[grpc]\nenabled = false\nunknown_field = \"bad\"\n");
	let err = load_str(&contents).unwrap_err().to_string();
	assert!(
		err.contains("unknown field"),
		"expected unknown field error, got: {err}"
	);
}

#[test]
fn load_configuration_grpc_decodes_valid() {
	let contents = r#"
frontend = "grpc_in"

[frontends.grpc_in]
type = "grpcproxy"
listen_address = "127.0.0.1"
listen_port = 9443
tls_cert_file = "proxy-cert.pem"
tls_key_file = "proxy-key.pem"
token = "inbound-token"
backend = "grpc_out"
shim = "default_tunnel"

[backends.grpc_out]
type = "grpcproxy"
server_address = "tunnel.example.com:443"
tls = true
tls_server_name = "tunnel.internal"
token = "outbound-token"

[shims.default_tunnel]
buffer_size = 32768
"#;
	let cfg = load_str(contents).expect("load valid grpc configuration");

	let fe = cfg.frontends.get("grpc_in").expect("grpc_in");
	assert_eq!(fe.kind(), config::FrontendKind::Grpc);
	let FrontendConfiguration::Grpc(grpc_fe) = fe else {
		panic!("grpc_in is not grpc: {fe:?}");
	};
	assert_eq!(grpc_fe.listen_address, "127.0.0.1");
	assert_eq!(grpc_fe.listen_port, 9443);
	assert_eq!(grpc_fe.tls_cert_file, "proxy-cert.pem");
	assert_eq!(grpc_fe.tls_key_file, "proxy-key.pem");
	assert_eq!(grpc_fe.token, "inbound-token");
	assert_eq!(grpc_fe.backend, "grpc_out");
	assert_eq!(grpc_fe.shim, "default_tunnel");

	let be = cfg.backends.get("grpc_out").expect("grpc_out");
	assert_eq!(be.kind(), config::BackendKind::Grpc);
	let config::BackendConfiguration::Grpc(grpc_be) = be else {
		panic!("grpc_out is not grpc: {be:?}");
	};
	assert_eq!(grpc_be.server_address, "tunnel.example.com:443");
	assert!(grpc_be.tls);
	assert_eq!(grpc_be.tls_server_name, "tunnel.internal");
	assert!(!grpc_be.tls_insecure_skip_verify);
	assert_eq!(grpc_be.token, "outbound-token");
}

#[test]
fn load_configuration_grpc_errors() {
	let valid = r#"
frontend = "g"

[frontends.g]
type = "grpcproxy"
listen_address = "127.0.0.1"
listen_port = 9443
backend = "out"
shim = "s"

[backends.out]
type = "grpcproxy"
server_address = "tunnel.example.com:443"

[shims.s]
"#;
	let cases: &[(&str, &str, &str)] = &[
		(
			"unknown grpc frontend field",
			&valid.replace("listen_port = 9443", "listen_port = 9443\nextra = true"),
			"frontends.g.extra",
		),
		(
			"unknown grpc backend field",
			&valid.replace(
				r#"server_address = "tunnel.example.com:443""#,
				"server_address = \"tunnel.example.com:443\"\nproxy_address = \"should-not-be-accepted:1\"",
			),
			"backends.out.proxy_address",
		),
		(
			"grpc frontend missing address",
			&valid.replace("listen_address = \"127.0.0.1\"\n", ""),
			r#"frontend "g": listen_address is required"#,
		),
		(
			"grpc frontend missing port",
			&valid.replace("listen_port = 9443\n", ""),
			r#"frontend "g": listen_port is required"#,
		),
		(
			"grpc frontend unpaired tls cert",
			&valid.replace(
				"listen_port = 9443",
				"listen_port = 9443\ntls_cert_file = \"proxy-cert.pem\"",
			),
			r#"frontend "g": tls_cert_file and tls_key_file"#,
		),
		(
			"grpc frontend missing backend reference",
			&valid.replace(r#"backend = "out""#, r#"backend = "missing""#),
			r#"frontend "g": backend "missing" does not exist"#,
		),
		(
			"grpc frontend missing shim reference",
			&valid.replace(r#"shim = "s""#, r#"shim = "missing""#),
			r#"frontend "g": shim "missing" does not exist"#,
		),
		(
			"grpc backend missing server address",
			&valid.replace("server_address = \"tunnel.example.com:443\"\n", ""),
			r#"backend "out": server_address is required"#,
		),
		(
			"grpc backend invalid server address",
			&valid.replace(
				"tunnel.example.com:443",
				"tunnel.example.com",
			),
			r#"backend "out": server_address must be in host:port form"#,
		),
		(
			"grpc backend zero port",
			&valid.replace(
				"tunnel.example.com:443",
				"tunnel.example.com:0",
			),
			r#"backend "out": server_address port must be between 1 and 65535"#,
		),
		(
			"grpc backend tls options without tls",
			&valid.replace(
				r#"server_address = "tunnel.example.com:443""#,
				"server_address = \"tunnel.example.com:443\"\ntls_server_name = \"tunnel.internal\"",
			),
			r#"backend "out": tls_ca_file, tls_server_name, and tls_insecure_skip_verify require tls = true"#,
		),
		(
			"grpc backend skip verify with ca file",
			&valid.replace(
				r#"server_address = "tunnel.example.com:443""#,
				"server_address = \"tunnel.example.com:443\"\ntls = true\ntls_ca_file = \"ca.pem\"\ntls_insecure_skip_verify = true",
			),
			r#"backend "out": tls_insecure_skip_verify and tls_ca_file are mutually exclusive"#,
		),
	];

	for (name, config, want_err) in cases {
		let err = load_str(config).unwrap_err().to_string();
		assert!(
			err.contains(want_err),
			"[{name}] error = {err:?}, want substring {want_err:?}"
		);
	}
}
