//! HTTP CONNECT proxy server tests.
//!
//! Tests cover:
//! - `server_configuration_validate_table`: runtime config validation (the
//!   file-config branch is covered in `tests/config.rs`).
//! - `new_server_tls_configuration`, `new_server_defaults_camouflage_method`,
//!   `new_server_preserves_shim_buffer_size`: `Server::new` behavior.
//! - `server_open_proxy_tunnel`, `server_tls_proxy_tunnel`,
//!   `server_tls_authentication_and_camouflage`, `server_tls_backend_failure`,
//!   `server_tls_rejects_plaintext`, `server_authed_proxy_tunnel`,
//!   `server_dial_failure`, `server_auth_required_407`,
//!   `server_camouflage_auth_failure_405`, `server_context_cancel`:
//!   end-to-end server behavior via real TCP connections.
//! - `server_stats_tracking`, `server_stats_dial_failure`,
//!   `server_stats_nil_safe`: stats integration.

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use base64::Engine as _;
use puppy_core::backend::{
	Backend, BackendError, BoxedStream, Capability, Dialer, Protocol, Target,
};
use puppy_core::stats::{ConnectionRegistry, EventBus, StatsRegistry};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use direct::DirectBackend;
use httpproxy_fe::{CamouflageMethod, ConfigError, Server, ServerConfiguration};

// ---------------------------------------------------------------------------
// Test backends (ErrorBackend and UdpOnlyBackend).
// ---------------------------------------------------------------------------

/// Backend whose `dial` always returns `err`.
struct ErrorBackend {
	err: &'static str,
}

#[async_trait]
impl Backend for ErrorBackend {
	fn capabilities(&self) -> Vec<Capability> {
		vec![Capability {
			network: "tcp".to_string(),
			protocol: Protocol::Any,
		}]
	}

	async fn dial(
		&self,
		_target: Target,
		_dialer: &dyn Dialer,
	) -> Result<BoxedStream, BackendError> {
		Err(BackendError::Other(self.err.to_string()))
	}
}

/// Backend that only declares UDP support.
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

// ---------------------------------------------------------------------------
// Test helpers (testCertificateFiles, dialTLSProxy, startServer,
// echoUpstream, dialThroughProxy).
// ---------------------------------------------------------------------------

/// Generates a self-signed certificate for `localhost`/`127.0.0.1` and writes
/// it (plus its private key) to a temp directory. Returns
/// `(cert_file, key_file, root_ca_der)`.
fn test_certificate_files() -> (String, String, Vec<u8>) {
	use rcgen::{CertificateParams, KeyPair};
	let mut params =
		CertificateParams::new(vec!["localhost".to_string()]).expect("CertificateParams");
	params
		.subject_alt_names
		.push(rcgen::SanType::IpAddress(std::net::IpAddr::V4(
			std::net::Ipv4Addr::new(127, 0, 0, 1),
		)));
	let key_pair = KeyPair::generate().expect("generate key");
	let cert = params.self_signed(&key_pair).expect("self-signed");
	let cert_pem = cert.pem();
	let key_pem = key_pair.serialize_pem();

	let dir = std::env::temp_dir().join(format!(
		"puppy-httpproxy-fe-test-{}-{}",
		std::process::id(),
		std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.unwrap()
			.as_nanos()
	));
	let _ = std::fs::create_dir_all(&dir);
	let cert_file = dir.join("proxy-cert.pem");
	let key_file = dir.join("proxy-key.pem");
	std::fs::write(&cert_file, cert_pem.as_bytes()).expect("write cert");
	std::fs::write(&key_file, key_pem.as_bytes()).expect("write key");

	let root_ca_der = cert.der().to_vec();
	(
		cert_file.to_string_lossy().to_string(),
		key_file.to_string_lossy().to_string(),
		root_ca_der,
	)
}

/// Builds a rustls client config that trusts only the test root CA, with
/// `alpn_protocols` set to `["http/1.1"]`.
fn client_tls_config_with_root(root_ca_der: Vec<u8>) -> Arc<rustls::ClientConfig> {
	let mut roots = rustls::RootCertStore::empty();
	roots
		.add(rustls::pki_types::CertificateDer::from(root_ca_der))
		.expect("add root");
	let mut config = rustls::ClientConfig::builder()
		.with_root_certificates(roots)
		.with_no_client_auth();
	config.alpn_protocols = vec![b"http/1.1".to_vec()];
	Arc::new(config)
}

/// Dials the HTTPS proxy at `addr` with a 2-second timeout and returns the
/// TLS connection.
async fn dial_tls_proxy(
	addr: &str,
	root_ca_der: Vec<u8>,
) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
	let config = client_tls_config_with_root(root_ca_der);
	let connector = tokio_rustls::TlsConnector::from(config);
	let sock = tokio::time::timeout(Duration::from_secs(2), tokio::net::TcpStream::connect(addr))
		.await
		.expect("dial timeout")
		.expect("dial proxy");
	let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
	tokio::time::timeout(Duration::from_secs(2), connector.connect(server_name, sock))
		.await
		.expect("TLS timeout")
		.expect("TLS handshake")
}

/// Returns a baseline `ServerConfiguration` for tests.
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
		stats: None,
		conn_reg: None,
		bus: None,
	}
}

/// Starts a `Server` on a random localhost port. Returns the bound address
/// and a `tokio::sync::oneshot::Sender` to trigger shutdown.
async fn start_server(
	mut cfg: ServerConfiguration,
) -> (
	String,
	tokio::sync::oneshot::Sender<()>,
	tokio::task::JoinHandle<Result<(), Box<dyn std::error::Error + Send + Sync>>>,
) {
	// Grab a free port from the OS, then release it so Server::run can rebind.
	let ln = TcpListener::bind("127.0.0.1:0").await.expect("free port");
	let addr = ln.local_addr().unwrap();
	let host = addr.ip().to_string();
	let port = addr.port();
	drop(ln);

	cfg.listen_address = host.clone();
	cfg.listen_port = port;

	let server = Server::new(cfg).expect("NewServer");
	let (tx, rx) = tokio::sync::oneshot::channel::<()>();
	let handle = tokio::spawn(async move {
		server
			.run(async move {
				let _ = rx.await;
			})
			.await
	});

	let bound_addr = format!("{host}:{port}");
	// Wait until the listener is ready by retrying a dial briefly.
	let deadline = Instant::now() + Duration::from_secs(2);
	while Instant::now() < deadline {
		if tokio::net::TcpStream::connect(&bound_addr).await.is_ok() {
			break;
		}
		tokio::time::sleep(Duration::from_millis(50)).await;
	}
	(bound_addr, tx, handle)
}

/// Starts a `Server` with stats dependencies injected.
async fn start_server_with_stats(
	mut cfg: ServerConfiguration,
) -> (
	String,
	Arc<StatsRegistry>,
	Arc<ConnectionRegistry>,
	tokio::sync::oneshot::Sender<()>,
	tokio::task::JoinHandle<Result<(), Box<dyn std::error::Error + Send + Sync>>>,
) {
	let registry = Arc::new(StatsRegistry::new());
	let conn_reg = Arc::new(ConnectionRegistry::new());
	let bus = Arc::new(EventBus::new());
	cfg.stats = Some(registry.clone());
	cfg.conn_reg = Some(conn_reg.clone());
	cfg.bus = Some(bus.clone());
	cfg.name = "test-frontend".to_string();
	let (addr, tx, handle) = start_server(cfg).await;
	(addr, registry, conn_reg, tx, handle)
}

/// Starts an echo upstream on a random localhost port and returns its address.
async fn echo_upstream() -> String {
	let ln = TcpListener::bind("127.0.0.1:0").await.expect("echo listen");
	let addr = ln.local_addr().unwrap().to_string();
	tokio::spawn(async move {
		loop {
			match ln.accept().await {
				Ok((mut c, _)) => {
					tokio::spawn(async move {
						let (mut rd, mut wr) = c.split();
						let _ = tokio::io::copy(&mut rd, &mut wr).await;
						let _ = wr.shutdown().await;
					});
				}
				Err(_) => return,
			}
		}
	});
	addr
}

/// Performs a CONNECT handshake through the proxy at `proxy_addr` and returns
/// the tunneled TCP stream.
async fn dial_through_proxy(proxy_addr: &str, target: &str, auth: &str) -> tokio::net::TcpStream {
	let mut conn = tokio::net::TcpStream::connect(proxy_addr)
		.await
		.expect("dial proxy");
	let mut req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
	if !auth.is_empty() {
		let creds = base64::engine::general_purpose::STANDARD.encode(auth.as_bytes());
		req.push_str(&format!("Proxy-Authorization: Basic {creds}\r\n"));
	}
	req.push_str("\r\n");
	conn.write_all(req.as_bytes()).await.expect("write CONNECT");
	let (status, _) = read_response(&mut conn).await.expect("read response");
	assert!(
		status.starts_with("HTTP/1.1 200"),
		"CONNECT status = {status:?}"
	);
	conn
}

/// Reads a full HTTP response (status line + headers + Content-Length body)
/// from `conn`. Returns `(status_line, headers)`.
async fn read_response(
	conn: &mut tokio::net::TcpStream,
) -> std::io::Result<(String, Vec<(String, String)>)> {
	let mut buf = Vec::new();
	let mut tmp = [0u8; 4096];
	let mut header_end: Option<usize> = None;
	while header_end.is_none() {
		let n = conn.read(&mut tmp).await?;
		if n == 0 {
			return Err(std::io::Error::new(
				std::io::ErrorKind::UnexpectedEof,
				"EOF before response headers",
			));
		}
		buf.extend_from_slice(&tmp[..n]);
		if let Some(idx) = find_subslice(&buf, b"\r\n\r\n") {
			header_end = Some(idx + 4);
		}
	}
	let header_end = header_end.unwrap();
	let header_str = std::str::from_utf8(&buf[..header_end]).map_err(|e| {
		std::io::Error::new(
			std::io::ErrorKind::InvalidData,
			format!("headers utf8: {e}"),
		)
	})?;
	let mut lines = header_str.split("\r\n");
	let status_line = lines.next().unwrap().to_string();
	let mut headers: Vec<(String, String)> = Vec::new();
	for line in lines {
		if line.is_empty() {
			break;
		}
		if let Some((name, value)) = line.split_once(": ") {
			headers.push((name.to_string(), value.to_string()));
		}
	}
	let content_length: Option<usize> = headers
		.iter()
		.find(|(k, _)| k.eq_ignore_ascii_case("Content-Length"))
		.and_then(|(_, v)| v.parse().ok());
	if let Some(n) = content_length {
		let body_end = header_end + n;
		while buf.len() < body_end {
			let n = conn.read(&mut tmp).await?;
			if n == 0 {
				break;
			}
			buf.extend_from_slice(&tmp[..n]);
		}
	}
	Ok((status_line, headers))
}

fn header_get<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
	headers
		.iter()
		.find(|(k, _)| k.eq_ignore_ascii_case(name))
		.map(|(_, v)| v.as_str())
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
	haystack.windows(needle.len()).position(|w| w == needle)
}

// ---------------------------------------------------------------------------
// server_configuration_validate_table
// ---------------------------------------------------------------------------

/// Table-driven validation of `ServerConfiguration::validate`: each case
/// mutates a baseline config and checks the resulting error substring (or
/// that the config validates cleanly). Covers missing address/port,
/// TCP-unsupported backend, half-set TLS credentials, half-set auth
/// credentials, and two valid baselines (open and authed). Parallel to the
/// table in `tests/config.rs` but exercises the validation path against
/// the runtime struct directly.
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

// ---------------------------------------------------------------------------
// new_server_tls_configuration
// ---------------------------------------------------------------------------

/// Verifies `Server::new` accepts a valid cert/key pair and surfaces a
/// "load TLS certificate and key" error for: a missing cert file, an
/// invalid cert file, and a cert/key mismatch.
#[test]
fn new_server_tls_configuration() {
	let (cert_file, key_file, _roots) = test_certificate_files();

	let cfg = ServerConfiguration {
		listen_address: "127.0.0.1".to_string(),
		listen_port: 8080,
		tls_cert_file: cert_file.clone(),
		tls_key_file: key_file.clone(),
		backend: Arc::new(DirectBackend::new()),
		..base_runtime_config()
	};
	let s = Server::new(cfg).expect("NewServer");
	let _ = s;

	// Missing cert file.
	let cfg = ServerConfiguration {
		listen_address: "127.0.0.1".to_string(),
		listen_port: 8080,
		tls_cert_file: "/nonexistent/missing-cert.pem".to_string(),
		tls_key_file: key_file.clone(),
		backend: Arc::new(DirectBackend::new()),
		..base_runtime_config()
	};
	let err = match Server::new(cfg) {
		Err(e) => e,
		Ok(_) => panic!("expected error for missing cert"),
	};
	assert!(
		err.to_string().contains("load TLS certificate and key"),
		"missing certificate error = {err}"
	);

	// Invalid cert file.
	let invalid_cert = std::env::temp_dir().join("puppy-invalid-cert.pem");
	std::fs::write(&invalid_cert, b"not a certificate").expect("write invalid cert");
	let cfg = ServerConfiguration {
		listen_address: "127.0.0.1".to_string(),
		listen_port: 8080,
		tls_cert_file: invalid_cert.to_string_lossy().to_string(),
		tls_key_file: key_file.clone(),
		backend: Arc::new(DirectBackend::new()),
		..base_runtime_config()
	};
	let err = match Server::new(cfg) {
		Err(e) => e,
		Ok(_) => panic!("expected error for invalid cert"),
	};
	assert!(
		err.to_string().contains("load TLS certificate and key"),
		"invalid certificate error = {err}"
	);

	// Mismatched cert and key.
	let (_other_cert, other_key, _other_roots) = test_certificate_files();
	let cfg = ServerConfiguration {
		listen_address: "127.0.0.1".to_string(),
		listen_port: 8080,
		tls_cert_file: cert_file,
		tls_key_file: other_key,
		backend: Arc::new(DirectBackend::new()),
		..base_runtime_config()
	};
	let err = match Server::new(cfg) {
		Err(e) => e,
		Ok(_) => panic!("expected error for mismatched key"),
	};
	assert!(
		err.to_string().contains("load TLS certificate and key"),
		"mismatched certificate and key error = {err}"
	);
}

// ---------------------------------------------------------------------------
// new_server_defaults_camouflage_method
// ---------------------------------------------------------------------------

/// Verifies `Server::new` defaults a zeroed `camouflage_method` to
/// `CamouflageMethod::Return404`.
#[test]
fn new_server_defaults_camouflage_method() {
	let cfg = ServerConfiguration {
		listen_address: "127.0.0.1".to_string(),
		listen_port: 8080,
		backend: Arc::new(DirectBackend::new()),
		..base_runtime_config()
	};
	let s = Server::new(cfg).expect("NewServer");
	assert_eq!(s.config().camouflage_method, CamouflageMethod::Return404);
}

// ---------------------------------------------------------------------------
// new_server_preserves_shim_buffer_size
// ---------------------------------------------------------------------------

/// Verifies `Server::new` preserves the configured `shim_buffer_size`
/// (e.g. 64 KiB) rather than overwriting it with a default.
#[test]
fn new_server_preserves_shim_buffer_size() {
	let cfg = ServerConfiguration {
		listen_address: "127.0.0.1".to_string(),
		listen_port: 8080,
		backend: Arc::new(DirectBackend::new()),
		shim_buffer_size: 64 * 1024,
		..base_runtime_config()
	};
	let s = Server::new(cfg).expect("NewServer");
	assert_eq!(s.config().shim_buffer_size, 64 * 1024);
}

// ---------------------------------------------------------------------------
// server_open_proxy_tunnel
// ---------------------------------------------------------------------------

/// End-to-end: a plaintext open proxy CONNECTs to an echo upstream, and
/// bytes written through the tunnel are echoed back unchanged.
#[tokio::test]
async fn server_open_proxy_tunnel() {
	let upstream_addr = echo_upstream().await;
	let (proxy_addr, _tx, _handle) = start_server(base_runtime_config()).await;

	let mut conn = dial_through_proxy(&proxy_addr, &upstream_addr, "").await;
	let msg = b"hello-tunnel";
	conn.write_all(msg).await.expect("write");
	let mut got = vec![0u8; msg.len()];
	conn.read_exact(&mut got).await.expect("read");
	assert_eq!(&got, msg);
}

// ---------------------------------------------------------------------------
// server_tls_proxy_tunnel
// ---------------------------------------------------------------------------

/// End-to-end over TLS: a TLS-wrapped proxy negotiates ALPN `http/1.1`,
/// accepts a CONNECT to an echo upstream, and tunnels bidirectional data
/// after the `200` response.
#[tokio::test]
async fn server_tls_proxy_tunnel() {
	let upstream_addr = echo_upstream().await;
	let (cert_file, key_file, roots) = test_certificate_files();
	let cfg = ServerConfiguration {
		tls_cert_file: cert_file,
		tls_key_file: key_file,
		..base_runtime_config()
	};
	let (proxy_addr, _tx, _handle) = start_server(cfg).await;

	let mut conn = dial_tls_proxy(&proxy_addr, roots).await;
	// Verify ALPN negotiated `http/1.1`.
	let (_io, conn_state) = conn.get_ref();
	assert_eq!(
		conn_state.alpn_protocol(),
		Some(b"http/1.1".as_ref()),
		"negotiated ALPN"
	);

	let req = format!("CONNECT {upstream_addr} HTTP/1.1\r\nHost: {upstream_addr}\r\n\r\n");
	conn.write_all(req.as_bytes()).await.expect("write CONNECT");

	let mut buf = vec![0u8; 4096];
	let mut total = 0;
	loop {
		let n = conn.read(&mut buf[total..]).await.expect("read");
		if n == 0 {
			break;
		}
		total += n;
		if find_subslice(&buf[..total], b"\r\n\r\n").is_some() {
			break;
		}
	}
	let resp = std::str::from_utf8(&buf[..total]).unwrap();
	assert!(resp.starts_with("HTTP/1.1 200"), "status = {resp:?}");

	let msg = b"hello-over-https-proxy";
	conn.write_all(msg).await.expect("write tunnel data");
	let mut got = vec![0u8; msg.len()];
	conn.read_exact(&mut got).await.expect("read tunnel data");
	assert_eq!(&got, msg);
}

// ---------------------------------------------------------------------------
// server_tls_authentication_and_camouflage
// ---------------------------------------------------------------------------

/// Verifies a TLS proxy with auth configured: returns `407` for an
/// unauthenticated CONNECT, returns `200` for a CONNECT with correct
/// credentials, and (with camouflage enabled) returns `405` without a
/// `Proxy-Authenticate` header for an unauthenticated CONNECT.
#[tokio::test]
async fn server_tls_authentication_and_camouflage() {
	let upstream_addr = echo_upstream().await;
	let (cert_file, key_file, roots) = test_certificate_files();

	let cfg = ServerConfiguration {
		tls_cert_file: cert_file.clone(),
		tls_key_file: key_file.clone(),
		username: "alice".to_string(),
		password: "secret".to_string(),
		..base_runtime_config()
	};
	let (proxy_addr, _tx, _handle) = start_server(cfg).await;

	// Unauthenticated CONNECT -> 407.
	let mut conn = dial_tls_proxy(&proxy_addr, roots.clone()).await;
	conn.write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
		.await
		.expect("write CONNECT");
	let mut buf = vec![0u8; 4096];
	let n = conn.read(&mut buf).await.expect("read");
	let resp = std::str::from_utf8(&buf[..n]).unwrap();
	assert!(resp.starts_with("HTTP/1.1 407"), "unauth status = {resp:?}");

	// Authenticated CONNECT -> 200 + tunnel.
	let mut conn = dial_tls_proxy(&proxy_addr, roots.clone()).await;
	let creds = base64::engine::general_purpose::STANDARD.encode(b"alice:secret");
	let req = format!(
		"CONNECT {upstream_addr} HTTP/1.1\r\nHost: {upstream_addr}\r\nProxy-Authorization: Basic {creds}\r\n\r\n"
	);
	conn.write_all(req.as_bytes())
		.await
		.expect("write authed CONNECT");
	let n = conn.read(&mut buf).await.expect("read");
	let resp = std::str::from_utf8(&buf[..n]).unwrap();
	assert!(resp.starts_with("HTTP/1.1 200"), "authed status = {resp:?}");

	// Camouflage: CONNECT without auth -> 405 (no Proxy-Authenticate).
	let cfg = ServerConfiguration {
		tls_cert_file: cert_file,
		tls_key_file: key_file,
		username: "alice".to_string(),
		password: "secret".to_string(),
		camouflage: true,
		..base_runtime_config()
	};
	let (camo_addr, _tx, _handle) = start_server(cfg).await;
	let mut conn = dial_tls_proxy(&camo_addr, roots).await;
	conn.write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
		.await
		.expect("write camouflage CONNECT");
	let n = conn.read(&mut buf).await.expect("read");
	let resp = std::str::from_utf8(&buf[..n]).unwrap();
	assert!(
		resp.starts_with("HTTP/1.1 405"),
		"camouflage status = {resp:?}"
	);
	assert!(
		!resp.to_ascii_lowercase().contains("proxy-authenticate"),
		"camouflage should not include Proxy-Authenticate: {resp:?}"
	);
}

// ---------------------------------------------------------------------------
// server_tls_backend_failure
// ---------------------------------------------------------------------------

/// Verifies that when the backend's `dial` fails, a TLS proxy responds to
/// the CONNECT with `502 Bad Gateway`.
#[tokio::test]
async fn server_tls_backend_failure() {
	let (cert_file, key_file, roots) = test_certificate_files();
	let mut cfg = ServerConfiguration {
		tls_cert_file: cert_file,
		tls_key_file: key_file,
		..base_runtime_config()
	};
	cfg.backend = Arc::new(ErrorBackend {
		err: "upstream unreachable",
	});
	let (proxy_addr, _tx, _handle) = start_server(cfg).await;

	let mut conn = dial_tls_proxy(&proxy_addr, roots).await;
	conn.write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
		.await
		.expect("write CONNECT");
	let mut buf = vec![0u8; 4096];
	let n = conn.read(&mut buf).await.expect("read");
	let resp = std::str::from_utf8(&buf[..n]).unwrap();
	assert!(resp.starts_with("HTTP/1.1 502"), "status = {resp:?}");
}

// ---------------------------------------------------------------------------
// server_tls_rejects_plaintext
// ---------------------------------------------------------------------------

/// Verifies a TLS-only proxy does not emit a plaintext HTTP response to a
/// plaintext CONNECT: the first bytes the client reads must not start with
/// `HTTP/` (they are TLS alert bytes instead).
#[tokio::test]
async fn server_tls_rejects_plaintext() {
	let (cert_file, key_file, _roots) = test_certificate_files();
	let cfg = ServerConfiguration {
		tls_cert_file: cert_file,
		tls_key_file: key_file,
		..base_runtime_config()
	};
	let (proxy_addr, _tx, _handle) = start_server(cfg).await;

	let mut conn = tokio::net::TcpStream::connect(&proxy_addr)
		.await
		.expect("dial proxy");
	conn.write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
		.await
		.expect("write plaintext CONNECT");

	let mut buf = vec![0u8; 16];
	let n = tokio::time::timeout(Duration::from_secs(2), conn.read(&mut buf))
		.await
		.expect("read timeout")
		.expect("read");
	let got = std::str::from_utf8(&buf[..n]).unwrap_or("<binary>");
	assert!(
		!got.starts_with("HTTP/"),
		"HTTPS proxy returned a plaintext HTTP response: {got:?}"
	);
}

// ---------------------------------------------------------------------------
// server_authed_proxy_tunnel
// ---------------------------------------------------------------------------

/// End-to-end: a plaintext proxy with auth configured tunnels traffic to
/// an echo upstream when the CONNECT carries correct credentials.
#[tokio::test]
async fn server_authed_proxy_tunnel() {
	let upstream_addr = echo_upstream().await;
	let cfg = ServerConfiguration {
		username: "alice".to_string(),
		password: "secret".to_string(),
		..base_runtime_config()
	};
	let (proxy_addr, _tx, _handle) = start_server(cfg).await;

	let mut conn = dial_through_proxy(&proxy_addr, &upstream_addr, "alice:secret").await;
	let msg = b"authed-tunnel";
	conn.write_all(msg).await.expect("write");
	let mut got = vec![0u8; msg.len()];
	conn.read_exact(&mut got).await.expect("read");
	assert_eq!(&got, msg);
}

// ---------------------------------------------------------------------------
// server_dial_failure
// ---------------------------------------------------------------------------

/// Verifies a plaintext proxy returns `502 Bad Gateway` when the backend's
/// `dial` fails.
#[tokio::test]
async fn server_dial_failure() {
	let mut cfg = base_runtime_config();
	cfg.backend = Arc::new(ErrorBackend {
		err: "upstream unreachable",
	});
	let (proxy_addr, _tx, _handle) = start_server(cfg).await;

	let mut conn = tokio::net::TcpStream::connect(&proxy_addr)
		.await
		.expect("dial proxy");
	conn.write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
		.await
		.expect("write CONNECT");
	let (status, _) = read_response(&mut conn).await.expect("read response");
	assert!(status.starts_with("HTTP/1.1 502"), "status = {status:?}");
}

// ---------------------------------------------------------------------------
// server_auth_required_407
// ---------------------------------------------------------------------------

/// Verifies a plaintext proxy with auth configured returns `407 Proxy
/// Authentication Required` with a `Proxy-Authenticate: Basic` challenge
/// for an unauthenticated CONNECT.
#[tokio::test]
async fn server_auth_required_407() {
	let cfg = ServerConfiguration {
		username: "alice".to_string(),
		password: "secret".to_string(),
		..base_runtime_config()
	};
	let (proxy_addr, _tx, _handle) = start_server(cfg).await;

	let mut conn = tokio::net::TcpStream::connect(&proxy_addr)
		.await
		.expect("dial proxy");
	conn.write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
		.await
		.expect("write CONNECT");
	let (status, headers) = read_response(&mut conn).await.expect("read response");
	assert!(status.starts_with("HTTP/1.1 407"), "status = {status:?}");
	let auth = header_get(&headers, "Proxy-Authenticate").unwrap_or("");
	assert!(auth.contains("Basic"), "Proxy-Authenticate = {auth:?}");
}

// ---------------------------------------------------------------------------
// server_camouflage_auth_failure_405
// ---------------------------------------------------------------------------

/// Verifies a plaintext proxy with auth + camouflage configured returns
/// `405 Method Not Allowed` (with `Allow: GET, HEAD` and no
/// `Proxy-Authenticate`) for an unauthenticated CONNECT, hiding the
/// proxy's auth scheme.
#[tokio::test]
async fn server_camouflage_auth_failure_405() {
	let cfg = ServerConfiguration {
		username: "alice".to_string(),
		password: "secret".to_string(),
		camouflage: true,
		..base_runtime_config()
	};
	let (proxy_addr, _tx, _handle) = start_server(cfg).await;

	let mut conn = tokio::net::TcpStream::connect(&proxy_addr)
		.await
		.expect("dial proxy");
	conn.write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
		.await
		.expect("write CONNECT");
	let (status, headers) = read_response(&mut conn).await.expect("read response");
	assert!(status.starts_with("HTTP/1.1 405"), "status = {status:?}");
	assert_eq!(header_get(&headers, "Allow"), Some("GET, HEAD"));
	assert_eq!(header_get(&headers, "Proxy-Authenticate"), None);
}

// ---------------------------------------------------------------------------
// server_context_cancel
// ---------------------------------------------------------------------------

/// Verifies that triggering the shutdown signal causes `Server::run` to
/// return `Ok(())` promptly (within 2s), and that the server was reachable
/// before shutdown.
#[tokio::test]
async fn server_context_cancel() {
	let (proxy_addr, tx, handle) = start_server(base_runtime_config()).await;

	// Verify the server is up.
	{
		let _ = tokio::net::TcpStream::connect(&proxy_addr)
			.await
			.expect("dial");
	}

	// Cancel and wait for Run to return Ok(()).
	let _ = tx.send(());
	let result = tokio::time::timeout(Duration::from_secs(2), handle)
		.await
		.expect("Run did not return after cancel")
		.expect("task panicked");
	assert!(
		result.is_ok(),
		"Run returned error after cancel: {:?}",
		result
	);
}

// ---------------------------------------------------------------------------
// server_stats_tracking
// ---------------------------------------------------------------------------

/// Verifies the stats integration over a full connection lifecycle: after
/// a successful tunnel round-trip, `total_connections` and
/// `dial_successes` increment, `bytes_in`/`bytes_out` account for the
/// payload, and after the client closes, `active_connections` and the
/// connection registry count return to 0.
#[tokio::test]
async fn server_stats_tracking() {
	let upstream_addr = echo_upstream().await;
	let (addr, registry, conn_reg, _tx, _handle) =
		start_server_with_stats(base_runtime_config()).await;

	let mut conn = dial_through_proxy(&addr, &upstream_addr, "").await;
	let msg = b"stats-test-data!";
	conn.write_all(msg).await.expect("write");
	let mut got = vec![0u8; msg.len()];
	conn.read_exact(&mut got).await.expect("read");
	drop(conn);

	// Wait for the server to process the connection close and update counters.
	let deadline = Instant::now() + Duration::from_secs(2);
	while Instant::now() < deadline {
		let snap = registry.snapshot();
		if snap.total_connections >= 1 && snap.dial_successes >= 1 {
			break;
		}
		tokio::time::sleep(Duration::from_millis(10)).await;
	}
	let snap = registry.snapshot();
	assert!(
		snap.total_connections >= 1,
		"TotalConnections = {}",
		snap.total_connections
	);
	assert_eq!(
		snap.dial_successes, 1,
		"DialSuccesses = {}",
		snap.dial_successes
	);
	assert_eq!(
		snap.dial_failures, 0,
		"DialFailures = {}",
		snap.dial_failures
	);
	assert!(
		snap.bytes_in >= msg.len() as u64,
		"BytesIn = {}, want >= {}",
		snap.bytes_in,
		msg.len()
	);
	assert!(
		snap.bytes_out >= msg.len() as u64,
		"BytesOut = {}, want >= {}",
		snap.bytes_out,
		msg.len()
	);

	// After the connection closes, active count should return to 0.
	let deadline = Instant::now() + Duration::from_secs(2);
	while Instant::now() < deadline {
		if registry.snapshot().active_connections == 0 {
			break;
		}
		tokio::time::sleep(Duration::from_millis(10)).await;
	}
	let snap = registry.snapshot();
	assert_eq!(
		snap.active_connections, 0,
		"ActiveConnections = {}, want 0 after close",
		snap.active_connections
	);
	assert_eq!(
		conn_reg.count(),
		0,
		"connReg.count = {}, want 0 after close",
		conn_reg.count()
	);
}

// ---------------------------------------------------------------------------
// server_stats_dial_failure
// ---------------------------------------------------------------------------

/// Verifies stats track dial failures: when the backend's `dial` fails,
/// `dial_failures` increments to 1 and `dial_successes` stays at 0.
#[tokio::test]
async fn server_stats_dial_failure() {
	let mut cfg = base_runtime_config();
	cfg.backend = Arc::new(ErrorBackend {
		err: "upstream unreachable",
	});
	let (addr, registry, _conn_reg, _tx, _handle) = start_server_with_stats(cfg).await;

	let mut conn = tokio::net::TcpStream::connect(&addr)
		.await
		.expect("dial proxy");
	conn.write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
		.await
		.expect("write CONNECT");
	let (status, _) = read_response(&mut conn).await.expect("read response");
	assert!(status.starts_with("HTTP/1.1 502"), "status = {status:?}");

	let deadline = Instant::now() + Duration::from_secs(2);
	while Instant::now() < deadline {
		if registry.snapshot().dial_failures >= 1 {
			break;
		}
		tokio::time::sleep(Duration::from_millis(10)).await;
	}
	let snap = registry.snapshot();
	assert_eq!(
		snap.dial_failures, 1,
		"DialFailures = {}",
		snap.dial_failures
	);
	assert_eq!(
		snap.dial_successes, 0,
		"DialSuccesses = {}",
		snap.dial_successes
	);
}

// ---------------------------------------------------------------------------
// server_stats_nil_safe
// ---------------------------------------------------------------------------

/// Verifies the server runs and tunnels traffic correctly when no stats
/// dependencies are wired (no `StatsRegistry`, `ConnectionRegistry`, or
/// `EventBus`), i.e. the nil-stats path is safe.
#[tokio::test]
async fn server_stats_nil_safe() {
	let upstream_addr = echo_upstream().await;
	let (proxy_addr, _tx, _handle) = start_server(base_runtime_config()).await;

	let mut conn = dial_through_proxy(&proxy_addr, &upstream_addr, "").await;
	let msg = b"nil-stats-ok";
	conn.write_all(msg).await.expect("write");
	let mut got = vec![0u8; msg.len()];
	conn.read_exact(&mut got).await.expect("read");
	assert_eq!(&got, msg);
}
