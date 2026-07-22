//! gRPC tunnel proxy server tests.
//!
//! Tests cover:
//! - `new_server_tls_load_errors`, `new_server_preserves_shim_buffer_size`:
//!   `Server::new` behavior.
//! - `server_open_tunnel`, `server_tls_tunnel`, `server_token_required`,
//!   `server_dial_failure`, `server_missing_connect_frame`,
//!   `server_non_connect_first_frame`, `server_context_cancel`: end-to-end
//!   server behavior over real gRPC channels.
//! - `server_stats_tracking`, `server_stats_dial_failure`: stats integration.

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use grpc_tunnel::tunnel_client::TunnelClient;
use grpc_tunnel::{client_channel, connect_frame, payload_frame, Frame, GrpcStream};
use puppy_core::backend::{
	Backend, BackendError, BoxedStream, Capability, Dialer, Protocol, Target,
};
use puppy_core::stats::{ConnectionRegistry, EventBus, StatsRegistry};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_stream::wrappers::ReceiverStream;
use tonic::metadata::MetadataValue;
use tonic::transport::{Certificate, Channel, ClientTlsConfig};
use tonic::{Code, Request, Status};

use direct::DirectBackend;
use grpcproxy_fe::{ConfigError, Server, ServerConfiguration};

// ---------------------------------------------------------------------------
// Test backends (ErrorBackend).
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

// ---------------------------------------------------------------------------
// Test helpers.
// ---------------------------------------------------------------------------

/// Generates a self-signed certificate for `localhost`/`127.0.0.1` and writes
/// it (plus its private key) to a temp directory. Returns
/// `(cert_file, key_file, cert_pem)`.
fn test_certificate_files() -> (String, String, String) {
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
		"puppy-grpcproxy-fe-test-{}-{}",
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

	(
		cert_file.to_string_lossy().to_string(),
		key_file.to_string_lossy().to_string(),
		cert_pem,
	)
}

/// Returns a baseline `ServerConfiguration` for tests.
fn base_runtime_config() -> ServerConfiguration {
	ServerConfiguration {
		listen_address: "127.0.0.1".to_string(),
		listen_port: 1,
		tls_cert_file: String::new(),
		tls_key_file: String::new(),
		token: String::new(),
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

/// Builds a plaintext gRPC channel to the frontend at `addr`.
async fn connect_channel(addr: &str) -> Channel {
	Channel::from_shared(format!("http://{addr}"))
		.expect("endpoint")
		.connect()
		.await
		.expect("channel connect")
}

/// Inserts the bearer-token authorization metadata into `request` when
/// `token` is non-empty.
fn apply_token(request: &mut Request<ReceiverStream<Frame>>, token: &str) {
	if !token.is_empty() {
		let value = MetadataValue::try_from(format!("Bearer {token}")).expect("metadata value");
		request.metadata_mut().insert("authorization", value);
	}
}

/// Opens a tunnel to `host:port` through the frontend on `channel` and
/// returns the client and the tunnel byte stream. The client must be kept
/// alive for the stream to stay usable.
async fn dial_tunnel(
	channel: Channel,
	host: &str,
	port: u16,
	token: &str,
) -> (TunnelClient<Channel>, GrpcStream) {
	let mut client = TunnelClient::new(channel);
	let (tx, rx) = client_channel();
	let mut request = Request::new(ReceiverStream::new(rx));
	apply_token(&mut request, token);
	tx.send(connect_frame("tcp", host, port))
		.await
		.expect("send connect frame");
	let response = client.connect(request).await.expect("connect");
	let stream = GrpcStream::new(response.into_inner(), tx);
	(client, stream)
}

/// Runs a `connect` RPC that is expected to fail and returns the status.
/// `first_frame` is sent before the call; `None` produces an empty request
/// stream.
async fn connect_expect_status(
	channel: Channel,
	first_frame: Option<Frame>,
	token: &str,
) -> Status {
	let mut client = TunnelClient::new(channel);
	let (tx, rx) = client_channel();
	let mut request = Request::new(ReceiverStream::new(rx));
	apply_token(&mut request, token);
	if let Some(frame) = first_frame {
		tx.send(frame).await.expect("send first frame");
	}
	drop(tx);
	match client.connect(request).await {
		Ok(_) => panic!("expected error status, got Ok"),
		Err(status) => status,
	}
}

// ---------------------------------------------------------------------------
// new_server_tls_load_errors
// ---------------------------------------------------------------------------

/// Verifies `Server::new` accepts a valid cert/key pair and surfaces a
/// "load TLS certificate and key" error for a missing cert file and a
/// missing key file.
#[test]
fn new_server_tls_load_errors() {
	let (cert_file, key_file, _cert_pem) = test_certificate_files();

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

	// Missing key file.
	let cfg = ServerConfiguration {
		tls_cert_file: cert_file,
		tls_key_file: "/nonexistent/missing-key.pem".to_string(),
		backend: Arc::new(DirectBackend::new()),
		..base_runtime_config()
	};
	let err = match Server::new(cfg) {
		Err(e) => e,
		Ok(_) => panic!("expected error for missing key"),
	};
	assert!(
		err.to_string().contains("load TLS certificate and key"),
		"missing key error = {err}"
	);

	// Half-set TLS material is a validation error, not a load error.
	let mut cfg = base_runtime_config();
	cfg.tls_cert_file = "proxy-cert.pem".to_string();
	match cfg.validate() {
		Err(ConfigError::Validation(msg)) => {
			assert!(msg.contains("certificate and key files"), "error = {msg}");
		}
		other => panic!("expected validation error, got {other:?}"),
	}
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
// server_open_tunnel
// ---------------------------------------------------------------------------

/// End-to-end: a plaintext frontend tunnels a `connect` to an echo upstream,
/// and bytes written through the tunnel are echoed back unchanged.
#[tokio::test]
async fn server_open_tunnel() {
	let upstream_addr = echo_upstream().await;
	let (proxy_addr, _tx, _handle) = start_server(base_runtime_config()).await;

	let channel = connect_channel(&proxy_addr).await;
	let (host, port) = upstream_addr.rsplit_once(':').expect("host:port");
	let (_client, mut stream) = dial_tunnel(channel, host, port.parse().unwrap(), "").await;

	let msg = b"hello-grpc-tunnel";
	stream.write_all(msg).await.expect("write");
	let mut got = vec![0u8; msg.len()];
	stream.read_exact(&mut got).await.expect("read");
	assert_eq!(&got, msg);
}

// ---------------------------------------------------------------------------
// server_tls_tunnel
// ---------------------------------------------------------------------------

/// End-to-end over TLS: the frontend serves the tunnel endpoint with a
/// self-signed identity; a client trusting only that certificate tunnels
/// traffic to the echo upstream.
#[tokio::test]
async fn server_tls_tunnel() {
	let upstream_addr = echo_upstream().await;
	let (cert_file, key_file, cert_pem) = test_certificate_files();
	let cfg = ServerConfiguration {
		tls_cert_file: cert_file,
		tls_key_file: key_file,
		..base_runtime_config()
	};
	let (proxy_addr, _tx, _handle) = start_server(cfg).await;

	let tls = ClientTlsConfig::new()
		.ca_certificate(Certificate::from_pem(cert_pem))
		.domain_name("localhost");
	let channel = Channel::from_shared(format!("https://{proxy_addr}"))
		.expect("endpoint")
		.tls_config(tls)
		.expect("tls config")
		.connect()
		.await
		.expect("TLS channel connect");

	let (host, port) = upstream_addr.rsplit_once(':').expect("host:port");
	let (_client, mut stream) = dial_tunnel(channel, host, port.parse().unwrap(), "").await;

	let msg = b"hello-over-tls-grpc-tunnel";
	stream.write_all(msg).await.expect("write");
	let mut got = vec![0u8; msg.len()];
	stream.read_exact(&mut got).await.expect("read");
	assert_eq!(&got, msg);
}

// ---------------------------------------------------------------------------
// server_token_required
// ---------------------------------------------------------------------------

/// Verifies a frontend with `token` configured rejects calls without (or
/// with a wrong) bearer token with `Unauthenticated`, and accepts the
/// correct token.
#[tokio::test]
async fn server_token_required() {
	let upstream_addr = echo_upstream().await;
	let cfg = ServerConfiguration {
		token: "sekret".to_string(),
		..base_runtime_config()
	};
	let (proxy_addr, _tx, _handle) = start_server(cfg).await;

	// Missing token -> Unauthenticated.
	let channel = connect_channel(&proxy_addr).await;
	let (host, port) = upstream_addr.rsplit_once(':').expect("host:port");
	let status = connect_expect_status(
		channel,
		Some(connect_frame("tcp", host, port.parse().unwrap())),
		"",
	)
	.await;
	assert_eq!(status.code(), Code::Unauthenticated, "status = {status}");

	// Wrong token -> Unauthenticated.
	let channel = connect_channel(&proxy_addr).await;
	let status = connect_expect_status(
		channel,
		Some(connect_frame("tcp", host, port.parse().unwrap())),
		"wrong",
	)
	.await;
	assert_eq!(status.code(), Code::Unauthenticated, "status = {status}");

	// Correct token -> tunnel works.
	let channel = connect_channel(&proxy_addr).await;
	let (_client, mut stream) = dial_tunnel(channel, host, port.parse().unwrap(), "sekret").await;
	let msg = b"authed-grpc-tunnel";
	stream.write_all(msg).await.expect("write");
	let mut got = vec![0u8; msg.len()];
	stream.read_exact(&mut got).await.expect("read");
	assert_eq!(&got, msg);
}

// ---------------------------------------------------------------------------
// server_dial_failure
// ---------------------------------------------------------------------------

/// Verifies the frontend answers `Unavailable` when the backend's `dial`
/// fails.
#[tokio::test]
async fn server_dial_failure() {
	let mut cfg = base_runtime_config();
	cfg.backend = Arc::new(ErrorBackend {
		err: "upstream unreachable",
	});
	let (proxy_addr, _tx, _handle) = start_server(cfg).await;

	let channel = connect_channel(&proxy_addr).await;
	let status =
		connect_expect_status(channel, Some(connect_frame("tcp", "example.com", 443)), "").await;
	assert_eq!(status.code(), Code::Unavailable, "status = {status}");
}

// ---------------------------------------------------------------------------
// server_missing_connect_frame
// ---------------------------------------------------------------------------

/// Verifies an empty request stream (client closed without sending a connect
/// frame) is rejected with `InvalidArgument`.
#[tokio::test]
async fn server_missing_connect_frame() {
	let (proxy_addr, _tx, _handle) = start_server(base_runtime_config()).await;

	let channel = connect_channel(&proxy_addr).await;
	let status = connect_expect_status(channel, None, "").await;
	assert_eq!(status.code(), Code::InvalidArgument, "status = {status}");
}

// ---------------------------------------------------------------------------
// server_non_connect_first_frame
// ---------------------------------------------------------------------------

/// Verifies a first frame that is not a connect frame is rejected with
/// `InvalidArgument`.
#[tokio::test]
async fn server_non_connect_first_frame() {
	let (proxy_addr, _tx, _handle) = start_server(base_runtime_config()).await;

	let channel = connect_channel(&proxy_addr).await;
	let status = connect_expect_status(channel, Some(payload_frame(b"junk")), "").await;
	assert_eq!(status.code(), Code::InvalidArgument, "status = {status}");
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
		let _channel = connect_channel(&proxy_addr).await;
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

/// Verifies the stats integration over a full tunnel lifecycle: after a
/// successful round-trip, `total_connections` and `dial_successes` increment,
/// `bytes_in`/`bytes_out` account for the payload, and after the client
/// closes, `active_connections` and the connection registry count return to
/// 0.
#[tokio::test]
async fn server_stats_tracking() {
	let upstream_addr = echo_upstream().await;
	let (addr, registry, conn_reg, _tx, _handle) =
		start_server_with_stats(base_runtime_config()).await;

	let channel = connect_channel(&addr).await;
	let (host, port) = upstream_addr.rsplit_once(':').expect("host:port");
	let (client, mut stream) = dial_tunnel(channel, host, port.parse().unwrap(), "").await;

	let msg = b"stats-test-data!";
	stream.write_all(msg).await.expect("write");
	let mut got = vec![0u8; msg.len()];
	stream.read_exact(&mut got).await.expect("read");
	assert_eq!(&got, msg);

	// Close the tunnel: dropping the stream ends the request channel, which
	// the server observes as EOF and tears the connection down.
	drop(stream);
	drop(client);

	// Wait for the server to process the close and update counters.
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

	// After the tunnel closes, active count should return to 0.
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

	let channel = connect_channel(&addr).await;
	let status =
		connect_expect_status(channel, Some(connect_frame("tcp", "example.com", 443)), "").await;
	assert_eq!(status.code(), Code::Unavailable, "status = {status}");

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
