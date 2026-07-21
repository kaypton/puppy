//! Tests for the direct backend.
//!
//! Cases:
//! - `dial_uses_provided_dialer`: a mocked dialer captures the network and
//!   address and returns an error; the backend propagates the error.
//! - `dial_tcp`: a TCP echo server accepts a direct dial and echoes bytes.
//! - `dial_network_defaults_to_tcp`: empty `network` resolves to "tcp" and
//!   dials the echo server successfully.
//! - `backend_capabilities`: capabilities declare TCP and UDP with
//!   `Protocol::Any`.

use std::sync::Arc;

use async_trait::async_trait;
use puppy_core::backend::{
	supports_any_protocol, Backend, BoxedStream, Capability, Dialer, Protocol, Target,
};

use direct::DirectBackend;

/// Dialer that records the last `(network, address)` it received and returns
/// the configured error (or a closed-channel stream when error is `None`).
struct RecordingDialer {
	error: Option<std::io::Error>,
	calls: Arc<std::sync::Mutex<Vec<(String, String)>>>,
}

type DialCalls = Arc<std::sync::Mutex<Vec<(String, String)>>>;

impl RecordingDialer {
	fn failing(err: std::io::Error) -> (Self, DialCalls) {
		let calls: DialCalls = Arc::new(std::sync::Mutex::new(Vec::new()));
		(
			Self {
				error: Some(err),
				calls: calls.clone(),
			},
			calls,
		)
	}
}

#[async_trait]
impl Dialer for RecordingDialer {
	async fn dial_context(
		&self,
		network: &str,
		address: &str,
	) -> Result<BoxedStream, std::io::Error> {
		self.calls
			.lock()
			.unwrap()
			.push((network.to_string(), address.to_string()));
		match &self.error {
			Some(e) => Err(std::io::Error::new(e.kind(), e.to_string())),
			None => Err(std::io::Error::other("no stream configured")),
		}
	}
}

#[tokio::test]
async fn dial_uses_provided_dialer() {
	let want_err = std::io::Error::other("dial stopped");
	let (dialer, calls) = RecordingDialer::failing(want_err);

	let target = Target {
		network: "udp".to_string(),
		protocol: Protocol::Unknown,
		host: "192.0.2.1".to_string(),
		port: 53,
	};
	let result = DirectBackend::new().dial(target, &dialer).await;
	let err = match result {
		Err(e) => e,
		Ok(_) => panic!("expected dial error, got Ok"),
	};
	let msg = err.to_string();
	assert!(
		msg.contains("dial stopped"),
		"error should mention 'dial stopped', got: {msg}"
	);

	let calls = calls.lock().unwrap();
	assert_eq!(calls.len(), 1, "dialer should be called exactly once");
	assert_eq!(calls[0].0, "udp", "network");
	assert_eq!(calls[0].1, "192.0.2.1:53", "address");
}

/// Starts a local TCP echo server bound to `127.0.0.1:0`. Returns the actual
/// address. The server is shut down when the returned handle is dropped.
async fn echo_server() -> String {
	use tokio::io::{AsyncReadExt, AsyncWriteExt};
	use tokio::net::TcpListener;

	let ln = TcpListener::bind("127.0.0.1:0").await.expect("listen");
	let addr = ln.local_addr().unwrap().to_string();
	tokio::spawn(async move {
		while let Ok((mut sock, _)) = ln.accept().await {
			tokio::spawn(async move {
				// Echo bytes back until EOF.
				let mut buf = [0u8; 1024];
				loop {
					match sock.read(&mut buf).await {
						Ok(0) | Err(_) => break,
						Ok(n) => {
							if sock.write_all(&buf[..n]).await.is_err() {
								break;
							}
						}
					}
				}
			});
		}
	});
	addr
}

fn parse_addr(addr: &str) -> (String, u16) {
	let (host, port_str) = addr.rsplit_once(':').expect("addr has :port");
	let port: u16 = port_str.parse().expect("port parses");
	(host.to_string(), port)
}

#[tokio::test]
async fn dial_tcp() {
	use tokio::io::{AsyncReadExt, AsyncWriteExt};

	let addr = echo_server().await;
	let (host, port) = parse_addr(&addr);

	let backend = DirectBackend::new();
	let target = Target {
		network: "tcp".to_string(),
		protocol: Protocol::Unknown,
		host,
		port,
	};

	// Use the SystemDialer to establish a real connection.
	let dialer = puppy_core::backend::SystemDialer;
	let mut conn = backend
		.dial(target, &dialer)
		.await
		.expect("dial should succeed");

	let msg = b"direct-echo";
	conn.write_all(msg).await.expect("write");
	let mut got = vec![0u8; msg.len()];
	conn.read_exact(&mut got).await.expect("read");
	assert_eq!(got, msg);
}

#[tokio::test]
async fn dial_network_defaults_to_tcp() {
	use tokio::io::{AsyncReadExt, AsyncWriteExt};

	let addr = echo_server().await;
	let (host, port) = parse_addr(&addr);

	let backend = DirectBackend::new();
	// `network` intentionally left empty; `Target::net()` should default to
	// "tcp".
	let target = Target {
		network: String::new(),
		protocol: Protocol::Unknown,
		host,
		port,
	};

	let dialer = puppy_core::backend::SystemDialer;
	let mut conn = backend
		.dial(target, &dialer)
		.await
		.expect("dial with empty network should succeed");

	let msg = b"default-tcp";
	conn.write_all(msg).await.expect("write");
	let mut got = vec![0u8; msg.len()];
	conn.read_exact(&mut got).await.expect("read");
	assert_eq!(got, msg);
}

#[test]
fn backend_capabilities() {
	let capabilities = DirectBackend::new().capabilities();
	for network in ["tcp", "udp"] {
		assert!(
			supports_any_protocol(&capabilities, network),
			"direct backend should support {network} with any protocol"
		);
	}
}

#[test]
fn capabilities_match_documented_shape() {
	// Ensure the capability list matches the documented order exactly.
	let caps: Vec<Capability> = DirectBackend::new().capabilities();
	assert_eq!(caps.len(), 2);
	assert_eq!(caps[0].network, "tcp");
	assert_eq!(caps[0].protocol, Protocol::Any);
	assert_eq!(caps[1].network, "udp");
	assert_eq!(caps[1].protocol, Protocol::Any);
}

#[test]
fn default_backend_is_constructible() {
	// `Default` impl exists for callers that prefer the trait method. Clippy
	// prefers the unit-struct literal, but we explicitly exercise `default()`
	// to assert the impl is wired up.
	#[allow(clippy::default_constructed_unit_structs)]
	let _ = DirectBackend::default();
}
