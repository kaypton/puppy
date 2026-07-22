//! Backend tests for the gRPC tunnel proxy backend.
//!
//! Test groups:
//! - `backend_configuration_validate_*`: table-driven validation cases.
//! - `backend_capabilities`: capability assertions.
//! - `backend_tunnel_echo`: plaintext tunnel round trip and target recording.
//! - `backend_tunnel_channel_reuse`: two dials share the cached channel.
//! - `backend_tunnel_token_*`: bearer token accepted / rejected.
//! - `backend_tunnel_tls_echo`: TLS tunnel verified against a CA file.
//! - `backend_tunnel_tls_insecure_echo`: TLS tunnel with verification off.
//! - `backend_dial_unreachable`: connection failure surfaces as BackendError.

use std::pin::Pin;
use std::sync::{Arc, Mutex};

use futures_util::{Stream, StreamExt};

use grpc_tunnel::tunnel_server::{Tunnel, TunnelServer};
use grpc_tunnel::{parse_connect, server_stream, Frame, GrpcStream};
use puppy_core::backend::{
	supports_any_protocol, supports_network, Backend, BoxedStream, Protocol, Target,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tonic::transport::{Identity, Server, ServerTlsConfig};
use tonic::{Request, Response, Status};

use grpcproxy_be::{BackendConfiguration, GrpcProxyBackend};

// ---------------------------------------------------------------------------
// Fake gRPC tunnel server (records the connect frame, then echoes payloads).
// ---------------------------------------------------------------------------

type RecordedTargets = Arc<Mutex<Vec<(String, String, u16)>>>;

struct FakeTunnel {
	expected_token: Option<String>,
	recorded: RecordedTargets,
}

#[tonic::async_trait]
impl Tunnel for FakeTunnel {
	type ConnectStream = Pin<Box<dyn Stream<Item = Result<Frame, Status>> + Send>>;

	async fn connect(
		&self,
		request: Request<tonic::Streaming<Frame>>,
	) -> Result<Response<Self::ConnectStream>, Status> {
		if let Some(expected) = &self.expected_token {
			let want = format!("Bearer {expected}");
			let got = request
				.metadata()
				.get("authorization")
				.and_then(|v| v.to_str().ok());
			if got != Some(want.as_str()) {
				return Err(Status::unauthenticated("missing or invalid token"));
			}
		}

		let mut frames = request.into_inner();
		let first = frames
			.message()
			.await?
			.ok_or_else(|| Status::invalid_argument("empty request stream"))?;
		let target = parse_connect(first)?;
		self.recorded.lock().unwrap().push(target);

		let (stream, responses) = server_stream(frames);
		tokio::spawn(echo_loop(stream));
		Ok(Response::new(Box::pin(
			ReceiverStream::new(responses).map(Ok),
		)))
	}
}

/// Echoes payload bytes back into the tunnel until the peer disconnects.
async fn echo_loop(mut stream: GrpcStream) {
	let mut buf = [0u8; 8192];
	loop {
		match stream.read(&mut buf).await {
			Ok(0) | Err(_) => break,
			Ok(n) => {
				if stream.write_all(&buf[..n]).await.is_err() {
					break;
				}
			}
		}
	}
}

/// Starts the fake tunnel server in plaintext mode. Returns the listen
/// address and the shared target log. The server stops when the test runtime
/// shuts down.
async fn fake_tunnel_server(expected_token: Option<String>) -> (String, RecordedTargets) {
	let ln = TcpListener::bind("127.0.0.1:0").await.expect("listen");
	let addr = ln.local_addr().unwrap().to_string();
	let recorded: RecordedTargets = Arc::new(Mutex::new(Vec::new()));
	let service = TunnelServer::new(FakeTunnel {
		expected_token,
		recorded: recorded.clone(),
	});
	tokio::spawn(async move {
		Server::builder()
			.add_service(service)
			.serve_with_incoming(TcpListenerStream::new(ln))
			.await
			.expect("tunnel server");
	});
	(addr, recorded)
}

/// Starts the fake tunnel server in TLS mode using the provided cert/key PEM.
async fn fake_tls_tunnel_server(cert_pem: &str, key_pem: &str) -> (String, RecordedTargets) {
	let ln = TcpListener::bind("127.0.0.1:0").await.expect("listen");
	let addr = ln.local_addr().unwrap().to_string();
	let recorded: RecordedTargets = Arc::new(Mutex::new(Vec::new()));
	let service = TunnelServer::new(FakeTunnel {
		expected_token: None,
		recorded: recorded.clone(),
	});
	let identity = Identity::from_pem(cert_pem, key_pem);
	tokio::spawn(async move {
		Server::builder()
			.tls_config(ServerTlsConfig::new().identity(identity))
			.expect("server TLS config")
			.add_service(service)
			.serve_with_incoming(TcpListenerStream::new(ln))
			.await
			.expect("tunnel server");
	});
	(addr, recorded)
}

/// Generates a self-signed certificate for `localhost`/`127.0.0.1` and
/// returns `(cert_pem, key_pem)`.
fn test_tls_certificate() -> (String, String) {
	use rcgen::{CertificateParams, KeyPair};
	let mut params = CertificateParams::new(vec!["localhost".to_string()]).expect("params");
	params
		.subject_alt_names
		.push(rcgen::SanType::IpAddress(std::net::IpAddr::V4(
			std::net::Ipv4Addr::new(127, 0, 0, 1),
		)));
	let key_pair = KeyPair::generate().expect("generate key");
	let cert = params.self_signed(&key_pair).expect("self-signed");
	(cert.pem(), key_pair.serialize_pem())
}

fn test_target() -> Target {
	Target {
		network: "tcp".to_string(),
		protocol: Protocol::Unknown,
		host: "example.com".to_string(),
		port: 443,
	}
}

fn system_dialer() -> puppy_core::backend::SystemDialer {
	puppy_core::backend::SystemDialer
}

async fn assert_echo(conn: &mut BoxedStream, msg: &[u8]) {
	conn.write_all(msg).await.expect("write");
	let mut got = vec![0u8; msg.len()];
	conn.read_exact(&mut got).await.expect("read");
	assert_eq!(got, msg, "echo mismatch");
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn backend_configuration_validate_table() {
	let cases: &[(&str, BackendConfiguration, Option<&str>)] = &[
		(
			"missing server address",
			BackendConfiguration::default(),
			Some("server address is required"),
		),
		(
			"valid plaintext",
			BackendConfiguration {
				server_address: "127.0.0.1:1".to_string(),
				..Default::default()
			},
			None,
		),
		(
			"valid token",
			BackendConfiguration {
				server_address: "127.0.0.1:1".to_string(),
				token: "secret".to_string(),
				..Default::default()
			},
			None,
		),
		(
			"valid tls",
			BackendConfiguration {
				server_address: "127.0.0.1:1".to_string(),
				tls: true,
				..Default::default()
			},
			None,
		),
		(
			"ca file without tls",
			BackendConfiguration {
				server_address: "127.0.0.1:1".to_string(),
				tls_ca_file: "ca.pem".to_string(),
				..Default::default()
			},
			Some("require tls = true"),
		),
		(
			"server name without tls",
			BackendConfiguration {
				server_address: "127.0.0.1:1".to_string(),
				tls_server_name: "tunnel.internal".to_string(),
				..Default::default()
			},
			Some("require tls = true"),
		),
		(
			"insecure without tls",
			BackendConfiguration {
				server_address: "127.0.0.1:1".to_string(),
				tls_insecure_skip_verify: true,
				..Default::default()
			},
			Some("require tls = true"),
		),
		(
			"insecure with ca file",
			BackendConfiguration {
				server_address: "127.0.0.1:1".to_string(),
				tls: true,
				tls_ca_file: "ca.pem".to_string(),
				tls_insecure_skip_verify: true,
				..Default::default()
			},
			Some("mutually exclusive"),
		),
	];
	for (name, cfg, want_err) in cases {
		let result = cfg.validate();
		match want_err {
			None => assert!(
				result.is_ok(),
				"{name}: unexpected error {:?}",
				result.err()
			),
			Some(sub) => match result {
				Ok(()) => panic!("{name}: expected error containing {sub:?}, got Ok"),
				Err(e) => {
					assert!(
						e.to_string().contains(sub),
						"{name}: error = {e}, want substring {sub:?}"
					);
				}
			},
		}
	}
}

#[test]
fn backend_capabilities() {
	let backend = GrpcProxyBackend::new(BackendConfiguration {
		server_address: "127.0.0.1:1".to_string(),
		..Default::default()
	})
	.expect("backend construction");
	let capabilities = backend.capabilities();
	assert!(
		supports_any_protocol(&capabilities, "tcp"),
		"gRPC tunnel backend should support any TCP application protocol"
	);
	assert!(
		!supports_network(&capabilities, "udp"),
		"gRPC tunnel backend should not support UDP"
	);
}

#[tokio::test]
async fn backend_tunnel_echo() {
	let (addr, recorded) = fake_tunnel_server(None).await;

	let backend = GrpcProxyBackend::new(BackendConfiguration {
		server_address: addr,
		..Default::default()
	})
	.expect("backend construction");

	let mut conn = backend
		.dial(test_target(), &system_dialer())
		.await
		.expect("dial");
	assert_echo(&mut conn, b"grpc-tunnel-echo").await;

	let recorded = recorded.lock().unwrap();
	assert_eq!(
		recorded.as_slice(),
		&[("tcp".to_string(), "example.com".to_string(), 443)],
		"server should record the connect frame target"
	);
}

#[tokio::test]
async fn backend_tunnel_channel_reuse() {
	let (addr, recorded) = fake_tunnel_server(None).await;

	let backend = GrpcProxyBackend::new(BackendConfiguration {
		server_address: addr,
		..Default::default()
	})
	.expect("backend construction");

	// Two dials over the shared channel both work; each opens its own stream.
	let mut first = backend
		.dial(test_target(), &system_dialer())
		.await
		.expect("first dial");
	let mut second = backend
		.dial(test_target(), &system_dialer())
		.await
		.expect("second dial");
	assert_echo(&mut first, b"first-stream").await;
	assert_echo(&mut second, b"second-stream").await;

	assert_eq!(recorded.lock().unwrap().len(), 2, "one stream per dial");
}

#[tokio::test]
async fn backend_tunnel_token_accepted() {
	let (addr, _) = fake_tunnel_server(Some("secret-token".to_string())).await;

	let backend = GrpcProxyBackend::new(BackendConfiguration {
		server_address: addr,
		token: "secret-token".to_string(),
		..Default::default()
	})
	.expect("backend construction");

	let mut conn = backend
		.dial(test_target(), &system_dialer())
		.await
		.expect("dial");
	assert_echo(&mut conn, b"authed-tunnel").await;
}

#[tokio::test]
async fn backend_tunnel_token_missing() {
	let (addr, _) = fake_tunnel_server(Some("secret-token".to_string())).await;

	let backend = GrpcProxyBackend::new(BackendConfiguration {
		server_address: addr,
		..Default::default()
	})
	.expect("backend construction");

	let err = match backend.dial(test_target(), &system_dialer()).await {
		Err(e) => e,
		Ok(_) => panic!("expected error for missing token, got Ok"),
	};
	assert!(
		err.to_string().contains("grpcproxy: open tunnel stream"),
		"error = {err}"
	);
	assert!(err.to_string().contains("Unauthenticated"), "error = {err}");
}

#[tokio::test]
async fn backend_tunnel_token_wrong() {
	let (addr, _) = fake_tunnel_server(Some("secret-token".to_string())).await;

	let backend = GrpcProxyBackend::new(BackendConfiguration {
		server_address: addr,
		token: "wrong-token".to_string(),
		..Default::default()
	})
	.expect("backend construction");

	let err = match backend.dial(test_target(), &system_dialer()).await {
		Err(e) => e,
		Ok(_) => panic!("expected error for wrong token, got Ok"),
	};
	assert!(err.to_string().contains("Unauthenticated"), "error = {err}");
}

#[tokio::test]
async fn backend_tunnel_tls_echo() {
	let (cert_pem, key_pem) = test_tls_certificate();
	let (addr, recorded) = fake_tls_tunnel_server(&cert_pem, &key_pem).await;

	// Write the trust pool to a CA file so GrpcProxyBackend::new builds the
	// rustls client config itself.
	let dir = std::env::temp_dir();
	let ca_file = dir.join(format!("grpcproxy-be-ca-{}.pem", std::process::id()));
	std::fs::write(&ca_file, cert_pem.as_bytes()).expect("write CA file");

	let backend = GrpcProxyBackend::new(BackendConfiguration {
		server_address: addr,
		tls: true,
		tls_ca_file: ca_file.to_string_lossy().to_string(),
		tls_server_name: "localhost".to_string(),
		..Default::default()
	})
	.expect("backend construction");

	let mut conn = backend
		.dial(test_target(), &system_dialer())
		.await
		.expect("dial");
	assert_echo(&mut conn, b"tls-tunnel-echo").await;
	assert_eq!(recorded.lock().unwrap().len(), 1);

	let _ = std::fs::remove_file(&ca_file);
}

#[tokio::test]
async fn backend_tunnel_tls_insecure_echo() {
	let (cert_pem, key_pem) = test_tls_certificate();
	let (addr, _) = fake_tls_tunnel_server(&cert_pem, &key_pem).await;

	// The self-signed certificate is not trusted, but verification is off.
	let backend = GrpcProxyBackend::new(BackendConfiguration {
		server_address: addr,
		tls: true,
		tls_server_name: "localhost".to_string(),
		tls_insecure_skip_verify: true,
		..Default::default()
	})
	.expect("backend construction");

	let mut conn = backend
		.dial(test_target(), &system_dialer())
		.await
		.expect("dial");
	assert_echo(&mut conn, b"insecure-tls-tunnel").await;
}

#[tokio::test]
async fn backend_dial_unreachable() {
	let backend = GrpcProxyBackend::new(BackendConfiguration {
		server_address: "127.0.0.1:1".to_string(), // nothing listening
		..Default::default()
	})
	.expect("backend construction");

	let err = match backend.dial(test_target(), &system_dialer()).await {
		Err(e) => e,
		Ok(_) => panic!("expected error, got Ok"),
	};
	assert!(
		err.to_string().contains("grpcproxy:"),
		"error = {err}, want 'grpcproxy:' prefix"
	);
}
