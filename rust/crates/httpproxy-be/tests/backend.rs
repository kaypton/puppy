//! Backend tests for the HTTP CONNECT chaining backend.
//!
//! Test groups:
//! - `backend_configuration_validate_*`: table-driven validation cases.
//! - `backend_capabilities`: capability assertions.
//! - `backend_chain_through_http_proxy`: chaining through a plaintext proxy.
//! - `backend_authed_upstream`: chaining through an authed plaintext proxy.
//! - `backend_authed_upstream_wrong_creds`: 407 on wrong credentials.
//! - `backend_upstream_rejects`: 403 from the upstream proxy.
//! - `backend_dial_failure`: dialer-level failure.
//! - `backend_chain_through_tls_proxy`: chaining through a TLS proxy.
//! - `backend_authed_tls_upstream`: chaining through an authed TLS proxy.
//! - `backend_authed_tls_upstream_wrong_creds`: 407 on wrong credentials
//!   over TLS.
//! - `backend_tls_handshake_failure`: TLS handshake failure.
//! - `backend_tls_built_from_ca_file`: TLS config built from a CA file.
//! - `backend_tls_ca_validation_failure`: TLS CA validation failure.

use std::sync::Arc;

use async_trait::async_trait;
use puppy_core::backend::{
	supports_any_protocol, supports_network, Backend, BoxedStream, Dialer, Protocol, Target,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use httpproxy_be::{BackendConfiguration, HttpProxyBackend};

// ---------------------------------------------------------------------------
// Mini upstream proxies (plaintext and TLS).
// ---------------------------------------------------------------------------

/// Starts a minimal HTTP CONNECT upstream proxy that accepts CONNECT requests
/// (optionally requiring Basic auth) and tunnels to the requested target.
/// Returns the proxy address. The listener is shut down when the returned
/// handle is dropped.
async fn mini_proxy(require_user: &str, require_pass: &str) -> String {
	let ln = TcpListener::bind("127.0.0.1:0").await.expect("listen");
	let addr = ln.local_addr().unwrap().to_string();
	let require_user = require_user.to_string();
	let require_pass = require_pass.to_string();
	tokio::spawn(async move {
		while let Ok((sock, _)) = ln.accept().await {
			let ru = require_user.clone();
			let rp = require_pass.clone();
			tokio::spawn(async move {
				handle_mini_proxy_conn(sock, &ru, &rp).await;
			});
		}
	});
	addr
}

async fn handle_mini_proxy_conn<S>(conn: S, require_user: &str, require_pass: &str)
where
	S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
	let _ =
		tokio::time::timeout(std::time::Duration::from_secs(5), async {
			let mut conn = conn;
			// Read CONNECT request line + headers.
			let mut buf = vec![0u8; 4096];
			let mut total = 0;
			loop {
				let n = conn.read(&mut buf[total..]).await.unwrap_or(0);
				if n == 0 {
					return;
				}
				total += n;
				if buf[..total].windows(4).any(|w| w == b"\r\n\r\n") {
					break;
				}
				if total >= buf.len() {
					return;
				}
			}
			let request = String::from_utf8_lossy(&buf[..total]).to_string();

			// First line: "CONNECT host:port HTTP/1.1"
			let first_line = request.lines().next().unwrap_or("");
			let mut parts = first_line.split_whitespace();
			let method = parts.next().unwrap_or("");
			let target_addr = parts.next().unwrap_or("");

			if method != "CONNECT" {
				let _ = conn
					.write_all(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
					.await;
				return;
			}

			if !require_user.is_empty() {
				// Find Proxy-Authorization header.
				let creds = base64::engine::general_purpose::STANDARD
					.encode(format!("{require_user}:{require_pass}"));
				let expected = format!("Proxy-Authorization: Basic {creds}");
				let found = request.lines().any(|l| l.eq_ignore_ascii_case(&expected));
				if !found {
					let _ = conn
						.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
						.await;
					return;
				}
			}

			// Dial the target and start tunneling.
			let upstream = match tokio::net::TcpStream::connect(target_addr).await {
				Ok(s) => s,
				Err(_) => {
					let _ = conn
						.write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
						.await;
					return;
				}
			};

			if conn
				.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
				.await
				.is_err()
			{
				return;
			}

			// Tunnel bytes between `conn` and `upstream`. Any buffered bytes
			// past the request header in `buf` are pre-pended to `conn`'s
			// read side via a wrapper.
			let header_end = buf[..total]
				.windows(4)
				.position(|w| w == b"\r\n\r\n")
				.map(|i| i + 4)
				.unwrap_or(total);
			let leftover = buf[header_end..total].to_vec();

			let conn_wrapper = LeftoverStream::new(conn, leftover);
			let (mut conn_r, mut conn_w) = tokio::io::split(conn_wrapper);
			let (mut up_r, mut up_w) = tokio::io::split(upstream);

			let c2u = async {
				let _ = tokio::io::copy(&mut conn_r, &mut up_w).await;
				let _ = up_w.shutdown().await;
			};
			let u2c = async {
				let _ = tokio::io::copy(&mut up_r, &mut conn_w).await;
				let _ = conn_w.shutdown().await;
			};
			let _ = tokio::join!(c2u, u2c);
		})
		.await;
}

/// Wraps a stream so the first read returns `leftover` before delegating to
/// the underlying stream.
struct LeftoverStream<S> {
	inner: S,
	leftover: Vec<u8>,
}

impl<S> LeftoverStream<S> {
	fn new(inner: S, leftover: Vec<u8>) -> Self {
		Self { inner, leftover }
	}
}

impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for LeftoverStream<S> {
	fn poll_read(
		self: std::pin::Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
		buf: &mut tokio::io::ReadBuf<'_>,
	) -> std::task::Poll<std::io::Result<()>> {
		let this = self.get_mut();
		if !this.leftover.is_empty() {
			let n = std::cmp::min(this.leftover.len(), buf.remaining());
			buf.put_slice(&this.leftover[..n]);
			this.leftover.drain(..n);
			return std::task::Poll::Ready(Ok(()));
		}
		std::pin::Pin::new(&mut this.inner).poll_read(cx, buf)
	}
}

impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for LeftoverStream<S> {
	fn poll_write(
		self: std::pin::Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
		src: &[u8],
	) -> std::task::Poll<std::io::Result<usize>> {
		std::pin::Pin::new(&mut self.get_mut().inner).poll_write(cx, src)
	}

	fn poll_flush(
		self: std::pin::Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
	) -> std::task::Poll<std::io::Result<()>> {
		std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
	}

	fn poll_shutdown(
		self: std::pin::Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
	) -> std::task::Poll<std::io::Result<()>> {
		std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
	}
}

/// Starts a local TCP echo server. Returns the listen address.
async fn echo_server() -> String {
	let ln = TcpListener::bind("127.0.0.1:0").await.expect("listen");
	let addr = ln.local_addr().unwrap().to_string();
	tokio::spawn(async move {
		while let Ok((mut sock, _)) = ln.accept().await {
			tokio::spawn(async move {
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

fn parse_target(addr: &str) -> Target {
	let (host, port_str) = addr.rsplit_once(':').expect("addr has :port");
	Target {
		network: "tcp".to_string(),
		protocol: Protocol::Unknown,
		host: host.to_string(),
		port: port_str.parse().expect("port parses"),
	}
}

/// Dialer that always returns the given error.
struct FailingDialer {
	err: std::io::Error,
}

#[async_trait]
impl Dialer for FailingDialer {
	async fn dial_context(
		&self,
		_network: &str,
		_address: &str,
	) -> Result<BoxedStream, std::io::Error> {
		Err(std::io::Error::new(self.err.kind(), self.err.to_string()))
	}
}

/// Insecure client config (no certificate verification).
fn insecure_client_config() -> Arc<rustls::ClientConfig> {
	Arc::new(
		rustls::ClientConfig::builder()
			.dangerous()
			.with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
			.with_no_client_auth(),
	)
}

#[derive(Debug)]
struct NoCertificateVerification;

impl rustls::client::danger::ServerCertVerifier for NoCertificateVerification {
	fn verify_server_cert(
		&self,
		_end_entity: &rustls::pki_types::CertificateDer<'_>,
		_intermediates: &[rustls::pki_types::CertificateDer<'_>],
		_server_name: &rustls::pki_types::ServerName<'_>,
		_ocsp_response: &[u8],
		_now: rustls::pki_types::UnixTime,
	) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
		Ok(rustls::client::danger::ServerCertVerified::assertion())
	}

	fn verify_tls12_signature(
		&self,
		_message: &[u8],
		_cert: &rustls::pki_types::CertificateDer<'_>,
		_dss: &rustls::DigitallySignedStruct,
	) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
		Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
	}

	fn verify_tls13_signature(
		&self,
		_message: &[u8],
		_cert: &rustls::pki_types::CertificateDer<'_>,
		_dss: &rustls::DigitallySignedStruct,
	) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
		Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
	}

	fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
		vec![
			rustls::SignatureScheme::RSA_PKCS1_SHA256,
			rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
			rustls::SignatureScheme::RSA_PSS_SHA256,
			rustls::SignatureScheme::RSA_PKCS1_SHA384,
			rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
			rustls::SignatureScheme::RSA_PSS_SHA384,
			rustls::SignatureScheme::RSA_PKCS1_SHA512,
			rustls::SignatureScheme::RSA_PSS_SHA512,
			rustls::SignatureScheme::ED25519,
			rustls::SignatureScheme::ED448,
		]
	}
}

/// Generates a self-signed RSA certificate for `localhost`/`127.0.0.1` and
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

/// Starts a TLS-wrapped mini proxy using the provided cert/key PEM. Returns
/// the listen address.
async fn mini_tls_proxy(
	cert_pem: &str,
	key_pem: &str,
	require_user: &str,
	require_pass: &str,
) -> String {
	let ln = TcpListener::bind("127.0.0.1:0").await.expect("listen");
	let addr = ln.local_addr().unwrap().to_string();

	let mut cert_chain = Vec::new();
	let mut cert_reader = std::io::Cursor::new(cert_pem.as_bytes());
	for cert in rustls_pemfile::certs(&mut cert_reader) {
		cert_chain.push(cert.expect("parse cert"));
	}
	let mut key_reader = std::io::Cursor::new(key_pem.as_bytes());
	let key = rustls_pemfile::private_key(&mut key_reader)
		.expect("parse key")
		.expect("a key");

	let certs: Vec<_> = cert_chain
		.into_iter()
		.map(|c| rustls::pki_types::CertificateDer::from(c.to_vec()))
		.collect();

	let tls_config = rustls::ServerConfig::builder()
		.with_no_client_auth()
		.with_single_cert(certs, key)
		.expect("server config");
	let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));

	let require_user = require_user.to_string();
	let require_pass = require_pass.to_string();
	tokio::spawn(async move {
		while let Ok((sock, _)) = ln.accept().await {
			let ru = require_user.clone();
			let rp = require_pass.clone();
			let acceptor = acceptor.clone();
			tokio::spawn(async move {
				let tls = match acceptor.accept(sock).await {
					Ok(t) => t,
					Err(_) => return,
				};
				handle_mini_proxy_conn(tls, &ru, &rp).await;
			});
		}
	});
	addr
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn backend_configuration_validate_table() {
	let cases: &[(&str, BackendConfiguration, Option<&str>)] = &[
		(
			"missing proxy address",
			BackendConfiguration::default(),
			Some("proxy address"),
		),
		(
			"username only",
			BackendConfiguration {
				proxy_address: "127.0.0.1:1".to_string(),
				username: "u".to_string(),
				..Default::default()
			},
			Some("username and password"),
		),
		(
			"password only",
			BackendConfiguration {
				proxy_address: "127.0.0.1:1".to_string(),
				password: "p".to_string(),
				..Default::default()
			},
			Some("username and password"),
		),
		(
			"valid open",
			BackendConfiguration {
				proxy_address: "127.0.0.1:1".to_string(),
				..Default::default()
			},
			None,
		),
		(
			"valid authed",
			BackendConfiguration {
				proxy_address: "127.0.0.1:1".to_string(),
				username: "u".to_string(),
				password: "p".to_string(),
				..Default::default()
			},
			None,
		),
		(
			"valid tls",
			BackendConfiguration {
				proxy_address: "127.0.0.1:1".to_string(),
				tls: true,
				..Default::default()
			},
			None,
		),
		(
			"ca file without tls",
			BackendConfiguration {
				proxy_address: "127.0.0.1:1".to_string(),
				tls_ca_file: "ca.pem".to_string(),
				..Default::default()
			},
			Some("require tls = true"),
		),
		(
			"server name without tls",
			BackendConfiguration {
				proxy_address: "127.0.0.1:1".to_string(),
				tls_server_name: "proxy.internal".to_string(),
				..Default::default()
			},
			Some("require tls = true"),
		),
		(
			"insecure without tls",
			BackendConfiguration {
				proxy_address: "127.0.0.1:1".to_string(),
				tls_insecure_skip_verify: true,
				..Default::default()
			},
			Some("require tls = true"),
		),
		(
			"insecure with ca file",
			BackendConfiguration {
				proxy_address: "127.0.0.1:1".to_string(),
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
	let backend = HttpProxyBackend::new(BackendConfiguration {
		proxy_address: "127.0.0.1:1".to_string(),
		..Default::default()
	})
	.expect("backend construction");
	let capabilities = backend.capabilities();
	assert!(
		supports_any_protocol(&capabilities, "tcp"),
		"HTTP CONNECT backend should support any TCP application protocol"
	);
	assert!(
		!supports_network(&capabilities, "udp"),
		"HTTP CONNECT backend should not support UDP"
	);
}

async fn assert_echo(conn: &mut BoxedStream, msg: &[u8]) {
	conn.write_all(msg).await.expect("write");
	let mut got = vec![0u8; msg.len()];
	conn.read_exact(&mut got).await.expect("read");
	assert_eq!(got, msg, "echo mismatch");
}

fn system_dialer() -> puppy_core::backend::SystemDialer {
	puppy_core::backend::SystemDialer
}

#[tokio::test]
async fn backend_chain_through_http_proxy() {
	let echo_addr = echo_server().await;
	let proxy_addr = mini_proxy("", "").await;

	let backend = HttpProxyBackend::new(BackendConfiguration {
		proxy_address: proxy_addr,
		..Default::default()
	})
	.expect("backend construction");

	let mut conn = backend
		.dial(parse_target(&echo_addr), &system_dialer())
		.await
		.expect("dial");
	assert_echo(&mut conn, b"chained-echo").await;
}

#[tokio::test]
async fn backend_authed_upstream() {
	let echo_addr = echo_server().await;
	let proxy_addr = mini_proxy("alice", "secret").await;

	let backend = HttpProxyBackend::new(BackendConfiguration {
		proxy_address: proxy_addr,
		username: "alice".to_string(),
		password: "secret".to_string(),
		..Default::default()
	})
	.expect("backend construction");

	let mut conn = backend
		.dial(parse_target(&echo_addr), &system_dialer())
		.await
		.expect("dial");
	assert_echo(&mut conn, b"authed-chain").await;
}

#[tokio::test]
async fn backend_authed_upstream_wrong_creds() {
	let echo_addr = echo_server().await;
	let proxy_addr = mini_proxy("alice", "secret").await;

	let backend = HttpProxyBackend::new(BackendConfiguration {
		proxy_address: proxy_addr,
		username: "alice".to_string(),
		password: "wrong".to_string(),
		..Default::default()
	})
	.expect("backend construction");

	let result = backend
		.dial(parse_target(&echo_addr), &system_dialer())
		.await;
	let err = match result {
		Err(e) => e,
		Ok(_) => panic!("expected error for wrong credentials, got Ok"),
	};
	assert!(err.to_string().contains("407"), "error = {err}, want '407'");
}

#[tokio::test]
async fn backend_upstream_rejects() {
	// Start a server that always refuses CONNECT with 403.
	let ln = TcpListener::bind("127.0.0.1:0").await.expect("listen");
	let proxy_addr = ln.local_addr().unwrap().to_string();
	tokio::spawn(async move {
		while let Ok((mut sock, _)) = ln.accept().await {
			tokio::spawn(async move {
				let mut buf = vec![0u8; 4096];
				let _ = sock.read(&mut buf).await;
				let _ = sock
					.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
					.await;
			});
		}
	});

	let backend = HttpProxyBackend::new(BackendConfiguration {
		proxy_address: proxy_addr,
		..Default::default()
	})
	.expect("backend construction");

	let target = Target {
		network: "tcp".to_string(),
		protocol: Protocol::Unknown,
		host: "example.com".to_string(),
		port: 443,
	};
	let result = backend.dial(target, &system_dialer()).await;
	let err = match result {
		Err(e) => e,
		Ok(_) => panic!("expected error, got Ok"),
	};
	assert!(err.to_string().contains("403"), "error = {err}, want '403'");
}

#[tokio::test]
async fn backend_dial_failure() {
	let backend = HttpProxyBackend::new(BackendConfiguration {
		proxy_address: "127.0.0.1:1".to_string(), // nothing listening
		..Default::default()
	})
	.expect("backend construction");

	let failing_dialer = FailingDialer {
		err: std::io::Error::other("unreachable"),
	};
	let target = Target {
		network: "tcp".to_string(),
		protocol: Protocol::Unknown,
		host: "example.com".to_string(),
		port: 443,
	};
	let err = match backend.dial(target, &failing_dialer).await {
		Err(e) => e,
		Ok(_) => panic!("expected error, got Ok"),
	};
	assert!(
		err.to_string().contains("dial upstream proxy"),
		"error = {err}, want 'dial upstream proxy'"
	);
}

#[tokio::test]
async fn backend_chain_through_tls_proxy() {
	let echo_addr = echo_server().await;
	let (cert_pem, key_pem) = test_tls_certificate();
	let proxy_addr = mini_tls_proxy(&cert_pem, &key_pem, "", "").await;

	let backend = HttpProxyBackend::new(BackendConfiguration {
		proxy_address: proxy_addr,
		tls: true,
		tls_config: Some(insecure_client_config()),
		..Default::default()
	})
	.expect("backend construction");

	let mut conn = backend
		.dial(parse_target(&echo_addr), &system_dialer())
		.await
		.expect("dial");
	assert_echo(&mut conn, b"tls-chained-echo").await;
}

#[tokio::test]
async fn backend_authed_tls_upstream() {
	let echo_addr = echo_server().await;
	let (cert_pem, key_pem) = test_tls_certificate();
	let proxy_addr = mini_tls_proxy(&cert_pem, &key_pem, "alice", "secret").await;

	let backend = HttpProxyBackend::new(BackendConfiguration {
		proxy_address: proxy_addr,
		username: "alice".to_string(),
		password: "secret".to_string(),
		tls: true,
		tls_config: Some(insecure_client_config()),
		..Default::default()
	})
	.expect("backend construction");

	let mut conn = backend
		.dial(parse_target(&echo_addr), &system_dialer())
		.await
		.expect("dial");
	assert_echo(&mut conn, b"authed-tls-chain").await;
}

#[tokio::test]
async fn backend_authed_tls_upstream_wrong_creds() {
	let echo_addr = echo_server().await;
	let (cert_pem, key_pem) = test_tls_certificate();
	let proxy_addr = mini_tls_proxy(&cert_pem, &key_pem, "alice", "secret").await;

	let backend = HttpProxyBackend::new(BackendConfiguration {
		proxy_address: proxy_addr,
		username: "alice".to_string(),
		password: "wrong".to_string(),
		tls: true,
		tls_config: Some(insecure_client_config()),
		..Default::default()
	})
	.expect("backend construction");

	let err = match backend
		.dial(parse_target(&echo_addr), &system_dialer())
		.await
	{
		Err(e) => e,
		Ok(_) => panic!("expected error for wrong credentials, got Ok"),
	};
	assert!(err.to_string().contains("407"), "error = {err}, want '407'");
}

#[tokio::test]
async fn backend_tls_handshake_failure() {
	// Plaintext mini_proxy, but backend is configured for TLS; handshake fails.
	let echo_addr = echo_server().await;
	let proxy_addr = mini_proxy("", "").await;
	let _ = echo_addr;

	let backend = HttpProxyBackend::new(BackendConfiguration {
		proxy_address: proxy_addr,
		tls: true,
		tls_config: Some(insecure_client_config()),
		..Default::default()
	})
	.expect("backend construction");

	let target = parse_target(&echo_addr);
	let err = match backend.dial(target, &system_dialer()).await {
		Err(e) => e,
		Ok(_) => panic!("expected TLS handshake error, got Ok"),
	};
	assert!(
		err.to_string().contains("TLS handshake"),
		"error = {err}, want 'TLS handshake'"
	);
}

#[tokio::test]
async fn backend_tls_built_from_ca_file() {
	let echo_addr = echo_server().await;
	let (cert_pem, key_pem) = test_tls_certificate();
	let proxy_addr = mini_tls_proxy(&cert_pem, &key_pem, "", "").await;

	// Write the trust pool to a CA file so HttpProxyBackend::new builds the
	// rustls client config itself rather than receiving an injected one.
	let dir = std::env::temp_dir();
	let ca_file = dir.join(format!("httpproxy-be-ca-{}.pem", std::process::id()));
	std::fs::write(&ca_file, cert_pem.as_bytes()).expect("write CA file");

	let backend = HttpProxyBackend::new(BackendConfiguration {
		proxy_address: proxy_addr,
		tls: true,
		tls_ca_file: ca_file.to_string_lossy().to_string(),
		tls_server_name: "localhost".to_string(),
		..Default::default()
	})
	.expect("backend construction");

	let mut conn = backend
		.dial(parse_target(&echo_addr), &system_dialer())
		.await
		.expect("dial");
	assert_echo(&mut conn, b"ca-file-chain").await;

	let _ = std::fs::remove_file(&ca_file);
}

#[tokio::test]
async fn backend_tls_ca_validation_failure() {
	let echo_addr = echo_server().await;
	let (cert_pem, key_pem) = test_tls_certificate();
	let proxy_addr = mini_tls_proxy(&cert_pem, &key_pem, "", "").await;
	let _ = echo_addr;

	// TLS enabled with no CA file and not skipping verification: the
	// self-signed test certificate is not in the system roots, so the
	// handshake must fail.
	let backend = HttpProxyBackend::new(BackendConfiguration {
		proxy_address: proxy_addr,
		tls: true,
		tls_server_name: "localhost".to_string(),
		..Default::default()
	})
	.expect("backend construction");

	let target = parse_target(&echo_addr);
	let err = match backend.dial(target, &system_dialer()).await {
		Err(e) => e,
		Ok(_) => panic!("expected TLS verification error, got Ok"),
	};
	assert!(
		err.to_string().contains("TLS handshake"),
		"error = {err}, want 'TLS handshake'"
	);
}

// Re-export so the test file can use base64 from outside.
use base64::Engine as _;
