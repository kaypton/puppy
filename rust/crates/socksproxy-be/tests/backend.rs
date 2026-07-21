//! Backend tests for the SOCKS5 chaining backend.
//!
//! Test groups:
//! - `backend_configuration_validate_table`: 10 table-driven validation cases.
//! - `backend_capabilities`: capability reporting.
//! - `backend_chain_through_socks5`: tunnels through an unauthenticated
//!   upstream SOCKS5 proxy.
//! - `backend_authed_upstream`: authenticates to the upstream with
//!   username/password.
//! - `backend_authed_upstream_wrong_creds`: rejected credentials surface as
//!   an error.
//! - `backend_auth_required_but_no_creds`: upstream demands auth but the
//!   backend has none configured.
//! - `backend_upstream_rejects_connect`: upstream refuses the CONNECT.
//! - `backend_dial_failure`: dialer-level failures surface as errors.
//! - `backend_domain_target`: domain-name targets are forwarded verbatim.
//! - `backend_ipv6_target`: IPv6 targets are forwarded verbatim.
//! - `backend_chain_through_tls_proxy`: TLS-wrapped upstream SOCKS5 proxy.
//! - `backend_authed_tls_upstream`: TLS upstream with username/password.
//! - `backend_authed_tls_upstream_wrong_creds`: TLS upstream with wrong
//!   credentials.
//! - `backend_tls_handshake_failure`: TLS handshake errors surface cleanly.
//! - `backend_tls_built_from_ca_file`: custom CA file is trusted.
//! - `backend_tls_ca_validation_failure`: CA validation failures surface
//!   cleanly.
//! - `encode_socks5_request_table`: request encoder table-driven cases.
//! - `socks5_reply_text_delegates_to_common`: reply text delegates to
//!   `puppy_core::socks5`.

use std::sync::Arc;

use async_trait::async_trait;
use puppy_core::backend::{
	supports_any_protocol, supports_network, Backend, BoxedStream, Dialer, Protocol, Target,
};
use puppy_core::socks5;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use socksproxy_be::{encode_socks5_request, BackendConfiguration, SocksProxyBackend};

// ---------------------------------------------------------------------------
// Mini upstream SOCKS5 proxies (plaintext and TLS).
// ---------------------------------------------------------------------------

/// Starts a minimal SOCKS5 upstream proxy that accepts CONNECT requests
/// (optionally requiring username/password auth) and tunnels to the requested
/// target. Returns the proxy address. The listener is shut down when the
/// runtime is idle.
async fn mini_socks5(require_user: &str, require_pass: &str) -> String {
	let ln = TcpListener::bind("127.0.0.1:0").await.expect("listen");
	let addr = ln.local_addr().unwrap().to_string();
	let require_user = require_user.to_string();
	let require_pass = require_pass.to_string();
	tokio::spawn(async move {
		while let Ok((sock, _)) = ln.accept().await {
			let ru = require_user.clone();
			let rp = require_pass.clone();
			tokio::spawn(async move {
				handle_mini_socks5_conn(sock, &ru, &rp).await;
			});
		}
	});
	addr
}

/// Handles a single connection to the mini SOCKS5 proxy.
async fn handle_mini_socks5_conn<S>(conn: S, require_user: &str, require_pass: &str)
where
	S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
	let _ = tokio::time::timeout(std::time::Duration::from_secs(5), async {
		let mut conn = conn;

		// Method negotiation: read VER + NMETHODS + METHODS.
		let mut header = [0u8; 2];
		if conn.read_exact(&mut header).await.is_err() {
			return;
		}
		if header[0] != socks5::VERSION {
			return;
		}
		let mut methods = vec![0u8; header[1] as usize];
		if conn.read_exact(&mut methods).await.is_err() {
			return;
		}

		let mut selected = socks5::METHOD_NO_ACCEPTABLE;
		for &m in &methods {
			if !require_user.is_empty() {
				if m == socks5::METHOD_USERNAME_PASSWORD {
					selected = m;
					break;
				}
			} else if m == socks5::METHOD_NO_AUTH {
				selected = m;
				break;
			}
		}
		if conn.write_all(&[socks5::VERSION, selected]).await.is_err() {
			return;
		}
		if selected == socks5::METHOD_NO_ACCEPTABLE {
			return;
		}

		if selected == socks5::METHOD_USERNAME_PASSWORD {
			let mut auth_header = [0u8; 2];
			if conn.read_exact(&mut auth_header).await.is_err() {
				return;
			}
			if auth_header[0] != socks5::AUTH_VERSION {
				return;
			}
			let ulen = auth_header[1] as usize;
			let mut user = vec![0u8; ulen];
			if conn.read_exact(&mut user).await.is_err() {
				return;
			}
			let mut plen_byte = [0u8; 1];
			if conn.read_exact(&mut plen_byte).await.is_err() {
				return;
			}
			let mut pass = vec![0u8; plen_byte[0] as usize];
			if conn.read_exact(&mut pass).await.is_err() {
				return;
			}
			if user != require_user.as_bytes() || pass != require_pass.as_bytes() {
				let _ = conn.write_all(&[socks5::AUTH_VERSION, 0x01]).await;
				return;
			}
			if conn.write_all(&[socks5::AUTH_VERSION, 0x00]).await.is_err() {
				return;
			}
		}

		// CONNECT request.
		let mut req_header = [0u8; 4];
		if conn.read_exact(&mut req_header).await.is_err() {
			return;
		}
		if req_header[0] != socks5::VERSION || req_header[1] != socks5::CMD_CONNECT {
			let _ = conn
				.write_all(&[
					socks5::VERSION,
					0x07,
					0x00,
					socks5::ATYP_IPV4,
					0,
					0,
					0,
					0,
					0,
					0,
				])
				.await;
			return;
		}
		let host = match read_socks5_addr(&mut conn, req_header[3]).await {
			Ok(h) => h,
			Err(_) => return,
		};
		let mut port_bytes = [0u8; 2];
		if conn.read_exact(&mut port_bytes).await.is_err() {
			return;
		}
		let port = u16::from_be_bytes(port_bytes);
		let target = format!("{host}:{port}");

		let upstream = match tokio::net::TcpStream::connect(&target).await {
			Ok(s) => s,
			Err(_) => {
				let _ = conn
					.write_all(&[
						socks5::VERSION,
						0x04,
						0x00,
						socks5::ATYP_IPV4,
						0,
						0,
						0,
						0,
						0,
						0,
					])
					.await;
				return;
			}
		};
		if conn
			.write_all(&[
				socks5::VERSION,
				socks5::REP_SUCCESS,
				0x00,
				socks5::ATYP_IPV4,
				0,
				0,
				0,
				0,
				0,
				0,
			])
			.await
			.is_err()
		{
			return;
		}

		// Tunnel bytes between conn and upstream.
		let (mut conn_r, mut conn_w) = tokio::io::split(conn);
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

/// Reads only the DST.ADDR portion (no port) for the mini SOCKS5 proxy.
async fn read_socks5_addr<R: AsyncReadExt + Unpin>(
	reader: &mut R,
	atyp: u8,
) -> std::io::Result<String> {
	match atyp {
		socks5::ATYP_IPV4 => {
			let mut addr = [0u8; 4];
			reader.read_exact(&mut addr).await?;
			Ok(std::net::Ipv4Addr::from(addr).to_string())
		}
		socks5::ATYP_IPV6 => {
			let mut addr = [0u8; 16];
			reader.read_exact(&mut addr).await?;
			Ok(std::net::Ipv6Addr::from(addr).to_string())
		}
		socks5::ATYP_DOMAIN => {
			let mut len_byte = [0u8; 1];
			reader.read_exact(&mut len_byte).await?;
			let mut domain = vec![0u8; len_byte[0] as usize];
			reader.read_exact(&mut domain).await?;
			String::from_utf8(domain)
				.map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
		}
		other => Err(std::io::Error::other(format!(
			"unknown address type 0x{other:02x}"
		))),
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

/// Dialer that always returns the given error. Used to exercise dialer-level
/// failures.
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

/// Starts a TLS-wrapped mini SOCKS5 proxy using the provided cert/key PEM.
/// Returns the listen address.
async fn mini_tls_socks5(
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
				handle_mini_socks5_conn(tls, &ru, &rp).await;
			});
		}
	});
	addr
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Table-driven validation of `BackendConfiguration::validate`: each case
/// constructs a runtime config and checks the resulting error substring
/// (or that the config validates cleanly). Covers missing proxy address,
/// half-set credentials, three TLS-adjacent fields set without `tls = true`,
/// the `tls_ca_file` / `tls_insecure_skip_verify` mutual exclusion, and
/// three valid baselines (open, authed, TLS).
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

/// Verifies the SOCKS5 chaining backend advertises a capability for any
/// TCP application protocol and does not advertise UDP support.
#[test]
fn backend_capabilities() {
	let backend = SocksProxyBackend::new(BackendConfiguration {
		proxy_address: "127.0.0.1:1".to_string(),
		..Default::default()
	})
	.expect("NewBackend");
	let capabilities = backend.capabilities();
	assert!(
		supports_any_protocol(&capabilities, "tcp"),
		"SOCKS5 backend should support any TCP application protocol"
	);
	assert!(
		!supports_network(&capabilities, "udp"),
		"SOCKS5 backend should not support UDP"
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

/// End-to-end: the backend tunnels traffic through an unauthenticated
/// upstream SOCKS5 proxy to an echo server, and bytes written through the
/// tunneled connection are echoed back unchanged.
#[tokio::test]
async fn backend_chain_through_socks5() {
	let echo_addr = echo_server().await;
	let proxy_addr = mini_socks5("", "").await;

	let backend = SocksProxyBackend::new(BackendConfiguration {
		proxy_address: proxy_addr,
		..Default::default()
	})
	.expect("NewBackend");

	let mut conn = backend
		.dial(parse_target(&echo_addr), &system_dialer())
		.await
		.expect("Dial");
	assert_echo(&mut conn, b"chained-echo").await;
}

/// End-to-end: the backend authenticates to an upstream SOCKS5 proxy using
/// username/password (RFC 1929) and tunnels traffic to an echo server.
#[tokio::test]
async fn backend_authed_upstream() {
	let echo_addr = echo_server().await;
	let proxy_addr = mini_socks5("alice", "secret").await;

	let backend = SocksProxyBackend::new(BackendConfiguration {
		proxy_address: proxy_addr,
		username: "alice".to_string(),
		password: "secret".to_string(),
		..Default::default()
	})
	.expect("NewBackend");

	let mut conn = backend
		.dial(parse_target(&echo_addr), &system_dialer())
		.await
		.expect("Dial");
	assert_echo(&mut conn, b"authed-chain").await;
}

/// Verifies that when the upstream SOCKS5 proxy rejects the offered
/// credentials, `dial` fails with an error containing "rejected
/// credentials".
#[tokio::test]
async fn backend_authed_upstream_wrong_creds() {
	let echo_addr = echo_server().await;
	let proxy_addr = mini_socks5("alice", "secret").await;

	let backend = SocksProxyBackend::new(BackendConfiguration {
		proxy_address: proxy_addr,
		username: "alice".to_string(),
		password: "wrong".to_string(),
		..Default::default()
	})
	.expect("NewBackend");

	let err = match backend
		.dial(parse_target(&echo_addr), &system_dialer())
		.await
	{
		Err(e) => e,
		Ok(_) => panic!("expected error for wrong credentials, got Ok"),
	};
	assert!(
		err.to_string().contains("rejected credentials"),
		"error = {err}, want 'rejected credentials'"
	);
}

/// Verifies that when the upstream SOCKS5 proxy requires auth but the
/// backend has no credentials configured, `dial` fails with an error
/// containing "no acceptable method" (the method-selection handshake has
/// no mutually acceptable auth method).
#[tokio::test]
async fn backend_auth_required_but_no_creds() {
	let echo_addr = echo_server().await;
	let proxy_addr = mini_socks5("alice", "secret").await;

	let backend = SocksProxyBackend::new(BackendConfiguration {
		proxy_address: proxy_addr,
		..Default::default()
	})
	.expect("NewBackend");

	let err = match backend
		.dial(parse_target(&echo_addr), &system_dialer())
		.await
	{
		Err(e) => e,
		Ok(_) => panic!("expected error when upstream requires auth but no creds offered, got Ok"),
	};
	assert!(
		err.to_string().contains("no acceptable method"),
		"error = {err}, want 'no acceptable method'"
	);
}

/// Verifies that when the upstream SOCKS5 proxy completes method
/// negotiation (no-auth) but refuses the CONNECT with REP=0x05
/// (connection refused), `dial` surfaces an error containing "connection
/// refused".
#[tokio::test]
async fn backend_upstream_rejects_connect() {
	// An upstream that completes the method negotiation (no-auth) then always
	// refuses CONNECT with rep=0x05 (connection refused).
	let ln = TcpListener::bind("127.0.0.1:0").await.expect("listen");
	let proxy_addr = ln.local_addr().unwrap().to_string();
	tokio::spawn(async move {
		while let Ok((mut sock, _)) = ln.accept().await {
			tokio::spawn(async move {
				let _ = tokio::time::timeout(std::time::Duration::from_secs(5), async {
					let mut header = [0u8; 2];
					if sock.read_exact(&mut header).await.is_err() {
						return;
					}
					let mut methods = vec![0u8; header[1] as usize];
					if sock.read_exact(&mut methods).await.is_err() {
						return;
					}
					if sock
						.write_all(&[socks5::VERSION, socks5::METHOD_NO_AUTH])
						.await
						.is_err()
					{
						return;
					}
					let mut req_header = [0u8; 4];
					if sock.read_exact(&mut req_header).await.is_err() {
						return;
					}
					// Consume DST.ADDR (variable length) + DST.PORT.
					if read_socks5_addr(&mut sock, req_header[3]).await.is_err() {
						return;
					}
					let mut port_bytes = [0u8; 2];
					let _ = sock.read_exact(&mut port_bytes).await;
					let _ = sock
						.write_all(&[
							socks5::VERSION,
							0x05,
							0x00,
							socks5::ATYP_IPV4,
							0,
							0,
							0,
							0,
							0,
							0,
						])
						.await;
				})
				.await;
			});
		}
	});

	let backend = SocksProxyBackend::new(BackendConfiguration {
		proxy_address: proxy_addr,
		..Default::default()
	})
	.expect("NewBackend");

	let target = Target {
		network: "tcp".to_string(),
		protocol: Protocol::Unknown,
		host: "example.com".to_string(),
		port: 443,
	};
	let err = match backend.dial(target, &system_dialer()).await {
		Err(e) => e,
		Ok(_) => panic!("expected error, got Ok"),
	};
	assert!(
		err.to_string().contains("connection refused"),
		"error = {err}, want 'connection refused'"
	);
}

/// Verifies that when the dialer itself fails to reach the upstream proxy,
/// `dial` surfaces an error containing "dial upstream proxy" (as opposed
/// to a SOCKS5-protocol-level failure).
#[tokio::test]
async fn backend_dial_failure() {
	let backend = SocksProxyBackend::new(BackendConfiguration {
		proxy_address: "127.0.0.1:1".to_string(), // nothing listening
		..Default::default()
	})
	.expect("NewBackend");

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

/// Verifies a domain-name target (e.g. "localhost") is forwarded to the
/// upstream SOCKS5 proxy verbatim (ATYP=domain) and the proxy resolves it,
/// yielding a working tunnel to the echo server.
#[tokio::test]
async fn backend_domain_target() {
	let echo_addr = echo_server().await;
	let proxy_addr = mini_socks5("", "").await;

	let backend = SocksProxyBackend::new(BackendConfiguration {
		proxy_address: proxy_addr,
		..Default::default()
	})
	.expect("NewBackend");

	// Use "localhost" so the mini proxy resolves it back to the loopback
	// echo server's port.
	let (_host, port_str) = echo_addr.rsplit_once(':').expect("addr has :port");
	let port: u16 = port_str.parse().expect("port parses");
	let target = Target {
		network: "tcp".to_string(),
		protocol: Protocol::Unknown,
		host: "localhost".to_string(),
		port,
	};
	let mut conn = backend.dial(target, &system_dialer()).await.expect("Dial");
	assert_echo(&mut conn, b"domain-target-echo").await;
}

/// Verifies an IPv6 target (`[::1]:port`) is forwarded to the upstream
/// SOCKS5 proxy (ATYP=IPv6) and tunnels traffic to an IPv6 echo server.
/// Skipped when IPv6 loopback is unavailable on the host.
#[tokio::test]
async fn backend_ipv6_target() {
	// Skip if IPv6 loopback is unavailable.
	let echo_ln = match TcpListener::bind("[::1]:0").await {
		Ok(l) => l,
		Err(e) => {
			eprintln!("IPv6 not available: {e}");
			return;
		}
	};
	let echo_addr = echo_ln.local_addr().unwrap().to_string();
	tokio::spawn(async move {
		while let Ok((mut sock, _)) = echo_ln.accept().await {
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

	let proxy_addr = mini_socks5("", "").await;
	let backend = SocksProxyBackend::new(BackendConfiguration {
		proxy_address: proxy_addr,
		..Default::default()
	})
	.expect("NewBackend");

	let target = parse_target(&echo_addr);
	let mut conn = backend.dial(target, &system_dialer()).await.expect("Dial");
	assert_echo(&mut conn, b"ipv6-echo").await;
}

/// End-to-end over TLS: the backend wraps the upstream SOCKS5 connection
/// in TLS (with an insecure client config trusting the test cert) and
/// tunnels traffic through the TLS-wrapped proxy to an echo server.
#[tokio::test]
async fn backend_chain_through_tls_proxy() {
	let echo_addr = echo_server().await;
	let (cert_pem, key_pem) = test_tls_certificate();
	let proxy_addr = mini_tls_socks5(&cert_pem, &key_pem, "", "").await;

	let backend = SocksProxyBackend::new(BackendConfiguration {
		proxy_address: proxy_addr,
		tls: true,
		tls_config: Some(insecure_client_config()),
		..Default::default()
	})
	.expect("NewBackend");

	let mut conn = backend
		.dial(parse_target(&echo_addr), &system_dialer())
		.await
		.expect("Dial");
	assert_echo(&mut conn, b"tls-chained-echo").await;
}

/// End-to-end over TLS with auth: the backend wraps the upstream SOCKS5
/// connection in TLS and authenticates with username/password, then
/// tunnels traffic to an echo server.
#[tokio::test]
async fn backend_authed_tls_upstream() {
	let echo_addr = echo_server().await;
	let (cert_pem, key_pem) = test_tls_certificate();
	let proxy_addr = mini_tls_socks5(&cert_pem, &key_pem, "alice", "secret").await;

	let backend = SocksProxyBackend::new(BackendConfiguration {
		proxy_address: proxy_addr,
		username: "alice".to_string(),
		password: "secret".to_string(),
		tls: true,
		tls_config: Some(insecure_client_config()),
		..Default::default()
	})
	.expect("NewBackend");

	let mut conn = backend
		.dial(parse_target(&echo_addr), &system_dialer())
		.await
		.expect("Dial");
	assert_echo(&mut conn, b"authed-tls-chain").await;
}

/// Verifies that over a TLS-wrapped upstream SOCKS5 proxy, wrong
/// credentials cause `dial` to fail with an error containing "rejected
/// credentials" (the TLS layer succeeds; the SOCKS5 auth sub-negotiation
/// fails).
#[tokio::test]
async fn backend_authed_tls_upstream_wrong_creds() {
	let echo_addr = echo_server().await;
	let (cert_pem, key_pem) = test_tls_certificate();
	let proxy_addr = mini_tls_socks5(&cert_pem, &key_pem, "alice", "secret").await;

	let backend = SocksProxyBackend::new(BackendConfiguration {
		proxy_address: proxy_addr,
		username: "alice".to_string(),
		password: "wrong".to_string(),
		tls: true,
		tls_config: Some(insecure_client_config()),
		..Default::default()
	})
	.expect("NewBackend");

	let err = match backend
		.dial(parse_target(&echo_addr), &system_dialer())
		.await
	{
		Err(e) => e,
		Ok(_) => panic!("expected error for wrong credentials, got Ok"),
	};
	assert!(
		err.to_string().contains("rejected credentials"),
		"error = {err}, want 'rejected credentials'"
	);
}

/// Verifies that when TLS is enabled but the upstream is actually a
/// plaintext SOCKS5 proxy, `dial` fails with an error containing "TLS
/// handshake" (the TLS client hello gets a non-TLS response).
#[tokio::test]
async fn backend_tls_handshake_failure() {
	// Plaintext miniSOCKS5, but backend is configured for TLS; handshake fails.
	let echo_addr = echo_server().await;
	let proxy_addr = mini_socks5("", "").await;
	let _ = echo_addr;

	let backend = SocksProxyBackend::new(BackendConfiguration {
		proxy_address: proxy_addr,
		tls: true,
		tls_config: Some(insecure_client_config()),
		..Default::default()
	})
	.expect("NewBackend");

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

/// Verifies `new` builds the TLS client config from a `tls_ca_file` path
/// (rather than an injected `tls_config`) and the resulting backend
/// successfully tunnels through a TLS-wrapped SOCKS5 proxy whose
/// self-signed cert is in that CA file.
#[tokio::test]
async fn backend_tls_built_from_ca_file() {
	let echo_addr = echo_server().await;
	let (cert_pem, key_pem) = test_tls_certificate();
	let proxy_addr = mini_tls_socks5(&cert_pem, &key_pem, "", "").await;

	// Write the trust pool to a CA file so NewBackend builds the tls.Config
	// itself rather than receiving an injected TLSConfig.
	let dir = std::env::temp_dir();
	let ca_file = dir.join(format!("socksproxy-be-ca-{}.pem", std::process::id()));
	std::fs::write(&ca_file, cert_pem.as_bytes()).expect("write CA file");

	let backend = SocksProxyBackend::new(BackendConfiguration {
		proxy_address: proxy_addr,
		tls: true,
		tls_ca_file: ca_file.to_string_lossy().to_string(),
		tls_server_name: "localhost".to_string(),
		..Default::default()
	})
	.expect("NewBackend");

	let mut conn = backend
		.dial(parse_target(&echo_addr), &system_dialer())
		.await
		.expect("Dial");
	assert_echo(&mut conn, b"ca-file-chain").await;

	let _ = std::fs::remove_file(&ca_file);
}

/// Verifies that with TLS enabled, no CA file, and
/// `tls_insecure_skip_verify` unset, the handshake fails because the
/// upstream's self-signed test certificate is not in the system root
/// store. `dial` must surface an error containing "TLS handshake".
#[tokio::test]
async fn backend_tls_ca_validation_failure() {
	let echo_addr = echo_server().await;
	let (cert_pem, key_pem) = test_tls_certificate();
	let proxy_addr = mini_tls_socks5(&cert_pem, &key_pem, "", "").await;
	let _ = echo_addr;

	// TLS enabled with no CA file and not skipping verification: the
	// self-signed test certificate is not in the system roots, so the
	// handshake must fail.
	let backend = SocksProxyBackend::new(BackendConfiguration {
		proxy_address: proxy_addr,
		tls: true,
		tls_server_name: "localhost".to_string(),
		..Default::default()
	})
	.expect("NewBackend");

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

/// Table-driven test for `encode_socks5_request`: each case constructs a
/// `Target` and checks either that the encoded request begins with the
/// expected SOCKS5 header (`VER CMD RSV`) and uses the expected ATYP, or
/// that encoding fails with an error containing the expected substring.
/// Covers IPv4, IPv6, domain, empty host, and zero port.
#[test]
fn encode_socks5_request_table() {
	let cases: &[(&str, Target, Option<&str>, u8)] = &[
		(
			"ipv4",
			Target {
				network: "tcp".to_string(),
				protocol: Protocol::Unknown,
				host: "127.0.0.1".to_string(),
				port: 80,
			},
			None,
			socks5::ATYP_IPV4,
		),
		(
			"ipv6",
			Target {
				network: "tcp".to_string(),
				protocol: Protocol::Unknown,
				host: "::1".to_string(),
				port: 443,
			},
			None,
			socks5::ATYP_IPV6,
		),
		(
			"domain",
			Target {
				network: "tcp".to_string(),
				protocol: Protocol::Unknown,
				host: "example.com".to_string(),
				port: 8080,
			},
			None,
			socks5::ATYP_DOMAIN,
		),
		(
			"empty host",
			Target {
				network: "tcp".to_string(),
				protocol: Protocol::Unknown,
				host: "".to_string(),
				port: 80,
			},
			Some("target host is required"),
			0,
		),
		(
			"zero port",
			Target {
				network: "tcp".to_string(),
				protocol: Protocol::Unknown,
				host: "example.com".to_string(),
				port: 0,
			},
			Some("target port is required"),
			0,
		),
	];
	for (name, target, want_err, want_atyp) in cases {
		let result = encode_socks5_request(target);
		match want_err {
			None => {
				let req = result.expect("unexpected error");
				assert!(
					req[0] == socks5::VERSION && req[1] == socks5::CMD_CONNECT && req[2] == 0x00,
					"{name}: header = {:x?}, want [05 01 00]",
					&req[..3]
				);
				assert_eq!(req[3], *want_atyp, "{name}: atyp mismatch");
			}
			Some(sub) => {
				let err = match result {
					Err(e) => e,
					Ok(_) => panic!("{name}: expected error containing {sub:?}, got Ok"),
				};
				assert!(
					err.contains(sub),
					"{name}: error = {err}, want substring {sub:?}"
				);
			}
		}
	}
}

/// Verifies the shared `puppy_core::socks5::reply_text` helper (which the
/// backend relies on for SOCKS5 reply-code descriptions) produces the
/// expected strings for success, connection refused, and an unknown code.
#[test]
fn socks5_reply_text_delegates_to_common() {
	// The backend reports reply text via `puppy_core::socks5::reply_text`.
	// Verify the shared helper produces the strings the backend relies on.
	assert_eq!(socks5::reply_text(socks5::REP_SUCCESS), "succeeded");
	assert_eq!(
		socks5::reply_text(socks5::REP_CONNECTION_REFUSED),
		"connection refused"
	);
	assert!(
		socks5::reply_text(0xFF).contains("unknown error"),
		"rep 0xFF should be unknown error"
	);
}
