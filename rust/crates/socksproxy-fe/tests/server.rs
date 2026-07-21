//! SOCKS5 proxy server tests.
//!
//! Tests cover:
//! - `TestNewServer_TLSConfiguration`, `TestNewServer_PreservesShimBufferSize`:
//!   `Server::new` behavior.
//! - `TestServer_OpenProxyTunnel`, `TestServer_TLSProxyTunnels`,
//!   `TestServer_TLSRejectsPlaintext`, `TestServer_AuthedProxyTunnel`,
//!   `TestServer_AuthedProxyRejectsWrongCreds`: end-to-end server behavior via
//!   real TCP connections.
//! - `TestServer_DialFailure_RepGeneralFailure`,
//!   `TestServer_DialFailure_RepConnectionRefused`: dial error → REP mapping.
//! - `TestServer_ContextCancel`: graceful shutdown.
//!
//! The `TestServerConfiguration_Validate` cases are covered in
//! `tests/config.rs` to keep this file focused on server behavior.

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use puppy_core::backend::{
	Backend, BackendError, BoxedStream, Capability, Dialer, Protocol, Target,
};
use puppy_core::socks5::{
	read_socks5_address, ATYP_DOMAIN, ATYP_IPV4, AUTH_VERSION, CMD_CONNECT, METHOD_NO_AUTH,
	METHOD_USERNAME_PASSWORD, REP_CONNECTION_REFUSED, REP_GENERAL_FAILURE, REP_SUCCESS, VERSION,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;

use direct::DirectBackend;
use socksproxy_fe::{Server, ServerConfiguration};

// ---------------------------------------------------------------------------
// Test backends (errorBackend, udpOnlyBackend, dialerBackend).
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

/// Backend that uses an injected dialer to connect directly to the target,
/// exercising the frontend's REP mapping on dial errors.
struct DialerBackend {
	dialer: Arc<dyn Dialer>,
}

#[async_trait]
impl Backend for DialerBackend {
	fn capabilities(&self) -> Vec<Capability> {
		vec![Capability {
			network: "tcp".to_string(),
			protocol: Protocol::Any,
		}]
	}

	async fn dial(
		&self,
		target: Target,
		_dialer: &dyn Dialer,
	) -> Result<BoxedStream, BackendError> {
		self.dialer
			.dial_context(target.net(), &target.address())
			.await
			.map_err(BackendError::Io)
	}
}

/// Dialer whose `dial_context` always returns `ErrorKind::ConnectionRefused`.
struct RefusedDialer;

#[async_trait]
impl Dialer for RefusedDialer {
	async fn dial_context(
		&self,
		_network: &str,
		_address: &str,
	) -> Result<BoxedStream, std::io::Error> {
		Err(std::io::Error::from(std::io::ErrorKind::ConnectionRefused))
	}
}

// ---------------------------------------------------------------------------
// Test helpers (testCertificateFiles, dialTLSSocksProxy, startServer,
// echoUpstream, socksConnect, socksHandshake).
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
		"puppy-socksproxy-fe-test-{}-{}",
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

/// Builds a rustls client config that trusts only the test root CA.
fn client_tls_config_with_root(root_ca_der: Vec<u8>) -> Arc<rustls::ClientConfig> {
	let mut roots = rustls::RootCertStore::empty();
	roots
		.add(rustls::pki_types::CertificateDer::from(root_ca_der))
		.expect("add root");
	let config = rustls::ClientConfig::builder()
		.with_root_certificates(roots)
		.with_no_client_auth();
	Arc::new(config)
}

/// Dials the SOCKS5-over-TLS proxy at `addr` with a 2-second timeout and
/// returns the TLS connection.
async fn dial_tls_socks_proxy(
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

/// Performs a full SOCKS5 CONNECT handshake through the proxy at `proxy_addr`
/// (no auth) and returns the tunneled connection.
async fn socks_connect(
	proxy_addr: &str,
	target_host: &str,
	target_port: u16,
) -> tokio::net::TcpStream {
	let mut conn = tokio::net::TcpStream::connect(proxy_addr)
		.await
		.expect("dial proxy");
	socks_handshake(&mut conn, "", "", target_host, target_port)
		.await
		.expect("socks handshake");
	conn
}

/// Performs the SOCKS5 method negotiation, optional auth, and CONNECT request
/// on `conn`. Returns an error if any step fails or the reply is not success.
async fn socks_handshake<C>(
	conn: &mut C,
	username: &str,
	password: &str,
	target_host: &str,
	target_port: u16,
) -> Result<(), String>
where
	C: AsyncRead + AsyncWrite + Unpin,
{
	// Method negotiation.
	let methods = if username.is_empty() {
		vec![METHOD_NO_AUTH]
	} else {
		vec![METHOD_USERNAME_PASSWORD]
	};
	let mut req = vec![VERSION, methods.len() as u8];
	req.extend_from_slice(&methods);
	conn.write_all(&req).await.map_err(|e| e.to_string())?;
	let mut sel = [0u8; 2];
	conn.read_exact(&mut sel).await.map_err(|e| e.to_string())?;
	if sel[1] == 0xFF {
		return Err("no acceptable method".to_string());
	}
	if sel[1] == METHOD_USERNAME_PASSWORD {
		let mut creds = vec![AUTH_VERSION, username.len() as u8];
		creds.extend_from_slice(username.as_bytes());
		creds.push(password.len() as u8);
		creds.extend_from_slice(password.as_bytes());
		conn.write_all(&creds).await.map_err(|e| e.to_string())?;
		let mut auth_resp = [0u8; 2];
		conn.read_exact(&mut auth_resp)
			.await
			.map_err(|e| e.to_string())?;
		if auth_resp[1] != 0x00 {
			return Err("auth rejected".to_string());
		}
	}

	// CONNECT request.
	let mut req = vec![VERSION, CMD_CONNECT, 0x00];
	if let Ok(ip) = target_host.parse::<std::net::IpAddr>() {
		match ip {
			std::net::IpAddr::V4(v4) => {
				req.push(ATYP_IPV4);
				req.extend_from_slice(&v4.octets());
			}
			std::net::IpAddr::V6(v6) => {
				req.push(puppy_core::socks5::ATYP_IPV6);
				req.extend_from_slice(&v6.octets());
			}
		}
	} else {
		req.push(ATYP_DOMAIN);
		req.push(target_host.len() as u8);
		req.extend_from_slice(target_host.as_bytes());
	}
	req.extend_from_slice(&target_port.to_be_bytes());
	conn.write_all(&req).await.map_err(|e| e.to_string())?;

	let mut header = [0u8; 4];
	conn.read_exact(&mut header)
		.await
		.map_err(|e| e.to_string())?;
	if header[1] != REP_SUCCESS {
		return Err(format!("connect reply REP=0x{:02x}", header[1]));
	}
	let _ = read_socks5_address(conn, header[3])
		.await
		.map_err(|e| e.to_string())?;
	Ok(())
}

// ---------------------------------------------------------------------------
// TestNewServer_TLSConfiguration
// ---------------------------------------------------------------------------

#[test]
fn new_server_tls_configuration() {
	let (cert_file, key_file, _roots) = test_certificate_files();
	let cfg = ServerConfiguration {
		listen_address: "127.0.0.1".to_string(),
		listen_port: 1080,
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
		listen_port: 1080,
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
}

#[tokio::test]
async fn new_server_tls_configuration_no_alpn_negotiated() {
	// Verify the SOCKS5-over-TLS server does not advertise any ALPN protocol.
	let (cert_file, key_file, roots) = test_certificate_files();
	let cfg = ServerConfiguration {
		tls_cert_file: cert_file,
		tls_key_file: key_file,
		..base_runtime_config()
	};
	let (proxy_addr, _tx, _handle) = start_server(cfg).await;

	let conn = dial_tls_socks_proxy(&proxy_addr, roots).await;
	let (_io, conn_state) = conn.get_ref();
	assert!(
		conn_state.alpn_protocol().is_none(),
		"SOCKS5-over-TLS should not negotiate ALPN, got {:?}",
		conn_state.alpn_protocol()
	);
}

// ---------------------------------------------------------------------------
// TestNewServer_PreservesShimBufferSize
// ---------------------------------------------------------------------------

#[test]
fn new_server_preserves_shim_buffer_size() {
	let cfg = ServerConfiguration {
		listen_address: "127.0.0.1".to_string(),
		listen_port: 1080,
		backend: Arc::new(DirectBackend::new()),
		shim_buffer_size: 64 * 1024,
		..base_runtime_config()
	};
	let s = Server::new(cfg).expect("NewServer");
	assert_eq!(s.config().shim_buffer_size, 64 * 1024);
}

// ---------------------------------------------------------------------------
// TestServer_OpenProxyTunnel
// ---------------------------------------------------------------------------

#[tokio::test]
async fn server_open_proxy_tunnel() {
	let upstream_addr = echo_upstream().await;
	let (proxy_addr, _tx, _handle) = start_server(base_runtime_config()).await;

	let (host, port_str) = upstream_addr.rsplit_once(':').expect("addr has :port");
	let port: u16 = port_str.parse().expect("port parses");
	let mut conn = socks_connect(&proxy_addr, host, port).await;

	let msg = b"hello-tunnel";
	conn.write_all(msg).await.expect("write");
	let mut got = vec![0u8; msg.len()];
	conn.read_exact(&mut got).await.expect("read");
	assert_eq!(&got, msg);
}

// ---------------------------------------------------------------------------
// TestServer_AuthedProxyTunnel
// ---------------------------------------------------------------------------

#[tokio::test]
async fn server_authed_proxy_tunnel() {
	let upstream_addr = echo_upstream().await;
	let cfg = ServerConfiguration {
		username: "alice".to_string(),
		password: "secret".to_string(),
		..base_runtime_config()
	};
	let (proxy_addr, _tx, _handle) = start_server(cfg).await;

	let (host, port_str) = upstream_addr.rsplit_once(':').expect("addr has :port");
	let port: u16 = port_str.parse().expect("port parses");

	let mut conn = tokio::net::TcpStream::connect(&proxy_addr)
		.await
		.expect("dial proxy");
	socks_handshake(&mut conn, "alice", "secret", host, port)
		.await
		.expect("socks handshake");

	let msg = b"authed-tunnel";
	conn.write_all(msg).await.expect("write");
	let mut got = vec![0u8; msg.len()];
	conn.read_exact(&mut got).await.expect("read");
	assert_eq!(&got, msg);
}

// ---------------------------------------------------------------------------
// TestServer_AuthedProxyRejectsWrongCreds
// ---------------------------------------------------------------------------

#[tokio::test]
async fn server_authed_proxy_rejects_wrong_creds() {
	let upstream_addr = echo_upstream().await;
	let cfg = ServerConfiguration {
		username: "alice".to_string(),
		password: "secret".to_string(),
		..base_runtime_config()
	};
	let (proxy_addr, _tx, _handle) = start_server(cfg).await;

	let (host, port_str) = upstream_addr.rsplit_once(':').expect("addr has :port");
	let port: u16 = port_str.parse().expect("port parses");

	let mut conn = tokio::net::TcpStream::connect(&proxy_addr)
		.await
		.expect("dial proxy");
	let err = socks_handshake(&mut conn, "alice", "wrong", host, port)
		.await
		.expect_err("expected auth rejected");
	assert!(
		err.contains("auth rejected"),
		"error = {err}, want 'auth rejected'"
	);
}

// ---------------------------------------------------------------------------
// TestServer_TLSProxyTunnels
// ---------------------------------------------------------------------------

#[tokio::test]
async fn server_tls_proxy_tunnels() {
	let upstream_addr = echo_upstream().await;
	let (cert_file, key_file, roots) = test_certificate_files();
	let cfg = ServerConfiguration {
		tls_cert_file: cert_file,
		tls_key_file: key_file,
		..base_runtime_config()
	};
	let (proxy_addr, _tx, _handle) = start_server(cfg).await;

	let mut conn = dial_tls_socks_proxy(&proxy_addr, roots).await;
	let (host, port_str) = upstream_addr.rsplit_once(':').expect("addr has :port");
	let port: u16 = port_str.parse().expect("port parses");
	socks_handshake(&mut conn, "", "", host, port)
		.await
		.expect("socks handshake");

	let msg = b"hello-over-tls-socks";
	conn.write_all(msg).await.expect("write tunnel data");
	let mut got = vec![0u8; msg.len()];
	conn.read_exact(&mut got).await.expect("read tunnel data");
	assert_eq!(&got, msg);
}

// ---------------------------------------------------------------------------
// TestServer_TLSRejectsPlaintext
// ---------------------------------------------------------------------------

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
	// Send a SOCKS5 method negotiation in plaintext; the TLS listener must not
	// produce a valid SOCKS5 reply.
	conn.write_all(&[VERSION, 1, METHOD_NO_AUTH])
		.await
		.expect("write plaintext");
	let mut resp = vec![0u8; 16];
	let n = tokio::time::timeout(Duration::from_secs(2), conn.read(&mut resp))
		.await
		.expect("read timeout")
		.expect("read");
	// A valid SOCKS5 reply starts with 0x05; a TLS server returns a TLS
	// handshake.
	assert!(
		!(n >= 1 && resp[0] == VERSION),
		"TLS proxy returned a plaintext SOCKS5 reply: {:?}",
		&resp[..n]
	);
}

// ---------------------------------------------------------------------------
// TestServer_DialFailure_RepGeneralFailure
// ---------------------------------------------------------------------------

#[tokio::test]
async fn server_dial_failure_rep_general_failure() {
	let mut cfg = base_runtime_config();
	cfg.backend = Arc::new(ErrorBackend {
		err: "upstream unreachable",
	});
	let (proxy_addr, _tx, _handle) = start_server(cfg).await;

	let mut conn = tokio::net::TcpStream::connect(&proxy_addr)
		.await
		.expect("dial proxy");
	conn.write_all(&[VERSION, 1, METHOD_NO_AUTH])
		.await
		.expect("write method negotiation");
	let mut sel = [0u8; 2];
	conn.read_exact(&mut sel)
		.await
		.expect("read method selection");
	conn.write_all(&[
		VERSION,
		CMD_CONNECT,
		0x00,
		ATYP_DOMAIN,
		11,
		b'e',
		b'x',
		b'a',
		b'm',
		b'p',
		b'l',
		b'e',
		b'.',
		b'c',
		b'o',
		b'm',
		0x01,
		0xBB,
	])
	.await
	.expect("write CONNECT");
	let mut header = [0u8; 4];
	conn.read_exact(&mut header).await.expect("read reply");
	assert_eq!(
		header[1], REP_GENERAL_FAILURE,
		"REP = 0x{:02x}, want 0x01 (general failure)",
		header[1]
	);
}

// ---------------------------------------------------------------------------
// TestServer_DialFailure_RepConnectionRefused
// ---------------------------------------------------------------------------

#[tokio::test]
async fn server_dial_failure_rep_connection_refused() {
	// Grab a free port from the OS, then close the listener so the backend
	// dial hits a refused connection (the port has no listener).
	let ln = TcpListener::bind("127.0.0.1:0").await.expect("listen");
	let addr = ln.local_addr().unwrap();
	let host = addr.ip().to_string();
	let port = addr.port();
	drop(ln);

	let refused_backend = DialerBackend {
		dialer: Arc::new(RefusedDialer),
	};
	let cfg = ServerConfiguration {
		listen_address: host.clone(),
		listen_port: port,
		backend: Arc::new(refused_backend),
		..base_runtime_config()
	};
	let server = Server::new(cfg).expect("NewServer");
	let (tx, rx) = tokio::sync::oneshot::channel::<()>();
	let handle = tokio::spawn(async move {
		server
			.run(async move {
				let _ = rx.await;
			})
			.await
	});

	let bound = format!("{host}:{port}");
	let deadline = Instant::now() + Duration::from_secs(2);
	while Instant::now() < deadline {
		if tokio::net::TcpStream::connect(&bound).await.is_ok() {
			break;
		}
		tokio::time::sleep(Duration::from_millis(50)).await;
	}

	let mut conn = tokio::net::TcpStream::connect(&bound)
		.await
		.expect("dial proxy");
	conn.write_all(&[VERSION, 1, METHOD_NO_AUTH])
		.await
		.expect("write method negotiation");
	let mut sel = [0u8; 2];
	conn.read_exact(&mut sel)
		.await
		.expect("read method selection");
	conn.write_all(&[
		VERSION,
		CMD_CONNECT,
		0x00,
		ATYP_IPV4,
		127,
		0,
		0,
		1,
		0x1F,
		0x90,
	])
	.await
	.expect("write CONNECT");
	let mut header = [0u8; 4];
	conn.read_exact(&mut header).await.expect("read reply");
	assert_eq!(
		header[1], REP_CONNECTION_REFUSED,
		"REP = 0x{:02x}, want 0x05 (connection refused)",
		header[1]
	);

	let _ = tx.send(());
	let _ = handle.await;
}

// ---------------------------------------------------------------------------
// TestServer_ContextCancel
// ---------------------------------------------------------------------------

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
