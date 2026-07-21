//! SOCKS5 handshake tests.
//!
//! Each test spins up a localhost TCP listener, accepts one connection on the
//! server side, and drives `handshake::handshake` against it while the test
//! body writes/reads from the client side. TCP (rather than an in-memory
//! pipe) is used so synchronous write semantics would not deadlock the
//! handshake's reply writes.

use std::sync::Arc;
use std::time::Duration;

use puppy_core::backend::{BackendError, BoxedStream, Target};
use puppy_core::socks5::{
	read_socks5_address, ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6, AUTH_VERSION, CMD_CONNECT,
	METHOD_NO_ACCEPTABLE, METHOD_NO_AUTH, METHOD_USERNAME_PASSWORD, REP_ADDR_TYPE_NOT_SUPPORTED,
	REP_CMD_NOT_SUPPORTED, REP_CONNECTION_REFUSED, REP_GENERAL_FAILURE, REP_HOST_UNREACHABLE,
	REP_NETWORK_UNREACHABLE, REP_TTL_EXPIRED, VERSION,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use direct::DirectBackend;
use socksproxy_fe::handshake::{handshake, rep_for_dial_error};
use socksproxy_fe::ServerConfiguration;

// ---------------------------------------------------------------------------
// Helpers (newPipeConns, dialHandshake).
// ---------------------------------------------------------------------------

/// Returns a connected pair of TCP streams on localhost. The server stream is
/// wrapped in a `BoxedStream` for the handshake; the client stream is returned
/// raw so the test can write requests and read responses.
async fn new_pipe_conns() -> (TcpStream, BoxedStream) {
	let ln = TcpListener::bind("127.0.0.1:0").await.expect("listen");
	let addr = ln.local_addr().unwrap();
	let accept_task = tokio::spawn(async move {
		let (c, _) = ln.accept().await.expect("accept");
		c
	});
	let client = TcpStream::connect(addr).await.expect("dial");
	let server = accept_task.await.expect("accept task");
	(client, Box::new(server))
}

/// Runs `handshake` on `server` in a spawned task and returns a future
/// resolving to the `(target, frontend, err)` triple.
fn dial_handshake(
	server: BoxedStream,
	config: ServerConfiguration,
) -> tokio::task::JoinHandle<Result<(Target, BoxedStream), Box<dyn std::error::Error + Send + Sync>>>
{
	tokio::spawn(async move { handshake(server, &config).await })
}

/// Returns a baseline `ServerConfiguration` for the handshake tests.
fn base_config() -> ServerConfiguration {
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
		stats: None,
		conn_reg: None,
		bus: None,
	}
}

/// Writes VER+NMETHODS+METHODS to `conn`.
async fn send_method_negotiation(conn: &mut TcpStream, methods: &[u8]) {
	let mut req = vec![VERSION, methods.len() as u8];
	req.extend_from_slice(methods);
	conn.write_all(&req)
		.await
		.expect("write method negotiation");
}

/// Reads the 2-byte method selection reply.
async fn read_method_selection(conn: &mut TcpStream) -> u8 {
	let mut resp = [0u8; 2];
	conn.read_exact(&mut resp)
		.await
		.expect("read method selection");
	assert_eq!(
		resp[0], VERSION,
		"method selection version = 0x{:02x}",
		resp[0]
	);
	resp[1]
}

/// Writes a SOCKS5 CONNECT request for `host:port`.
async fn send_connect_request(conn: &mut TcpStream, host: &str, port: u16) {
	let mut req = vec![VERSION, CMD_CONNECT, 0x00];
	if let Ok(ip) = host.parse::<std::net::IpAddr>() {
		match ip {
			std::net::IpAddr::V4(v4) => {
				req.push(ATYP_IPV4);
				req.extend_from_slice(&v4.octets());
			}
			std::net::IpAddr::V6(v6) => {
				req.push(ATYP_IPV6);
				req.extend_from_slice(&v6.octets());
			}
		}
	} else {
		req.push(ATYP_DOMAIN);
		req.push(host.len() as u8);
		req.extend_from_slice(host.as_bytes());
	}
	req.extend_from_slice(&port.to_be_bytes());
	conn.write_all(&req).await.expect("write CONNECT request");
}

/// Reads a SOCKS5 reply and returns (REP, ATYP).
async fn read_reply(conn: &mut TcpStream) -> (u8, u8) {
	let mut header = [0u8; 4];
	conn.read_exact(&mut header)
		.await
		.expect("read reply header");
	assert_eq!(header[0], VERSION, "reply version = 0x{:02x}", header[0]);
	// Consume BND.ADDR + BND.PORT so the connection is left in a clean state.
	let _ = read_socks5_address(conn, header[3])
		.await
		.expect("read reply bind address");
	(header[1], header[3])
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn handshake_connect_success() {
	let cfg = base_config();
	let (mut client, server) = new_pipe_conns().await;
	let wait = dial_handshake(server, cfg);

	send_method_negotiation(&mut client, &[METHOD_NO_AUTH]).await;
	assert_eq!(
		read_method_selection(&mut client).await,
		METHOD_NO_AUTH,
		"selected method"
	);
	send_connect_request(&mut client, "example.com", 443).await;

	let result = wait.await.expect("handshake task");
	let (target, _frontend) = result.expect("handshake err");
	assert_eq!(target.host, "example.com");
	assert_eq!(target.port, 443);
}

#[tokio::test]
async fn handshake_connect_ipv4() {
	let cfg = base_config();
	let (mut client, server) = new_pipe_conns().await;
	let wait = dial_handshake(server, cfg);

	send_method_negotiation(&mut client, &[METHOD_NO_AUTH]).await;
	read_method_selection(&mut client).await;
	send_connect_request(&mut client, "127.0.0.1", 8080).await;

	let result = wait.await.expect("handshake task");
	let (target, _frontend) = result.expect("handshake err");
	assert_eq!(target.host, "127.0.0.1");
	assert_eq!(target.port, 8080);
}

#[tokio::test]
async fn handshake_connect_ipv6() {
	let cfg = base_config();
	let (mut client, server) = new_pipe_conns().await;
	let wait = dial_handshake(server, cfg);

	send_method_negotiation(&mut client, &[METHOD_NO_AUTH]).await;
	read_method_selection(&mut client).await;
	send_connect_request(&mut client, "::1", 443).await;

	let result = wait.await.expect("handshake task");
	let (target, _frontend) = result.expect("handshake err");
	assert_eq!(target.host, "::1");
	assert_eq!(target.port, 443);
}

#[tokio::test]
async fn handshake_auth_required_but_no_acceptable() {
	let mut cfg = base_config();
	cfg.username = "alice".to_string();
	cfg.password = "secret".to_string();
	let (mut client, server) = new_pipe_conns().await;
	let wait = dial_handshake(server, cfg);

	// Client offers only no-auth, but server requires username/password.
	send_method_negotiation(&mut client, &[METHOD_NO_AUTH]).await;
	assert_eq!(
		read_method_selection(&mut client).await,
		METHOD_NO_ACCEPTABLE,
		"selected method"
	);

	let result = wait.await.expect("handshake task");
	assert!(result.is_err(), "expected error, got Ok");
}

#[tokio::test]
async fn handshake_auth_success() {
	let mut cfg = base_config();
	cfg.username = "alice".to_string();
	cfg.password = "secret".to_string();
	let (mut client, server) = new_pipe_conns().await;
	let wait = dial_handshake(server, cfg);

	send_method_negotiation(&mut client, &[METHOD_USERNAME_PASSWORD]).await;
	assert_eq!(
		read_method_selection(&mut client).await,
		METHOD_USERNAME_PASSWORD,
		"selected method"
	);

	// Send RFC 1929 credentials.
	let creds = [
		AUTH_VERSION,
		5,
		b'a',
		b'l',
		b'i',
		b'c',
		b'e',
		6,
		b's',
		b'e',
		b'c',
		b'r',
		b'e',
		b't',
	];
	client.write_all(&creds).await.expect("write credentials");
	let mut auth_resp = [0u8; 2];
	client
		.read_exact(&mut auth_resp)
		.await
		.expect("read auth response");
	assert_eq!(auth_resp[0], AUTH_VERSION, "auth version");
	assert_eq!(auth_resp[1], 0x00, "auth status");

	send_connect_request(&mut client, "example.com", 443).await;

	let result = wait.await.expect("handshake task");
	let (target, _frontend) = result.expect("handshake err");
	assert_eq!(target.host, "example.com");
	assert_eq!(target.port, 443);
}

#[tokio::test]
async fn handshake_auth_wrong_credentials() {
	let mut cfg = base_config();
	cfg.username = "alice".to_string();
	cfg.password = "secret".to_string();
	let (mut client, server) = new_pipe_conns().await;
	let wait = dial_handshake(server, cfg);

	send_method_negotiation(&mut client, &[METHOD_USERNAME_PASSWORD]).await;
	read_method_selection(&mut client).await;

	let creds = [
		AUTH_VERSION,
		5,
		b'a',
		b'l',
		b'i',
		b'c',
		b'e',
		5,
		b'w',
		b'r',
		b'o',
		b'n',
		b'g',
	];
	client.write_all(&creds).await.expect("write credentials");
	let mut auth_resp = [0u8; 2];
	client
		.read_exact(&mut auth_resp)
		.await
		.expect("read auth response");
	assert_eq!(auth_resp[1], 0x01, "auth status = 0x{:02x}", auth_resp[1]);

	let result = wait.await.expect("handshake task");
	assert!(result.is_err(), "expected error, got Ok");
}

#[tokio::test]
async fn handshake_unsupported_command() {
	let cfg = base_config();
	let (mut client, server) = new_pipe_conns().await;
	let wait = dial_handshake(server, cfg);

	send_method_negotiation(&mut client, &[METHOD_NO_AUTH]).await;
	read_method_selection(&mut client).await;

	// BIND command (0x02) is unsupported.
	let req = [VERSION, 0x02, 0x00, ATYP_IPV4, 127, 0, 0, 1, 0x1F, 0x90];
	client.write_all(&req).await.expect("write BIND request");

	let result = wait.await.expect("handshake task");
	assert!(result.is_err(), "expected error, got Ok");
	let (rep, _) = read_reply(&mut client).await;
	assert_eq!(rep, REP_CMD_NOT_SUPPORTED, "REP = 0x{rep:02x}");
}

#[tokio::test]
async fn handshake_unknown_address_type() {
	let cfg = base_config();
	let (mut client, server) = new_pipe_conns().await;
	let wait = dial_handshake(server, cfg);

	send_method_negotiation(&mut client, &[METHOD_NO_AUTH]).await;
	read_method_selection(&mut client).await;

	// ATYP=0x09 is unknown.
	let req = [VERSION, CMD_CONNECT, 0x00, 0x09, 0, 0, 0, 0, 0, 0];
	client.write_all(&req).await.expect("write request");

	let result = wait.await.expect("handshake task");
	assert!(result.is_err(), "expected error, got Ok");
	let (rep, _) = read_reply(&mut client).await;
	assert_eq!(rep, REP_ADDR_TYPE_NOT_SUPPORTED, "REP = 0x{rep:02x}");
}

#[tokio::test]
async fn handshake_bad_version() {
	let cfg = base_config();
	let (mut client, server) = new_pipe_conns().await;
	let wait = dial_handshake(server, cfg);

	// SOCKS4 version byte 0x04.
	client.write_all(&[0x04, 0x01, 0x00]).await.expect("write");
	let result = wait.await.expect("handshake task");
	let err = match result {
		Err(e) => e,
		Ok(_) => panic!("expected error, got Ok"),
	};
	assert!(
		err.to_string().contains("unexpected SOCKS version"),
		"error = {err}"
	);
}

#[tokio::test]
async fn handshake_malformed_method_negotiation() {
	let cfg = base_config();
	let (mut client, server) = new_pipe_conns().await;
	let wait = dial_handshake(server, cfg);

	// Only the version byte, then EOF.
	client
		.write_all(&[VERSION])
		.await
		.expect("write version byte");
	drop(client);

	let result = wait.await.expect("handshake task");
	assert!(result.is_err(), "expected error, got Ok");
}

/// Verifies bytes the client sends immediately after the CONNECT request (before
/// the success reply) are preserved in the returned frontend stream.
#[tokio::test]
async fn handshake_buffered_bytes_preserved() {
	let cfg = base_config();
	let (mut client, server) = new_pipe_conns().await;
	let wait = dial_handshake(server, cfg);

	send_method_negotiation(&mut client, &[METHOD_NO_AUTH]).await;
	read_method_selection(&mut client).await;

	// CONNECT request plus early tunnel bytes in a single write.
	let mut req = vec![VERSION, CMD_CONNECT, 0x00, ATYP_DOMAIN, 11];
	req.extend_from_slice(b"example.com");
	req.extend_from_slice(&[0x01, 0xBB]); // port 443
	req.extend_from_slice(b"early-tunnel-data");
	client.write_all(&req).await.expect("write");

	let (_, mut frontend) = wait.await.expect("handshake task").expect("handshake err");

	let want = b"early-tunnel-data";
	let mut got = vec![0u8; want.len()];
	tokio::time::timeout(Duration::from_secs(2), frontend.read_exact(&mut got))
		.await
		.expect("read timeout")
		.expect("ReadFull");
	assert_eq!(&got, want);
}

// ---------------------------------------------------------------------------
// TestRepForDialError
// ---------------------------------------------------------------------------

#[test]
fn rep_for_dial_error_table() {
	use std::io::{Error, ErrorKind};
	let cases: &[(
		/* name */ &str,
		/* error */ BackendError,
		/* want */ u8,
	)] = &[
		(
			"connection refused",
			BackendError::Io(Error::from(ErrorKind::ConnectionRefused)),
			REP_CONNECTION_REFUSED,
		),
		(
			"host unreachable",
			BackendError::Io(Error::from(ErrorKind::HostUnreachable)),
			REP_HOST_UNREACHABLE,
		),
		(
			"network unreachable",
			BackendError::Io(Error::from(ErrorKind::NetworkUnreachable)),
			REP_NETWORK_UNREACHABLE,
		),
		(
			"deadline exceeded",
			BackendError::Io(Error::from(ErrorKind::TimedOut)),
			REP_TTL_EXPIRED,
		),
		(
			"generic",
			BackendError::Other("something else".to_string()),
			REP_GENERAL_FAILURE,
		),
	];
	for (name, err, want) in cases {
		let got = rep_for_dial_error(err);
		assert_eq!(
			got, *want,
			"{name}: rep_for_dial_error = 0x{got:02x}, want 0x{want:02x}"
		);
	}
}
