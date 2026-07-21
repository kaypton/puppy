//! HTTP CONNECT handshake tests.
//!
//! Each test spins up a localhost TCP listener, accepts one connection on the
//! server side, and drives `handshake::handshake` against it while the test
//! body writes/reads from the client side. TCP (rather than an in-memory
//! pipe) is used so synchronous write semantics do not deadlock the
//! handshake's error-response writes.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use puppy_core::backend::{BoxedStream, Target};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use direct::DirectBackend;
use httpproxy_fe::{handshake::handshake, ServerConfiguration};

// ---------------------------------------------------------------------------
// Helpers (newPipeConns, dialHandshake, readResponse).
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

/// Returns a baseline `ServerConfiguration` for handshake tests.
fn base_config() -> ServerConfiguration {
	ServerConfiguration {
		listen_address: "127.0.0.1".to_string(),
		listen_port: 1,
		tls_cert_file: String::new(),
		tls_key_file: String::new(),
		username: String::new(),
		password: String::new(),
		camouflage: false,
		camouflage_method: httpproxy_fe::CamouflageMethod::Return404,
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

/// Reads a full HTTP response (status line + headers + blank line + body)
/// from the client stream and returns `(status_line, headers, body)`.
async fn read_response(client: &mut TcpStream) -> (String, Vec<(String, String)>, Vec<u8>) {
	let mut buf = Vec::new();
	let mut tmp = [0u8; 4096];
	// Read until we have headers + Content-Length body.
	let mut header_end: Option<usize> = None;
	while header_end.is_none() {
		let n = client.read(&mut tmp).await.expect("read");
		if n == 0 {
			panic!("EOF before response headers");
		}
		buf.extend_from_slice(&tmp[..n]);
		if let Some(idx) = find_subslice(&buf, b"\r\n\r\n") {
			header_end = Some(idx + 4);
		}
	}
	let header_end = header_end.unwrap();
	let header_str = std::str::from_utf8(&buf[..header_end]).expect("headers utf8");
	let mut lines = header_str.split("\r\n");
	let status_line = lines.next().unwrap().to_string();
	let mut headers: Vec<(String, String)> = Vec::new();
	for line in lines {
		if line.is_empty() {
			break;
		}
		let (name, value) = line.split_once(": ").expect("header");
		headers.push((name.to_string(), value.to_string()));
	}
	// Read remaining body. If Content-Length is set, read until we have that
	// many bytes; otherwise read until EOF (which won't happen because we
	// don't close).
	let content_length: Option<usize> = headers
		.iter()
		.find(|(k, _)| k.eq_ignore_ascii_case("Content-Length"))
		.and_then(|(_, v)| v.parse().ok());
	let body_end = match content_length {
		Some(n) => header_end + n,
		None => buf.len(),
	};
	while buf.len() < body_end {
		let n = client.read(&mut tmp).await.expect("read body");
		if n == 0 {
			break;
		}
		buf.extend_from_slice(&tmp[..n]);
	}
	let body = buf[header_end..body_end].to_vec();
	(status_line, headers, body)
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
// Tests.
// ---------------------------------------------------------------------------

/// Verifies a well-formed `CONNECT host:port` request parses successfully
/// and yields the correct target host and port.
#[tokio::test]
async fn handshake_connect_success() {
	let cfg = base_config();
	let (mut client, server) = new_pipe_conns().await;
	let wait = dial_handshake(server, cfg);

	client
		.write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
		.await
		.expect("write CONNECT");

	let result = wait.await.expect("handshake task");
	let (target, _frontend) = result.expect("handshake err");
	assert_eq!(target.host, "example.com");
	assert_eq!(target.port, 443);
}

/// Verifies a `CONNECT host` request without an explicit port defaults to
/// 443 (the HTTPS default) in the parsed target.
#[tokio::test]
async fn handshake_connect_no_port_defaults_443() {
	let cfg = base_config();
	let (mut client, server) = new_pipe_conns().await;
	let wait = dial_handshake(server, cfg);

	client
		.write_all(b"CONNECT example.com HTTP/1.1\r\nHost: example.com\r\n\r\n")
		.await
		.expect("write CONNECT");

	let result = wait.await.expect("handshake task");
	let (target, _frontend) = result.expect("handshake err");
	assert_eq!(target.host, "example.com");
	assert_eq!(target.port, 443);
}

/// Verifies a non-CONNECT method (e.g. `GET`) is rejected with a `405
/// Method Not Allowed` response and the handshake returns an error.
#[tokio::test]
async fn handshake_non_connect_method() {
	let cfg = base_config();
	let (mut client, server) = new_pipe_conns().await;
	let wait = dial_handshake(server, cfg);

	client
		.write_all(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
		.await
		.expect("write GET");

	let result = wait.await.expect("handshake task");
	assert!(result.is_err(), "expected error");
	let (status, _, _) = read_response(&mut client).await;
	assert!(status.contains("405"), "status = {status:?}");
}

/// Verifies that with camouflage enabled, a non-CONNECT method is answered
/// with a `404 Not Found` page masquerading as nginx (Content-Type
/// `text/html`, `Server: nginx`, body containing the nginx 404 markup) and
/// that no `Proxy-Authenticate` header is leaked.
#[tokio::test]
async fn handshake_camouflage_non_connect_method() {
	let mut cfg = base_config();
	cfg.camouflage = true;
	let (mut client, server) = new_pipe_conns().await;
	let wait = dial_handshake(server, cfg);

	client
		.write_all(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
		.await
		.expect("write GET");

	let result = wait.await.expect("handshake task");
	assert!(result.is_err(), "expected error");
	let (status, headers, body) = read_response(&mut client).await;
	assert!(status.contains("404"), "status = {status:?}");
	assert_eq!(header_get(&headers, "Content-Type"), Some("text/html"));
	assert_eq!(header_get(&headers, "Server"), Some("nginx"));
	let body_str = String::from_utf8_lossy(&body);
	assert!(
		body_str.contains("<h1>404 Not Found</h1>") && body_str.contains("<center>nginx</center>"),
		"body = {body_str:?}"
	);
	assert_eq!(header_get(&headers, "Proxy-Authenticate"), None);
}

/// Verifies a malformed request line (not HTTP) is rejected with a `400
/// Bad Request` response and the handshake returns an error.
#[tokio::test]
async fn handshake_malformed_request() {
	let cfg = base_config();
	let (mut client, server) = new_pipe_conns().await;
	let wait = dial_handshake(server, cfg);

	client
		.write_all(b"this is not http\r\n\r\n")
		.await
		.expect("write garbage");

	let result = wait.await.expect("handshake task");
	assert!(result.is_err(), "expected error");
	let (status, _, _) = read_response(&mut client).await;
	assert!(status.contains("400"), "status = {status:?}");
}

/// Verifies that when auth is configured, a CONNECT request with no
/// `Proxy-Authorization` header is rejected with `407 Proxy Authentication
/// Required` and a `Proxy-Authenticate: Basic` challenge.
#[tokio::test]
async fn handshake_auth_missing() {
	let mut cfg = base_config();
	cfg.username = "alice".to_string();
	cfg.password = "secret".to_string();
	let (mut client, server) = new_pipe_conns().await;
	let wait = dial_handshake(server, cfg);

	client
		.write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
		.await
		.expect("write CONNECT");

	let result = wait.await.expect("handshake task");
	assert!(result.is_err(), "expected error");
	let (status, headers, _) = read_response(&mut client).await;
	assert!(status.contains("407"), "status = {status:?}");
	let auth = header_get(&headers, "Proxy-Authenticate").unwrap_or("");
	assert!(auth.contains("Basic"), "Proxy-Authenticate = {auth:?}");
}

/// Verifies that when auth is configured, a CONNECT request with incorrect
/// credentials is rejected with `407 Proxy Authentication Required`.
#[tokio::test]
async fn handshake_auth_wrong() {
	let mut cfg = base_config();
	cfg.username = "alice".to_string();
	cfg.password = "secret".to_string();
	let (mut client, server) = new_pipe_conns().await;
	let wait = dial_handshake(server, cfg);

	let creds = base64::engine::general_purpose::STANDARD.encode(b"alice:wrong");
	let req = format!(
		"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Basic {creds}\r\n\r\n"
	);
	client
		.write_all(req.as_bytes())
		.await
		.expect("write CONNECT");

	let result = wait.await.expect("handshake task");
	assert!(result.is_err(), "expected error");
	let (status, _, _) = read_response(&mut client).await;
	assert!(status.contains("407"), "status = {status:?}");
}

/// Verifies that with camouflage enabled, auth failures (missing,
/// malformed, and wrong credentials) all collapse to a `405 Method Not
/// Allowed` response with `Allow: GET, HEAD` and no `Proxy-Authenticate`
/// header, so the proxy looks like an ordinary origin server rather than
/// revealing its proxy auth scheme.
#[tokio::test]
async fn handshake_camouflage_auth_failures() {
	struct Case {
		name: &'static str,
		header: &'static str,
	}
	let cases = [
		Case {
			name: "missing",
			header: "",
		},
		Case {
			name: "malformed",
			header: "Proxy-Authorization: Basic not-base64!\r\n",
		},
		Case {
			name: "wrong",
			header: "Proxy-Authorization: Basic ",
		},
	];

	for case in cases {
		let mut cfg = base_config();
		cfg.username = "alice".to_string();
		cfg.password = "secret".to_string();
		cfg.camouflage = true;
		let (mut client, server) = new_pipe_conns().await;
		let wait = dial_handshake(server, cfg);

		let mut req = format!(
			"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n{}",
			case.header
		);
		if case.name == "wrong" {
			let creds = base64::engine::general_purpose::STANDARD.encode(b"alice:wrong");
			req.push_str(&creds);
			req.push_str("\r\n");
		}
		req.push_str("\r\n");
		client
			.write_all(req.as_bytes())
			.await
			.expect("write CONNECT");

		let result = wait.await.expect("handshake task");
		assert!(result.is_err(), "{}: expected error", case.name);
		let (status, headers, _) = read_response(&mut client).await;
		assert!(status.contains("405"), "{}: status = {status:?}", case.name);
		assert_eq!(
			header_get(&headers, "Allow"),
			Some("GET, HEAD"),
			"{}: Allow",
			case.name
		);
		assert_eq!(
			header_get(&headers, "Proxy-Authenticate"),
			None,
			"{}: Proxy-Authenticate",
			case.name
		);
	}
}

/// Verifies that with camouflage enabled, a malformed (non-HTTP) request
/// is still rejected with `400 Bad Request` (camouflage only changes the
/// response shape for non-CONNECT methods, not for unparseable input).
#[tokio::test]
async fn handshake_camouflage_malformed_request() {
	let mut cfg = base_config();
	cfg.camouflage = true;
	let (mut client, server) = new_pipe_conns().await;
	let wait = dial_handshake(server, cfg);

	client
		.write_all(b"this is not http\r\n\r\n")
		.await
		.expect("write garbage");

	let result = wait.await.expect("handshake task");
	assert!(result.is_err(), "expected error");
	let (status, _, _) = read_response(&mut client).await;
	assert!(status.contains("400"), "status = {status:?}");
}

/// Verifies that with camouflage and auth configured, a CONNECT request
/// carrying the correct `Proxy-Authorization: Basic` credentials succeeds
/// and yields the requested target.
#[tokio::test]
async fn handshake_auth_correct() {
	let mut cfg = base_config();
	cfg.username = "alice".to_string();
	cfg.password = "secret".to_string();
	cfg.camouflage = true;
	let (mut client, server) = new_pipe_conns().await;
	let wait = dial_handshake(server, cfg);

	let creds = base64::engine::general_purpose::STANDARD.encode(b"alice:secret");
	let req = format!(
		"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Basic {creds}\r\n\r\n"
	);
	client
		.write_all(req.as_bytes())
		.await
		.expect("write CONNECT");

	let result = wait.await.expect("handshake task");
	let (target, _frontend) = result.expect("handshake err");
	assert_eq!(target.host, "example.com");
	assert_eq!(target.port, 443);
}

/// Verifies bytes the client sends immediately after the CONNECT header (before
/// the 200 response) are preserved in the returned frontend stream.
#[tokio::test]
async fn handshake_buffered_bytes_preserved() {
	let cfg = base_config();
	let (mut client, server) = new_pipe_conns().await;
	let wait = dial_handshake(server, cfg);

	let request =
		"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\nearly-tunnel-data";
	client.write_all(request.as_bytes()).await.expect("write");

	let result = wait.await.expect("handshake task");
	let (_, mut frontend) = result.expect("handshake err");

	let want = b"early-tunnel-data";
	let mut got = vec![0u8; want.len()];
	tokio::time::timeout(Duration::from_secs(2), frontend.read_exact(&mut got))
		.await
		.expect("read timeout")
		.expect("ReadFull");
	assert_eq!(&got, want);
}
