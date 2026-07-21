//! HTTP CONNECT handshake: request parsing, auth, camouflage responses.
//!
//! The handshake reads the CONNECT request, validates Basic proxy auth, and
//! returns the target plus a frontend stream that preserves any bytes the
//! client sent past the request header (common with TLS clients that pipeline
//! early tunnel data).

use base64::Engine;
use puppy_core::backend::{BoxedStream, Protocol, Target};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::config::{CamouflageMethod, ServerConfiguration};

/// Maximum size of buffered HTTP request headers before the handshake rejects
/// the request. Matches the common 64 KiB default used by HTTP servers.
const MAX_HEADER_BYTES: usize = 64 * 1024;

/// Reads the CONNECT request, validates auth, and returns the target plus a
/// frontend reader that preserves buffered bytes. On failure it writes the
/// appropriate HTTP error response to `conn` and returns `Err`.
pub async fn handshake(
	conn: BoxedStream,
	config: &ServerConfiguration,
) -> Result<(Target, BoxedStream), Box<dyn std::error::Error + Send + Sync>> {
	let mut reader = BufReader::new(conn);
	let request = match reader.read_http_request().await {
		Ok(r) => r,
		Err(_) => {
			write_error(&mut reader, 400, None).await?;
			return Err("read request".into());
		}
	};

	if request.method != "CONNECT" {
		if config.camouflage {
			write_camouflage_error(&mut reader, false, config).await?;
		} else {
			write_error(&mut reader, 405, None).await?;
		}
		return Err(format!("method not allowed: {}", request.method).into());
	}

	if !config.username.is_empty() && !check_auth(&request, &config.username, &config.password) {
		if config.camouflage {
			write_camouflage_error(&mut reader, true, config).await?;
		} else {
			write_error(
				&mut reader,
				407,
				Some(&[("Proxy-Authenticate", "Basic realm=\"proxy\"")]),
			)
			.await?;
		}
		return Err("authentication failed".into());
	}

	let raw_target = if !request.url.is_empty() {
		request.url.clone()
	} else if !request.host.is_empty() {
		request.host.clone()
	} else {
		write_error(&mut reader, 400, None).await?;
		return Err("missing target".into());
	};

	let (host, port_str) = match split_host_port(&raw_target) {
		Some(hp) => hp,
		None => {
			// No port: default to 443 (HTTPS).
			(raw_target, "443".to_string())
		}
	};

	let port: u16 = match port_str.parse() {
		Ok(p) => p,
		Err(_) => {
			write_error(&mut reader, 400, None).await?;
			return Err(format!("invalid port {port_str:?}").into());
		}
	};

	let target = Target {
		network: "tcp".to_string(),
		protocol: Protocol::Unknown,
		host,
		port,
	};

	Ok((target, reader.into_stream()))
}

/// Splits `host:port` or `[ipv6]:port`. Returns `None` if no port delimiter
/// is present (i.e. the input lacks a port component).
pub(crate) fn split_host_port(s: &str) -> Option<(String, String)> {
	if let Some(stripped) = s.strip_prefix('[') {
		let close = stripped.find(']')?;
		let host = &stripped[..close];
		let rest = &stripped[close + 1..];
		let port = rest.strip_prefix(':')?;
		Some((host.to_string(), port.to_string()))
	} else {
		let idx = s.rfind(':')?;
		Some((s[..idx].to_string(), s[idx + 1..].to_string()))
	}
}

/// Parsed HTTP request line + headers.
struct ParsedRequest {
	method: String,
	url: String,
	host: String,
	/// Lowercased header name → value. The first occurrence wins, matching
	/// common HTTP header lookup semantics.
	headers: Vec<(String, String)>,
}

impl ParsedRequest {
	fn header(&self, name: &str) -> Option<&str> {
		self.headers
			.iter()
			.find(|(k, _)| k.eq_ignore_ascii_case(name))
			.map(|(_, v)| v.as_str())
	}
}

/// Buffered reader: pulls bytes from the underlying stream into an internal
/// buffer for HTTP request parsing, then exposes the leftover bytes (those
/// past the end of the headers) as the initial content of the returned
/// `BoxedStream` so they are not lost when the tunnel takes over.
struct BufReader {
	inner: BoxedStream,
	/// Accumulated bytes from the underlying stream.
	buf: Vec<u8>,
	/// Cursor into `buf` for sequential reads.
	pos: usize,
}

impl BufReader {
	fn new(inner: BoxedStream) -> Self {
		Self {
			inner,
			buf: Vec::new(),
			pos: 0,
		}
	}

	/// Reads bytes into `buf` until the HTTP request headers end with
	/// `\r\n\r\n`. Parses the request and returns it. Any bytes pulled past
	/// the header terminator are kept in `buf` for subsequent reads.
	async fn read_http_request(&mut self) -> std::io::Result<ParsedRequest> {
		let mut tmp = [0u8; 4096];
		// Track how many bytes of `buf` have already been scanned for the
		// header terminator. Only the last 3 bytes of the previously-scanned
		// region need to be re-checked: `\r\n\r\n` is 4 bytes, so any
		// terminator spanning the old/new boundary shares at most 3 bytes
		// with the old region.
		let mut scanned = 0usize;
		loop {
			let window_start = scanned.saturating_sub(3);
			if let Some(idx) = find_subslice(&self.buf[window_start..], b"\r\n\r\n") {
				let header_end = window_start + idx + 4;
				return self.parse_request(header_end);
			}
			scanned = self.buf.len();
			if self.buf.len() > MAX_HEADER_BYTES {
				return Err(std::io::Error::new(
					std::io::ErrorKind::InvalidData,
					"request headers too large",
				));
			}
			let n = self.inner.read(&mut tmp).await?;
			if n == 0 {
				return Err(std::io::Error::new(
					std::io::ErrorKind::UnexpectedEof,
					"connection closed before end of headers",
				));
			}
			self.buf.extend_from_slice(&tmp[..n]);
		}
	}

	fn parse_request(&mut self, header_end: usize) -> std::io::Result<ParsedRequest> {
		let raw = &self.buf[..header_end];
		// Parse with httparse. 64 headers is a reasonable default for small
		// requests; httparse will report Partial if more are present.
		let mut headers = [httparse::EMPTY_HEADER; 64];
		let mut req = httparse::Request::new(&mut headers);
		let status = req
			.parse(raw)
			.map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
		let header_len = match status {
			httparse::Status::Complete(n) => n,
			httparse::Status::Partial => {
				return Err(std::io::Error::new(
					std::io::ErrorKind::InvalidData,
					"incomplete request",
				));
			}
		};
		let method = req.method.unwrap_or("").to_string();
		let url = req.path.unwrap_or("").to_string();
		let mut header_vec = Vec::new();
		let mut host = String::new();
		for h in req.headers.iter() {
			let name = h.name.to_string();
			let value = String::from_utf8_lossy(h.value).to_string();
			if name.eq_ignore_ascii_case("Host") && host.is_empty() {
				host = value.clone();
			}
			header_vec.push((name.to_ascii_lowercase(), value));
		}
		// Advance `pos` past the parsed request so the remaining bytes (any
		// post-header data the client sent eagerly) stay in `buf` for the
		// tunnel phase.
		self.pos = header_len;
		Ok(ParsedRequest {
			method,
			url,
			host,
			headers: header_vec,
		})
	}

	/// Consumes the reader and returns a stream that yields leftover buffered
	/// bytes first, then delegates to the underlying stream.
	fn into_stream(self) -> BoxedStream {
		Box::new(BufferedConn::new(self.inner, self.buf, self.pos))
	}
}

impl AsyncRead for BufReader {
	fn poll_read(
		self: std::pin::Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
		dst: &mut tokio::io::ReadBuf<'_>,
	) -> std::task::Poll<std::io::Result<()>> {
		let this = self.get_mut();
		if this.pos < this.buf.len() {
			let n = std::cmp::min(this.buf.len() - this.pos, dst.remaining());
			dst.put_slice(&this.buf[this.pos..this.pos + n]);
			this.pos += n;
			return std::task::Poll::Ready(Ok(()));
		}
		std::pin::Pin::new(&mut this.inner).poll_read(cx, dst)
	}
}

impl AsyncWrite for BufReader {
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

/// Wraps a stream so the first reads return bytes pulled past the HTTP
/// request header before delegating to the underlying stream.
struct BufferedConn {
	inner: BoxedStream,
	buf: Vec<u8>,
	pos: usize,
}

impl BufferedConn {
	fn new(inner: BoxedStream, buf: Vec<u8>, pos: usize) -> Self {
		Self { inner, buf, pos }
	}
}

impl AsyncRead for BufferedConn {
	fn poll_read(
		self: std::pin::Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
		dst: &mut tokio::io::ReadBuf<'_>,
	) -> std::task::Poll<std::io::Result<()>> {
		let this = self.get_mut();
		if this.pos < this.buf.len() {
			let n = std::cmp::min(this.buf.len() - this.pos, dst.remaining());
			dst.put_slice(&this.buf[this.pos..this.pos + n]);
			this.pos += n;
			return std::task::Poll::Ready(Ok(()));
		}
		std::pin::Pin::new(&mut this.inner).poll_read(cx, dst)
	}
}

impl AsyncWrite for BufferedConn {
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

/// Writes a minimal HTTP error response.
async fn write_error(
	conn: &mut (impl AsyncWrite + Unpin),
	code: u16,
	headers: Option<&[(&str, &str)]>,
) -> std::io::Result<()> {
	let body = format!("{}\n", http_status_text(code));
	write_response(conn, code, headers, body.as_bytes()).await
}

/// Writes a camouflage error response.
async fn write_camouflage_error(
	conn: &mut (impl AsyncWrite + Unpin),
	connect_method: bool,
	config: &ServerConfiguration,
) -> std::io::Result<()> {
	match config.camouflage_method {
		CamouflageMethod::Return404 => {
			if connect_method {
				write_error(conn, 405, Some(&[("Allow", "GET, HEAD")])).await
			} else {
				write_response(
					conn,
					404,
					Some(&[("Content-Type", "text/html"), ("Server", "nginx")]),
					NOT_FOUND_HTML.as_bytes(),
				)
				.await
			}
		}
	}
}

/// Writes a full HTTP/1.1 response.
async fn write_response(
	conn: &mut (impl AsyncWrite + Unpin),
	code: u16,
	headers: Option<&[(&str, &str)]>,
	body: &[u8],
) -> std::io::Result<()> {
	let mut out = String::new();
	out.push_str(&format!("HTTP/1.1 {code} {}\r\n", http_status_text(code)));
	if let Some(hs) = headers {
		for (k, v) in hs {
			out.push_str(&format!("{k}: {v}\r\n"));
		}
	}
	out.push_str(&format!("Content-Length: {}\r\n", body.len()));
	out.push_str("Connection: close\r\n");
	out.push_str("\r\n");
	conn.write_all(out.as_bytes()).await?;
	conn.write_all(body).await?;
	Ok(())
}

/// Returns the canonical HTTP status text for `code`, matching the
/// conventional `net/http.StatusText` strings.
fn http_status_text(code: u16) -> &'static str {
	match code {
		200 => "OK",
		400 => "Bad Request",
		404 => "Not Found",
		405 => "Method Not Allowed",
		407 => "Proxy Authentication Required",
		502 => "Bad Gateway",
		_ => "Unknown",
	}
}

/// The nginx-style 404 body returned by camouflage mode.
const NOT_FOUND_HTML: &str = "<html>\r\n<head><title>404 Not Found</title></head>\r\n<body>\r\n<center><h1>404 Not Found</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n";

/// Validates the Proxy-Authorization header against the configured credentials
/// using constant-time comparison.
fn check_auth(req: &ParsedRequest, expected_user: &str, expected_pass: &str) -> bool {
	let (user, pass, ok) = proxy_basic_auth(req);
	if !ok {
		return false;
	}
	let u_match = bool::from(subtle::ConstantTimeEq::ct_eq(
		user.as_bytes(),
		expected_user.as_bytes(),
	));
	let p_match = bool::from(subtle::ConstantTimeEq::ct_eq(
		pass.as_bytes(),
		expected_pass.as_bytes(),
	));
	u_match && p_match
}

/// Extracts username/password from a Basic Proxy-Authorization header.
fn proxy_basic_auth(req: &ParsedRequest) -> (String, String, bool) {
	let v = match req.header("Proxy-Authorization") {
		Some(v) => v,
		None => return (String::new(), String::new(), false),
	};
	const PREFIX: &str = "Basic ";
	let rest = match v.strip_prefix(PREFIX) {
		Some(r) => r,
		None => return (String::new(), String::new(), false),
	};
	let decoded = match base64::engine::general_purpose::STANDARD.decode(rest) {
		Ok(d) => d,
		Err(_) => return (String::new(), String::new(), false),
	};
	let decoded_str = match std::str::from_utf8(&decoded) {
		Ok(s) => s,
		Err(_) => return (String::new(), String::new(), false),
	};
	let (user, pass) = match decoded_str.split_once(':') {
		Some((u, p)) => (u.to_string(), p.to_string()),
		None => return (String::new(), String::new(), false),
	};
	(user, pass, true)
}

/// Finds the first occurrence of `needle` in `haystack`. Returns `None` if not
/// found. Used for `\r\n\r\n` detection.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
	haystack.windows(needle.len()).position(|w| w == needle)
}
