//! SOCKS5 server-side handshake: method negotiation, optional RFC 1929
//! username/password authentication, and CONNECT request parsing.
//!
//! The handshake reads bytes via a `BufReader` so any bytes the client sent
//! past the SOCKS5 request (common with TLS clients that pipeline early
//! tunnel data) are preserved in the returned frontend stream.

use puppy_core::backend::{BoxedStream, Protocol, Target};
use puppy_core::socks5::{
	read_socks5_address, ATYP_IPV4, AUTH_VERSION, CMD_CONNECT, METHOD_NO_ACCEPTABLE,
	METHOD_NO_AUTH, METHOD_USERNAME_PASSWORD, REP_ADDR_TYPE_NOT_SUPPORTED, REP_CMD_NOT_SUPPORTED,
	VERSION,
};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::config::ServerConfiguration;

/// Performs the SOCKS5 server-side handshake: method negotiation, optional
/// RFC 1929 username/password authentication, and CONNECT request parsing.
/// Returns the target plus a frontend stream that preserves buffered bytes.
/// On failure it writes the appropriate SOCKS5 reply to `conn` and returns
/// `Err`.
pub async fn handshake(
	conn: BoxedStream,
	config: &ServerConfiguration,
) -> Result<(Target, BoxedStream), Box<dyn std::error::Error + Send + Sync>> {
	let mut reader = BufReader::new(conn);

	let method = negotiate_method(&mut reader, config).await?;

	if method == METHOD_USERNAME_PASSWORD {
		authenticate(&mut reader, config).await?;
	}

	let target = read_connect(&mut reader).await?;

	Ok((target, reader.into_stream()))
}

/// Reads VER+NMETHODS+METHODS and selects the authentication method.
///
/// When the server has credentials it accepts only username/password (0x02);
/// otherwise it accepts only no-auth (0x00). On no acceptable method it
/// writes 0xFF and returns an error.
async fn negotiate_method(
	reader: &mut BufReader,
	config: &ServerConfiguration,
) -> Result<u8, Box<dyn std::error::Error + Send + Sync>> {
	let mut header = [0u8; 2];
	if let Err(e) = reader.read_exact(&mut header).await {
		return Err(format!("read method negotiation: {e}").into());
	}
	if header[0] != VERSION {
		return Err(format!(
			"unexpected SOCKS version 0x{:02x} during method negotiation",
			header[0]
		)
		.into());
	}
	let nmethods = header[1] as usize;
	let mut methods = vec![0u8; nmethods];
	if let Err(e) = reader.read_exact(&mut methods).await {
		return Err(format!("read methods: {e}").into());
	}

	let require_auth = !config.username.is_empty();
	let want = if require_auth {
		METHOD_USERNAME_PASSWORD
	} else {
		METHOD_NO_AUTH
	};
	let mut accepted = METHOD_NO_ACCEPTABLE;
	for &m in &methods {
		if m == want {
			accepted = m;
			break;
		}
	}
	if let Err(e) = reader.write_all(&[VERSION, accepted]).await {
		return Err(format!("write method selection: {e}").into());
	}
	if accepted == METHOD_NO_ACCEPTABLE {
		return Err("no acceptable authentication method".into());
	}
	Ok(accepted)
}

/// Performs the RFC 1929 username/password sub-negotiation, validating
/// credentials with constant-time comparison. On failure it writes the auth
/// failure reply and returns an error.
async fn authenticate(
	reader: &mut BufReader,
	config: &ServerConfiguration,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
	let mut auth_header = [0u8; 2];
	if let Err(e) = reader.read_exact(&mut auth_header).await {
		return Err(format!("read auth version and username length: {e}").into());
	}
	if auth_header[0] != AUTH_VERSION {
		return Err(format!("unexpected auth version 0x{:02x}", auth_header[0]).into());
	}
	let ulen = auth_header[1] as usize;
	let mut user = vec![0u8; ulen];
	if let Err(e) = reader.read_exact(&mut user).await {
		return Err(format!("read username: {e}").into());
	}
	let mut plen_byte = [0u8; 1];
	if let Err(e) = reader.read_exact(&mut plen_byte).await {
		return Err(format!("read password length: {e}").into());
	}
	let plen = plen_byte[0] as usize;
	let mut pass = vec![0u8; plen];
	if let Err(e) = reader.read_exact(&mut pass).await {
		return Err(format!("read password: {e}").into());
	}

	let u_match = bool::from(user.ct_eq(config.username.as_bytes()));
	let p_match = bool::from(pass.ct_eq(config.password.as_bytes()));
	if !u_match || !p_match {
		let _ = reader.write_all(&[AUTH_VERSION, 0x01]).await;
		return Err("authentication failed".into());
	}
	if let Err(e) = reader.write_all(&[AUTH_VERSION, 0x00]).await {
		return Err(format!("write auth success: {e}").into());
	}
	Ok(())
}

/// Parses the SOCKS5 CONNECT request and returns the target. Only CONNECT
/// (0x01) is supported. On failure it writes the appropriate SOCKS5 reply and
/// returns an error.
async fn read_connect(
	reader: &mut BufReader,
) -> Result<Target, Box<dyn std::error::Error + Send + Sync>> {
	let mut req_header = [0u8; 4];
	if let Err(e) = reader.read_exact(&mut req_header).await {
		return Err(format!("read CONNECT request: {e}").into());
	}
	if req_header[0] != VERSION {
		return Err(format!(
			"unexpected SOCKS version 0x{:02x} in CONNECT request",
			req_header[0]
		)
		.into());
	}
	if req_header[1] != CMD_CONNECT {
		let _ = write_reply(reader, REP_CMD_NOT_SUPPORTED).await;
		return Err(format!("unsupported command 0x{:02x}", req_header[1]).into());
	}

	let atyp = req_header[3];
	match read_socks5_address(reader, atyp).await {
		Ok((host, port)) => Ok(Target {
			network: "tcp".to_string(),
			protocol: Protocol::Unknown,
			host,
			port,
		}),
		Err(e) => {
			let _ = write_reply(reader, REP_ADDR_TYPE_NOT_SUPPORTED).await;
			Err(format!("read target address: {e}").into())
		}
	}
}

/// Writes a SOCKS5 reply with the given REP code and a zeroed BND.ADDR
/// (0.0.0.0) / BND.PORT (0).
///
/// Public so the server module can reuse it for dial-failure replies.
pub async fn write_reply(conn: &mut (impl AsyncWrite + Unpin), rep: u8) -> std::io::Result<()> {
	// VER REP RSV ATYP IPv4(4) PORT(2)
	conn.write_all(&[VERSION, rep, 0x00, ATYP_IPV4, 0, 0, 0, 0, 0, 0])
		.await
}

/// Buffered reader: pulls bytes from the underlying stream into an internal
/// buffer for SOCKS5 request parsing, then exposes the leftover bytes (those
/// past the end of the request) as the initial content of the returned
/// `BoxedStream` so they are not lost when the tunnel takes over.
pub(crate) struct BufReader {
	inner: BoxedStream,
	/// Accumulated bytes from the underlying stream that have not yet been
	/// consumed by the tunnel.
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

/// Wraps a stream so the first reads return bytes pulled past the SOCKS5
/// request before delegating to the underlying stream.
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

/// Maps a backend dial error to a SOCKS5 REP code so clients receive a
/// meaningful failure reason.
///
/// Matches on `std::io::ErrorKind` for the system errno cases, then falls
/// back to `REP_GENERAL_FAILURE`. The `Arc<...>` form preserves the boxed
/// error type used by `Backend::dial`.
pub fn rep_for_dial_error(err: &puppy_core::backend::BackendError) -> u8 {
	use puppy_core::socks5::*;
	use std::io::ErrorKind;
	let Some(io) = err.io_error() else {
		return REP_GENERAL_FAILURE;
	};
	match io.kind() {
		ErrorKind::ConnectionRefused => REP_CONNECTION_REFUSED,
		ErrorKind::HostUnreachable => REP_HOST_UNREACHABLE,
		ErrorKind::NetworkUnreachable => REP_NETWORK_UNREACHABLE,
		ErrorKind::TimedOut => REP_TTL_EXPIRED,
		_ => REP_GENERAL_FAILURE,
	}
}
