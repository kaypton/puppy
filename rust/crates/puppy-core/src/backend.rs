//! Backend trait, Dialer trait, Target, Protocol, Capability.

use std::net::IpAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Default network when `Target::network` is empty.
pub const DEFAULT_NETWORK: &str = "tcp";

/// A connection target: host + port + optional protocol hint.
///
/// The `network` field is empty for most callers and resolved to `"tcp"` via
/// `Net()`; we preserve that semantics here.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Target {
	/// `"tcp"` or `"udp"`; empty defaults to `"tcp"` via [`Target::net`].
	pub network: String,
	/// Protocol hint carried from the frontend; empty treated as `Unknown`.
	pub protocol: Protocol,
	/// Destination host: domain or literal IP.
	pub host: String,
	/// Destination port.
	pub port: u16,
}

impl Target {
	/// Returns `network` if non-empty, otherwise `"tcp"`.
	pub fn net(&self) -> &str {
		if self.network.is_empty() {
			DEFAULT_NETWORK
		} else {
			&self.network
		}
	}

	/// Joins host and port using `net.JoinHostPort` semantics: IPv6 literals are
	/// bracketed.
	pub fn address(&self) -> String {
		match self.host.parse::<IpAddr>() {
			Ok(IpAddr::V6(_)) => format!("[{}]:{}", self.host, self.port),
			_ => format!("{}:{}", self.host, self.port),
		}
	}
}

/// Application protocol hint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum Protocol {
	/// Matches anything.
	Any,
	/// Default when no hint is provided.
	#[default]
	Unknown,
	Http,
	Tls,
	Dns,
}

impl Protocol {
	pub fn as_str(self) -> &'static str {
		match self {
			Protocol::Any => "*",
			Protocol::Unknown => "unknown",
			Protocol::Http => "http",
			Protocol::Tls => "tls",
			Protocol::Dns => "dns",
		}
	}
}

/// A capability declares what network/protocol a backend can handle.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Capability {
	pub network: String,
	pub protocol: Protocol,
}

/// Returns true if any capability declares `network`.
pub fn supports_network(caps: &[Capability], network: &str) -> bool {
	caps.iter().any(|c| c.network == network)
}

/// Returns true if any capability declares `network` with the wildcard `Any`
/// protocol.
pub fn supports_any_protocol(caps: &[Capability], network: &str) -> bool {
	caps.iter()
		.any(|c| c.network == network && c.protocol == Protocol::Any)
}

/// Returns true if some capability can serve `target`. An empty `target.protocol`
/// is normalized to `Unknown`; a capability matches when its network equals
/// `target.net()` and its protocol is `Any` or equals the (normalized) target
/// protocol.
pub fn supports(caps: &[Capability], target: &Target) -> bool {
	let net = target.net();
	let proto = if target.protocol == Protocol::Unknown {
		Protocol::Unknown
	} else {
		target.protocol
	};
	caps.iter()
		.any(|c| c.network == net && (c.protocol == Protocol::Any || c.protocol == proto))
}

/// A type-erased bidirectional byte stream returned by [`Backend::dial`].
pub type BoxedStream = Box<dyn Stream + Send + Unpin>;

/// Object-safe combined read/write/close trait used as the return type of
/// `Backend::dial`.
#[async_trait::async_trait]
pub trait Stream: tokio::io::AsyncRead + tokio::io::AsyncWrite {}

#[async_trait]
impl<T> Stream for T where T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send {}

/// Backend dialer: produces outbound connections.
#[async_trait]
pub trait Backend: Send + Sync {
	/// Declares which network/protocol pairs this backend can handle.
	fn capabilities(&self) -> Vec<Capability>;

	/// Dials `target` via `dialer` and returns the established stream.
	async fn dial(&self, target: Target, dialer: &dyn Dialer) -> Result<BoxedStream, BackendError>;
}

/// Dialer abstraction over `net.Dialer.DialContext`.
///
/// Returns a boxed stream so the same trait can describe TCP, UDP, and mocked
/// dialers.
#[async_trait]
pub trait Dialer: Send + Sync {
	async fn dial_context(
		&self,
		network: &str,
		address: &str,
	) -> Result<BoxedStream, std::io::Error>;
}

/// System-default dialer (no egress binding).
///
/// Dials TCP via `tokio::net::TcpStream` and UDP via
/// `tokio::net::UdpSocket::connect`. Other networks fall back to TCP.
pub struct SystemDialer;

#[async_trait]
impl Dialer for SystemDialer {
	async fn dial_context(
		&self,
		network: &str,
		address: &str,
	) -> Result<BoxedStream, std::io::Error> {
		match network {
			"udp" => {
				let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
				sock.connect(address).await?;
				Ok(Box::new(UdpStream::new(sock)))
			}
			_ => {
				let stream = tokio::net::TcpStream::connect(address).await?;
				Ok(Box::new(stream))
			}
		}
	}
}

/// Stream adapter over a connected `tokio::net::UdpSocket`.
///
/// Tokio's `UdpSocket` does not implement `AsyncRead`/`AsyncWrite` because
/// UDP is datagram-oriented. For proxy use we treat a connected UDP socket as
/// a byte stream: each `poll_read` receives one datagram (truncated to the
/// buffer), and each `poll_write` sends one datagram. This matches the
/// `net.Dialer.DialContext("udp", ...)` semantics when used as an
/// `io.ReadWriteCloser`.
pub struct UdpStream {
	sock: tokio::net::UdpSocket,
}

impl UdpStream {
	pub fn new(sock: tokio::net::UdpSocket) -> Self {
		Self { sock }
	}
}

impl AsyncRead for UdpStream {
	fn poll_read(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &mut ReadBuf<'_>,
	) -> Poll<std::io::Result<()>> {
		let this = self.get_mut();
		this.sock.poll_recv(cx, buf)
	}
}

impl AsyncWrite for UdpStream {
	fn poll_write(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &[u8],
	) -> Poll<std::io::Result<usize>> {
		self.get_mut().sock.poll_send(cx, buf)
	}

	fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
		Poll::Ready(Ok(()))
	}

	fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
		Poll::Ready(Ok(()))
	}
}

/// Errors returned by backends.
#[derive(thiserror::Error, Debug)]
pub enum BackendError {
	/// Wrapped `std::io::Error` from a dialer or stream operation. Preserves
	/// the original `ErrorKind` so callers (e.g. SOCKS5 frontend's
	/// `rep_for_dial_error`) can match on it.
	#[error("{0}")]
	Io(#[from] std::io::Error),
	/// Generic backend error with a descriptive string. Used when the
	/// underlying error has no meaningful `ErrorKind` (e.g. a protocol
	/// violation reported by the backend itself).
	#[error("{0}")]
	Other(String),
}

impl BackendError {
	/// Returns the underlying `std::io::Error` if this is `BackendError::Io`,
	/// otherwise `None`. Used by the SOCKS5 frontend to map dial errors to
	/// SOCKS5 reply codes.
	pub fn io_error(&self) -> Option<&std::io::Error> {
		match self {
			BackendError::Io(e) => Some(e),
			BackendError::Other(_) => None,
		}
	}
}
