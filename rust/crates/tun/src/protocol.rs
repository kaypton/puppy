//! Application-protocol detection: HTTP (1.x and HTTP/2 client preface) and
//! TLS ClientHello.
//!
//! Mirrors Go `pkg/tunproxy/protocol.go`.

use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use puppy_core::backend::Protocol;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::time::timeout;

/// HTTP/2 client connection preface (RFC 7540 §3.5).
pub const HTTP2_CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Result of [`classify_protocol`]: the detected protocol (or `Unknown`) plus
/// whether the prefix is *complete* in the sense that no further bytes could
/// change the classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Classification {
	pub protocol: Protocol,
	pub complete: bool,
}

/// Classifies a buffered prefix as one of HTTP / TLS / Unknown.
///
/// Returns `complete=false` only while the prefix could still become a
/// supported protocol with additional bytes. Once the prefix is unambiguously
/// a supported protocol, or unambiguously *not* one, returns `complete=true`.
///
/// Mirrors Go `classifyProtocol` (pkg/tunproxy/protocol.go:89) byte-for-byte.
pub fn classify_protocol(prefix: &[u8]) -> Classification {
	if prefix.is_empty() {
		return Classification {
			protocol: Protocol::Unknown,
			complete: false,
		};
	}

	// HTTP/2 preface check.
	if prefix.len() >= HTTP2_CLIENT_PREFACE.len() && prefix.starts_with(HTTP2_CLIENT_PREFACE) {
		return Classification {
			protocol: Protocol::Http,
			complete: true,
		};
	}
	if prefix.len() < HTTP2_CLIENT_PREFACE.len() && prefix == &HTTP2_CLIENT_PREFACE[..prefix.len()]
	{
		return Classification {
			protocol: Protocol::Unknown,
			complete: false,
		};
	}

	// TLS handshake: first byte 0x16 (Handshake), version 0x03.0X.
	if prefix[0] == 0x16 {
		if prefix.len() < 3 {
			return Classification {
				protocol: Protocol::Unknown,
				complete: false,
			};
		}
		if prefix[1] != 0x03 || prefix[2] > 0x04 {
			return Classification {
				protocol: Protocol::Unknown,
				complete: true,
			};
		}
		if prefix.len() < 6 {
			return Classification {
				protocol: Protocol::Unknown,
				complete: false,
			};
		}
		if prefix[5] == 0x01 {
			return Classification {
				protocol: Protocol::Tls,
				complete: true,
			};
		}
		return Classification {
			protocol: Protocol::Unknown,
			complete: true,
		};
	}

	// HTTP request-line heuristic.
	let line_end = prefix.windows(2).position(|w| w == b"\r\n");
	let line: &[u8] = match line_end {
		Some(end) => &prefix[..end],
		None => prefix,
	};
	let first_space = line.iter().position(|&b| b == b' ');
	let first_space = match first_space {
		None => {
			// No space yet: every byte so far must be a valid HTTP token char.
			for &b in line {
				if !is_http_token_byte(b) {
					return Classification {
						protocol: Protocol::Unknown,
						complete: true,
					};
				}
			}
			return Classification {
				protocol: Protocol::Unknown,
				complete: false,
			};
		}
		Some(0) => {
			return Classification {
				protocol: Protocol::Unknown,
				complete: true,
			};
		}
		Some(p) => p,
	};
	for &b in &line[..first_space] {
		if !is_http_token_byte(b) {
			return Classification {
				protocol: Protocol::Unknown,
				complete: true,
			};
		}
	}
	let rest = &line[first_space + 1..];
	let second_space = rest.iter().position(|&b| b == b' ');
	let second_space = match second_space {
		None => {
			// No second space yet: need CRLF to confirm.
			if line_end.is_some() {
				return Classification {
					protocol: Protocol::Unknown,
					complete: true,
				};
			}
			return Classification {
				protocol: Protocol::Unknown,
				complete: false,
			};
		}
		Some(0) => {
			return Classification {
				protocol: Protocol::Unknown,
				complete: true,
			};
		}
		Some(p) => p,
	};
	let version = &rest[second_space + 1..];
	let valid_v10 = b"HTTP/1.0";
	let valid_v11 = b"HTTP/1.1";
	let version_invalid = if version.len() > valid_v10.len() {
		true
	} else {
		let cmp_v10 = &valid_v10[..version.len().min(valid_v10.len())];
		let cmp_v11 = &valid_v11[..version.len().min(valid_v11.len())];
		!((version == cmp_v10) || (version == cmp_v11))
	};
	if version_invalid {
		return Classification {
			protocol: Protocol::Unknown,
			complete: true,
		};
	}
	if line_end.is_none() {
		return Classification {
			protocol: Protocol::Unknown,
			complete: false,
		};
	}
	if version == valid_v10 || version == valid_v11 {
		return Classification {
			protocol: Protocol::Http,
			complete: true,
		};
	}
	Classification {
		protocol: Protocol::Unknown,
		complete: true,
	}
}

/// Returns true if `b` is a valid HTTP token character (RFC 7230 §3.2.6).
///
/// Mirrors Go `isHTTPTokenByte` (pkg/tunproxy/protocol.go:167).
fn is_http_token_byte(b: u8) -> bool {
	b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// Stream wrapper that replays a buffered prefix before delegating to the
/// underlying stream. Mirrors Go `replayConn` (pkg/tunproxy/protocol.go:16).
pub struct ReplayStream<S> {
	prefix: Vec<u8>,
	pos: usize,
	inner: S,
}

impl<S> ReplayStream<S> {
	/// Creates a new `ReplayStream` that yields `prefix` first, then `inner`.
	pub fn new(prefix: Vec<u8>, inner: S) -> Self {
		Self {
			prefix,
			pos: 0,
			inner,
		}
	}
}

impl<S: AsyncRead + Unpin> AsyncRead for ReplayStream<S> {
	fn poll_read(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &mut ReadBuf<'_>,
	) -> Poll<std::io::Result<()>> {
		let this = self.get_mut();
		if this.pos < this.prefix.len() {
			let remaining = &this.prefix[this.pos..];
			let n = remaining.len().min(buf.remaining());
			buf.put_slice(&remaining[..n]);
			this.pos += n;
			return Poll::Ready(Ok(()));
		}
		Pin::new(&mut this.inner).poll_read(cx, buf)
	}
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ReplayStream<S> {
	fn poll_write(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &[u8],
	) -> Poll<std::io::Result<usize>> {
		Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
	}

	fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
		Pin::new(&mut self.get_mut().inner).poll_flush(cx)
	}

	fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
		Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
	}
}

/// Outcome of [`detect_protocol`]: the detected protocol (or `Unknown`) plus a
/// stream that replays the consumed prefix before continuing with `conn`.
pub struct DetectedStream<S> {
	pub protocol: Protocol,
	pub stream: ReplayStream<S>,
}

/// Incrementally reads a client prefix and classifies its application protocol.
///
/// Bytes consumed during detection are returned through a [`ReplayStream`] so
/// downstream code sees the original stream unchanged. Detection stops as soon
/// as the prefix can be classified (or further bytes cannot change the
/// classification), the deadline elapses, or `max_bytes` is reached.
///
/// Mirrors Go `detectProtocol` (pkg/tunproxy/protocol.go:31). The Go version
/// uses a goroutine to interrupt a blocked read on context cancellation; the
/// Rust version achieves the same with `tokio::time::timeout` racing against
/// a `tokio::select!` on the cancellation token.
pub async fn detect_protocol<S>(
	cx_cancel: tokio_util::sync::CancellationToken,
	mut conn: S,
	timeout_dur: Duration,
	max_bytes: usize,
) -> std::io::Result<DetectedStream<S>>
where
	S: AsyncRead + AsyncWrite + Unpin,
{
	let mut prefix: Vec<u8> = Vec::with_capacity(max_bytes.min(4096));

	while prefix.len() < max_bytes {
		let class = classify_protocol(&prefix);
		if class.complete {
			return Ok(DetectedStream {
				protocol: class.protocol,
				stream: ReplayStream::new(prefix, conn),
			});
		}

		let mut buf = vec![0u8; 4096.min(max_bytes - prefix.len())];
		let read_fut = conn.read(&mut buf);
		let read_result = tokio::select! {
			biased;
			_ = cx_cancel.cancelled() => {
				return Err(std::io::Error::new(std::io::ErrorKind::Interrupted, "context canceled"));
			}
			r = timeout(timeout_dur, read_fut) => match r {
				Ok(r) => r,
				Err(_elapsed) => {
					// Timeout: return whatever prefix we have as Unknown.
					return Ok(DetectedStream {
						protocol: Protocol::Unknown,
						stream: ReplayStream::new(prefix, conn),
					});
				}
			},
		};

		match read_result {
			Ok(0) => {
				// EOF: return whatever prefix we have as Unknown.
				return Ok(DetectedStream {
					protocol: Protocol::Unknown,
					stream: ReplayStream::new(prefix, conn),
				});
			}
			Ok(n) => {
				prefix.extend_from_slice(&buf[..n]);
			}
			Err(e) => return Err(e),
		}
	}

	// Reached max_bytes: classify the buffer one last time.
	let class = classify_protocol(&prefix);
	Ok(DetectedStream {
		protocol: class.protocol,
		stream: ReplayStream::new(prefix, conn),
	})
}

#[cfg(test)]
mod tests {
	use super::*;
	use puppy_core::backend::Protocol;

	#[test]
	fn classify_partial_http_method() {
		let c = classify_protocol(b"GE");
		assert_eq!(c.protocol, Protocol::Unknown);
		assert!(!c.complete);
	}

	#[test]
	fn classify_partial_http_request_line() {
		let c = classify_protocol(b"GET / HTTP/1.");
		assert_eq!(c.protocol, Protocol::Unknown);
		assert!(!c.complete);
	}

	#[test]
	fn classify_http_1_1() {
		let c = classify_protocol(b"GET / HTTP/1.1\r\n");
		assert_eq!(c.protocol, Protocol::Http);
		assert!(c.complete);
	}

	#[test]
	fn classify_http_1_0() {
		let c = classify_protocol(b"POST /submit HTTP/1.0\r\n");
		assert_eq!(c.protocol, Protocol::Http);
		assert!(c.complete);
	}

	#[test]
	fn classify_partial_http2() {
		let c = classify_protocol(&HTTP2_CLIENT_PREFACE[..8]);
		assert_eq!(c.protocol, Protocol::Unknown);
		assert!(!c.complete);
	}

	#[test]
	fn classify_http2() {
		let c = classify_protocol(HTTP2_CLIENT_PREFACE);
		assert_eq!(c.protocol, Protocol::Http);
		assert!(c.complete);
	}

	#[test]
	fn classify_http2_with_first_frame() {
		let mut prefix = HTTP2_CLIENT_PREFACE.to_vec();
		prefix.extend_from_slice(&[0x00, 0x00, 0x00]);
		let c = classify_protocol(&prefix);
		assert_eq!(c.protocol, Protocol::Http);
		assert!(c.complete);
	}

	#[test]
	fn classify_partial_tls() {
		let c = classify_protocol(&[0x16, 0x03, 0x03, 0x00, 0x10]);
		assert_eq!(c.protocol, Protocol::Unknown);
		assert!(!c.complete);
	}

	#[test]
	fn classify_tls_client_hello() {
		let c = classify_protocol(&[0x16, 0x03, 0x03, 0x00, 0x10, 0x01]);
		assert_eq!(c.protocol, Protocol::Tls);
		assert!(c.complete);
	}

	#[test]
	fn classify_tls_non_client_handshake() {
		let c = classify_protocol(&[0x16, 0x03, 0x03, 0x00, 0x10, 0x02]);
		assert_eq!(c.protocol, Protocol::Unknown);
		assert!(c.complete);
	}

	#[test]
	fn classify_unknown() {
		let c = classify_protocol(&[0x01, 0x02]);
		assert_eq!(c.protocol, Protocol::Unknown);
		assert!(c.complete);
	}

	#[test]
	fn classify_invalid_http_version() {
		let c = classify_protocol(b"GET / FTP/1.0\r\n");
		assert_eq!(c.protocol, Protocol::Unknown);
		assert!(c.complete);
	}

	// --- detect_protocol integration tests ---

	use tokio::io::{AsyncReadExt, AsyncWriteExt};
	use tokio_test::io::Builder;

	#[tokio::test]
	async fn detect_preserves_fragmented_prefix() {
		// Use a duplex async stream so we can write incrementally.
		let (mut client, server) = tokio::io::duplex(1024);
		let payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\nbody";

		let writer = tokio::spawn(async move {
			client.write_all(&payload[..2]).await.unwrap();
			tokio::time::sleep(Duration::from_millis(10)).await;
			client.write_all(&payload[2..]).await.unwrap();
			// keep client alive until test ends
			tokio::time::sleep(Duration::from_secs(1)).await;
			let _ = client;
		});

		let token = tokio_util::sync::CancellationToken::new();
		let detected = detect_protocol(token, server, Duration::from_secs(1), 16 * 1024)
			.await
			.unwrap();
		assert_eq!(detected.protocol, Protocol::Http);

		let mut got = vec![0u8; payload.len()];
		let mut s = detected.stream;
		s.read_exact(&mut got).await.unwrap();
		assert_eq!(&got, payload);
		writer.abort();
	}

	#[tokio::test]
	async fn detect_timeout_returns_unknown_and_prefix() {
		// Use tokio_test mock stream: writes "GE" then closes write side with error
		// (Go test uses net.Pipe with client only writing "GE").
		// We emulate with a hand-rolled stream that yields "GE" then never more.
		let (mut client, server) = tokio::io::duplex(1024);
		let writer = tokio::spawn(async move {
			client.write_all(b"GE").await.unwrap();
			// keep the client half open so server doesn't get EOF
			tokio::time::sleep(Duration::from_secs(2)).await;
		});

		let token = tokio_util::sync::CancellationToken::new();
		let detected = detect_protocol(token, server, Duration::from_millis(20), 16 * 1024)
			.await
			.unwrap();
		assert_eq!(detected.protocol, Protocol::Unknown);
		let mut got = [0u8; 2];
		let mut s = detected.stream;
		s.read_exact(&mut got).await.unwrap();
		assert_eq!(&got, b"GE");
		writer.abort();
	}

	#[tokio::test]
	async fn detect_max_bytes_returns_unknown() {
		// Mock stream that yields a complete HTTP request; max_bytes caps at 8.
		let mock = Builder::new()
			.read(b"GET / HT") // first read returns 8 bytes
			.build();
		let token = tokio_util::sync::CancellationToken::new();
		let detected = detect_protocol(token, mock, Duration::from_secs(1), 8)
			.await
			.unwrap();
		assert_eq!(detected.protocol, Protocol::Unknown);
		let mut got = [0u8; 8];
		let mut s = detected.stream;
		s.read_exact(&mut got).await.unwrap();
		assert_eq!(&got, b"GET / HT");
	}
}
