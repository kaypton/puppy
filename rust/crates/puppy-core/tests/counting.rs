//! Tests for `counting.rs`.
//!
//! The tests use a synchronous in-memory mock (`PipeConn`) with the following
//! semantics: writes append to an internal `Vec<u8>`; reads drain from it; EOF
//! when empty. The Rust `CountingConn` wraps an `AsyncRead + AsyncWrite`
//! stream, so `PipeConn` exercises that trait surface.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use puppy_core::counting::CountingConn;
use puppy_core::stats::{ConnectionInfo, ConnectionRegistry, StatsRegistry};

/// In-memory `AsyncRead + AsyncWrite` backed by a `Vec<u8>`. Reads drain the
/// buffer (EOF when empty); writes append. Tracks `closed` for assertions.
struct PipeConn {
	buf: Vec<u8>,
	closed: bool,
}

impl PipeConn {
	fn new() -> Self {
		Self {
			buf: Vec::new(),
			closed: false,
		}
	}
}

impl AsyncRead for PipeConn {
	fn poll_read(
		self: Pin<&mut Self>,
		_cx: &mut Context<'_>,
		buf: &mut ReadBuf<'_>,
	) -> Poll<io::Result<()>> {
		let this = self.get_mut();
		if this.buf.is_empty() {
			return Poll::Ready(Ok(())); // EOF: 0 bytes
		}
		let n = std::cmp::min(this.buf.len(), buf.remaining());
		buf.put_slice(&this.buf[..n]);
		this.buf.drain(..n);
		Poll::Ready(Ok(()))
	}
}

impl AsyncWrite for PipeConn {
	fn poll_write(
		self: Pin<&mut Self>,
		_cx: &mut Context<'_>,
		buf: &[u8],
	) -> Poll<io::Result<usize>> {
		let this = self.get_mut();
		this.buf.extend_from_slice(buf);
		Poll::Ready(Ok(buf.len()))
	}

	fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		Poll::Ready(Ok(()))
	}

	fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		self.get_mut().closed = true;
		Poll::Ready(Ok(()))
	}
}

/// `AsyncRead + AsyncWrite` that returns `err` on every read/write.
struct ErrorConn {
	err: io::Error,
}

impl AsyncRead for ErrorConn {
	fn poll_read(
		self: Pin<&mut Self>,
		_cx: &mut Context<'_>,
		_buf: &mut ReadBuf<'_>,
	) -> Poll<io::Result<()>> {
		Poll::Ready(Err(io::Error::new(self.get_mut().err.kind(), "read err")))
	}
}

impl AsyncWrite for ErrorConn {
	fn poll_write(
		self: Pin<&mut Self>,
		_cx: &mut Context<'_>,
		_buf: &[u8],
	) -> Poll<io::Result<usize>> {
		Poll::Ready(Err(io::Error::new(self.get_mut().err.kind(), "write err")))
	}

	fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		Poll::Ready(Ok(()))
	}

	fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		Poll::Ready(Ok(()))
	}
}

fn make_info() -> Arc<ConnectionInfo> {
	Arc::new(ConnectionInfo::new("c1", "fe", "1.2.3.4:5"))
}

/// Verifies that bytes read through `CountingConn` are accounted on both
/// the per-connection `ConnectionInfo` and the aggregate `StatsRegistry`.
#[tokio::test]
async fn read_counts_bytes_in() {
	let mut pipe = PipeConn::new();
	pipe.buf.extend_from_slice(b"hello world");

	let info = make_info();
	let registry = Arc::new(StatsRegistry::new());
	let mut cc = CountingConn::new(pipe, Some(info.clone()), Some(registry.clone()));

	let mut buf = [0u8; 32];
	let n = cc.read(&mut buf).await.unwrap();
	assert_eq!(n, 11);
	assert_eq!(info.bytes_in(), 11);
	let snap = registry.snapshot();
	assert_eq!(snap.bytes_in, 11);
}

/// Verifies that bytes written through `CountingConn` are accounted on both
/// the per-connection `ConnectionInfo` and the aggregate `StatsRegistry`.
#[tokio::test]
async fn write_counts_bytes_out() {
	let pipe = PipeConn::new();
	let info = make_info();
	let registry = Arc::new(StatsRegistry::new());
	let mut cc = CountingConn::new(pipe, Some(info.clone()), Some(registry.clone()));

	let data = b"response data";
	let n = cc.write(data).await.unwrap();
	assert_eq!(n, data.len());
	assert_eq!(info.bytes_out(), data.len() as u64);
	let snap = registry.snapshot();
	assert_eq!(snap.bytes_out, data.len() as u64);
}

/// Confirms `CountingConn` works without an info/registry attached: reads
/// and writes pass through to the underlying stream without panicking.
#[tokio::test]
async fn nil_info_and_registry_pass_through() {
	let mut pipe = PipeConn::new();
	pipe.buf.extend_from_slice(b"test");

	let mut cc = CountingConn::new(pipe, None, None);
	let mut buf = [0u8; 4];
	let n = cc.read(&mut buf).await.unwrap();
	assert_eq!(n, 4);
	let n = cc.write(b"ok").await.unwrap();
	assert_eq!(n, 2);
}

/// Confirms `shutdown` is forwarded to the wrapped stream so the remote
/// peer observes EOF on subsequent reads.
#[tokio::test]
async fn close_closes_underlying() {
	// Shutdown the wrapped stream; the other end of the duplex should observe
	// EOF on subsequent reads.
	let (mut a, b) = tokio::io::duplex(64);
	let mut cc = CountingConn::new(b, None, None);
	cc.shutdown().await.unwrap();
	// After shutdown, reading from `a` should return 0 (EOF).
	let mut buf = [0u8; 1];
	let n = a.read(&mut buf).await.unwrap();
	assert_eq!(n, 0, "expected EOF after shutdown");
}

/// Verifies that several interleaved reads and writes accumulate their byte
/// counts correctly on both the per-connection info and the registry.
#[tokio::test]
async fn multiple_reads_and_writes_accumulate() {
	// Use a tokio duplex so we can feed the counting wrapper from the other
	// end of the pipe without re-borrowing the wrapped stream directly.
	let (mut tx, rx) = tokio::io::duplex(64);
	let info = make_info();
	let registry = Arc::new(StatsRegistry::new());
	let mut cc = CountingConn::new(rx, Some(info.clone()), Some(registry.clone()));

	// Read 1: "aaa"
	tx.write_all(b"aaa").await.unwrap();
	let mut b1 = [0u8; 3];
	cc.read_exact(&mut b1).await.unwrap();

	// Write 1: "bb"
	let _ = cc.write(b"bb").await.unwrap();

	// Read 2: "cccc"
	tx.write_all(b"cccc").await.unwrap();
	let mut b2 = [0u8; 4];
	cc.read_exact(&mut b2).await.unwrap();

	// Write 2: "ddddd"
	let _ = cc.write(b"ddddd").await.unwrap();

	assert_eq!(info.bytes_in(), 7); // 3 + 4
	assert_eq!(info.bytes_out(), 7); // 2 + 5
	let snap = registry.snapshot();
	assert_eq!(snap.bytes_in, 7);
	assert_eq!(snap.bytes_out, 7);
}

/// Confirms that read/write errors from the underlying stream are
/// propagated unchanged (preserving `io::ErrorKind`) and not swallowed by
/// the counting layer.
#[tokio::test]
async fn propagates_errors() {
	let err = io::Error::other("boom");
	let err_kind = err.kind();
	let conn = ErrorConn { err };
	let mut cc = CountingConn::new(conn, None, None);
	let read_err = cc.read(&mut [0u8; 1]).await.unwrap_err();
	assert_eq!(read_err.kind(), err_kind);
	let write_err = cc.write(b"x").await.unwrap_err();
	assert_eq!(write_err.kind(), err_kind);
}

/// End-to-end check that `CountingConn` interoperates with the real
/// `ConnectionRegistry`: registering the info, performing IO through the
/// wrapper, then removing the connection leaves the registry empty and
/// marks the info as closed.
#[tokio::test]
async fn registry_and_info_integration() {
	// Verify the counting wrapper interop with the real ConnectionRegistry:
	// registering the info, wrapping a stream, doing IO, then removing should
	// leave the registry empty and ClosedAt set.
	let registry = Arc::new(StatsRegistry::new());
	let conn_reg = ConnectionRegistry::new();
	let info = Arc::new(ConnectionInfo::new("conn-1", "fe1", "1.2.3.4:1234"));
	let info = conn_reg.register(info);
	assert_eq!(conn_reg.count(), 1);

	let mut pipe = PipeConn::new();
	pipe.buf.extend_from_slice(b"abcd");
	let mut cc = CountingConn::new(pipe, Some(info.clone()), Some(registry.clone()));

	let mut buf = [0u8; 4];
	cc.read_exact(&mut buf).await.unwrap();
	assert_eq!(info.bytes_in(), 4);

	conn_reg.remove(&info.id);
	assert_eq!(conn_reg.count(), 0);
	assert!(info.is_closed());
}
