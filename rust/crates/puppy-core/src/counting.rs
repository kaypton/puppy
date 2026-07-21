//! Byte-counting wrapper for client-side connections.
//!
//! Only the client side is wrapped: bytes read from the client count as
//! `BytesIn` and bytes written to the client count as `BytesOut`. The backend
//! connection is not wrapped, which avoids double-counting.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::stats::{ConnectionInfo, StatsRegistry};

/// Wraps an `AsyncRead + AsyncWrite` stream and tallies bytes into the
/// associated per-connection info and global registry. Either may be `None`,
/// in which case counting is skipped for that level.
pub struct CountingConn<S> {
	inner: S,
	info: Option<Arc<ConnectionInfo>>,
	registry: Option<Arc<StatsRegistry>>,
}

impl<S> CountingConn<S> {
	/// Returns a new `CountingConn`. Read bytes are recorded as inbound
	/// (client → proxy) and write bytes as outbound (proxy → client).
	pub fn new(
		inner: S,
		info: Option<Arc<ConnectionInfo>>,
		registry: Option<Arc<StatsRegistry>>,
	) -> Self {
		Self {
			inner,
			info,
			registry,
		}
	}

	/// Returns a reference to the inner stream.
	pub fn inner(&self) -> &S {
		&self.inner
	}

	/// Returns a mutable reference to the inner stream.
	pub fn inner_mut(&mut self) -> &mut S {
		&mut self.inner
	}

	/// Consumes the wrapper and returns the inner stream.
	pub fn into_inner(self) -> S {
		self.inner
	}

	fn record_in(&self, n: usize) {
		if n == 0 {
			return;
		}
		if let Some(info) = &self.info {
			info.add_bytes_in(n);
		}
		if let Some(reg) = &self.registry {
			reg.add_bytes_in(n);
		}
	}

	fn record_out(&self, n: usize) {
		if n == 0 {
			return;
		}
		if let Some(info) = &self.info {
			info.add_bytes_out(n);
		}
		if let Some(reg) = &self.registry {
			reg.add_bytes_out(n);
		}
	}
}

impl<S: AsyncRead + Unpin> AsyncRead for CountingConn<S> {
	fn poll_read(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &mut ReadBuf<'_>,
	) -> Poll<io::Result<()>> {
		let this = self.get_mut();
		let filled_before = buf.filled().len();
		let inner = Pin::new(&mut this.inner);
		match inner.poll_read(cx, buf) {
			Poll::Ready(Ok(())) => {
				let n = buf.filled().len() - filled_before;
				this.record_in(n);
				Poll::Ready(Ok(()))
			}
			other => other,
		}
	}
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CountingConn<S> {
	fn poll_write(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &[u8],
	) -> Poll<io::Result<usize>> {
		let this = self.get_mut();
		let inner = Pin::new(&mut this.inner);
		match inner.poll_write(cx, buf) {
			Poll::Ready(Ok(n)) => {
				this.record_out(n);
				Poll::Ready(Ok(n))
			}
			other => other,
		}
	}

	fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		let this = self.get_mut();
		Pin::new(&mut this.inner).poll_flush(cx)
	}

	fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		let this = self.get_mut();
		Pin::new(&mut this.inner).poll_shutdown(cx)
	}
}
