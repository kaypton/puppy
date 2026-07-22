//! Shared protobuf definitions and stream adapters for the gRPC tunnel.
//!
//! The tunnel carries a bidirectional stream of [`Frame`] messages. The first
//! frame sent by the client is always a connect frame describing the target;
//! every subsequent frame in either direction is a payload frame carrying raw
//! stream bytes.
//!
//! Wiring on the client side (grpcproxy-be):
//!
//! 1. Create the outbound frame channel with [`client_channel`].
//! 2. Wrap the receiver in `tokio_stream::wrappers::ReceiverStream` and pass
//!    it as the request stream to `v1::tunnel_client::TunnelClient::connect`.
//! 3. Send [`connect_frame`] through the sender, then build the data stream
//!    with `GrpcStream::new(responses, sender)`, where `responses` is the
//!    `tonic::Streaming<Frame>` returned by the call.
//!
//! Wiring on the server side (grpcproxy-fe):
//!
//! 1. Pull the first frame from the request `tonic::Streaming<Frame>` and
//!    decode it with [`parse_connect`].
//! 2. Build the data stream and the response channel with
//!    [`server_stream`], passing the remaining request stream.
//! 3. Wrap the returned receiver in `tokio_stream::wrappers::ReceiverStream`
//!    and return it as the response stream.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use futures_util::Stream;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio_util::sync::PollSender;
use tonic::Status;

/// Generated code for the `puppy.tunnel.v1` protobuf package.
pub mod v1 {
	tonic::include_proto!("puppy.tunnel.v1");
}

pub use v1::*;

/// Default capacity of the frame channels created by [`client_channel`] and
/// [`server_stream`].
pub const CHANNEL_CAPACITY: usize = 64;

/// Builds the initial connect frame announcing the target to the tunnel peer.
pub fn connect_frame(network: &str, host: &str, port: u16) -> Frame {
	Frame {
		kind: Some(frame::Kind::Connect(ConnectRequest {
			network: network.to_owned(),
			host: host.to_owned(),
			port: u32::from(port),
		})),
	}
}

/// Builds a payload frame carrying raw stream bytes.
pub fn payload_frame(data: impl Into<Vec<u8>>) -> Frame {
	Frame {
		kind: Some(frame::Kind::Payload(data.into())),
	}
}

/// Decodes the initial connect frame into `(network, host, port)`.
///
/// Returns `Status::invalid_argument` if the frame is not a connect frame or
/// the port does not fit into `u16`.
// Status is the error type handlers return to tonic, so it is not boxed.
#[allow(clippy::result_large_err)]
pub fn parse_connect(frame: Frame) -> Result<(String, String, u16), Status> {
	match frame.kind {
		Some(frame::Kind::Connect(connect)) => {
			let port = u16::try_from(connect.port).map_err(|_| {
				Status::invalid_argument(format!("port {} out of range", connect.port))
			})?;
			Ok((connect.network, connect.host, port))
		}
		_ => Err(Status::invalid_argument(
			"first frame must be a connect frame",
		)),
	}
}

/// Creates the outbound frame channel for the client side of a tunnel.
///
/// Wrap the receiver in `tokio_stream::wrappers::ReceiverStream` and pass it
/// as the request stream to `TunnelClient::connect`; keep the sender to send
/// the connect frame and to build the [`GrpcStream`].
pub fn client_channel() -> (mpsc::Sender<Frame>, mpsc::Receiver<Frame>) {
	mpsc::channel(CHANNEL_CAPACITY)
}

/// Builds the server side of a tunnel from the remaining request stream.
///
/// The first connect frame must already have been consumed from `requests`
/// (see [`parse_connect`]). Wrap the returned receiver in
/// `tokio_stream::wrappers::ReceiverStream` and return it as the response
/// stream of the `Connect` handler.
pub fn server_stream(requests: tonic::Streaming<Frame>) -> (GrpcStream, mpsc::Receiver<Frame>) {
	let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
	(GrpcStream::new(requests, tx), rx)
}

/// Adapts a pair of tunnel frame streams into a single bidirectional byte
/// stream implementing [`AsyncRead`] and [`AsyncWrite`].
///
/// Reads poll the receive stream for payload frames; connect frames arriving
/// after the handshake are rejected as protocol errors, receive-side `Status`
/// errors surface as I/O errors, and end of stream reads as EOF. Writes are
/// framed as payloads and pushed into the send channel; a closed channel
/// surfaces as `BrokenPipe`. Flush is a no-op and shutdown succeeds
/// immediately, leaving the channel to close when the stream is dropped.
pub struct GrpcStream {
	rx: Pin<Box<dyn Stream<Item = Result<Frame, Status>> + Send>>,
	tx: PollSender<Frame>,
	read_buf: Bytes,
}

impl GrpcStream {
	/// Creates a stream reading frames from `rx` and writing payload frames
	/// into `tx`.
	pub fn new(
		rx: impl Stream<Item = Result<Frame, Status>> + Send + 'static,
		tx: mpsc::Sender<Frame>,
	) -> Self {
		Self {
			rx: Box::pin(rx),
			tx: PollSender::new(tx),
			read_buf: Bytes::new(),
		}
	}
}

impl AsyncRead for GrpcStream {
	fn poll_read(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &mut ReadBuf<'_>,
	) -> Poll<io::Result<()>> {
		let this = self.get_mut();
		loop {
			if !this.read_buf.is_empty() {
				let chunk = this
					.read_buf
					.split_to(this.read_buf.len().min(buf.remaining()));
				buf.put_slice(&chunk);
				return Poll::Ready(Ok(()));
			}
			match this.rx.as_mut().poll_next(cx) {
				Poll::Ready(Some(Ok(frame))) => match frame.kind {
					Some(frame::Kind::Payload(data)) => this.read_buf = data.into(),
					Some(frame::Kind::Connect(_)) => {
						return Poll::Ready(Err(io::Error::new(
							io::ErrorKind::InvalidData,
							"unexpected connect frame",
						)));
					}
					None => {
						return Poll::Ready(Err(io::Error::new(
							io::ErrorKind::InvalidData,
							"frame without kind",
						)));
					}
				},
				Poll::Ready(Some(Err(status))) => {
					return Poll::Ready(Err(io::Error::other(status)))
				}
				Poll::Ready(None) => return Poll::Ready(Ok(())),
				Poll::Pending => return Poll::Pending,
			}
		}
	}
}

impl AsyncWrite for GrpcStream {
	fn poll_write(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &[u8],
	) -> Poll<io::Result<usize>> {
		let this = self.get_mut();
		match this.tx.poll_reserve(cx) {
			Poll::Ready(Ok(())) => match this.tx.send_item(payload_frame(buf)) {
				Ok(()) => Poll::Ready(Ok(buf.len())),
				Err(_) => Poll::Ready(Err(broken_pipe())),
			},
			Poll::Ready(Err(_)) => Poll::Ready(Err(broken_pipe())),
			Poll::Pending => Poll::Pending,
		}
	}

	fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		Poll::Ready(Ok(()))
	}

	fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
		Poll::Ready(Ok(()))
	}
}

fn broken_pipe() -> io::Error {
	io::Error::new(io::ErrorKind::BrokenPipe, "tunnel frame channel closed")
}
