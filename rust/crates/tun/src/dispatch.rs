//! Session dispatcher: accepts TCP/UDP sessions from the netstack and
//! forwards them to a backend via [`Backend::dial`].
//!
//! Mirrors Go `pkg/tunproxy/dispatch.go`. The dispatcher implements
//! [`SessionHandler`] so the netstack can call it directly. Each session runs
//! on its own tokio task. DNS (port 53) is redirected to the configured
//! DNS-over-TCP target with two-byte length framing.
//!
//! Unlike the Go version (which uses gVisor's `ForwarderRequest` to obtain a
//! `net.Conn`), the Rust netstack (`stack.rs`) hands the dispatcher a
//! [`TcpSession`]/[`UdpSession`] carrying a `SocketHandle`. The dispatcher
//! then constructs an async stream wrapper ([`TcpSocketStream`] /
//! [`UdpSocketStream`]) that drives I/O on the smoltcp socket via command
//! channels handled by the poll loop. This module owns the command types, the
//! dispatch logic, and the relay/free-function helpers.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use puppy_core::backend::{
	supports, supports_any_protocol, supports_network, Backend, BoxedStream, Dialer, Protocol,
	Target,
};
use puppy_core::counting::CountingConn;
use puppy_core::shim::{ShimServer, ShimServerConfiguration};
use puppy_core::stats::{
	generate_connection_id, ConnectionInfo, ConnectionRegistry, EventBus, EventType, StatsRegistry,
};
use smoltcp::wire::IpAddress;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use crate::stack::{SessionHandler, TcpSession, UdpSession};

/// DNS port (53). Mirrors Go `dnsPort`.
const DNS_PORT: u16 = 53;
/// Maximum DNS message size. Mirrors Go `maxDNSMessageSize = 1<<16 - 1`.
const MAX_DNS_MESSAGE_SIZE: usize = 65535;
/// UDP relay buffer size. Mirrors Go `pipeUDP` (`make([]byte, 2048)`).
const UDP_PIPE_BUF: usize = 2048;
/// Command channel depth for socket I/O proxies.
pub const SOCKET_CMD_CHANNEL: usize = 64;

/// Configuration for [`Dispatcher`]. Mirrors Go `DispatcherConfiguration`.
///
/// All fields are clones of the runtime configuration captured at dispatcher
/// construction time. `Arc<dyn Backend>` / `Arc<dyn Dialer>` are cheap to
/// clone and shared with spawned session tasks.
pub struct DispatcherConfiguration {
	/// Ordered backend candidates.
	pub backends: Vec<Arc<dyn Backend>>,
	/// Catch-all backend.
	pub fallback: Arc<dyn Backend>,
	/// Egress dialer. Used for backend `dial` calls.
	pub dialer: Arc<dyn Dialer>,
	/// Fixed DNS-over-TCP target for port-53 redirection. `None` disables.
	pub dns: Option<Target>,
	/// Shim copy buffer size in bytes.
	pub shim_buf: usize,
	/// UDP idle timeout.
	pub udp_idle: Duration,
	/// Protocol-detect timeout.
	pub detect_timeout: Duration,
	/// Protocol-detect byte cap.
	pub detect_max_bytes: usize,
	/// Frontend name (for stats attribution).
	pub name: String,
	/// Global counter registry. `None` disables.
	pub stats: Option<Arc<StatsRegistry>>,
	/// Active-connection registry. `None` disables.
	pub conn_reg: Option<Arc<ConnectionRegistry>>,
	/// Event bus. `None` disables.
	pub bus: Option<Arc<EventBus>>,
}

/// Command sent from a TCP session task to the poll loop to drive I/O on its
/// smoltcp socket.
pub enum TcpSocketCmd {
	/// Pull a chunk of received bytes from the socket. `Ok(None)` indicates
	/// the socket is closed / has no more data.
	Read {
		reply: oneshot::Sender<std::io::Result<Option<Vec<u8>>>>,
	},
	/// Enqueue `data` for transmission. Reply is the number of bytes accepted.
	Write {
		data: Vec<u8>,
		reply: oneshot::Sender<std::io::Result<usize>>,
	},
	/// Close the socket and remove it from the socket set.
	Close,
}

/// Reply payload for [`UdpSocketCmd::Recv`]: payload bytes plus the remote
/// endpoint, or `None` when the flow is closed.
pub type UdpRecvReply = std::io::Result<Option<(Vec<u8>, (IpAddress, u16))>>;

/// Command sent from a UDP session task to the poll loop.
pub enum UdpSocketCmd {
	/// Receive one datagram. Reply carries payload + remote endpoint, or
	/// `Ok(None)` when the flow is closed.
	Recv {
		reply: oneshot::Sender<UdpRecvReply>,
	},
	/// Send `data` to `remote`. Reply is the number of bytes accepted.
	Send {
		data: Vec<u8>,
		remote: (IpAddress, u16),
		reply: oneshot::Sender<std::io::Result<usize>>,
	},
	/// Close the socket and remove it from the socket set.
	Close,
}

/// Async stream wrapper around a smoltcp TCP socket. I/O is driven by sending
/// commands to the poll loop and awaiting replies.
type TcpReadFuture =
	std::pin::Pin<Box<dyn Future<Output = std::io::Result<Option<Vec<u8>>>> + Send + 'static>>;
type SocketWriteFuture =
	std::pin::Pin<Box<dyn Future<Output = std::io::Result<usize>> + Send + 'static>>;

pub struct TcpSocketStream {
	cmd_tx: mpsc::Sender<TcpSocketCmd>,
	/// Buffered bytes from a previous read that haven't been consumed yet.
	read_buf: Vec<u8>,
	read_pos: usize,
	read_fut: Option<TcpReadFuture>,
	write_fut: Option<SocketWriteFuture>,
	close_sent: bool,
}

impl TcpSocketStream {
	/// Creates a new stream backed by `cmd_tx`. The poll loop owns `cmd_rx`
	/// and processes one command per poll iteration.
	pub fn new(cmd_tx: mpsc::Sender<TcpSocketCmd>) -> Self {
		Self {
			cmd_tx,
			read_buf: Vec::new(),
			read_pos: 0,
			read_fut: None,
			write_fut: None,
			close_sent: false,
		}
	}

	/// Signals the poll loop to close the underlying smoltcp socket. Best-effort:
	/// errors are ignored (the session task is winding down regardless).
	pub async fn close(&mut self) {
		if !self.close_sent {
			let _ = self.cmd_tx.send(TcpSocketCmd::Close).await;
			self.close_sent = true;
		}
	}

	fn try_close(&mut self) {
		if !self.close_sent {
			let _ = self.cmd_tx.try_send(TcpSocketCmd::Close);
			self.close_sent = true;
		}
	}
}

impl AsyncRead for TcpSocketStream {
	fn poll_read(
		self: std::pin::Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
		buf: &mut tokio::io::ReadBuf<'_>,
	) -> std::task::Poll<std::io::Result<()>> {
		let this = self.get_mut();
		// If we have buffered data, serve from it first.
		if this.read_pos < this.read_buf.len() {
			let remaining = &this.read_buf[this.read_pos..];
			let n = remaining.len().min(buf.remaining());
			buf.put_slice(&remaining[..n]);
			this.read_pos += n;
			if this.read_pos == this.read_buf.len() {
				this.read_buf.clear();
				this.read_pos = 0;
			}
			return std::task::Poll::Ready(Ok(()));
		}

		if this.read_fut.is_none() {
			let cmd_tx = this.cmd_tx.clone();
			this.read_fut = Some(Box::pin(async move {
				let (reply_tx, reply_rx) = oneshot::channel();
				cmd_tx
					.send(TcpSocketCmd::Read { reply: reply_tx })
					.await
					.map_err(|_| std::io::Error::other("tunproxy: poll loop dropped command"))?;
				match reply_rx.await {
					Ok(result) => result,
					Err(_) => Err(std::io::Error::other("tunproxy: poll loop dropped reply")),
				}
			}));
		}
		let poll = this.read_fut.as_mut().unwrap().as_mut().poll(cx);
		if poll.is_ready() {
			this.read_fut = None;
		}
		match poll {
			std::task::Poll::Ready(Ok(Some(data))) => {
				if data.is_empty() {
					cx.waker().wake_by_ref();
					return std::task::Poll::Pending;
				}
				let n = data.len().min(buf.remaining());
				buf.put_slice(&data[..n]);
				if n < data.len() {
					this.read_buf = data;
					this.read_pos = n;
				}
				std::task::Poll::Ready(Ok(()))
			}
			std::task::Poll::Ready(Ok(None)) => std::task::Poll::Ready(Ok(())),
			std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(e)),
			std::task::Poll::Pending => std::task::Poll::Pending,
		}
	}
}

impl AsyncWrite for TcpSocketStream {
	fn poll_write(
		self: std::pin::Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
		buf: &[u8],
	) -> std::task::Poll<std::io::Result<usize>> {
		let this = self.get_mut();
		if buf.is_empty() {
			return std::task::Poll::Ready(Ok(0));
		}
		if this.write_fut.is_none() {
			let cmd_tx = this.cmd_tx.clone();
			let data = buf.to_vec();
			this.write_fut = Some(Box::pin(async move {
				let (reply_tx, reply_rx) = oneshot::channel();
				cmd_tx
					.send(TcpSocketCmd::Write {
						data,
						reply: reply_tx,
					})
					.await
					.map_err(|_| std::io::Error::other("tunproxy: poll loop dropped command"))?;
				match reply_rx.await {
					Ok(result) => result,
					Err(_) => Err(std::io::Error::other("tunproxy: poll loop dropped reply")),
				}
			}));
		}
		let poll = this.write_fut.as_mut().unwrap().as_mut().poll(cx);
		if poll.is_ready() {
			this.write_fut = None;
		}
		poll
	}

	fn poll_flush(
		self: std::pin::Pin<&mut Self>,
		_cx: &mut std::task::Context<'_>,
	) -> std::task::Poll<std::io::Result<()>> {
		std::task::Poll::Ready(Ok(()))
	}

	fn poll_shutdown(
		mut self: std::pin::Pin<&mut Self>,
		_cx: &mut std::task::Context<'_>,
	) -> std::task::Poll<std::io::Result<()>> {
		self.try_close();
		std::task::Poll::Ready(Ok(()))
	}
}

impl Drop for TcpSocketStream {
	fn drop(&mut self) {
		self.try_close();
	}
}

/// Async stream wrapper around a smoltcp UDP socket.
type UdpReadFuture = std::pin::Pin<
	Box<dyn Future<Output = std::io::Result<Option<(Vec<u8>, (IpAddress, u16))>>> + Send + 'static>,
>;

pub struct UdpSocketStream {
	cmd_tx: mpsc::Sender<UdpSocketCmd>,
	read_buf: Vec<u8>,
	read_pos: usize,
	/// Remote endpoint used for writes when the caller has no other way to
	/// specify one (e.g. via `AsyncWrite`). Set at construction time from the
	/// session's peer.
	remote: (IpAddress, u16),
	read_fut: Option<UdpReadFuture>,
	write_fut: Option<SocketWriteFuture>,
	close_sent: bool,
}

impl UdpSocketStream {
	/// Creates a new UDP stream backed by `cmd_tx` with a fixed `remote` for
	/// writes that go through the `AsyncWrite` interface.
	pub fn new(cmd_tx: mpsc::Sender<UdpSocketCmd>, remote: (IpAddress, u16)) -> Self {
		Self {
			cmd_tx,
			read_buf: Vec::new(),
			read_pos: 0,
			remote,
			read_fut: None,
			write_fut: None,
			close_sent: false,
		}
	}

	/// Best-effort close signal to the poll loop.
	pub async fn close(&mut self) {
		if !self.close_sent {
			let _ = self.cmd_tx.send(UdpSocketCmd::Close).await;
			self.close_sent = true;
		}
	}

	fn try_close(&mut self) {
		if !self.close_sent {
			let _ = self.cmd_tx.try_send(UdpSocketCmd::Close);
			self.close_sent = true;
		}
	}
}

impl AsyncRead for UdpSocketStream {
	fn poll_read(
		self: std::pin::Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
		buf: &mut tokio::io::ReadBuf<'_>,
	) -> std::task::Poll<std::io::Result<()>> {
		let this = self.get_mut();
		if this.read_pos < this.read_buf.len() {
			let remaining = &this.read_buf[this.read_pos..];
			let n = remaining.len().min(buf.remaining());
			buf.put_slice(&remaining[..n]);
			this.read_pos += n;
			if this.read_pos == this.read_buf.len() {
				this.read_buf.clear();
				this.read_pos = 0;
			}
			return std::task::Poll::Ready(Ok(()));
		}
		if this.read_fut.is_none() {
			let cmd_tx = this.cmd_tx.clone();
			this.read_fut = Some(Box::pin(async move {
				let (reply_tx, reply_rx) = oneshot::channel();
				cmd_tx
					.send(UdpSocketCmd::Recv { reply: reply_tx })
					.await
					.map_err(|_| std::io::Error::other("tunproxy: poll loop dropped command"))?;
				match reply_rx.await {
					Ok(result) => result,
					Err(_) => Err(std::io::Error::other("tunproxy: poll loop dropped reply")),
				}
			}));
		}
		let poll = this.read_fut.as_mut().unwrap().as_mut().poll(cx);
		if poll.is_ready() {
			this.read_fut = None;
		}
		match poll {
			std::task::Poll::Ready(Ok(Some((data, _remote)))) => {
				if data.is_empty() {
					cx.waker().wake_by_ref();
					return std::task::Poll::Pending;
				}
				let n = data.len().min(buf.remaining());
				buf.put_slice(&data[..n]);
				if n < data.len() {
					this.read_buf = data;
					this.read_pos = n;
				}
				std::task::Poll::Ready(Ok(()))
			}
			std::task::Poll::Ready(Ok(None)) => std::task::Poll::Ready(Ok(())),
			std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(e)),
			std::task::Poll::Pending => std::task::Poll::Pending,
		}
	}
}

impl AsyncWrite for UdpSocketStream {
	fn poll_write(
		self: std::pin::Pin<&mut Self>,
		cx: &mut std::task::Context<'_>,
		buf: &[u8],
	) -> std::task::Poll<std::io::Result<usize>> {
		let this = self.get_mut();
		if buf.is_empty() {
			return std::task::Poll::Ready(Ok(0));
		}
		if this.write_fut.is_none() {
			let cmd_tx = this.cmd_tx.clone();
			let data = buf.to_vec();
			let remote = this.remote;
			this.write_fut = Some(Box::pin(async move {
				let (reply_tx, reply_rx) = oneshot::channel();
				cmd_tx
					.send(UdpSocketCmd::Send {
						data,
						remote,
						reply: reply_tx,
					})
					.await
					.map_err(|_| std::io::Error::other("tunproxy: poll loop dropped command"))?;
				match reply_rx.await {
					Ok(result) => result,
					Err(_) => Err(std::io::Error::other("tunproxy: poll loop dropped reply")),
				}
			}));
		}
		let poll = this.write_fut.as_mut().unwrap().as_mut().poll(cx);
		if poll.is_ready() {
			this.write_fut = None;
		}
		poll
	}

	fn poll_flush(
		self: std::pin::Pin<&mut Self>,
		_cx: &mut std::task::Context<'_>,
	) -> std::task::Poll<std::io::Result<()>> {
		std::task::Poll::Ready(Ok(()))
	}

	fn poll_shutdown(
		mut self: std::pin::Pin<&mut Self>,
		_cx: &mut std::task::Context<'_>,
	) -> std::task::Poll<std::io::Result<()>> {
		self.try_close();
		std::task::Poll::Ready(Ok(()))
	}
}

impl Drop for UdpSocketStream {
	fn drop(&mut self) {
		self.try_close();
	}
}

/// Dispatcher implements `SessionHandler`. Each accepted session spawns a
/// tokio task that dials the backend and relays bytes.
///
/// Construct via [`Dispatcher::new`] which returns `Arc<Dispatcher>`; the
/// `Arc` is cloned into each spawned task so the dispatcher is shared across
/// all in-flight sessions. Mirrors Go's `*dispatcher` with a `sync.WaitGroup`
/// tracking spawned goroutines.
pub struct Dispatcher {
	cfg: DispatcherConfiguration,
	cancel: CancellationToken,
	/// Tracks spawned session tasks so `wait` can block until all in-flight
	/// sessions have exited. Mirrors Go `dispatcher.wg sync.WaitGroup`. Wrapped
	/// in `Arc` so per-session `Dispatcher` clones (matching Go's value-
	/// receiver semantics) share the same task set.
	tasks: Arc<tokio::sync::Mutex<tokio::task::JoinSet<()>>>,
	/// Handle to the tokio runtime that owns session tasks. The netstack poll
	/// loop runs on a dedicated OS thread without a runtime context, so
	/// `handle_tcp`/`handle_udp` must spawn via `JoinSet::spawn_on` using this
	/// handle rather than `JoinSet::spawn` (which calls `tokio::spawn` and
	/// panics outside a runtime).
	handle: tokio::runtime::Handle,
}

impl Dispatcher {
	/// Constructs a new dispatcher wrapped in `Arc` so it can be cheaply
	/// cloned into each spawned session task.
	///
	/// Must be called from within a tokio runtime context so the dispatcher
	/// can capture a `Handle` for spawning session tasks from the netstack
	/// thread (which has no runtime of its own).
	pub fn new(cfg: DispatcherConfiguration, cancel: CancellationToken) -> Arc<Self> {
		Arc::new(Self {
			cfg,
			cancel,
			tasks: Arc::new(tokio::sync::Mutex::new(tokio::task::JoinSet::new())),
			handle: tokio::runtime::Handle::current(),
		})
	}

	/// Returns the cancellation token. Session tasks clone this to race
	/// against relay completion.
	pub fn cancel_token(&self) -> CancellationToken {
		self.cancel.clone()
	}

	/// Blocks until all in-flight TCP and UDP sessions have exited. Mirrors
	/// Go `dispatcher.wait`. The dispatcher's `cancel` token should be
	/// cancelled before calling `wait` so session tasks observe shutdown and
	/// exit promptly.
	pub async fn wait(&self) {
		let mut tasks = self.tasks.lock().await;
		while tasks.join_next().await.is_some() {}
	}

	/// Returns the configured DNS redirect target for `target` if `target`
	/// targets port 53 and a DNS redirect is configured. Mirrors Go
	/// `redirectDNS`.
	pub fn redirect_dns(&self, target: &Target) -> Option<Target> {
		if target.port != DNS_PORT {
			return None;
		}
		self.cfg.dns.clone()
	}

	/// Selects the first backend that supports `target`, falling back to the
	/// catch-all. Returns `(backend, index, is_fallback)`. Mirrors Go
	/// `selectBackend`.
	pub fn select_backend(&self, target: &Target) -> (Arc<dyn Backend>, i64, bool) {
		for (i, backend) in self.cfg.backends.iter().enumerate() {
			if supports(&backend.capabilities(), target) {
				return (Arc::clone(backend), i as i64, false);
			}
		}
		(Arc::clone(&self.cfg.fallback), -1, true)
	}

	/// Selects the first backend that supports TCP, falling back. Mirrors Go
	/// `selectTCPBackend`.
	pub fn select_tcp_backend(&self) -> (Arc<dyn Backend>, i64, bool) {
		for (i, backend) in self.cfg.backends.iter().enumerate() {
			if supports_network(&backend.capabilities(), "tcp") {
				return (Arc::clone(backend), i as i64, false);
			}
		}
		(Arc::clone(&self.cfg.fallback), -1, true)
	}

	/// Returns a reference to the egress dialer.
	fn dialer(&self) -> &dyn Dialer {
		self.cfg.dialer.as_ref()
	}

	/// Increments the total counter if present.
	fn inc_total(&self) {
		if let Some(stats) = &self.cfg.stats {
			stats.inc_total();
		}
	}

	/// Increments dial-failure counter and publishes an event. Mirrors Go's
	/// inlined dial-failure handling in `serveTCPConn`/`serveUDP`.
	fn report_dial_failure(&self, target: &Target, remote_addr: &str) {
		if let Some(stats) = &self.cfg.stats {
			stats.inc_dial_failure();
		}
		if let Some(bus) = &self.cfg.bus {
			bus.publish(puppy_core::stats::Event {
				event_type: EventType::DialFailed,
				time: std::time::Instant::now(),
				frontend: self.cfg.name.clone(),
				connection_id: String::new(),
				target: target.address(),
				remote_addr: remote_addr.to_string(),
				message: "backend dial failed".to_string(),
			});
		}
	}

	/// Registers a connection and returns the registered `ConnectionInfo`.
	/// Uses [`ConnectionInfo::with_target`] so target/protocol/network are
	/// populated without unsafe mutation. Mirrors Go's
	/// `connReg.Register(&stats.ConnectionInfo{...})` literal.
	fn register_conn(&self, target: &Target, remote_addr: &str) -> Option<Arc<ConnectionInfo>> {
		let conn_reg = self.cfg.conn_reg.as_ref()?;
		let info = Arc::new(ConnectionInfo::with_target(
			generate_connection_id(),
			self.cfg.name.clone(),
			remote_addr.to_string(),
			target.clone(),
			target.protocol,
			target.net().to_string(),
		));
		let info = conn_reg.register(info);
		if let Some(stats) = &self.cfg.stats {
			stats.inc_active();
		}
		if let Some(bus) = &self.cfg.bus {
			bus.publish(puppy_core::stats::Event {
				event_type: EventType::Connect,
				time: std::time::Instant::now(),
				frontend: self.cfg.name.clone(),
				connection_id: info.id.clone(),
				target: target.address(),
				remote_addr: remote_addr.to_string(),
				message: String::new(),
			});
		}
		Some(info)
	}

	/// Removes a connection from the registry, decrements active, publishes
	/// disconnect. No-op when `info` is `None`. Mirrors Go `removeTCPConn` /
	/// `removeUDPConn`.
	fn remove_conn(&self, info: Option<&ConnectionInfo>, remote_addr: &str, target: &Target) {
		let info = match info {
			Some(i) => i,
			None => return,
		};
		if let Some(conn_reg) = &self.cfg.conn_reg {
			conn_reg.remove(&info.id);
		}
		if let Some(stats) = &self.cfg.stats {
			stats.dec_active();
		}
		if let Some(bus) = &self.cfg.bus {
			bus.publish(puppy_core::stats::Event {
				event_type: EventType::Disconnect,
				time: std::time::Instant::now(),
				frontend: self.cfg.name.clone(),
				connection_id: info.id.clone(),
				target: target.address(),
				remote_addr: remote_addr.to_string(),
				message: String::new(),
			});
		}
	}

	/// Wraps `frontend` with a [`CountingConn`] when either a connection
	/// registry or stats registry is configured. Otherwise returns `frontend`
	/// unchanged. Mirrors Go's `wrappedFrontend := counting.NewConn(...)` block.
	fn wrap_counting(
		&self,
		frontend: BoxedStream,
		info: Option<Arc<ConnectionInfo>>,
	) -> BoxedStream {
		if self.cfg.conn_reg.is_some() || self.cfg.stats.is_some() {
			Box::new(CountingConn::new(frontend, info, self.cfg.stats.clone()))
		} else {
			frontend
		}
	}

	/// Runs a TCP relay: wraps the frontend with counting, constructs a
	/// `ShimServer`, and blocks until the copy completes or the dispatcher is
	/// cancelled. Mirrors Go `runTCPRelay`.
	async fn run_tcp_relay(
		self: Arc<Self>,
		frontend: BoxedStream,
		upstream: BoxedStream,
		target: &Target,
		remote_addr: &str,
	) {
		let conn_info = self.register_conn(target, remote_addr);
		if let Some(stats) = &self.cfg.stats {
			stats.inc_dial_success();
		}

		let wrapped_frontend = self.wrap_counting(frontend, conn_info.clone());

		let shim_cfg = ShimServerConfiguration {
			frontend: Some(wrapped_frontend),
			backend: Some(upstream),
			buffer_size: self.cfg.shim_buf,
		};
		let shim = match ShimServer::new(shim_cfg) {
			Ok(s) => s,
			Err(e) => {
				tracing::error!(target: "tunproxy", "shim configuration invalid: {e}");
				self.remove_conn(conn_info.as_deref(), remote_addr, target);
				return;
			}
		};
		tracing::info!(target: "tunproxy", "tcp tunnel established: target={}", target.address());
		let cancel = self.cancel.clone();
		shim.run_until(async move { cancel.cancelled().await })
			.await;
		self.remove_conn(conn_info.as_deref(), remote_addr, target);
	}

	/// Serves a TCP session: backend selection, optional protocol detection,
	/// dial, and relay. Mirrors Go `serveTCP` + `serveTCPConn`.
	async fn serve_tcp(self: Arc<Self>, session: TcpSession) {
		let (local_ip, local_port) = session.local;
		let (remote_ip, remote_port) = session.remote;
		let remote_addr = format!("{}:{}", remote_ip, remote_port);
		let host = local_ip.to_string();
		let mut target = Target {
			network: "tcp".to_string(),
			protocol: Protocol::Unknown,
			host,
			port: local_port,
		};
		let _original_target = target.clone();

		let dns_redirect = self.redirect_dns(&target);
		let is_dns_redirect = dns_redirect.is_some();
		if let Some(dns_target) = dns_redirect {
			target = dns_target;
		}

		// The poll loop created `cmd_tx` and passed it via the session; use
		// it to construct the async stream wrapper that drives I/O.
		let frontend: BoxedStream = Box::new(TcpSocketStream::new(session.cmd_tx));

		// Select backend.
		let (mut backend, mut backend_index, mut fallback) = if is_dns_redirect {
			self.select_backend(&target)
		} else {
			self.select_tcp_backend()
		};

		let mut frontend_conn: BoxedStream = frontend;

		// Protocol detection (only for non-DNS, non-Any-protocol backends).
		if !is_dns_redirect
			&& backend_index >= 0
			&& !supports_any_protocol(&backend.capabilities(), "tcp")
		{
			let detect_token = self.cancel.clone();
			match crate::protocol::detect_protocol(
				detect_token,
				frontend_conn,
				self.cfg.detect_timeout,
				self.cfg.detect_max_bytes,
			)
			.await
			{
				Ok(detected) => {
					target.protocol = detected.protocol;
					frontend_conn = Box::new(detected.stream);
				}
				Err(e) => {
					tracing::info!(target: "tunproxy", "tcp protocol detection failed: target={} err={e}", target.address());
					return;
				}
			}
			// Re-select backend with detected protocol.
			(backend, backend_index, fallback) = self.select_backend(&target);
		} else if !is_dns_redirect {
			target.protocol = Protocol::Unknown;
		}

		tracing::info!(
			target: "tunproxy",
			"tcp backend selected: target={} protocol={:?} backend_index={} fallback={}",
			target.address(), target.protocol, backend_index, fallback
		);

		let upstream = match backend.dial(target.clone(), self.dialer()).await {
			Ok(s) => s,
			Err(e) => {
				self.report_dial_failure(&target, &remote_addr);
				tracing::info!(target: "tunproxy", "tcp backend dial failed: target={} err={e}", target.address());
				return;
			}
		};
		self.run_tcp_relay(frontend_conn, upstream, &target, &remote_addr)
			.await;
	}

	/// Serves a UDP session: backend dial, idle-timeout relay. Mirrors Go
	/// `serveUDP`.
	async fn serve_udp(self: Arc<Self>, session: UdpSession) {
		let (local_ip, local_port) = session.local;
		let (remote_ip, remote_port) = session.remote;
		let remote_addr = format!("{}:{}", remote_ip, remote_port);
		let host = local_ip.to_string();
		let mut target = Target {
			network: "udp".to_string(),
			protocol: Protocol::Unknown,
			host,
			port: local_port,
		};

		// DNS redirect for UDP.
		if let Some(dns_target) = self.redirect_dns(&target) {
			self.serve_udp_dns(session, dns_target, &remote_addr, &target)
				.await;
			return;
		}
		target.protocol = Protocol::Unknown;

		let (backend, backend_index, fallback) = self.select_backend(&target);
		tracing::info!(
			target: "tunproxy",
			"udp route selected: target={} backend_index={} fallback={} remote_addr={}",
			target.address(), backend_index, fallback, remote_addr
		);
		let upstream = match backend.dial(target.clone(), self.dialer()).await {
			Ok(s) => s,
			Err(e) => {
				self.report_dial_failure(&target, &remote_addr);
				tracing::info!(target: "tunproxy", "udp backend dial failed: target={} err={e}", target.address());
				return;
			}
		};
		if let Some(stats) = &self.cfg.stats {
			stats.inc_dial_success();
		}

		let frontend: BoxedStream = Box::new(UdpSocketStream::new(session.cmd_tx, session.remote));
		let conn_info = self.register_conn(&target, &remote_addr);
		let wrapped_frontend = self.wrap_counting(frontend, conn_info.clone());

		tracing::info!(target: "tunproxy", "udp tunnel established: target={}", target.address());

		// Run bidirectional copy with idle timeout.
		let idle = self.cfg.udp_idle;
		let cancel = self.cancel.clone();
		tokio::select! {
			_ = relay_udp(wrapped_frontend, upstream, idle, cancel.clone()) => {}
			_ = cancel.cancelled() => {}
		}
		self.remove_conn(conn_info.as_deref(), &remote_addr, &target);
	}

	/// Serves a UDP DNS session: frames each datagram with a two-byte length
	/// prefix and carries it over a TCP backend connection. Mirrors Go
	/// `serveUDPDNS`.
	async fn serve_udp_dns(
		self: Arc<Self>,
		session: UdpSession,
		dns_target: Target,
		remote_addr: &str,
		original_target: &Target,
	) {
		let (backend, backend_index, fallback) = self.select_backend(&dns_target);
		tracing::info!(
			target: "tunproxy",
			"udp dns route selected: original_target={} target={} backend_index={} fallback={}",
			original_target.address(), dns_target.address(), backend_index, fallback
		);
		let upstream = match backend.dial(dns_target.clone(), self.dialer()).await {
			Ok(s) => s,
			Err(e) => {
				self.report_dial_failure(&dns_target, remote_addr);
				tracing::info!(target: "tunproxy", "udp dns backend dial failed: target={} err={e}", dns_target.address());
				return;
			}
		};
		if let Some(stats) = &self.cfg.stats {
			stats.inc_dial_success();
		}

		let frontend: BoxedStream = Box::new(UdpSocketStream::new(session.cmd_tx, session.remote));
		let conn_info = self.register_conn(&dns_target, remote_addr);
		let wrapped_frontend = self.wrap_counting(frontend, conn_info.clone());

		tracing::info!(target: "tunproxy", "udp dns tunnel established: target={}", dns_target.address());

		let idle = self.cfg.udp_idle;
		let cancel = self.cancel.clone();
		tokio::select! {
			_ = relay_udp_dns(wrapped_frontend, upstream, idle, cancel.clone()) => {}
			_ = cancel.cancelled() => {}
		}
		self.remove_conn(conn_info.as_deref(), remote_addr, &dns_target);
	}

	/// Forwards a TCP DNS connection redirected from the systemd-resolved stub
	/// to the configured DNS target. Mirrors Go
	/// `dispatcher.serveInterceptedDNSStream`.
	async fn serve_intercepted_dns_stream(self: Arc<Self>, frontend: BoxedStream) {
		let dns_target = match &self.cfg.dns {
			Some(t) => t.clone(),
			None => {
				tracing::error!(
					target: "tunproxy",
					"systemd-resolved tcp dns interception has no configured target"
				);
				return;
			}
		};
		if let Some(stats) = &self.cfg.stats {
			stats.inc_total();
		}
		let (backend, backend_index, fallback) = self.select_backend(&dns_target);
		tracing::info!(
			target: "tunproxy",
			"systemd-resolved tcp dns route selected: target={} backend_index={} fallback={}",
			dns_target.address(), backend_index, fallback
		);
		let upstream = match backend.dial(dns_target.clone(), self.dialer()).await {
			Ok(s) => s,
			Err(e) => {
				self.report_dial_failure(&dns_target, "127.0.0.1");
				tracing::info!(
					target: "tunproxy",
					"systemd-resolved tcp dns backend dial failed: target={} err={e}",
					dns_target.address()
				);
				return;
			}
		};
		self.run_tcp_relay(frontend, upstream, &dns_target, "127.0.0.1")
			.await;
	}
}

#[async_trait]
impl crate::route::DnsInterceptHandler for Dispatcher {
	async fn serve_intercepted_dns_stream(&self, stream: BoxedStream) {
		let dispatcher = Arc::new(Dispatcher {
			cfg: clone_cfg(&self.cfg),
			cancel: self.cancel.clone(),
			tasks: Arc::clone(&self.tasks),
			handle: self.handle.clone(),
		});
		let mut tasks = self.tasks.lock().await;
		tasks.spawn_on(
			async move {
				dispatcher.serve_intercepted_dns_stream(stream).await;
			},
			&self.handle,
		);
	}

	fn resolve_intercepted_dns_datagram(&self, query: &[u8]) -> std::io::Result<Vec<u8>> {
		let dns_target = self.cfg.dns.clone().ok_or_else(|| {
			std::io::Error::other("systemd-resolved DNS interception has no configured target")
		})?;
		if query.is_empty() {
			return Err(std::io::Error::other("empty UDP DNS message"));
		}
		if query.len() > MAX_DNS_MESSAGE_SIZE {
			return Err(std::io::Error::other(
				"UDP DNS message exceeds maximum size",
			));
		}
		let (backend, _backend_index, _fallback) = self.select_backend(&dns_target);
		let dialer: Arc<dyn Dialer> = Arc::clone(&self.cfg.dialer);
		let dns_target_clone = dns_target.clone();
		let query_owned = query.to_vec();
		// Drive the async dial+frame exchange to completion from the
		// synchronous trait method. `block_in_place` is safe when running on
		// a multi-thread tokio runtime, which is how puppy-server is
		// configured (`rt-multi-thread` feature).
		tokio::task::block_in_place(|| {
			let rt_handle = tokio::runtime::Handle::current();
			rt_handle.block_on(async move {
				let mut upstream = backend
					.dial(dns_target_clone.clone(), dialer.as_ref())
					.await
					.map_err(|e| std::io::Error::other(format!("backend dial: {e}")))?;
				write_dns_frame(&mut upstream, &query_owned).await?;
				let response = match read_dns_frame(&mut upstream).await? {
					Some(b) => b,
					None => return Err(std::io::Error::other("empty TCP DNS message")),
				};
				// `upstream` (a `BoxedStream`) is dropped at the end of this
				// closure, mirroring Go's `defer upstream.Close()`.
				Ok(response)
			})
		})
	}
}

impl SessionHandler for Dispatcher {
	fn handle_tcp(&self, session: TcpSession) {
		self.inc_total();
		let dispatcher = Arc::new(Dispatcher {
			cfg: clone_cfg(&self.cfg),
			cancel: self.cancel.clone(),
			tasks: Arc::clone(&self.tasks),
			handle: self.handle.clone(),
		});
		let mut tasks = self.tasks.blocking_lock();
		tasks.spawn_on(
			async move {
				dispatcher.serve_tcp(session).await;
			},
			&self.handle,
		);
	}

	fn handle_udp(&self, session: UdpSession) {
		self.inc_total();
		let dispatcher = Arc::new(Dispatcher {
			cfg: clone_cfg(&self.cfg),
			cancel: self.cancel.clone(),
			tasks: Arc::clone(&self.tasks),
			handle: self.handle.clone(),
		});
		let mut tasks = self.tasks.blocking_lock();
		tasks.spawn_on(
			async move {
				dispatcher.serve_udp(session).await;
			},
			&self.handle,
		);
	}
}

/// Clones the shareable fields of [`DispatcherConfiguration`] into a new
/// instance. `Arc` clones are cheap; `Option<Target>` and `String` are
/// cloned outright. Used when spawning per-session dispatchers so each task
/// owns its own `DispatcherConfiguration` (matching Go's value-receiver
/// semantics on `*dispatcher`).
fn clone_cfg(cfg: &DispatcherConfiguration) -> DispatcherConfiguration {
	DispatcherConfiguration {
		backends: cfg.backends.clone(),
		fallback: Arc::clone(&cfg.fallback),
		dialer: Arc::clone(&cfg.dialer),
		dns: cfg.dns.clone(),
		shim_buf: cfg.shim_buf,
		udp_idle: cfg.udp_idle,
		detect_timeout: cfg.detect_timeout,
		detect_max_bytes: cfg.detect_max_bytes,
		name: cfg.name.clone(),
		stats: cfg.stats.clone(),
		conn_reg: cfg.conn_reg.clone(),
		bus: cfg.bus.clone(),
	}
}

/// Bidirectional UDP relay with idle timeout. Mirrors Go's `pipeUDP` pair
/// plus `watchUDPIdle`. Each successful read in either direction resets the
/// idle timer; cancellation via `cancel` aborts the loop.
///
/// Note: unlike Go's `io.ReadWriteCloser` semantics where one UDP datagram
/// equals one `Read`/`Write`, the Rust stream wrappers expose UDP as a byte
/// stream. This is consistent with the rest of the codebase (which proxies
/// UDP via `tokio::net::UdpSocket` treated as a stream) and matches Go's
/// `net.Dialer.DialContext("udp", ...)` behavior when used as a stream.
async fn relay_udp(
	frontend: BoxedStream,
	backend: BoxedStream,
	idle: Duration,
	cancel: CancellationToken,
) {
	let (mut fe_read, mut fe_write) = tokio::io::split(frontend);
	let (mut be_read, mut be_write) = tokio::io::split(backend);

	let cancel_fut = cancel.cancelled();
	tokio::pin!(cancel_fut);

	let mut fe_buf = vec![0u8; UDP_PIPE_BUF];
	let mut be_buf = vec![0u8; UDP_PIPE_BUF];
	let mut idle_deadline = tokio::time::Instant::now() + idle;

	loop {
		tokio::select! {
			_ = &mut cancel_fut => break,
			// frontend -> backend
			r = fe_read.read(&mut fe_buf) => {
				match r {
					Ok(0) | Err(_) => break,
					Ok(n) => {
						if be_write.write_all(&fe_buf[..n]).await.is_err() {
							break;
						}
						idle_deadline = tokio::time::Instant::now() + idle;
					}
				}
			}
			// backend -> frontend
			r = be_read.read(&mut be_buf) => {
				match r {
					Ok(0) | Err(_) => break,
					Ok(n) => {
						if fe_write.write_all(&be_buf[..n]).await.is_err() {
							break;
						}
						idle_deadline = tokio::time::Instant::now() + idle;
					}
				}
			}
			// idle timeout
			_ = tokio::time::sleep_until(idle_deadline) => break,
		}
	}
}

/// Bidirectional UDP-DNS-to-TCP relay with two-byte length framing. Mirrors
/// Go's `pipeUDPToDNSStream` + `pipeDNSStreamToUDP` pair.
async fn relay_udp_dns(
	frontend: BoxedStream,
	backend: BoxedStream,
	idle: Duration,
	cancel: CancellationToken,
) {
	let (mut fe_read, mut fe_write) = tokio::io::split(frontend);
	let (mut be_read, mut be_write) = tokio::io::split(backend);

	let cancel_fut = cancel.cancelled();
	tokio::pin!(cancel_fut);

	let mut fe_buf = vec![0u8; MAX_DNS_MESSAGE_SIZE];
	let mut idle_deadline = tokio::time::Instant::now() + idle;

	loop {
		tokio::select! {
			_ = &mut cancel_fut => break,
			// frontend (UDP datagram) -> backend (TCP with length prefix)
			r = fe_read.read(&mut fe_buf) => {
				match r {
					Ok(0) | Err(_) => break,
					Ok(n) => {
						if n == 0 {
							break;
						}
						if n > MAX_DNS_MESSAGE_SIZE {
							break;
						}
						let mut frame = vec![0u8; 2 + n];
						frame[0..2].copy_from_slice(&(n as u16).to_be_bytes());
						frame[2..].copy_from_slice(&fe_buf[..n]);
						if be_write.write_all(&frame).await.is_err() {
							break;
						}
						idle_deadline = tokio::time::Instant::now() + idle;
					}
				}
			}
			// backend (TCP with length prefix) -> frontend (UDP datagram)
			r = read_dns_frame(&mut be_read) => {
				match r {
					Ok(None) => break,
					Ok(Some(message)) => {
						if fe_write.write_all(&message).await.is_err() {
							break;
						}
						idle_deadline = tokio::time::Instant::now() + idle;
					}
					Err(_) => break,
				}
			}
			// idle timeout
			_ = tokio::time::sleep_until(idle_deadline) => break,
		}
	}
}

/// Reads a two-byte length-prefixed DNS message from a TCP stream. Returns
/// `Ok(None)` on clean EOF before any bytes are read; returns
/// `Err(io::Error::other("empty TCP DNS message"))` when the length prefix
/// is zero. Mirrors Go's `io.ReadFull` + size-check in `pipeDNSStreamToUDP`
/// and `resolveInterceptedDNSDatagram`.
pub async fn read_dns_frame<R: AsyncRead + Unpin>(
	reader: &mut R,
) -> std::io::Result<Option<Vec<u8>>> {
	let mut length = [0u8; 2];
	match reader.read_exact(&mut length).await {
		Ok(_) => {}
		Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
		Err(e) => return Err(e),
	}
	let size = u16::from_be_bytes(length) as usize;
	if size == 0 {
		return Err(std::io::Error::other("empty TCP DNS message"));
	}
	let mut message = vec![0u8; size];
	reader.read_exact(&mut message).await?;
	Ok(Some(message))
}

/// Frames `query` with a two-byte length prefix and writes it to `writer`.
/// Mirrors Go's `frame := make([]byte, 2+len(query))` block in
/// `resolveInterceptedDNSDatagram`.
pub async fn write_dns_frame<W: AsyncWrite + Unpin>(
	writer: &mut W,
	query: &[u8],
) -> std::io::Result<()> {
	if query.is_empty() {
		return Err(std::io::Error::other("empty UDP DNS message"));
	}
	if query.len() > MAX_DNS_MESSAGE_SIZE {
		return Err(std::io::Error::other(
			"UDP DNS message exceeds maximum size",
		));
	}
	let mut frame = vec![0u8; 2 + query.len()];
	frame[0..2].copy_from_slice(&(query.len() as u16).to_be_bytes());
	frame[2..].copy_from_slice(query);
	writer.write_all(&frame).await
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::route::DnsInterceptHandler;
	use async_trait::async_trait;
	use puppy_core::backend::{Capability, Protocol as P, SystemDialer};
	use puppy_core::stats::{Event, StatsSnapshot};
	use smoltcp::iface::SocketHandle;
	use std::sync::atomic::{AtomicU32, Ordering};
	use std::time::Duration;
	use tokio::io::{AsyncReadExt, AsyncWriteExt};

	#[tokio::test]
	async fn tcp_socket_stream_preserves_pending_read_future() {
		let (cmd_tx, mut cmd_rx) = mpsc::channel(SOCKET_CMD_CHANNEL);
		let responder = tokio::spawn(async move {
			let TcpSocketCmd::Read { reply } = cmd_rx.recv().await.unwrap() else {
				panic!("expected read command");
			};
			tokio::time::sleep(Duration::from_millis(20)).await;
			let _ = reply.send(Ok(Some(b"delayed".to_vec())));
		});
		let mut stream = TcpSocketStream::new(cmd_tx);
		let mut data = [0u8; 7];
		tokio::time::timeout(Duration::from_secs(1), stream.read_exact(&mut data))
			.await
			.expect("read future was not woken")
			.unwrap();
		assert_eq!(&data, b"delayed");
		responder.await.unwrap();
	}

	#[tokio::test]
	async fn tcp_socket_stream_preserves_pending_write_future() {
		let (cmd_tx, mut cmd_rx) = mpsc::channel(SOCKET_CMD_CHANNEL);
		let responder = tokio::spawn(async move {
			let TcpSocketCmd::Write { data, reply } = cmd_rx.recv().await.unwrap() else {
				panic!("expected write command");
			};
			tokio::time::sleep(Duration::from_millis(20)).await;
			let len = data.len();
			let _ = reply.send(Ok(len));
		});
		let mut stream = TcpSocketStream::new(cmd_tx);
		tokio::time::timeout(Duration::from_secs(1), stream.write_all(b"delayed"))
			.await
			.expect("write future was not woken")
			.unwrap();
		responder.await.unwrap();
	}
	use tokio::sync::Mutex as AsyncMutex;

	// --- Constants ---

	#[test]
	fn dns_port_constant() {
		assert_eq!(DNS_PORT, 53);
	}

	#[test]
	fn max_dns_message_size_constant() {
		assert_eq!(MAX_DNS_MESSAGE_SIZE, 65535);
	}

	#[test]
	fn udp_pipe_buf_constant() {
		assert_eq!(UDP_PIPE_BUF, 2048);
	}

	// --- read_dns_frame ---

	#[tokio::test]
	async fn read_dns_frame_valid() {
		let data: Vec<u8> = [0x00, 0x04, b't', b'e', b's', b't'].to_vec();
		let mut cursor = std::io::Cursor::new(data);
		let result = read_dns_frame(&mut cursor).await.unwrap();
		assert_eq!(result, Some(b"test".to_vec()));
	}

	#[tokio::test]
	async fn read_dns_frame_eof() {
		let data: Vec<u8> = vec![];
		let mut cursor = std::io::Cursor::new(data);
		let result = read_dns_frame(&mut cursor).await.unwrap();
		assert_eq!(result, None);
	}

	#[tokio::test]
	async fn read_dns_frame_zero_length() {
		let data: Vec<u8> = vec![0x00, 0x00];
		let mut cursor = std::io::Cursor::new(data);
		let result = read_dns_frame(&mut cursor).await;
		assert!(result.is_err());
		assert_eq!(result.unwrap_err().to_string(), "empty TCP DNS message");
	}

	#[tokio::test]
	async fn read_dns_frame_truncated_payload() {
		// length = 4 but only 2 bytes follow
		let data: Vec<u8> = vec![0x00, 0x04, b't', b'e'];
		let mut cursor = std::io::Cursor::new(data);
		let result = read_dns_frame(&mut cursor).await;
		assert!(result.is_err());
		assert_eq!(
			result.unwrap_err().kind(),
			std::io::ErrorKind::UnexpectedEof
		);
	}

	#[tokio::test]
	async fn read_dns_frame_multiple_messages() {
		let mut data = vec![];
		// message 1: "abc"
		data.extend_from_slice(&3u16.to_be_bytes());
		data.extend_from_slice(b"abc");
		// message 2: "wxyz"
		data.extend_from_slice(&4u16.to_be_bytes());
		data.extend_from_slice(b"wxyz");
		let mut cursor = std::io::Cursor::new(data);
		assert_eq!(
			read_dns_frame(&mut cursor).await.unwrap(),
			Some(b"abc".to_vec())
		);
		assert_eq!(
			read_dns_frame(&mut cursor).await.unwrap(),
			Some(b"wxyz".to_vec())
		);
		assert_eq!(read_dns_frame(&mut cursor).await.unwrap(), None);
	}

	// --- write_dns_frame ---

	#[tokio::test]
	async fn write_dns_frame_valid() {
		let mut buf = Vec::new();
		write_dns_frame(&mut buf, b"query").await.unwrap();
		assert_eq!(buf, vec![0x00, 0x05, b'q', b'u', b'e', b'r', b'y']);
	}

	#[tokio::test]
	async fn write_dns_frame_empty_rejected() {
		let mut buf = Vec::new();
		let result = write_dns_frame(&mut buf, b"").await;
		assert!(result.is_err());
		assert_eq!(result.unwrap_err().to_string(), "empty UDP DNS message");
	}

	#[tokio::test]
	async fn write_dns_frame_oversize_rejected() {
		let mut buf = Vec::new();
		let big = vec![0u8; MAX_DNS_MESSAGE_SIZE + 1];
		let result = write_dns_frame(&mut buf, &big).await;
		assert!(result.is_err());
		assert_eq!(
			result.unwrap_err().to_string(),
			"UDP DNS message exceeds maximum size"
		);
	}

	// --- Mock backends ---

	/// Backend that records the dialed target and returns a pre-made stream
	/// (or an error). Mirrors Go's `dialBackend`.
	///
	/// The stream is stored behind a `tokio::sync::Mutex` so the backend is
	/// `Sync` (a bare `BoxedStream` is `Send` but not `Sync`). `dial` takes
	/// the stream out of the mutex — only one dial is expected per backend
	/// instance in tests.
	struct DialBackend {
		capabilities: Vec<Capability>,
		stream: AsyncMutex<Option<BoxedStream>>,
		err: Option<String>,
		targets: Arc<AsyncMutex<Vec<Target>>>,
	}

	impl DialBackend {
		fn new_with_stream(capabilities: Vec<Capability>, stream: BoxedStream) -> Self {
			Self {
				capabilities,
				stream: AsyncMutex::new(Some(stream)),
				err: None,
				targets: Arc::new(AsyncMutex::new(Vec::new())),
			}
		}

		fn new_with_error(capabilities: Vec<Capability>, err: impl Into<String>) -> Self {
			Self {
				capabilities,
				stream: AsyncMutex::new(None),
				err: Some(err.into()),
				targets: Arc::new(AsyncMutex::new(Vec::new())),
			}
		}

		async fn targets(&self) -> Vec<Target> {
			self.targets.lock().await.clone()
		}
	}

	#[async_trait]
	impl Backend for DialBackend {
		fn capabilities(&self) -> Vec<Capability> {
			self.capabilities.clone()
		}
		async fn dial(
			&self,
			target: Target,
			_dialer: &dyn Dialer,
		) -> Result<BoxedStream, puppy_core::backend::BackendError> {
			self.targets.lock().await.push(target.clone());
			if let Some(msg) = &self.err {
				return Err(puppy_core::backend::BackendError::Other(msg.clone()));
			}
			let stream = self
				.stream
				.lock()
				.await
				.take()
				.expect("DialBackend with no stream and no error");
			Ok(stream)
		}
	}

	/// Backend that blocks on a CancellationToken inside `dial`. Mirrors Go's
	/// `blockingBackend`.
	struct BlockingBackend {
		capabilities: Vec<Capability>,
		calls: Arc<AtomicU32>,
		started: Arc<tokio::sync::Notify>,
	}

	impl BlockingBackend {
		fn new() -> (Self, Arc<AtomicU32>, Arc<tokio::sync::Notify>) {
			let calls = Arc::new(AtomicU32::new(0));
			let started = Arc::new(tokio::sync::Notify::new());
			(
				Self {
					capabilities: vec![Capability {
						network: "udp".to_string(),
						protocol: Protocol::Any,
					}],
					calls: Arc::clone(&calls),
					started: Arc::clone(&started),
				},
				calls,
				started,
			)
		}
	}

	#[async_trait]
	impl Backend for BlockingBackend {
		fn capabilities(&self) -> Vec<Capability> {
			self.capabilities.clone()
		}
		async fn dial(
			&self,
			_target: Target,
			_dialer: &dyn Dialer,
		) -> Result<BoxedStream, puppy_core::backend::BackendError> {
			self.calls.fetch_add(1, Ordering::SeqCst);
			self.started.notify_waiters();
			// Block forever (until the future is dropped).
			std::future::pending::<()>().await;
			Err(puppy_core::backend::BackendError::Other(
				"unreachable".to_string(),
			))
		}
	}

	/// Backend that records capabilities but errors on dial. Mirrors Go's
	/// `capabilityBackend`.
	struct CapabilityBackend {
		capabilities: Vec<Capability>,
	}

	#[async_trait]
	impl Backend for CapabilityBackend {
		fn capabilities(&self) -> Vec<Capability> {
			self.capabilities.clone()
		}
		async fn dial(
			&self,
			_target: Target,
			_dialer: &dyn Dialer,
		) -> Result<BoxedStream, puppy_core::backend::BackendError> {
			Err(puppy_core::backend::BackendError::Other(
				"not used".to_string(),
			))
		}
	}

	/// A wrapper that makes a `tokio::io::DuplexStream` cloneable by routing
	/// all I/O through a single inner DuplexStream shared via `Arc<Mutex>`.
	/// Used so tests can hand the same end to multiple consumers.
	/// In practice tests use `tokio::io::duplex` and split ownership, so this
	/// is unused — kept as a placeholder to document the approach.
	#[allow(dead_code)]
	struct _CloneableDuplex;

	// --- Dispatcher config helpers ---

	fn dns_target() -> Target {
		Target {
			network: "tcp".to_string(),
			protocol: Protocol::Dns,
			host: "1.1.1.1".to_string(),
			port: 53,
		}
	}

	fn fallback_backend() -> Arc<dyn Backend> {
		Arc::new(CapabilityBackend {
			capabilities: vec![Capability {
				network: "tcp".to_string(),
				protocol: Protocol::Any,
			}],
		})
	}

	/// Builds a minimal `DispatcherConfiguration` from the given backends /
	/// fallback / dialer.
	#[allow(clippy::too_many_arguments)]
	fn make_cfg(
		backends: Vec<Arc<dyn Backend>>,
		fallback: Arc<dyn Backend>,
		dialer: Arc<dyn Dialer>,
		dns: Option<Target>,
		stats: Option<Arc<StatsRegistry>>,
		conn_reg: Option<Arc<ConnectionRegistry>>,
		bus: Option<Arc<EventBus>>,
		name: &str,
	) -> DispatcherConfiguration {
		DispatcherConfiguration {
			backends,
			fallback,
			dialer,
			dns,
			shim_buf: 1024,
			udp_idle: Duration::from_secs(1),
			detect_timeout: Duration::from_secs(1),
			detect_max_bytes: 16 * 1024,
			name: name.to_string(),
			stats,
			conn_reg,
			bus,
		}
	}

	/// Wraps a dispatcher in `Arc` with a fresh cancellation token.
	fn make_dispatcher(cfg: DispatcherConfiguration) -> Arc<Dispatcher> {
		Dispatcher::new(cfg, CancellationToken::new())
	}

	#[tokio::test]
	async fn protocol_detection_dials_reselected_backend() {
		let http = Arc::new(DialBackend::new_with_error(
			vec![Capability {
				network: "tcp".to_string(),
				protocol: Protocol::Http,
			}],
			"wrong backend",
		));
		let tls = Arc::new(DialBackend::new_with_error(
			vec![Capability {
				network: "tcp".to_string(),
				protocol: Protocol::Tls,
			}],
			"selected backend",
		));
		let cfg = make_cfg(
			vec![
				http.clone() as Arc<dyn Backend>,
				tls.clone() as Arc<dyn Backend>,
			],
			fallback_backend(),
			Arc::new(SystemDialer),
			None,
			None,
			None,
			None,
			"test",
		);
		let dispatcher = make_dispatcher(cfg);
		let (cmd_tx, mut cmd_rx) = mpsc::channel(SOCKET_CMD_CHANNEL);
		let responder = tokio::spawn(async move {
			if let Some(TcpSocketCmd::Read { reply }) = cmd_rx.recv().await {
				let _ = reply.send(Ok(Some(vec![0x16, 0x03, 0x03, 0x00, 0x10, 0x01])));
			}
		});
		dispatcher
			.serve_tcp(TcpSession {
				local: (
					IpAddress::Ipv4(smoltcp::wire::Ipv4Address([203, 0, 113, 10])),
					443,
				),
				remote: (
					IpAddress::Ipv4(smoltcp::wire::Ipv4Address([10, 0, 0, 2])),
					50000,
				),
				handle: SocketHandle::default(),
				cmd_tx,
			})
			.await;
		responder.await.unwrap();
		assert!(http.targets().await.is_empty());
		let targets = tls.targets().await;
		assert_eq!(targets.len(), 1);
		assert_eq!(targets[0].protocol, Protocol::Tls);
	}

	// --- select_backend / select_tcp_backend / redirect_dns ---

	#[tokio::test]
	async fn select_backend_by_priority_and_protocol() {
		let http = Arc::new(CapabilityBackend {
			capabilities: vec![Capability {
				network: "tcp".to_string(),
				protocol: Protocol::Http,
			}],
		}) as Arc<dyn Backend>;
		let tls = Arc::new(CapabilityBackend {
			capabilities: vec![Capability {
				network: "tcp".to_string(),
				protocol: Protocol::Tls,
			}],
		}) as Arc<dyn Backend>;
		let wildcard = Arc::new(CapabilityBackend {
			capabilities: vec![Capability {
				network: "tcp".to_string(),
				protocol: Protocol::Any,
			}],
		}) as Arc<dyn Backend>;
		let fallback = fallback_backend();
		let dispatcher = make_dispatcher(make_cfg(
			vec![Arc::clone(&http), Arc::clone(&tls), Arc::clone(&wildcard)],
			Arc::clone(&fallback),
			Arc::new(SystemDialer),
			None,
			None,
			None,
			None,
			"test",
		));

		// HTTP target -> first backend.
		let (b, i, f) = dispatcher.select_backend(&Target {
			network: "tcp".to_string(),
			protocol: Protocol::Http,
			host: String::new(),
			port: 0,
		});
		assert_eq!(i, 0);
		assert!(!f);
		assert!(Arc::ptr_eq(&b, &http));

		// TLS target -> second backend.
		let (b, i, f) = dispatcher.select_backend(&Target {
			network: "tcp".to_string(),
			protocol: Protocol::Tls,
			host: String::new(),
			port: 0,
		});
		assert_eq!(i, 1);
		assert!(!f);
		assert!(Arc::ptr_eq(&b, &tls));

		// Unknown protocol -> wildcard backend (Any).
		let (b, i, f) = dispatcher.select_backend(&Target {
			network: "tcp".to_string(),
			protocol: Protocol::Unknown,
			host: String::new(),
			port: 0,
		});
		assert_eq!(i, 2);
		assert!(!f);
		assert!(Arc::ptr_eq(&b, &wildcard));

		// UDP target with no UDP backend -> fallback.
		let (b, i, f) = dispatcher.select_backend(&Target {
			network: "udp".to_string(),
			protocol: Protocol::Unknown,
			host: String::new(),
			port: 0,
		});
		assert_eq!(i, -1);
		assert!(f);
		assert!(Arc::ptr_eq(&b, &fallback));
	}

	#[tokio::test]
	async fn select_tcp_backend_returns_first_tcp_capable() {
		let udp_only = Arc::new(CapabilityBackend {
			capabilities: vec![Capability {
				network: "udp".to_string(),
				protocol: Protocol::Any,
			}],
		}) as Arc<dyn Backend>;
		let tcp_any = Arc::new(CapabilityBackend {
			capabilities: vec![Capability {
				network: "tcp".to_string(),
				protocol: Protocol::Any,
			}],
		}) as Arc<dyn Backend>;
		let fallback = fallback_backend();
		let dispatcher = make_dispatcher(make_cfg(
			vec![Arc::clone(&udp_only), Arc::clone(&tcp_any)],
			Arc::clone(&fallback),
			Arc::new(SystemDialer),
			None,
			None,
			None,
			None,
			"test",
		));
		let (b, i, f) = dispatcher.select_tcp_backend();
		assert_eq!(i, 1);
		assert!(!f);
		assert!(Arc::ptr_eq(&b, &tcp_any));
	}

	#[tokio::test]
	async fn select_tcp_backend_falls_back_when_no_tcp_backend() {
		let udp_only = Arc::new(CapabilityBackend {
			capabilities: vec![Capability {
				network: "udp".to_string(),
				protocol: Protocol::Any,
			}],
		}) as Arc<dyn Backend>;
		let fallback = fallback_backend();
		let dispatcher = make_dispatcher(make_cfg(
			vec![Arc::clone(&udp_only)],
			Arc::clone(&fallback),
			Arc::new(SystemDialer),
			None,
			None,
			None,
			None,
			"test",
		));
		let (b, i, f) = dispatcher.select_tcp_backend();
		assert_eq!(i, -1);
		assert!(f);
		assert!(Arc::ptr_eq(&b, &fallback));
	}

	#[tokio::test]
	async fn redirect_dns_redirects_port_53() {
		let dispatcher = make_dispatcher(make_cfg(
			Vec::new(),
			fallback_backend(),
			Arc::new(SystemDialer),
			Some(dns_target()),
			None,
			None,
			None,
			"test",
		));
		let original = Target {
			network: "udp".to_string(),
			protocol: Protocol::Unknown,
			host: "192.0.2.53".to_string(),
			port: 53,
		};
		let redirected = dispatcher
			.redirect_dns(&original)
			.expect("port 53 should redirect");
		assert_eq!(redirected, dns_target());
	}

	#[tokio::test]
	async fn redirect_dns_passes_through_non_53() {
		let dispatcher = make_dispatcher(make_cfg(
			Vec::new(),
			fallback_backend(),
			Arc::new(SystemDialer),
			Some(dns_target()),
			None,
			None,
			None,
			"test",
		));
		let original = Target {
			network: "udp".to_string(),
			protocol: Protocol::Unknown,
			host: "192.0.2.53".to_string(),
			port: 5353,
		};
		assert!(dispatcher.redirect_dns(&original).is_none());
	}

	#[tokio::test]
	async fn redirect_dns_disabled_when_dns_none() {
		let dispatcher = make_dispatcher(make_cfg(
			Vec::new(),
			fallback_backend(),
			Arc::new(SystemDialer),
			None,
			None,
			None,
			None,
			"test",
		));
		let original = Target {
			network: "udp".to_string(),
			protocol: Protocol::Unknown,
			host: "192.0.2.53".to_string(),
			port: 53,
		};
		assert!(dispatcher.redirect_dns(&original).is_none());
	}

	// --- serve_udp_dns end-to-end (uses mock backend + duplex) ---

	#[tokio::test]
	async fn serve_udp_dns_frames_and_routes_tcp() {
		// Two ends of a duplex: `upstream` is given to the dispatcher (it
		// becomes the backend's dialed stream); `resolver` is held by the
		// test to act as the upstream DNS server.
		let (upstream, resolver) = tokio::io::duplex(1024);

		let backend = Arc::new(DialBackend::new_with_stream(
			vec![Capability {
				network: "tcp".to_string(),
				protocol: Protocol::Dns,
			}],
			Box::new(upstream),
		));
		let backend_dyn: Arc<dyn Backend> = Arc::clone(&backend) as Arc<dyn Backend>;

		let cancel = CancellationToken::new();
		let cfg = make_cfg(
			vec![Arc::clone(&backend_dyn)],
			fallback_backend(),
			Arc::new(SystemDialer),
			Some(dns_target()),
			None,
			None,
			None,
			"test",
		);
		let dispatcher = Dispatcher::new(cfg, cancel.clone());

		// The dispatcher's UDP frontend is also a duplex we don't directly
		// own — `serve_udp_dns` creates it internally via `UdpSocketStream`.
		// That stream is wired to the poll loop in P9.10; for now we verify
		// the *backend-side* behavior: the backend should be dialed with the
		// DNS target, and any bytes the (future) frontend writes should be
		// framed and arrive on `resolver`.
		//
		// Because the UdpSocketStream has no real poll-loop wiring yet, the
		// dispatcher's relay task will hang waiting on its cmd_rx. We can
		// still observe the backend dial by spawning serve_udp_dns and
		// reading from `resolver`.
		let (udp_cmd_tx, _udp_cmd_rx) = mpsc::channel::<UdpSocketCmd>(SOCKET_CMD_CHANNEL);
		let session = UdpSession {
			local: (
				IpAddress::Ipv4(smoltcp::wire::Ipv4Address([192, 0, 2, 53])),
				53,
			),
			remote: (
				IpAddress::Ipv4(smoltcp::wire::Ipv4Address([127, 0, 0, 1])),
				12345,
			),
			handle: SocketHandle::default(),
			first_packet: vec![],
			cmd_tx: udp_cmd_tx,
		};
		let d = Arc::clone(&dispatcher);
		let task = tokio::spawn(async move {
			d.serve_udp_dns(
				session,
				dns_target(),
				"127.0.0.1:12345",
				&Target {
					network: "udp".to_string(),
					protocol: Protocol::Unknown,
					host: "192.0.2.53".to_string(),
					port: 53,
				},
			)
			.await;
		});

		// Backend should have been dialed with the DNS target. Poll in a
		// loop because `serve_udp_dns` runs on a spawned task and the dial
		// may not have completed yet.
		let dialed = tokio::time::timeout(Duration::from_secs(1), async {
			loop {
				let t = backend.targets().await;
				if !t.is_empty() {
					return t;
				}
				tokio::time::sleep(Duration::from_millis(10)).await;
			}
		})
		.await
		.expect("backend dial timeout");
		assert_eq!(dialed, vec![dns_target()]);

		// Cancel to wind down the task (its relay has no real data flowing).
		cancel.cancel();
		let _ = tokio::time::timeout(Duration::from_secs(1), task).await;
		drop(resolver);
	}

	// --- Stats lifecycle: TCP dial failure ---
	#[tokio::test]
	async fn tcp_dial_failure_publishes_dial_failed_event() {
		let registry = Arc::new(StatsRegistry::new());
		let conn_reg = Arc::new(ConnectionRegistry::new());
		let bus = Arc::new(EventBus::new());
		let (mut rx, _guard) = bus.subscribe(&[
			EventType::Connect,
			EventType::Disconnect,
			EventType::DialFailed,
		]);

		let backend = Arc::new(DialBackend::new_with_error(
			vec![Capability {
				network: "tcp".to_string(),
				protocol: Protocol::Dns,
			}],
			"refused",
		));
		let backend_dyn: Arc<dyn Backend> = Arc::clone(&backend) as Arc<dyn Backend>;

		let cancel = CancellationToken::new();
		let cfg = make_cfg(
			vec![Arc::clone(&backend_dyn)],
			fallback_backend(),
			Arc::new(SystemDialer),
			Some(dns_target()),
			Some(Arc::clone(&registry)),
			Some(Arc::clone(&conn_reg)),
			Some(Arc::clone(&bus)),
			"tun-test",
		);
		let dispatcher = Dispatcher::new(cfg, cancel.clone());

		// Drive `serve_tcp` with a session that targets port 53 so the DNS
		// redirect kicks in (matches Go's serveInterceptedDNSStream path
		// which selects the DNS backend and then fails the dial).
		let (tcp_cmd_tx, _tcp_cmd_rx) = mpsc::channel::<TcpSocketCmd>(SOCKET_CMD_CHANNEL);
		let session = TcpSession {
			local: (
				IpAddress::Ipv4(smoltcp::wire::Ipv4Address([1, 1, 1, 1])),
				53,
			),
			remote: (
				IpAddress::Ipv4(smoltcp::wire::Ipv4Address([127, 0, 0, 1])),
				50000,
			),
			handle: SocketHandle::default(),
			cmd_tx: tcp_cmd_tx,
		};
		let d = Arc::clone(&dispatcher);
		d.serve_tcp(session).await;

		// Backend dialed with the DNS target.
		let dialed = backend.targets().await;
		assert_eq!(dialed, vec![dns_target()]);

		// DialFailed event published.
		let ev = tokio::time::timeout(Duration::from_secs(1), rx.recv())
			.await
			.expect("event timeout")
			.expect("event channel closed");
		assert_eq!(ev.event_type, EventType::DialFailed);
		assert_eq!(ev.frontend, "tun-test");
		assert_eq!(ev.message, "backend dial failed");
		assert_eq!(ev.target, dns_target().address());

		// Snapshot counters.
		let snap = registry.snapshot();
		assert_eq!(snap.total_connections, 0); // serve_tcp doesn't call inc_total (handle_tcp does)
		assert_eq!(snap.dial_successes, 0);
		assert_eq!(snap.dial_failures, 1);
		assert_eq!(snap.active_connections, 0);
		assert_eq!(conn_reg.count(), 0);
	}

	// --- Stats lifecycle: TCP successful tunnel ---

	#[tokio::test]
	async fn tcp_successful_tunnel_lifecycle() {
		let registry = Arc::new(StatsRegistry::new());
		let conn_reg = Arc::new(ConnectionRegistry::new());
		let bus = Arc::new(EventBus::new());
		let (mut rx, _guard) = bus.subscribe(&[
			EventType::Connect,
			EventType::Disconnect,
			EventType::DialFailed,
		]);

		// `frontend_client` is the test-side end; `frontend` is the
		// dispatcher-side end (plays the role of the TUN-side stream).
		let (frontend, mut frontend_client) = tokio::io::duplex(1024);
		// `upstream` is the dispatcher-side end; `upstream_peer` is the
		// far-end (plays the role of the backend's dialed connection).
		let (upstream, mut upstream_peer) = tokio::io::duplex(1024);

		let cancel = CancellationToken::new();
		let cfg = make_cfg(
			Vec::new(),
			fallback_backend(),
			Arc::new(SystemDialer),
			None,
			Some(Arc::clone(&registry)),
			Some(Arc::clone(&conn_reg)),
			Some(Arc::clone(&bus)),
			"tun-test",
		);
		let dispatcher = Dispatcher::new(cfg, cancel.clone());

		let target = Target {
			network: "tcp".to_string(),
			protocol: Protocol::Unknown,
			host: "203.0.113.9".to_string(),
			port: 80,
		};
		let remote_addr = "127.0.0.1:50000".to_string();
		let d = Arc::clone(&dispatcher);
		let relay_task = tokio::spawn(async move {
			d.run_tcp_relay(
				Box::new(frontend),
				Box::new(upstream),
				&target,
				&remote_addr,
			)
			.await;
		});

		// Connect event.
		let ev = tokio::time::timeout(Duration::from_secs(1), rx.recv())
			.await
			.expect("connect timeout")
			.expect("connect channel closed");
		assert_eq!(ev.event_type, EventType::Connect);
		assert_eq!(ev.frontend, "tun-test");
		assert_eq!(ev.remote_addr, "127.0.0.1:50000");
		assert_eq!(conn_reg.count(), 1);

		// Exchange data: client -> upstream.
		let client_write = b"hello upstream";
		frontend_client.write_all(client_write).await.unwrap();
		let mut up_read = vec![0u8; client_write.len()];
		upstream_peer.read_exact(&mut up_read).await.unwrap();
		assert_eq!(&up_read, client_write);

		// Exchange data: upstream -> client.
		let up_write = b"hello client";
		upstream_peer.write_all(up_write).await.unwrap();
		let mut client_read = vec![0u8; up_write.len()];
		frontend_client.read_exact(&mut client_read).await.unwrap();
		assert_eq!(&client_read, up_write);

		// Close the client side; the relay should wind down and publish
		// Disconnect.
		drop(frontend_client);
		drop(upstream_peer);

		// Wait for the relay task to finish.
		tokio::time::timeout(Duration::from_secs(2), relay_task)
			.await
			.expect("relay task timeout")
			.expect("relay task panicked");

		// Disconnect event.
		let ev = tokio::time::timeout(Duration::from_secs(1), rx.recv())
			.await
			.expect("disconnect timeout")
			.expect("disconnect channel closed");
		assert_eq!(ev.event_type, EventType::Disconnect);
		assert_eq!(ev.remote_addr, "127.0.0.1:50000");

		// Snapshot counters.
		let snap = registry.snapshot();
		assert_eq!(snap.total_connections, 0); // run_tcp_relay doesn't inc_total
		assert_eq!(snap.dial_successes, 1);
		assert_eq!(snap.dial_failures, 0);
		assert_eq!(snap.active_connections, 0);
		assert_eq!(snap.bytes_in, client_write.len() as u64);
		assert_eq!(snap.bytes_out, up_write.len() as u64);
		assert_eq!(conn_reg.count(), 0);
	}

	// --- Stats lifecycle: UDP dial failure ---

	#[tokio::test]
	async fn udp_dial_failure_publishes_dial_failed_event() {
		let registry = Arc::new(StatsRegistry::new());
		let conn_reg = Arc::new(ConnectionRegistry::new());
		let bus = Arc::new(EventBus::new());
		let (mut rx, _guard) = bus.subscribe(&[
			EventType::Connect,
			EventType::Disconnect,
			EventType::DialFailed,
		]);

		let backend = Arc::new(DialBackend::new_with_error(
			vec![Capability {
				network: "udp".to_string(),
				protocol: Protocol::Any,
			}],
			"refused",
		)) as Arc<dyn Backend>;

		let cancel = CancellationToken::new();
		let cfg = make_cfg(
			vec![Arc::clone(&backend)],
			fallback_backend(),
			Arc::new(SystemDialer),
			None,
			Some(Arc::clone(&registry)),
			Some(Arc::clone(&conn_reg)),
			Some(Arc::clone(&bus)),
			"tun-test",
		);
		let dispatcher = Dispatcher::new(cfg, cancel.clone());

		// We can't easily call `serve_udp` directly (it builds a
		// UdpSocketStream tied to the poll loop). Instead, verify the
		// report_dial_failure path by calling it explicitly — this is the
		// exact same code path serve_udp invokes on a dial error.
		let target = Target {
			network: "udp".to_string(),
			protocol: Protocol::Unknown,
			host: "203.0.113.9".to_string(),
			port: 80,
		};
		dispatcher.report_dial_failure(&target, "127.0.0.1:50000");

		let ev = tokio::time::timeout(Duration::from_secs(1), rx.recv())
			.await
			.expect("event timeout")
			.expect("event channel closed");
		assert_eq!(ev.event_type, EventType::DialFailed);
		assert_eq!(ev.frontend, "tun-test");
		assert_eq!(ev.message, "backend dial failed");
		assert_eq!(ev.target, target.address());

		let snap = registry.snapshot();
		assert_eq!(snap.dial_failures, 1);
		assert_eq!(snap.dial_successes, 0);
		assert_eq!(conn_reg.count(), 0);
	}

	// --- relay_udp free function ---

	#[tokio::test]
	async fn relay_udp_relays_both_directions() {
		let (fe, mut fe_peer) = tokio::io::duplex(1024);
		let (be, mut be_peer) = tokio::io::duplex(1024);
		let cancel = CancellationToken::new();

		let task = tokio::spawn(relay_udp(
			Box::new(fe),
			Box::new(be),
			Duration::from_secs(5),
			cancel.clone(),
		));

		// frontend -> backend
		fe_peer.write_all(b"abc").await.unwrap();
		let mut buf = [0u8; 3];
		be_peer.read_exact(&mut buf).await.unwrap();
		assert_eq!(&buf, b"abc");

		// backend -> frontend
		be_peer.write_all(b"xyz").await.unwrap();
		let mut buf = [0u8; 3];
		fe_peer.read_exact(&mut buf).await.unwrap();
		assert_eq!(&buf, b"xyz");

		// Cancel should wind down the task.
		cancel.cancel();
		let _ = tokio::time::timeout(Duration::from_secs(1), task).await;
	}

	#[tokio::test]
	async fn relay_udp_idle_timeout_exits() {
		let (fe, _fe_peer) = tokio::io::duplex(1024);
		let (be, _be_peer) = tokio::io::duplex(1024);
		let cancel = CancellationToken::new();

		let start = tokio::time::Instant::now();
		relay_udp(
			Box::new(fe),
			Box::new(be),
			Duration::from_millis(50),
			cancel,
		)
		.await;
		let elapsed = start.elapsed();
		assert!(elapsed >= Duration::from_millis(40));
		assert!(elapsed < Duration::from_millis(500));
	}

	#[tokio::test]
	async fn relay_udp_eof_exits() {
		let (fe, fe_peer) = tokio::io::duplex(1024);
		let (be, _be_peer) = tokio::io::duplex(1024);
		let cancel = CancellationToken::new();

		let task = tokio::spawn(relay_udp(
			Box::new(fe),
			Box::new(be),
			Duration::from_secs(5),
			cancel,
		));

		// Close the frontend peer; fe_read should get EOF and break the loop.
		drop(fe_peer);
		let _ = tokio::time::timeout(Duration::from_secs(1), task)
			.await
			.expect("relay should exit on EOF");
	}

	// --- relay_udp_dns free function ---

	#[tokio::test]
	async fn relay_udp_dns_frames_frontend_to_backend() {
		let (fe, mut fe_peer) = tokio::io::duplex(1024);
		let (be, mut be_peer) = tokio::io::duplex(1024);
		let cancel = CancellationToken::new();

		let task = tokio::spawn(relay_udp_dns(
			Box::new(fe),
			Box::new(be),
			Duration::from_secs(5),
			cancel.clone(),
		));

		// Write a UDP "datagram" from the frontend side.
		fe_peer.write_all(b"query").await.unwrap();

		// Backend should receive the framed version: 2-byte length + payload.
		let mut length = [0u8; 2];
		be_peer.read_exact(&mut length).await.unwrap();
		assert_eq!(u16::from_be_bytes(length), 5);
		let mut payload = [0u8; 5];
		be_peer.read_exact(&mut payload).await.unwrap();
		assert_eq!(&payload, b"query");

		cancel.cancel();
		let _ = tokio::time::timeout(Duration::from_secs(1), task).await;
	}

	#[tokio::test]
	async fn relay_udp_dns_unframes_backend_to_frontend() {
		let (fe, mut fe_peer) = tokio::io::duplex(1024);
		let (be, mut be_peer) = tokio::io::duplex(1024);
		let cancel = CancellationToken::new();

		let task = tokio::spawn(relay_udp_dns(
			Box::new(fe),
			Box::new(be),
			Duration::from_secs(5),
			cancel.clone(),
		));

		// Backend sends a framed DNS response.
		let response = b"answer";
		let mut frame = vec![0u8; 2 + response.len()];
		frame[0..2].copy_from_slice(&(response.len() as u16).to_be_bytes());
		frame[2..].copy_from_slice(response);
		be_peer.write_all(&frame).await.unwrap();

		// Frontend should receive just the payload (unframed).
		let mut got = vec![0u8; response.len()];
		fe_peer.read_exact(&mut got).await.unwrap();
		assert_eq!(&got, response);

		cancel.cancel();
		let _ = tokio::time::timeout(Duration::from_secs(1), task).await;
	}

	#[tokio::test]
	async fn relay_udp_dns_idle_timeout_exits() {
		let (fe, _fe_peer) = tokio::io::duplex(1024);
		let (be, _be_peer) = tokio::io::duplex(1024);
		let cancel = CancellationToken::new();

		let start = tokio::time::Instant::now();
		relay_udp_dns(
			Box::new(fe),
			Box::new(be),
			Duration::from_millis(50),
			cancel,
		)
		.await;
		let elapsed = start.elapsed();
		assert!(elapsed >= Duration::from_millis(40));
		assert!(elapsed < Duration::from_millis(500));
	}

	#[tokio::test]
	async fn relay_udp_dns_rejects_empty_frame_from_backend() {
		// A zero-length frame from the backend should cause read_dns_frame to
		// error, which breaks the relay loop.
		let (fe, _fe_peer) = tokio::io::duplex(1024);
		let (be, mut be_peer) = tokio::io::duplex(1024);
		let cancel = CancellationToken::new();

		let task = tokio::spawn(relay_udp_dns(
			Box::new(fe),
			Box::new(be),
			Duration::from_secs(5),
			cancel,
		));

		be_peer.write_all(&[0x00, 0x00]).await.unwrap();

		// Task should exit promptly (read_dns_frame errors on zero length).
		let _ = tokio::time::timeout(Duration::from_secs(1), task)
			.await
			.expect("relay should exit on empty frame");
	}

	// --- DNS interception (DnsInterceptHandler impl) ---

	// Mirrors Go's `TestDispatcher_ResolveInterceptedDNSDatagram`.
	//
	// `resolve_intercepted_dns_datagram` uses `block_in_place` to drive async
	// I/O from a sync context, so the test must run on the multi-thread
	// runtime (the default for `#[tokio::test]` is current-thread; we use
	// `flavor = "multi_thread"`).
	#[tokio::test(flavor = "multi_thread")]
	async fn resolve_intercepted_dns_datagram_round_trips_framed_tcp() {
		let (upstream, mut resolver) = tokio::io::duplex(1024);
		let backend = Arc::new(DialBackend::new_with_stream(
			vec![Capability {
				network: "tcp".to_string(),
				protocol: Protocol::Dns,
			}],
			Box::new(upstream),
		));
		let backend_dyn: Arc<dyn Backend> = Arc::clone(&backend) as Arc<dyn Backend>;

		let cfg = make_cfg(
			vec![Arc::clone(&backend_dyn)],
			fallback_backend(),
			Arc::new(SystemDialer),
			Some(dns_target()),
			None,
			None,
			None,
			"test",
		);
		let dispatcher = Dispatcher::new(cfg, CancellationToken::new());

		let query = vec![0x12, 0x34, 0x01, 0x00];
		let want_response = vec![0x12, 0x34, 0x81, 0x80];

		// Upstream DNS resolver: read the framed query, echo a framed
		// response.
		let want_response_clone = want_response.clone();
		let query_clone = query.clone();
		let resolver_task = tokio::spawn(async move {
			let mut frame = vec![0u8; query_clone.len() + 2];
			resolver.read_exact(&mut frame).await?;
			assert_eq!(
				u16::from_be_bytes([frame[0], frame[1]]),
				query_clone.len() as u16
			);
			assert_eq!(&frame[2..], &query_clone[..]);
			let mut response = vec![0u8; want_response_clone.len() + 2];
			response[0..2].copy_from_slice(&(want_response_clone.len() as u16).to_be_bytes());
			response[2..].copy_from_slice(&want_response_clone);
			resolver.write_all(&response).await?;
			Ok::<(), std::io::Error>(())
		});

		let response = dispatcher
			.resolve_intercepted_dns_datagram(&query)
			.expect("resolve_intercepted_dns_datagram");
		assert_eq!(response, want_response);

		resolver_task
			.await
			.expect("resolver task panicked")
			.expect("resolver I/O error");

		// Backend should have been dialed with the DNS target.
		let dialed = backend.targets().await;
		assert_eq!(dialed, vec![dns_target()]);
	}

	#[tokio::test(flavor = "multi_thread")]
	async fn resolve_intercepted_dns_datagram_rejects_empty_query() {
		let (upstream, _resolver) = tokio::io::duplex(1024);
		let backend = Arc::new(DialBackend::new_with_stream(
			vec![Capability {
				network: "tcp".to_string(),
				protocol: Protocol::Dns,
			}],
			Box::new(upstream),
		));
		let backend_dyn: Arc<dyn Backend> = Arc::clone(&backend) as Arc<dyn Backend>;

		let cfg = make_cfg(
			vec![Arc::clone(&backend_dyn)],
			fallback_backend(),
			Arc::new(SystemDialer),
			Some(dns_target()),
			None,
			None,
			None,
			"test",
		);
		let dispatcher = Dispatcher::new(cfg, CancellationToken::new());

		let err = dispatcher
			.resolve_intercepted_dns_datagram(&[])
			.expect_err("empty query should error");
		assert!(
			err.to_string().contains("empty UDP DNS"),
			"unexpected error: {err}"
		);
	}

	#[tokio::test(flavor = "multi_thread")]
	async fn resolve_intercepted_dns_datagram_errors_without_dns_target() {
		let (upstream, _resolver) = tokio::io::duplex(1024);
		let backend = Arc::new(DialBackend::new_with_stream(
			vec![Capability {
				network: "tcp".to_string(),
				protocol: Protocol::Dns,
			}],
			Box::new(upstream),
		));
		let backend_dyn: Arc<dyn Backend> = Arc::clone(&backend) as Arc<dyn Backend>;

		// No DNS target configured.
		let cfg = make_cfg(
			vec![Arc::clone(&backend_dyn)],
			fallback_backend(),
			Arc::new(SystemDialer),
			None,
			None,
			None,
			None,
			"test",
		);
		let dispatcher = Dispatcher::new(cfg, CancellationToken::new());

		let err = dispatcher
			.resolve_intercepted_dns_datagram(&[0x01])
			.expect_err("missing DNS target should error");
		assert!(
			err.to_string().contains("no configured target"),
			"unexpected error: {err}"
		);
	}

	// --- Blocking backend (mirrors Go's blockingBackend) ---

	#[tokio::test]
	async fn blocking_backend_dial_blocks_until_dropped() {
		let (backend, calls, started) = BlockingBackend::new();
		let backend: Arc<dyn Backend> = Arc::new(backend);
		let cancel = CancellationToken::new();

		let cancel_for_task = cancel.clone();
		let backend_clone = Arc::clone(&backend);
		let dial_task = tokio::spawn(async move {
			backend_clone
				.dial(
					Target {
						network: "udp".to_string(),
						protocol: Protocol::Unknown,
						host: String::new(),
						port: 0,
					},
					&SystemDialer as &dyn Dialer,
				)
				.await
		});

		// Wait for the dial to start.
		tokio::time::timeout(Duration::from_secs(1), started.notified())
			.await
			.expect("dial should start");
		assert_eq!(calls.load(Ordering::SeqCst), 1);

		// Cancel drops the future (task aborted), which should let the
		// pending() inside dial resolve as dropped.
		cancel_for_task.cancel();
		// Aborting the task drops the in-progress dial future.
		dial_task.abort();
		// Give the runtime a moment to clean up.
		tokio::time::sleep(Duration::from_millis(10)).await;
		assert_eq!(calls.load(Ordering::SeqCst), 1);
	}

	// --- Snapshot sanity (mirrors Go's Snapshot assertions) ---

	#[test]
	fn stats_snapshot_default_fields() {
		let snap = StatsSnapshot::default();
		assert_eq!(snap.total_connections, 0);
		assert_eq!(snap.active_connections, 0);
		assert_eq!(snap.dial_successes, 0);
		assert_eq!(snap.dial_failures, 0);
		assert_eq!(snap.bytes_in, 0);
		assert_eq!(snap.bytes_out, 0);
	}

	#[test]
	fn event_type_as_str_matches_go() {
		assert_eq!(EventType::Connect.as_str(), "connect");
		assert_eq!(EventType::Disconnect.as_str(), "disconnect");
		assert_eq!(EventType::DialFailed.as_str(), "dial_failed");
	}

	#[test]
	fn event_new_has_empty_fields() {
		let ev = Event::new(EventType::Connect);
		assert_eq!(ev.frontend, "");
		assert_eq!(ev.connection_id, "");
		assert_eq!(ev.target, "");
		assert_eq!(ev.remote_addr, "");
		assert_eq!(ev.message, "");
	}

	// --- Protocol sanity (mirrors Go's common.Protocol comparisons) ---

	#[test]
	fn protocol_as_str_matches_go() {
		assert_eq!(P::Any.as_str(), "*");
		assert_eq!(P::Unknown.as_str(), "unknown");
		assert_eq!(P::Http.as_str(), "http");
		assert_eq!(P::Tls.as_str(), "tls");
		assert_eq!(P::Dns.as_str(), "dns");
	}
}
