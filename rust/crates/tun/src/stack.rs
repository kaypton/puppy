//! smoltcp userspace netstack: bridges the TUN device to a TCP/UDP socket
//! set and dispatches accepted sessions to a handler.
//!
//! Mirrors Go `pkg/tunproxy/stack.go`. smoltcp 0.11 has no gVisor-style
//! `Forwarder` callbacks or any-port listener. This module inspects incoming
//! packets before they reach smoltcp, creates per-connection TCP listeners,
//! and demultiplexes UDP flows while sharing destination-bound transmit
//! sockets.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::time::Instant as StdInstant;

use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{self, Device, DeviceCapabilities, Medium};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::{Duration as SmolDuration, Instant as SmolInstant};
use smoltcp::wire::{
	HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint, IpProtocol, Ipv4Address,
	Ipv4Packet, Ipv6Address, Ipv6Packet, TcpPacket, UdpPacket,
};
use tokio::sync::{mpsc, oneshot};

use crate::addr::parse_addr_with_prefix;
use crate::dispatch::{TcpSocketCmd, UdpSocketCmd};

/// Channel depth for the inbound (TUN -> smoltcp) packet queue.
const INBOUND_QUEUE: usize = 512;
/// Channel depth for the outbound (smoltcp -> TUN) packet queue.
const OUTBOUND_QUEUE: usize = 512;
/// Default MTU when the device reports 0. Mirrors Go `defaultMTU`.
const DEFAULT_MTU: usize = 1500;
/// TCP receive/transmit buffer size.
const TCP_BUF_SIZE: usize = 65535;
/// UDP receive/transmit buffer payload size.
const UDP_BUF_SIZE: usize = 65535;
/// UDP metadata queue depth.
const UDP_META_QUEUE: usize = 64;
/// Poll loop sleep when no deadline.
const POLL_IDLE_MS: u64 = 5;
/// Maximum poll loop sleep in milliseconds.
const POLL_MAX_SLEEP_MS: u64 = 100;

/// A raw IP packet.
pub type Packet = Vec<u8>;

/// 4-tuple identifying a connection: (local_ip, local_port, remote_ip, remote_port).
type ConnKey = (IpAddress, u16, IpAddress, u16);
type UdpLocalKey = (IpAddress, u16);

struct TcpPendingWrite {
	data: Vec<u8>,
	reply: oneshot::Sender<io::Result<usize>>,
}

struct UdpPendingWrite {
	data: Vec<u8>,
	remote: (IpAddress, u16),
	reply: oneshot::Sender<io::Result<usize>>,
}

struct UdpFlowState {
	handle: SocketHandle,
	cmd_rx: mpsc::Receiver<UdpSocketCmd>,
	inbound: VecDeque<(Vec<u8>, (IpAddress, u16))>,
	pending_recv: Option<oneshot::Sender<crate::dispatch::UdpRecvReply>>,
	pending_write: Option<UdpPendingWrite>,
}

/// Converts a `std::time::Instant` to a smoltcp `Instant` relative to `start`.
fn smol_now(start: StdInstant) -> SmolInstant {
	SmolInstant::from_micros(start.elapsed().as_micros() as i64)
}

/// Inspects a raw IP packet. Returns `Some(key)` if it is a TCP SYN (no ACK),
/// where `key = (dst_ip, dst_port, src_ip, src_port)`.
fn inspect_syn(packet: &[u8]) -> Option<ConnKey> {
	let version = *packet.first()? >> 4;
	match version {
		4 => {
			let ipv4 = Ipv4Packet::new_checked(packet).ok()?;
			if ipv4.next_header() != IpProtocol::Tcp {
				return None;
			}
			let src = IpAddress::Ipv4(ipv4.src_addr());
			let dst = IpAddress::Ipv4(ipv4.dst_addr());
			let tcp = TcpPacket::new_checked(ipv4.payload()).ok()?;
			if !tcp.syn() || tcp.ack() {
				return None;
			}
			Some((dst, tcp.dst_port(), src, tcp.src_port()))
		}
		6 => {
			let ipv6 = Ipv6Packet::new_checked(packet).ok()?;
			if ipv6.next_header() != IpProtocol::Tcp {
				return None;
			}
			let src = IpAddress::Ipv6(ipv6.src_addr());
			let dst = IpAddress::Ipv6(ipv6.dst_addr());
			let tcp = TcpPacket::new_checked(ipv6.payload()).ok()?;
			if !tcp.syn() || tcp.ack() {
				return None;
			}
			Some((dst, tcp.dst_port(), src, tcp.src_port()))
		}
		_ => None,
	}
}

/// Inspects a raw IP packet. Returns `Some((key, payload))` if it is a UDP
/// packet, where `key = (dst_ip, dst_port, src_ip, src_port)` and `payload`
/// is the UDP payload.
fn inspect_udp(packet: &[u8]) -> Option<(ConnKey, Vec<u8>)> {
	let version = *packet.first()? >> 4;
	match version {
		4 => {
			let ipv4 = Ipv4Packet::new_checked(packet).ok()?;
			if ipv4.next_header() != IpProtocol::Udp {
				return None;
			}
			let src = IpAddress::Ipv4(ipv4.src_addr());
			let dst = IpAddress::Ipv4(ipv4.dst_addr());
			let udp = UdpPacket::new_checked(ipv4.payload()).ok()?;
			Some((
				(dst, udp.dst_port(), src, udp.src_port()),
				udp.payload().to_vec(),
			))
		}
		6 => {
			let ipv6 = Ipv6Packet::new_checked(packet).ok()?;
			if ipv6.next_header() != IpProtocol::Udp {
				return None;
			}
			let src = IpAddress::Ipv6(ipv6.src_addr());
			let dst = IpAddress::Ipv6(ipv6.dst_addr());
			let udp = UdpPacket::new_checked(ipv6.payload()).ok()?;
			Some((
				(dst, udp.dst_port(), src, udp.src_port()),
				udp.payload().to_vec(),
			))
		}
		_ => None,
	}
}

/// Bridge between async TUN I/O and smoltcp's synchronous `Device` trait.
struct TunDevice {
	rx_queue: VecDeque<Packet>,
	tx_queue: VecDeque<Packet>,
	mtu: usize,
}

impl TunDevice {
	fn new(mtu: usize) -> Self {
		Self {
			rx_queue: VecDeque::with_capacity(INBOUND_QUEUE),
			tx_queue: VecDeque::with_capacity(OUTBOUND_QUEUE),
			mtu,
		}
	}

	fn push_rx(&mut self, pkt: Packet) {
		if self.rx_queue.len() < INBOUND_QUEUE {
			self.rx_queue.push_back(pkt);
		}
	}

	fn drain_tx(&mut self) -> Vec<Packet> {
		self.tx_queue.drain(..).collect()
	}
}

impl Device for TunDevice {
	type RxToken<'a> = RxToken;
	type TxToken<'a> = TxToken<'a>;

	fn capabilities(&self) -> DeviceCapabilities {
		let mut caps = DeviceCapabilities::default();
		caps.max_transmission_unit = self.mtu;
		caps.medium = Medium::Ip;
		caps
	}

	fn receive(
		&mut self,
		_timestamp: SmolInstant,
	) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
		let pkt = self.rx_queue.pop_front()?;
		Some((
			RxToken { buffer: pkt },
			TxToken {
				queue: &mut self.tx_queue,
			},
		))
	}

	fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
		Some(TxToken {
			queue: &mut self.tx_queue,
		})
	}
}

struct RxToken {
	buffer: Packet,
}

impl phy::RxToken for RxToken {
	fn consume<R, F>(mut self, f: F) -> R
	where
		F: FnOnce(&mut [u8]) -> R,
	{
		f(&mut self.buffer)
	}
}

struct TxToken<'a> {
	queue: &'a mut VecDeque<Packet>,
}

impl<'a> phy::TxToken for TxToken<'a> {
	fn consume<R, F>(self, len: usize, f: F) -> R
	where
		F: FnOnce(&mut [u8]) -> R,
	{
		let mut buffer = vec![0u8; len];
		let result = f(&mut buffer);
		self.queue.push_back(buffer);
		result
	}
}

/// A connected TCP session presented to the dispatcher.
pub struct TcpSession {
	pub local: (IpAddress, u16),
	pub remote: (IpAddress, u16),
	pub handle: SocketHandle,
	/// Sender for the dispatcher to drive I/O on this socket. The poll loop
	/// owns the corresponding `cmd_rx` and processes commands each iteration.
	pub cmd_tx: mpsc::Sender<TcpSocketCmd>,
}

/// A connected UDP session presented to the dispatcher, with the first
/// datagram already captured.
pub struct UdpSession {
	pub local: (IpAddress, u16),
	pub remote: (IpAddress, u16),
	pub handle: SocketHandle,
	pub first_packet: Vec<u8>,
	/// Sender for the dispatcher to drive I/O on this socket. The poll loop
	/// owns the corresponding `cmd_rx` and processes commands each iteration.
	pub cmd_tx: mpsc::Sender<UdpSocketCmd>,
}

/// Trait implemented by the dispatch layer (P9.9). The netstack invokes the
/// corresponding method when a new TCP or UDP session is accepted.
pub trait SessionHandler: Send + 'static {
	/// Called when a new TCP connection has been accepted.
	fn handle_tcp(&self, session: TcpSession);
	/// Called when a new UDP flow has been accepted.
	fn handle_udp(&self, session: UdpSession);
}

impl<T: SessionHandler + Sync> SessionHandler for std::sync::Arc<T> {
	fn handle_tcp(&self, session: TcpSession) {
		(**self).handle_tcp(session);
	}
	fn handle_udp(&self, session: UdpSession) {
		(**self).handle_udp(session);
	}
}

/// Network stack handle. Owns the channels to the poll-loop thread.
pub struct NetworkStack {
	/// Sender for inbound packets (TUN -> smoltcp).
	rx_tx: mpsc::Sender<Packet>,
	/// Receiver for outbound packets (smoltcp -> TUN).
	tx_rx: parking_lot::Mutex<Option<mpsc::Receiver<Packet>>>,
	/// Stop signal for the poll loop.
	stop_tx: parking_lot::Mutex<Option<oneshot::Sender<()>>>,
	/// Join handle for the poll-loop thread.
	join: parking_lot::Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl NetworkStack {
	/// Builds the smoltcp `Interface`, spawns the poll-loop thread, and
	/// returns a handle.
	///
	/// Mirrors Go `newNetworkStack` (pkg/tunproxy/stack.go:58).
	pub fn new<H>(mtu: u32, addresses: Vec<String>, handler: H) -> io::Result<Self>
	where
		H: SessionHandler,
	{
		let mtu = if mtu == 0 { DEFAULT_MTU } else { mtu as usize };

		// Channels between the async world and the sync poll loop.
		let (rx_tx, rx_rx) = mpsc::channel::<Packet>(INBOUND_QUEUE);
		let (tx_tx, tx_rx) = mpsc::channel::<Packet>(OUTBOUND_QUEUE);
		let (stop_tx, stop_rx) = oneshot::channel::<()>();

		let mut poll_stack = PollLoopStack::new(mtu, addresses, rx_rx, tx_tx, stop_rx, handler)?;

		let join = std::thread::Builder::new()
			.name("tunproxy-netstack".into())
			.spawn(move || poll_stack.run())
			.map_err(|e| io::Error::other(format!("tunproxy: spawn netstack thread: {e}")))?;

		Ok(Self {
			rx_tx,
			tx_rx: parking_lot::Mutex::new(Some(tx_rx)),
			stop_tx: parking_lot::Mutex::new(Some(stop_tx)),
			join: parking_lot::Mutex::new(Some(join)),
		})
	}

	/// Pushes an inbound packet read from the TUN device into the netstack.
	pub async fn push_inbound(&self, pkt: Packet) {
		let _ = self.rx_tx.send(pkt).await;
	}

	/// Drains outbound packets that the netstack wants to write to the TUN.
	pub fn drain_outbound(&self) -> Vec<Packet> {
		let mut out = Vec::new();
		if let Some(rx) = self.tx_rx.lock().as_mut() {
			while let Ok(pkt) = rx.try_recv() {
				out.push(pkt);
			}
		}
		out
	}

	/// Takes ownership of the outbound packet receiver. After this call,
	/// [`drain_outbound`](Self::drain_outbound) returns an empty vector and
	/// [`recv_outbound`](Self::recv_outbound) returns `None`. The outbound
	/// pump ([`crate::pumps`]) uses this to consume packets without holding a
	/// `parking_lot` mutex across `.await`.
	pub fn take_outbound_receiver(&self) -> Option<mpsc::Receiver<Packet>> {
		self.tx_rx.lock().take()
	}

	/// Async-awaits the next outbound packet from the netstack. Returns
	/// `None` when all senders have been dropped (i.e. the poll loop has
	/// exited) or when the receiver has been taken via
	/// [`take_outbound_receiver`](Self::take_outbound_receiver).
	///
	/// This is a fallback used by tests that don't run the pumps; the real
	/// outbound pump owns the receiver via `take_outbound_receiver` and
	/// awaits `recv()` directly.
	pub async fn recv_outbound(&self) -> Option<Packet> {
		loop {
			{
				let mut guard = self.tx_rx.lock();
				match guard.as_mut() {
					None => return None,
					Some(rx) => match rx.try_recv() {
						Ok(pkt) => return Some(pkt),
						Err(mpsc::error::TryRecvError::Empty) => {}
						Err(mpsc::error::TryRecvError::Disconnected) => return None,
					},
				}
			}
			tokio::task::yield_now().await;
		}
	}

	/// Stops the poll loop and waits for the thread to exit. Idempotent.
	pub fn stop(&self) -> io::Result<()> {
		if let Some(stop) = self.stop_tx.lock().take() {
			let _ = stop.send(());
		}
		if let Some(join) = self.join.lock().take() {
			join.join()
				.map_err(|_| io::Error::other("tunproxy: netstack thread panicked"))?;
		}
		Ok(())
	}
}

impl Drop for NetworkStack {
	fn drop(&mut self) {
		let _ = self.stop();
	}
}

/// Owns the smoltcp `Interface`, `SocketSet`, and runs the poll loop on a
/// dedicated OS thread.
struct PollLoopStack<H> {
	iface: Interface,
	device: TunDevice,
	rx_rx: mpsc::Receiver<Packet>,
	tx_tx: mpsc::Sender<Packet>,
	stop_rx: oneshot::Receiver<()>,
	handler: H,
	sockets: SocketSet<'static>,
	/// TCP sockets that have been listened on a specific port but not yet
	/// established. Keyed by 4-tuple.
	pending_tcp: HashMap<ConnKey, SocketHandle>,
	/// Established TCP sessions keyed by socket handle. Value is the 4-tuple.
	established_tcp: HashMap<SocketHandle, ConnKey>,
	/// Shared UDP sockets keyed by original destination endpoint. Individual
	/// client flows are demultiplexed separately by their full 4-tuple.
	udp_sockets: HashMap<UdpLocalKey, SocketHandle>,
	udp_flows: HashMap<ConnKey, UdpFlowState>,
	/// Command receivers for established TCP sessions, keyed by socket handle.
	/// The poll loop drains these each iteration to drive socket I/O.
	tcp_cmd_rx: HashMap<SocketHandle, mpsc::Receiver<TcpSocketCmd>>,
	tcp_pending_read: HashMap<SocketHandle, oneshot::Sender<io::Result<Option<Vec<u8>>>>>,
	tcp_pending_write: HashMap<SocketHandle, TcpPendingWrite>,
	/// Start time for smoltcp timestamps.
	start: StdInstant,
}

impl<H: SessionHandler> PollLoopStack<H> {
	fn new(
		mtu: usize,
		addresses: Vec<String>,
		rx_rx: mpsc::Receiver<Packet>,
		tx_tx: mpsc::Sender<Packet>,
		stop_rx: oneshot::Receiver<()>,
		handler: H,
	) -> io::Result<Self> {
		let start = StdInstant::now();
		let mut device = TunDevice::new(mtu);
		let config = IfaceConfig::new(HardwareAddress::Ip);
		let mut iface = Interface::new(config, &mut device, SmolInstant::from_micros(0));
		let mut gateway4 = None;
		let mut gateway6 = None;

		for addr_str in &addresses {
			let parsed = parse_addr_with_prefix(addr_str).map_err(|e| {
				io::Error::other(format!("tunproxy: parse address {addr_str:?}: {e}"))
			})?;
			let cidr = build_ip_cidr(&parsed.bytes, parsed.prefix_len)?;
			match cidr.address() {
				IpAddress::Ipv4(addr) => {
					gateway4.get_or_insert(addr);
				}
				IpAddress::Ipv6(addr) => {
					gateway6.get_or_insert(addr);
				}
			};
			iface.update_ip_addrs(|addrs| {
				let _ = addrs.push(cidr);
			});
		}

		// Packets routed into a transparent TUN retain their original
		// destination address. Accept those addresses as local and make the
		// corresponding prefixes resolve through one of this interface's own
		// addresses, as required by smoltcp's AnyIP lookup.
		if let Some(gateway) = gateway4 {
			iface.set_any_ip(true);
			iface.routes_mut().add_default_ipv4_route(gateway).ok();
		}
		if let Some(gateway) = gateway6 {
			iface.routes_mut().add_default_ipv6_route(gateway).ok();
		}

		let sockets = SocketSet::new(vec![]);

		Ok(Self {
			iface,
			device,
			rx_rx,
			tx_tx,
			stop_rx,
			handler,
			sockets,
			pending_tcp: HashMap::new(),
			established_tcp: HashMap::new(),
			udp_sockets: HashMap::new(),
			udp_flows: HashMap::new(),
			tcp_cmd_rx: HashMap::new(),
			tcp_pending_read: HashMap::new(),
			tcp_pending_write: HashMap::new(),
			start,
		})
	}

	/// Main poll loop. Runs until `stop_rx` fires.
	///
	/// Mirrors Go `startPumps` (pkg/tunproxy/stack.go:127).
	fn run(&mut self) {
		loop {
			// Check for stop signal.
			if self.stop_rx.try_recv().is_ok() {
				return;
			}

			// Drain inbound packets from the channel into the device queue.
			// Inspect each one to create listeners for new flows before
			// smoltcp sees them (otherwise smoltcp would send RST).
			while let Ok(pkt) = self.rx_rx.try_recv() {
				self.handle_inbound_packet(pkt);
			}

			// Poll smoltcp.
			let now = smol_now(self.start);
			let _ = self.iface.poll(now, &mut self.device, &mut self.sockets);

			// Process session commands (drives TcpSocketStream/UdpSocketStream I/O).
			self.process_tcp_commands();
			self.process_udp_commands();

			// Check established TCP sessions for completion.
			self.process_tcp_sockets();

			// Drain outbound packets from the device queue to the channel.
			for pkt in self.device.drain_tx() {
				let _ = self.tx_tx.try_send(pkt);
			}

			// Compute the next poll deadline.
			let now = smol_now(self.start);
			let poll_delay = self
				.iface
				.poll_delay(now, &self.sockets)
				.unwrap_or(SmolDuration::from_millis(POLL_IDLE_MS))
				.min(SmolDuration::from_millis(POLL_MAX_SLEEP_MS));
			let sleep = std::time::Duration::from_micros(poll_delay.total_micros());
			std::thread::sleep(sleep);
		}
	}

	/// Handles an inbound packet: inspects it for new TCP SYNs and UDP flows,
	/// creates listeners as needed, then enqueues it for smoltcp.
	fn handle_inbound_packet(&mut self, pkt: Packet) {
		let mut enqueue_for_stack = true;
		// TCP SYN: create a listener if this is a new flow.
		if let Some(key) = inspect_syn(&pkt) {
			tracing::debug!(target: "tunproxy", "tcp syn observed: key={:?}", key);
			if !self.pending_tcp.contains_key(&key)
				&& !self.established_tcp.values().any(|v| *v == key)
			{
				self.create_tcp_listener(key);
			}
		}
		// UDP is demultiplexed by the full transparent 4-tuple here. Feeding the
		// same packet into smoltcp would make all flows sharing a destination
		// compete for the first destination-bound UDP socket.
		else if let Some((key, payload)) = inspect_udp(&pkt) {
			enqueue_for_stack = false;
			if let Some(flow) = self.udp_flows.get_mut(&key) {
				let remote = (key.2, key.3);
				if let Some(reply) = flow.pending_recv.take() {
					let _ = reply.send(Ok(Some((payload, remote))));
				} else {
					flow.inbound.push_back((payload, remote));
				}
			} else {
				self.create_udp_flow(key, payload);
			}
		}
		if enqueue_for_stack {
			self.device.push_rx(pkt);
		}
	}

	/// Creates a new TCP socket listening on the given local endpoint.
	fn create_tcp_listener(&mut self, key: ConnKey) {
		let rx_buffer = tcp::SocketBuffer::new(vec![0; TCP_BUF_SIZE]);
		let tx_buffer = tcp::SocketBuffer::new(vec![0; TCP_BUF_SIZE]);
		let mut socket = tcp::Socket::new(rx_buffer, tx_buffer);
		let endpoint = IpListenEndpoint {
			addr: Some(key.0),
			port: key.1,
		};
		if let Err(e) = socket.listen(endpoint) {
			tracing::info!(target: "tunproxy", "tcp listen failed on {:?}: {:?}", endpoint, e);
			return;
		}
		tracing::debug!(target: "tunproxy", "tcp listener created: key={:?}", key);
		let handle = self.sockets.add(socket);
		self.pending_tcp.insert(key, handle);
	}

	/// Creates a logical UDP flow and shares one smoltcp transmit socket with
	/// every flow targeting the same original destination endpoint.
	fn create_udp_flow(&mut self, key: ConnKey, first_packet: Vec<u8>) {
		let local = (key.0, key.1);
		let handle = if let Some(handle) = self.udp_sockets.get(&local) {
			*handle
		} else {
			let rx_buffer = udp::PacketBuffer::new(
				vec![udp::PacketMetadata::EMPTY; UDP_META_QUEUE],
				vec![0; UDP_BUF_SIZE],
			);
			let tx_buffer = udp::PacketBuffer::new(
				vec![udp::PacketMetadata::EMPTY; UDP_META_QUEUE],
				vec![0; UDP_BUF_SIZE],
			);
			let mut socket = udp::Socket::new(rx_buffer, tx_buffer);
			let endpoint = IpListenEndpoint {
				addr: Some(key.0),
				port: key.1,
			};
			if let Err(e) = socket.bind(endpoint) {
				tracing::debug!(target: "tunproxy", "udp bind failed on {endpoint:?}: {e:?}");
				return;
			}
			let handle = self.sockets.add(socket);
			self.udp_sockets.insert(local, handle);
			handle
		};

		let (cmd_tx, cmd_rx) = mpsc::channel::<UdpSocketCmd>(crate::dispatch::SOCKET_CMD_CHANNEL);
		let remote = (key.2, key.3);
		self.udp_flows.insert(
			key,
			UdpFlowState {
				handle,
				cmd_rx,
				inbound: VecDeque::from([(first_packet.clone(), remote)]),
				pending_recv: None,
				pending_write: None,
			},
		);
		let session = UdpSession {
			local,
			remote,
			handle,
			first_packet,
			cmd_tx,
		};
		self.handler.handle_udp(session);
	}

	/// Inspects pending and established TCP sockets for state transitions
	/// and dispatches established connections to the handler.
	fn process_tcp_sockets(&mut self) {
		// Check pending sockets for establishment.
		let pending_keys: Vec<_> = self.pending_tcp.keys().cloned().collect();
		for key in pending_keys {
			let handle = *self.pending_tcp.get(&key).unwrap();
			let socket = self.sockets.get_mut::<tcp::Socket>(handle);
			tracing::debug!(
				target: "tunproxy",
				"tcp pending socket state: key={:?} is_open={} is_listening={} may_send={} is_active={}",
				key, socket.is_open(), socket.is_listening(), socket.may_send(), socket.is_active()
			);
			// Dispatch only once the socket reaches ESTABLISHED (or
			// CLOSE-WAIT). `is_active()` is true in SYN-RECEIVED which is
			// too early; `may_send()` is true only after the 3-way
			// handshake completes.
			if socket.may_send() {
				// Connection established. Remove from pending and dispatch.
				self.pending_tcp.remove(&key);
				self.established_tcp.insert(handle, key);
				// Create the command channel for this session. The poll loop
				// keeps `cmd_rx`; the dispatcher gets `cmd_tx` via the session.
				let (cmd_tx, cmd_rx) =
					mpsc::channel::<TcpSocketCmd>(crate::dispatch::SOCKET_CMD_CHANNEL);
				self.tcp_cmd_rx.insert(handle, cmd_rx);
				let session = TcpSession {
					local: (key.0, key.1),
					remote: (key.2, key.3),
					handle,
					cmd_tx,
				};
				self.handler.handle_tcp(session);
			} else if !socket.is_listening() && !socket.is_open() {
				// Connection failed or closed. Remove.
				self.pending_tcp.remove(&key);
				self.sockets.remove(handle);
			}
		}

		// Check established sockets for closure.
		let established_handles: Vec<_> = self.established_tcp.keys().cloned().collect();
		for handle in established_handles {
			let socket = self.sockets.get_mut::<tcp::Socket>(handle);
			if !socket.is_open() {
				self.established_tcp.remove(&handle);
				self.tcp_cmd_rx.remove(&handle);
				if let Some(reply) = self.tcp_pending_read.remove(&handle) {
					let _ = reply.send(Ok(None));
				}
				if let Some(pending) = self.tcp_pending_write.remove(&handle) {
					let _ = pending.reply.send(Err(io::Error::new(
						io::ErrorKind::BrokenPipe,
						"tunproxy: TCP socket closed",
					)));
				}
				self.sockets.remove(handle);
			}
		}
	}

	/// Drains pending commands from each established TCP session's `cmd_rx`
	/// and applies them to the corresponding smoltcp socket. Mirrors the
	/// per-socket I/O dispatch in Go's `handleConn`.
	fn process_tcp_commands(&mut self) {
		let handles: Vec<_> = self.tcp_cmd_rx.keys().cloned().collect();
		for handle in handles {
			let mut commands = Vec::new();
			let mut disconnected = false;
			if let Some(cmd_rx) = self.tcp_cmd_rx.get_mut(&handle) {
				loop {
					match cmd_rx.try_recv() {
						Ok(cmd) => commands.push(cmd),
						Err(mpsc::error::TryRecvError::Empty) => break,
						Err(mpsc::error::TryRecvError::Disconnected) => {
							disconnected = true;
							break;
						}
					}
				}
			}

			let mut close = false;
			for cmd in commands {
				match cmd {
					TcpSocketCmd::Read { reply } => {
						if self.tcp_pending_read.insert(handle, reply).is_some() {
							tracing::warn!(target: "tunproxy", "duplicate pending TCP read");
						}
					}
					TcpSocketCmd::Write { data, reply } => {
						if self
							.tcp_pending_write
							.insert(handle, TcpPendingWrite { data, reply })
							.is_some()
						{
							tracing::warn!(target: "tunproxy", "duplicate pending TCP write");
						}
					}
					TcpSocketCmd::Close => {
						close = true;
					}
				}
			}

			if close || disconnected {
				let socket = self.sockets.get_mut::<tcp::Socket>(handle);
				socket.close();
				self.tcp_cmd_rx.remove(&handle);
			}

			let read_ready = {
				let socket = self.sockets.get::<tcp::Socket>(handle);
				socket.can_recv() || !socket.may_recv()
			};
			if read_ready {
				if let Some(reply) = self.tcp_pending_read.remove(&handle) {
					let socket = self.sockets.get_mut::<tcp::Socket>(handle);
					let result = if socket.can_recv() {
						let mut buf = vec![0u8; TCP_BUF_SIZE];
						match socket.recv_slice(&mut buf) {
							Ok(0) => Ok(None),
							Ok(n) => {
								buf.truncate(n);
								Ok(Some(buf))
							}
							Err(e) => Err(io::Error::other(format!("smoltcp recv: {e:?}"))),
						}
					} else {
						Ok(None)
					};
					let _ = reply.send(result);
				}
			}

			let write_ready = {
				let socket = self.sockets.get::<tcp::Socket>(handle);
				socket.can_send() || !socket.may_send()
			};
			if write_ready {
				if let Some(pending) = self.tcp_pending_write.remove(&handle) {
					let socket = self.sockets.get_mut::<tcp::Socket>(handle);
					let result = if socket.can_send() {
						socket
							.send_slice(&pending.data)
							.map_err(|e| io::Error::other(format!("smoltcp send: {e:?}")))
					} else {
						Err(io::Error::new(
							io::ErrorKind::BrokenPipe,
							"tunproxy: TCP socket closed",
						))
					};
					let _ = pending.reply.send(result);
				}
			}
		}
	}

	/// Drains pending commands from each active UDP session's `cmd_rx` and
	/// applies them to the corresponding smoltcp socket.
	fn process_udp_commands(&mut self) {
		let keys: Vec<_> = self.udp_flows.keys().copied().collect();
		for key in keys {
			let mut commands = Vec::new();
			let mut disconnected = false;
			if let Some(flow) = self.udp_flows.get_mut(&key) {
				loop {
					match flow.cmd_rx.try_recv() {
						Ok(cmd) => commands.push(cmd),
						Err(mpsc::error::TryRecvError::Empty) => break,
						Err(mpsc::error::TryRecvError::Disconnected) => {
							disconnected = true;
							break;
						}
					}
				}
			}

			let mut close = false;
			for cmd in commands {
				match cmd {
					UdpSocketCmd::Recv { reply } => {
						if let Some(flow) = self.udp_flows.get_mut(&key) {
							if let Some(datagram) = flow.inbound.pop_front() {
								let _ = reply.send(Ok(Some(datagram)));
							} else if flow.pending_recv.replace(reply).is_some() {
								tracing::warn!(target: "tunproxy", "duplicate pending UDP receive");
							}
						}
					}
					UdpSocketCmd::Send {
						data,
						remote,
						reply,
					} => {
						if let Some(flow) = self.udp_flows.get_mut(&key) {
							if flow
								.pending_write
								.replace(UdpPendingWrite {
									data,
									remote,
									reply,
								})
								.is_some()
							{
								tracing::warn!(target: "tunproxy", "duplicate pending UDP write");
							}
						}
					}
					UdpSocketCmd::Close => {
						close = true;
					}
				}
			}

			if close || disconnected {
				self.remove_udp_flow(key);
				continue;
			}

			let (handle, send_ready) = match self.udp_flows.get(&key) {
				Some(flow) => {
					let handle = flow.handle;
					let ready = self.sockets.get::<udp::Socket>(handle).can_send();
					(handle, ready)
				}
				None => continue,
			};
			if send_ready {
				let pending = self
					.udp_flows
					.get_mut(&key)
					.and_then(|flow| flow.pending_write.take());
				if let Some(pending) = pending {
					let endpoint = IpEndpoint {
						addr: pending.remote.0,
						port: pending.remote.1,
					};
					let result = self
						.sockets
						.get_mut::<udp::Socket>(handle)
						.send_slice(&pending.data, endpoint)
						.map(|()| pending.data.len())
						.map_err(|e| io::Error::other(format!("smoltcp udp send: {e:?}")));
					let _ = pending.reply.send(result);
				}
			}
		}
	}

	fn remove_udp_flow(&mut self, key: ConnKey) {
		let Some(mut flow) = self.udp_flows.remove(&key) else {
			return;
		};
		if let Some(reply) = flow.pending_recv.take() {
			let _ = reply.send(Ok(None));
		}
		if let Some(pending) = flow.pending_write.take() {
			let _ = pending.reply.send(Err(io::Error::new(
				io::ErrorKind::BrokenPipe,
				"tunproxy: UDP flow closed",
			)));
		}
		let handle = flow.handle;
		if !self.udp_flows.values().any(|other| other.handle == handle) {
			self.udp_sockets.retain(|_, value| *value != handle);
			self.sockets.remove(handle);
		}
	}
}

/// Builds a smoltcp `IpCidr` from raw address bytes and prefix length.
fn build_ip_cidr(bytes: &[u8], prefix_len: i32) -> io::Result<IpCidr> {
	match bytes.len() {
		4 => {
			let mut arr = [0u8; 4];
			arr.copy_from_slice(bytes);
			Ok(IpCidr::new(
				IpAddress::Ipv4(Ipv4Address(arr)),
				prefix_len as u8,
			))
		}
		16 => {
			let mut arr = [0u8; 16];
			arr.copy_from_slice(bytes);
			Ok(IpCidr::new(
				IpAddress::Ipv6(Ipv6Address(arr)),
				prefix_len as u8,
			))
		}
		_ => Err(io::Error::other("tunproxy: unsupported address length")),
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use smoltcp::phy::{RxToken as _, TxToken as _};
	use std::time::Duration;

	#[test]
	fn inspect_syn_ipv4() {
		// Minimal IPv4 SYN: 20-byte IP header + 20-byte TCP header.
		let mut pkt = vec![0u8; 40];
		// IP version 4, IHL 5.
		pkt[0] = 0x45;
		// Total length = 40.
		pkt[2..4].copy_from_slice(&40u16.to_be_bytes());
		// Protocol = TCP (6).
		pkt[9] = 6;
		// Source IP 10.0.0.2.
		pkt[12..16].copy_from_slice(&[10, 0, 0, 2]);
		// Destination IP 10.0.0.1.
		pkt[16..20].copy_from_slice(&[10, 0, 0, 1]);
		// TCP src port 12345.
		pkt[20..22].copy_from_slice(&12345u16.to_be_bytes());
		// TCP dst port 80.
		pkt[22..24].copy_from_slice(&80u16.to_be_bytes());
		// Data offset = 5 (20 bytes), SYN flag (0x02). Flags field is bytes 32-33
		// (big-endian), upper 4 bits = data offset.
		pkt[32..34].copy_from_slice(&0x5002u16.to_be_bytes());

		let key = inspect_syn(&pkt).expect("should detect SYN");
		assert_eq!(key.0, IpAddress::Ipv4(Ipv4Address([10, 0, 0, 1])));
		assert_eq!(key.1, 80);
		assert_eq!(key.2, IpAddress::Ipv4(Ipv4Address([10, 0, 0, 2])));
		assert_eq!(key.3, 12345);
	}

	#[test]
	fn inspect_syn_rejects_syn_ack() {
		let mut pkt = vec![0u8; 40];
		pkt[0] = 0x45;
		pkt[2..4].copy_from_slice(&40u16.to_be_bytes());
		pkt[9] = 6;
		pkt[12..16].copy_from_slice(&[10, 0, 0, 2]);
		pkt[16..20].copy_from_slice(&[10, 0, 0, 1]);
		pkt[20..22].copy_from_slice(&12345u16.to_be_bytes());
		pkt[22..24].copy_from_slice(&80u16.to_be_bytes());
		// Data offset = 5, SYN+ACK (0x12).
		pkt[32..34].copy_from_slice(&0x5012u16.to_be_bytes());

		assert!(inspect_syn(&pkt).is_none());
	}

	#[test]
	fn inspect_syn_rejects_non_tcp() {
		let mut pkt = vec![0u8; 40];
		pkt[0] = 0x45;
		pkt[2..4].copy_from_slice(&40u16.to_be_bytes());
		// Protocol = UDP (17).
		pkt[9] = 17;
		pkt[33] = 0x02;

		assert!(inspect_syn(&pkt).is_none());
	}

	#[test]
	fn inspect_syn_rejects_empty() {
		assert!(inspect_syn(&[]).is_none());
	}

	#[test]
	fn inspect_udp_ipv4() {
		// IPv4 header (20) + UDP header (8) + payload.
		let mut pkt = vec![0u8; 28 + 4];
		pkt[0] = 0x45;
		// IP total length = 32.
		pkt[2..4].copy_from_slice(&32u16.to_be_bytes());
		// Protocol = UDP.
		pkt[9] = 17;
		pkt[12..16].copy_from_slice(&[10, 0, 0, 2]);
		pkt[16..20].copy_from_slice(&[10, 0, 0, 1]);
		// UDP src port.
		pkt[20..22].copy_from_slice(&5353u16.to_be_bytes());
		// UDP dst port.
		pkt[22..24].copy_from_slice(&53u16.to_be_bytes());
		// UDP length = 12 (header + 4 payload).
		pkt[24..26].copy_from_slice(&12u16.to_be_bytes());
		// Payload.
		pkt[28..32].copy_from_slice(b"test");

		let (key, payload) = inspect_udp(&pkt).expect("should detect UDP");
		assert_eq!(key.0, IpAddress::Ipv4(Ipv4Address([10, 0, 0, 1])));
		assert_eq!(key.1, 53);
		assert_eq!(key.2, IpAddress::Ipv4(Ipv4Address([10, 0, 0, 2])));
		assert_eq!(key.3, 5353);
		assert_eq!(payload, b"test");
	}

	#[test]
	fn inspect_udp_rejects_non_udp() {
		let mut pkt = vec![0u8; 28];
		pkt[0] = 0x45;
		pkt[2..4].copy_from_slice(&28u16.to_be_bytes());
		// Protocol = TCP.
		pkt[9] = 6;
		assert!(inspect_udp(&pkt).is_none());
	}

	#[test]
	fn tun_device_push_and_pop() {
		let mut dev = TunDevice::new(1500);
		dev.push_rx(vec![1, 2, 3]);
		dev.push_rx(vec![4, 5, 6]);
		assert_eq!(dev.drain_tx(), Vec::<Vec<u8>>::new());
		let (rx, _tx) = dev.receive(SmolInstant::from_micros(0)).unwrap();
		rx.consume(|buf| {
			assert_eq!(buf, &[1, 2, 3]);
		});
	}

	#[test]
	fn tun_device_tx_token_enqueues() {
		let mut dev = TunDevice::new(1500);
		let tx = dev.transmit(SmolInstant::from_micros(0)).unwrap();
		tx.consume(5, |buf| {
			buf[..3].copy_from_slice(b"hi!");
		});
		let drained = dev.drain_tx();
		assert_eq!(drained.len(), 1);
		assert_eq!(&drained[0][..3], b"hi!");
		assert_eq!(drained[0].len(), 5);
	}

	#[test]
	fn tun_device_capabilities() {
		let dev = TunDevice::new(9000);
		let caps = dev.capabilities();
		assert_eq!(caps.max_transmission_unit, 9000);
		assert_eq!(caps.medium, Medium::Ip);
	}

	#[test]
	fn build_ip_cidr_v4() {
		let cidr = build_ip_cidr(&[10, 0, 0, 1], 24).unwrap();
		assert_eq!(cidr.address(), IpAddress::Ipv4(Ipv4Address([10, 0, 0, 1])));
		assert_eq!(cidr.prefix_len(), 24);
	}

	#[test]
	fn build_ip_cidr_v6() {
		let cidr = build_ip_cidr(&[0xfd; 16], 64).unwrap();
		match cidr.address() {
			IpAddress::Ipv6(addr) => assert_eq!(addr.0, [0xfd; 16]),
			_ => panic!("expected Ipv6"),
		}
		assert_eq!(cidr.prefix_len(), 64);
	}

	#[test]
	fn build_ip_cidr_invalid_length() {
		assert!(build_ip_cidr(&[1, 2, 3], 24).is_err());
	}

	struct CounterHandler {
		tcp: std::sync::atomic::AtomicUsize,
		udp: std::sync::atomic::AtomicUsize,
	}

	impl CounterHandler {
		fn new() -> Self {
			Self {
				tcp: std::sync::atomic::AtomicUsize::new(0),
				udp: std::sync::atomic::AtomicUsize::new(0),
			}
		}
	}

	impl SessionHandler for CounterHandler {
		fn handle_tcp(&self, _session: TcpSession) {
			self.tcp.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
		}
		fn handle_udp(&self, _session: UdpSession) {
			self.udp.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
		}
	}

	#[tokio::test]
	async fn network_stack_start_stop() {
		let handler = CounterHandler::new();
		let stack = NetworkStack::new(1500, vec!["10.0.0.1/24".to_string()], handler).unwrap();
		// Verify it can be stopped cleanly.
		stack.stop().unwrap();
	}

	#[tokio::test]
	async fn network_stack_invalid_address() {
		let handler = CounterHandler::new();
		let result = NetworkStack::new(1500, vec!["not-an-ip".to_string()], handler);
		assert!(result.is_err());
	}

	#[tokio::test]
	async fn network_stack_default_mtu() {
		let handler = CounterHandler::new();
		let stack = NetworkStack::new(0, vec!["10.0.0.1/24".to_string()], handler).unwrap();
		stack.stop().unwrap();
	}

	#[tokio::test]
	async fn network_stack_drain_outbound_empty() {
		let handler = CounterHandler::new();
		let stack = NetworkStack::new(1500, vec!["10.0.0.1/24".to_string()], handler).unwrap();
		// Give the thread a moment to start.
		tokio::time::sleep(Duration::from_millis(10)).await;
		let out = stack.drain_outbound();
		assert!(out.is_empty());
		stack.stop().unwrap();
	}

	#[tokio::test]
	async fn network_stack_push_inbound_no_crash() {
		let handler = CounterHandler::new();
		let stack = NetworkStack::new(1500, vec!["10.0.0.1/24".to_string()], handler).unwrap();
		// Push a garbage packet; the stack should not crash.
		stack.push_inbound(vec![0x45, 0x00]).await;
		tokio::time::sleep(Duration::from_millis(20)).await;
		stack.stop().unwrap();
	}
}
