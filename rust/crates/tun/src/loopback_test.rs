//! P9.11 loopback integration tests: drive the full smoltcp netstack with
//! pre-orchestrated IP packets and verify TCP/UDP sessions are dispatched to
//! the handler with correct session metadata.
//!
//! These tests do **not** require root or a real TUN device. They use the
//! `NetworkStack`'s `push_inbound` / `drain_outbound` channels as a virtual
//! TUN fd, mirroring the Go `stack_test.go` approach but adapted to smoltcp's
//! packet-level API.
//!
//! Mirrors Go `pkg/tunproxy/stack_test.go` and `dispatch_test.go` integration
//! scenarios that exercise the full accept → dispatch → relay path.

use std::sync::Arc;
use std::time::Duration;

use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{
	IpAddress, IpProtocol, Ipv4Address, Ipv4Packet, TcpControl, TcpPacket, TcpRepr, TcpSeqNumber,
};

use crate::dispatch::TcpSocketCmd;
use crate::stack::{NetworkStack, SessionHandler, TcpSession, UdpSession};

/// Source IP used by the "client" (pretend host on the TUN network).
const CLIENT_IP: [u8; 4] = [10, 0, 0, 2];
/// TUN-local IP (matches the address configured on the netstack).
const TUN_IP: [u8; 4] = [10, 0, 0, 1];
const PUBLIC_IP: [u8; 4] = [203, 0, 113, 10];

/// Builds a raw IPv4 + TCP packet from a high-level `TcpRepr`.
fn build_tcp_packet(src: [u8; 4], dst: [u8; 4], tcp: &TcpRepr<'_>) -> Vec<u8> {
	let tcp_len = tcp.buffer_len();
	let total_len = 20 + tcp_len;
	let mut buf = vec![0u8; total_len];

	// IPv4 header.
	buf[0] = 0x45; // version 4, IHL 5.
	buf[1] = 0x00; // DSCP/ECN.
	buf[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
	buf[4..6].copy_from_slice(&0u16.to_be_bytes()); // identification.
	buf[6..8].copy_from_slice(&0u16.to_be_bytes()); // flags + frag offset.
	buf[8] = 64; // hop limit.
	buf[9] = IpProtocol::Tcp.into();
	// checksum 0 (smoltcp verifies on receive; we leave it zeroed).
	buf[10..12].copy_from_slice(&0u16.to_be_bytes());
	buf[12..16].copy_from_slice(&src);
	buf[16..20].copy_from_slice(&dst);

	// Fill IPv4 header checksum.
	{
		let mut pkt = Ipv4Packet::new_unchecked(&mut buf);
		pkt.fill_checksum();
	}

	// TCP header + payload.
	{
		let mut tcp_pkt = TcpPacket::new_unchecked(&mut buf[20..]);
		tcp.emit(
			&mut tcp_pkt,
			&IpAddress::Ipv4(Ipv4Address(src)),
			&IpAddress::Ipv4(Ipv4Address(dst)),
			&ChecksumCapabilities::default(),
		);
	}

	buf
}

fn build_udp_packet(
	src: [u8; 4],
	dst: [u8; 4],
	src_port: u16,
	dst_port: u16,
	payload: &[u8],
) -> Vec<u8> {
	let udp_len = 8 + payload.len();
	let total_len = 20 + udp_len;
	let mut pkt = vec![0u8; total_len];
	pkt[0] = 0x45;
	pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
	pkt[8] = 64;
	pkt[9] = IpProtocol::Udp.into();
	pkt[12..16].copy_from_slice(&src);
	pkt[16..20].copy_from_slice(&dst);
	{
		let mut ip = Ipv4Packet::new_unchecked(&mut pkt);
		ip.fill_checksum();
	}
	pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
	pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
	pkt[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
	pkt[28..].copy_from_slice(payload);
	pkt
}

/// Handler that captures dispatched sessions for the test to inspect. The
/// handler is moved into the netstack thread (which has no tokio runtime),
/// so we use `std::sync::Mutex` and push synchronously rather than spawning.
#[derive(Clone)]
struct CaptureHandler {
	tcp_sessions: Arc<std::sync::Mutex<Vec<TcpSession>>>,
	udp_sessions: Arc<std::sync::Mutex<Vec<UdpSession>>>,
}

impl CaptureHandler {
	fn new() -> Self {
		Self {
			tcp_sessions: Arc::new(std::sync::Mutex::new(Vec::new())),
			udp_sessions: Arc::new(std::sync::Mutex::new(Vec::new())),
		}
	}
}

impl SessionHandler for CaptureHandler {
	fn handle_tcp(&self, session: TcpSession) {
		self.tcp_sessions.lock().unwrap().push(session);
	}
	fn handle_udp(&self, session: UdpSession) {
		self.udp_sessions.lock().unwrap().push(session);
	}
}

/// Drains `stack.drain_outbound()` repeatedly for up to `timeout`, returning
/// all collected packets.
async fn collect_outbound(stack: &NetworkStack, timeout: Duration) -> Vec<Vec<u8>> {
	let deadline = tokio::time::Instant::now() + timeout;
	let mut out = Vec::new();
	while tokio::time::Instant::now() < deadline {
		let drained = stack.drain_outbound();
		out.extend(drained);
		tokio::time::sleep(Duration::from_millis(2)).await;
	}
	out
}

/// Returns the first TCP packet in `packets` matching `src_port`/`dst_port`,
/// parsed into a `TcpRepr`.
fn find_tcp<'a>(packets: &'a [Vec<u8>], src_port: u16, dst_port: u16) -> Option<TcpRepr<'a>> {
	for pkt in packets {
		if pkt.len() < 40 {
			continue;
		}
		if pkt[0] >> 4 != 4 {
			continue;
		}
		let ipv4 = Ipv4Packet::new_checked(pkt).ok()?;
		if ipv4.next_header() != IpProtocol::Tcp {
			continue;
		}
		let tcp = TcpPacket::new_checked(ipv4.payload()).ok()?;
		if tcp.src_port() != src_port || tcp.dst_port() != dst_port {
			continue;
		}
		let src = IpAddress::Ipv4(ipv4.src_addr());
		let dst = IpAddress::Ipv4(ipv4.dst_addr());
		return TcpRepr::parse(&tcp, &src, &dst, &ChecksumCapabilities::default()).ok();
	}
	None
}

#[tokio::test]
async fn loopback_tcp_syn_creates_listener_and_emits_synack() {
	let handler = CaptureHandler::new();
	let stack = NetworkStack::new(1500, vec!["10.0.0.1/24".to_string()], handler.clone())
		.expect("NetworkStack::new");

	// Build a TCP SYN: client 10.0.0.2:12345 -> TUN 10.0.0.1:80.
	let syn = TcpRepr {
		src_port: 12345,
		dst_port: 80,
		control: TcpControl::Syn,
		seq_number: TcpSeqNumber(1000),
		ack_number: None,
		window_len: 65535,
		window_scale: None,
		max_seg_size: Some(1460),
		sack_permitted: true,
		sack_ranges: [None; 3],
		payload: &[],
	};
	let pkt = build_tcp_packet(CLIENT_IP, TUN_IP, &syn);
	stack.push_inbound(pkt).await;

	// Give the poll loop time to process and emit a SYN-ACK.
	let outbound = collect_outbound(&stack, Duration::from_millis(200)).await;

	// The netstack should have emitted a SYN-ACK from TUN:80 -> client:12345.
	let synack = find_tcp(&outbound, 80, 12345);
	assert!(
		synack.is_some(),
		"expected SYN-ACK from :80 to :12345 in {} outbound packets",
		outbound.len()
	);
	let synack = synack.unwrap();
	assert_eq!(synack.control, TcpControl::Syn);
	assert!(synack.ack_number.is_some());

	// Verify the handler has NOT yet been called (connection not established
	// until we complete the 3-way handshake).
	tokio::time::sleep(Duration::from_millis(20)).await;
	let tcp = handler.tcp_sessions.lock().unwrap();
	assert!(
		tcp.is_empty(),
		"handler should not be called until 3-way handshake completes"
	);

	stack.stop().unwrap();
}

#[tokio::test]
async fn transparent_tcp_syn_to_public_destination_emits_synack() {
	let handler = CaptureHandler::new();
	let stack = NetworkStack::new(1500, vec!["10.0.0.1/24".to_string()], handler)
		.expect("NetworkStack::new");
	let syn = TcpRepr {
		src_port: 12346,
		dst_port: 443,
		control: TcpControl::Syn,
		seq_number: TcpSeqNumber(2000),
		ack_number: None,
		window_len: 65535,
		window_scale: None,
		max_seg_size: Some(1460),
		sack_permitted: true,
		sack_ranges: [None; 3],
		payload: &[],
	};
	stack
		.push_inbound(build_tcp_packet(CLIENT_IP, PUBLIC_IP, &syn))
		.await;
	let outbound = collect_outbound(&stack, Duration::from_millis(200)).await;
	assert!(
		find_tcp(&outbound, 443, 12346).is_some(),
		"transparent public destination was not accepted"
	);
	stack.stop().unwrap();
}

#[tokio::test]
async fn loopback_tcp_three_way_handshake_dispatches_session() {
	let handler = CaptureHandler::new();
	let stack = NetworkStack::new(1500, vec!["10.0.0.1/24".to_string()], handler.clone())
		.expect("NetworkStack::new");

	let client_isn = TcpSeqNumber(1000);
	let client_port = 23456;
	let tun_port = 443;

	// 1. Send SYN.
	let syn = TcpRepr {
		src_port: client_port,
		dst_port: tun_port,
		control: TcpControl::Syn,
		seq_number: client_isn,
		ack_number: None,
		window_len: 65535,
		window_scale: None,
		max_seg_size: Some(1460),
		sack_permitted: true,
		sack_ranges: [None; 3],
		payload: &[],
	};
	stack
		.push_inbound(build_tcp_packet(CLIENT_IP, TUN_IP, &syn))
		.await;

	// 2. Collect SYN-ACK.
	let outbound = collect_outbound(&stack, Duration::from_millis(200)).await;
	let synack = find_tcp(&outbound, tun_port, client_port).expect("expected SYN-ACK");
	assert_eq!(synack.control, TcpControl::Syn);
	let tun_isn = synack.seq_number;
	let tun_ack = synack.ack_number.expect("SYN-ACK must have ACK");

	// 3. Send ACK to complete the handshake.
	let ack = TcpRepr {
		src_port: client_port,
		dst_port: tun_port,
		control: TcpControl::None,
		seq_number: tun_ack,
		ack_number: Some(tun_isn + 1),
		window_len: 65535,
		window_scale: None,
		max_seg_size: None,
		sack_permitted: false,
		sack_ranges: [None; 3],
		payload: &[],
	};
	stack
		.push_inbound(build_tcp_packet(CLIENT_IP, TUN_IP, &ack))
		.await;

	// 4. Wait for the handler to be called with the session.
	let session = tokio::time::timeout(Duration::from_millis(500), async {
		loop {
			let session = {
				let guard = handler.tcp_sessions.lock().unwrap();
				if guard.is_empty() {
					None
				} else {
					Some(guard[0].clone_handle())
				}
			};
			match session {
				Some(s) => return s,
				None => tokio::time::sleep(Duration::from_millis(5)).await,
			}
		}
	})
	.await
	.expect("handler not called after 3-way handshake");

	// Verify session metadata.
	assert_eq!(session.local.0, IpAddress::Ipv4(Ipv4Address(TUN_IP)));
	assert_eq!(session.local.1, tun_port);
	assert_eq!(session.remote.0, IpAddress::Ipv4(Ipv4Address(CLIENT_IP)));
	assert_eq!(session.remote.1, client_port);

	stack.stop().unwrap();
}

#[tokio::test]
async fn loopback_tcp_data_round_trip_through_command_channel() {
	let handler = CaptureHandler::new();
	let stack = NetworkStack::new(1500, vec!["10.0.0.1/24".to_string()], handler.clone())
		.expect("NetworkStack::new");

	let client_isn = TcpSeqNumber(7000);
	let client_port = 34567;
	let tun_port = 8080;

	// 3-way handshake (same as above).
	let syn = TcpRepr {
		src_port: client_port,
		dst_port: tun_port,
		control: TcpControl::Syn,
		seq_number: client_isn,
		ack_number: None,
		window_len: 65535,
		window_scale: None,
		max_seg_size: Some(1460),
		sack_permitted: true,
		sack_ranges: [None; 3],
		payload: &[],
	};
	stack
		.push_inbound(build_tcp_packet(CLIENT_IP, TUN_IP, &syn))
		.await;
	let outbound = collect_outbound(&stack, Duration::from_millis(200)).await;
	let synack = find_tcp(&outbound, tun_port, client_port).expect("SYN-ACK");
	let tun_isn = synack.seq_number;
	let tun_ack = synack.ack_number.unwrap();

	let ack = TcpRepr {
		src_port: client_port,
		dst_port: tun_port,
		control: TcpControl::None,
		seq_number: tun_ack,
		ack_number: Some(tun_isn + 1),
		window_len: 65535,
		window_scale: None,
		max_seg_size: None,
		sack_permitted: false,
		sack_ranges: [None; 3],
		payload: &[],
	};
	stack
		.push_inbound(build_tcp_packet(CLIENT_IP, TUN_IP, &ack))
		.await;

	// Wait for the handler to receive the session.
	let session = tokio::time::timeout(Duration::from_millis(500), async {
		loop {
			let cmd_tx = {
				let guard = handler.tcp_sessions.lock().unwrap();
				if guard.is_empty() {
					None
				} else {
					Some(guard[0].cmd_tx.clone())
				}
			};
			match cmd_tx {
				Some(tx) => return tx,
				None => tokio::time::sleep(Duration::from_millis(5)).await,
			}
		}
	})
	.await
	.expect("handler not called");

	// Issue the read before data arrives. The poll loop must retain it instead
	// of reporting a false EOF while the smoltcp socket is temporarily empty.
	let (reply_tx, mut reply_rx) = tokio::sync::oneshot::channel();
	session
		.send(TcpSocketCmd::Read { reply: reply_tx })
		.await
		.expect("send Read cmd");
	tokio::time::sleep(Duration::from_millis(20)).await;
	assert!(matches!(
		reply_rx.try_recv(),
		Err(tokio::sync::oneshot::error::TryRecvError::Empty)
	));

	// Send a data packet from the client.
	let payload = b"hello tun!";
	let data_pkt = TcpRepr {
		src_port: client_port,
		dst_port: tun_port,
		control: TcpControl::Psh,
		seq_number: tun_ack,
		ack_number: Some(tun_isn + 1),
		window_len: 65535,
		window_scale: None,
		max_seg_size: None,
		sack_permitted: false,
		sack_ranges: [None; 3],
		payload,
	};
	stack
		.push_inbound(build_tcp_packet(CLIENT_IP, TUN_IP, &data_pkt))
		.await;

	let read_result = tokio::time::timeout(Duration::from_millis(500), reply_rx)
		.await
		.expect("read timeout")
		.expect("reply dropped");
	let data = read_result.expect("read error");
	assert!(data.is_some(), "expected Some(data) from read, got None");
	let data = data.unwrap();
	assert!(
		data.windows(payload.len()).any(|w| w == payload),
		"expected {:?} in read data {:?}",
		payload,
		data
	);

	stack.stop().unwrap();
}

#[tokio::test]
async fn loopback_udp_packet_dispatches_session_with_first_packet() {
	let handler = CaptureHandler::new();
	let stack = NetworkStack::new(1500, vec!["10.0.0.1/24".to_string()], handler.clone())
		.expect("NetworkStack::new");

	// Build a UDP packet: client 10.0.0.2:5353 -> TUN 10.0.0.1:53.
	let src_port: u16 = 5353;
	let dst_port: u16 = 53;
	let payload = b"query";
	stack
		.push_inbound(build_udp_packet(
			CLIENT_IP, TUN_IP, src_port, dst_port, payload,
		))
		.await;

	// Wait for the handler to receive the UDP session.
	let session = tokio::time::timeout(Duration::from_millis(500), async {
		loop {
			let session = {
				let guard = handler.udp_sessions.lock().unwrap();
				if guard.is_empty() {
					None
				} else {
					Some(guard[0].clone_for_inspect())
				}
			};
			match session {
				Some(s) => return s,
				None => tokio::time::sleep(Duration::from_millis(5)).await,
			}
		}
	})
	.await
	.expect("UDP handler not called");

	// Verify session metadata.
	assert_eq!(session.local.0, IpAddress::Ipv4(Ipv4Address(TUN_IP)));
	assert_eq!(session.local.1, dst_port);
	assert_eq!(session.remote.0, IpAddress::Ipv4(Ipv4Address(CLIENT_IP)));
	assert_eq!(session.remote.1, src_port);
	// The first_packet should contain the UDP payload.
	assert_eq!(
		session.first_packet, payload,
		"first_packet should carry the UDP payload"
	);

	stack.stop().unwrap();
}

#[tokio::test]
async fn udp_flows_to_same_destination_are_demultiplexed_by_source_port() {
	let handler = CaptureHandler::new();
	let stack = NetworkStack::new(1500, vec!["10.0.0.1/24".to_string()], handler.clone())
		.expect("NetworkStack::new");
	stack
		.push_inbound(build_udp_packet(CLIENT_IP, PUBLIC_IP, 40001, 53, b"one"))
		.await;
	stack
		.push_inbound(build_udp_packet(CLIENT_IP, PUBLIC_IP, 40002, 53, b"two"))
		.await;

	let (first, second) = tokio::time::timeout(Duration::from_millis(500), async {
		loop {
			let senders = {
				let sessions = handler.udp_sessions.lock().unwrap();
				if sessions.len() == 2 {
					Some((sessions[0].cmd_tx.clone(), sessions[1].cmd_tx.clone()))
				} else {
					None
				}
			};
			if let Some(senders) = senders {
				break senders;
			}
			tokio::time::sleep(Duration::from_millis(5)).await;
		}
	})
	.await
	.expect("two UDP flows were not dispatched");

	async fn recv(tx: tokio::sync::mpsc::Sender<crate::dispatch::UdpSocketCmd>) -> Vec<u8> {
		let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
		tx.send(crate::dispatch::UdpSocketCmd::Recv { reply: reply_tx })
			.await
			.unwrap();
		reply_rx.await.unwrap().unwrap().unwrap().0
	}
	assert_eq!(recv(first).await, b"one");
	assert_eq!(recv(second).await, b"two");
	stack.stop().unwrap();
}

// Extension methods used by the tests above to clone the parts of a session
// needed for inspection without taking ownership of the full session (which
// would move the `cmd_tx`).
impl TcpSession {
	fn clone_handle(&self) -> TcpSessionClone {
		TcpSessionClone {
			local: self.local,
			remote: self.remote,
		}
	}
}

/// Subset of `TcpSession` needed by tests.
struct TcpSessionClone {
	local: (IpAddress, u16),
	remote: (IpAddress, u16),
}

impl UdpSession {
	fn clone_for_inspect(&self) -> UdpSessionInspect {
		UdpSessionInspect {
			local: self.local,
			remote: self.remote,
			first_packet: self.first_packet.clone(),
		}
	}
}

struct UdpSessionInspect {
	local: (IpAddress, u16),
	remote: (IpAddress, u16),
	first_packet: Vec<u8>,
}
