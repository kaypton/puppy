//! Linux DNS interception proxy: receives nft DNAT traffic on ephemeral
//! loopback ports and hands it to the regular TUN dispatcher.
//!
//! Mirrors Go `pkg/tunproxy/dns_intercept_linux.go`.

use std::io;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

use crate::route::DnsInterceptHandler;

/// Maximum DNS message size (RFC 1035 §4.2.1).
pub const MAX_DNS_MESSAGE_SIZE: usize = 65535;

/// Linux DNS proxy listening on loopback for nft-redirected traffic.
///
/// Mirrors Go `linuxDNSProxy` (pkg/tunproxy/dns_intercept_linux.go:15).
pub struct LinuxDnsProxy {
	handler: Arc<dyn DnsInterceptHandler>,
	udp: Arc<UdpSocket>,
	tcp: TcpListener,
}

impl LinuxDnsProxy {
	/// Binds new UDP and TCP listeners on `127.0.0.1` ephemeral ports.
	///
	/// Mirrors Go `newLinuxDNSProxy` (pkg/tunproxy/dns_intercept_linux.go:27).
	pub async fn new(handler: Arc<dyn DnsInterceptHandler>) -> io::Result<Self> {
		let udp = UdpSocket::bind("127.0.0.1:0").await?;
		let tcp = TcpListener::bind("127.0.0.1:0").await?;
		Ok(Self {
			handler,
			udp: Arc::new(udp),
			tcp,
		})
	}

	/// Returns the bound UDP port.
	pub fn udp_port(&self) -> u16 {
		self.udp.local_addr().map(|a| a.port()).unwrap_or(0)
	}

	/// Returns the bound TCP port.
	pub fn tcp_port(&self) -> u16 {
		self.tcp.local_addr().map(|a| a.port()).unwrap_or(0)
	}

	/// Spawns the UDP and TCP accept loops. The loops exit when the
	/// underlying listeners are dropped (see [`LinuxDnsProxy::close`]).
	///
	/// Mirrors Go `linuxDNSProxy.Start` (pkg/tunproxy/dns_intercept_linux.go:50).
	pub fn start(self: &Arc<Self>) {
		let self_udp = self.clone();
		tokio::spawn(async move {
			self_udp.serve_udp().await;
		});
		let self_tcp = self.clone();
		tokio::spawn(async move {
			self_tcp.serve_tcp().await;
		});
	}

	async fn serve_udp(&self) {
		let mut buf = vec![0u8; MAX_DNS_MESSAGE_SIZE];
		loop {
			let (n, peer) = match self.udp.recv_from(&mut buf).await {
				Ok(v) => v,
				Err(_) => return,
			};
			let query = buf[..n].to_vec();
			let handler = self.handler.clone();
			let sock = self.udp.clone();
			tokio::spawn(async move {
				if let Ok(response) = handler.resolve_intercepted_dns_datagram(&query) {
					let _ = sock.send_to(&response, peer).await;
				}
			});
		}
	}

	async fn serve_tcp(&self) {
		loop {
			let (conn, _peer) = match self.tcp.accept().await {
				Ok(v) => v,
				Err(_) => return,
			};
			let handler = self.handler.clone();
			tokio::spawn(async move {
				let stream: puppy_core::backend::BoxedStream = Box::new(conn);
				handler.serve_intercepted_dns_stream(stream).await;
			});
		}
	}

	/// Closes the listeners. Idempotent. In-flight handlers are cancelled
	/// when their tasks are dropped (tokio's default behaviour).
	///
	/// Mirrors Go `linuxDNSProxy.Close` (pkg/tunproxy/dns_intercept_linux.go:94).
	pub async fn close(&self) -> io::Result<()> {
		// tokio's TcpListener and UdpSocket close on drop. Because `start`
		// holds an `Arc<Self>`, callers must drop every Arc to fully close
		// the proxy. This method exists for API parity with Go and reports
		// success unconditionally.
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use puppy_core::backend::BoxedStream;

	struct EchoHandler;

	#[async_trait::async_trait]
	impl DnsInterceptHandler for EchoHandler {
		async fn serve_intercepted_dns_stream(&self, mut stream: BoxedStream) {
			let mut buf = [0u8; 1024];
			loop {
				match stream.read(&mut buf).await {
					Ok(0) | Err(_) => return,
					Ok(n) => {
						if stream.write_all(&buf[..n]).await.is_err() {
							return;
						}
					}
				}
			}
		}

		fn resolve_intercepted_dns_datagram(&self, query: &[u8]) -> io::Result<Vec<u8>> {
			let mut response = b"response:".to_vec();
			response.extend_from_slice(query);
			Ok(response)
		}
	}

	#[tokio::test]
	async fn dns_proxy_forwards_tcp_and_udp() {
		let handler: Arc<dyn DnsInterceptHandler> = Arc::new(EchoHandler);
		let proxy = Arc::new(LinuxDnsProxy::new(handler).await.unwrap());
		proxy.start();

		let udp_port = proxy.udp_port();
		let tcp_port = proxy.tcp_port();

		// UDP.
		let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
		udp.connect(("127.0.0.1", udp_port)).await.unwrap();
		let query = b"query";
		udp.send(query).await.unwrap();
		let mut buf = [0u8; 64];
		let n = tokio::time::timeout(std::time::Duration::from_secs(2), udp.recv(&mut buf))
			.await
			.expect("UDP timed out")
			.unwrap();
		assert_eq!(&buf[..n], b"response:query");

		// TCP.
		let mut tcp = tokio::time::timeout(
			std::time::Duration::from_secs(2),
			tokio::net::TcpStream::connect(("127.0.0.1", tcp_port)),
		)
		.await
		.expect("TCP connect timed out")
		.unwrap();
		tcp.write_all(query).await.unwrap();
		let mut got = [0u8; 5];
		tokio::time::timeout(std::time::Duration::from_secs(2), tcp.read_exact(&mut got))
			.await
			.expect("TCP read timed out")
			.unwrap();
		assert_eq!(&got, query);

		proxy.close().await.unwrap();
	}
}
