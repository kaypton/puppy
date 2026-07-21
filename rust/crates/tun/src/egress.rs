//! Egress-bound dialer: pins backend and DNS sockets to the physical
//! interfaces captured before split routes were installed.
//!
//! Mirrors Go `pkg/tunproxy/egress.go`, `egress_darwin.go`, `egress_linux.go`,
//! and `egress_other.go`. Uses `socket2` to apply `SO_BINDTODEVICE` +
//! `SO_MARK` (Linux) or `IP_BOUND_IF` / `IPV6_BOUND_IF` (macOS) on a fresh
//! socket, then hands it to tokio as a `TcpSocket` / `UdpSocket` for the
//! actual non-blocking `connect`.

use std::io;
use std::net::{IpAddr, SocketAddr};

use async_trait::async_trait;
use puppy_core::backend::{BoxedStream, Dialer, UdpStream};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::net::TcpSocket;

/// Bound dialer that pins outbound sockets to the configured egress
/// interfaces.
///
/// Mirrors Go `boundDialer` (pkg/tunproxy/egress.go:17) and the per-platform
/// `newSocketControl` implementations. Interface names are resolved to
/// indices at construction time so dials fail fast on a missing interface.
#[derive(Debug)]
pub struct BoundDialer {
	iface4: Option<String>,
	iface6: Option<String>,
}

impl BoundDialer {
	/// Creates a new dialer pinned to `iface4` (IPv4 egress) and `iface6`
	/// (IPv6 egress). Either may be empty to disable binding for that family.
	///
	/// Mirrors Go `newBoundDialer` (pkg/tunproxy/egress.go:17) and
	/// `newSocketControl` (pkg/tunproxy/egress_{darwin,linux}.go) which
	/// resolve interface names to indexes at construction time.
	pub fn new(iface4: &str, iface6: &str) -> Result<Self, io::Error> {
		verify_interface(iface4)?;
		verify_interface(iface6)?;
		Ok(Self {
			iface4: if iface4.is_empty() {
				None
			} else {
				Some(iface4.to_string())
			},
			iface6: if iface6.is_empty() {
				None
			} else {
				Some(iface6.to_string())
			},
		})
	}
}

/// Verifies that `iface` exists, returning `Ok(())` for an empty name.
///
/// Mirrors the `net.InterfaceByName` checks in
/// `pkg/tunproxy/egress_{darwin,linux}.go`.
fn verify_interface(iface: &str) -> Result<(), io::Error> {
	if iface.is_empty() {
		return Ok(());
	}
	if interface_index(iface).is_none() {
		return Err(io::Error::new(
			io::ErrorKind::NotFound,
			format!("tunproxy: find egress interface {iface}"),
		));
	}
	Ok(())
}

/// Returns the interface index for `name`, or `None` if no such interface
/// exists.
fn interface_index(name: &str) -> Option<u32> {
	let c_name = std::ffi::CString::new(name).ok()?;
	let idx = unsafe { libc::if_nametoindex(c_name.as_ptr()) };
	if idx == 0 {
		None
	} else {
		Some(idx)
	}
}

/// Selects the egress interface name and address family for a dial.
///
/// Mirrors Go `selectInterface` (pkg/tunproxy/egress.go:32). Network names
/// with a `4` or `6` suffix force that family; otherwise the family is
/// inferred from a literal destination IP, defaulting to IPv4 when both are
/// available.
fn select_interface<'a>(
	network: &str,
	address: &str,
	iface4: Option<&'a str>,
	iface6: Option<&'a str>,
) -> Result<(&'a str, IpFamily), io::Error> {
	if network.ends_with('4') {
		return Ok((
			iface4.ok_or_else(|| io::Error::other("tunproxy: no IPv4 egress interface"))?,
			IpFamily::V4,
		));
	}
	if network.ends_with('6') {
		return Ok((
			iface6.ok_or_else(|| io::Error::other("tunproxy: no IPv6 egress interface"))?,
			IpFamily::V6,
		));
	}
	// Try to parse the host part of `address` as a literal IP.
	if let Some(host) = split_host(address) {
		if let Ok(ip) = host.parse::<IpAddr>() {
			match ip {
				IpAddr::V4(_) => {
					return Ok((
						iface4.ok_or_else(|| {
							io::Error::other("tunproxy: no IPv4 egress interface")
						})?,
						IpFamily::V4,
					));
				}
				IpAddr::V6(_) => {
					return Ok((
						iface6.ok_or_else(|| {
							io::Error::other("tunproxy: no IPv6 egress interface")
						})?,
						IpFamily::V6,
					));
				}
			}
		}
	}
	// Hostname: prefer IPv4 egress, fall back to IPv6.
	if let Some(name) = iface4 {
		return Ok((name, IpFamily::V4));
	}
	if let Some(name) = iface6 {
		return Ok((name, IpFamily::V6));
	}
	Err(io::Error::other("tunproxy: no egress interface"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IpFamily {
	V4,
	V6,
}

impl IpFamily {
	fn domain(self) -> Domain {
		match self {
			IpFamily::V4 => Domain::IPV4,
			IpFamily::V6 => Domain::IPV6,
		}
	}
}

/// Splits `host:port` or `[ipv6]:port` and returns the host part.
fn split_host(address: &str) -> Option<&str> {
	if let Some(stripped) = address.strip_prefix('[') {
		let end = stripped.find(']')?;
		Some(&stripped[..end])
	} else {
		let (host, _port) = address.rsplit_once(':')?;
		Some(host)
	}
}

#[async_trait]
impl Dialer for BoundDialer {
	async fn dial_context(&self, network: &str, address: &str) -> io::Result<BoxedStream> {
		let (iface, family) = select_interface(
			network,
			address,
			self.iface4.as_deref(),
			self.iface6.as_deref(),
		)?;
		let sock_addr = resolve_address(address, family)?;

		if network == "udp" {
			// Match Go's net.Dialer: do NOT explicitly bind — let connect()
			// auto-bind to an ephemeral port. An explicit bind("0.0.0.0:0")
			// before connect() can cause the kernel to ignore IP_BOUND_IF
			// during the route lookup, resulting in ENETUNREACH when split
			// routes divert traffic to the TUN device.
			let sock = Socket::new(family.domain(), Type::DGRAM, Some(Protocol::UDP))?;
			apply_bound(&sock, family, iface)?;
			sock.set_nonblocking(true)?;
			let raw_fd = sock.into_raw_fd();
			// Safety: `sock` was just created and is owned. We transfer
			// ownership to the std socket and never use `sock` again.
			let std_sock = unsafe { std::net::UdpSocket::from_raw_fd(raw_fd) };
			let tokio_sock = tokio::net::UdpSocket::from_std(std_sock)?;
			tokio_sock.connect(sock_addr).await?;
			return Ok(Box::new(UdpStream::new(tokio_sock)));
		}

		// Default: TCP.
		let sock = Socket::new(family.domain(), Type::STREAM, Some(Protocol::TCP))?;
		apply_bound(&sock, family, iface)?;
		sock.set_nonblocking(true)?;
		let raw_fd = sock.into_raw_fd();
		let tcp_sock = unsafe { TcpSocket::from_raw_fd(raw_fd) };
		let stream = tcp_sock.connect(sock_addr).await?;
		Ok(Box::new(stream))
	}
}

/// Resolves `address` (host:port) to a single `SocketAddr` matching `family`.
fn resolve_address(address: &str, family: IpFamily) -> io::Result<SocketAddr> {
	use std::net::ToSocketAddrs;
	let addrs: Vec<SocketAddr> = address.to_socket_addrs()?.collect();
	match family {
		IpFamily::V4 => addrs.into_iter().find(|s| s.is_ipv4()).ok_or_else(|| {
			io::Error::new(
				io::ErrorKind::AddrNotAvailable,
				format!("tunproxy: no IPv4 address for {address}"),
			)
		}),
		IpFamily::V6 => addrs.into_iter().find(|s| s.is_ipv6()).ok_or_else(|| {
			io::Error::new(
				io::ErrorKind::AddrNotAvailable,
				format!("tunproxy: no IPv6 address for {address}"),
			)
		}),
	}
}

/// Applies the platform-specific socket option to bind `sock` to the given
/// interface. On Linux this also sets `SO_MARK` so the nft OUTPUT rule does
/// not redirect backend traffic back into the TUN.
///
/// Mirrors Go `configureLinuxSocket` (pkg/tunproxy/egress_linux.go:51) and
/// the per-family setsockopt calls in `egress_darwin.go`.
#[cfg(target_os = "linux")]
fn apply_bound(sock: &Socket, family: IpFamily, iface: &str) -> io::Result<()> {
	sock.bind_device(Some(iface.as_bytes()))
		.map_err(|e| io::Error::other(format!("bind socket to interface {iface}: {e}")))?;
	sock.set_mark(crate::nft::LINUX_BYPASS_MARK)
		.map_err(|e| io::Error::other(format!("mark socket for TUN bypass: {e}")))?;
	let _ = family;
	Ok(())
}

#[cfg(target_os = "macos")]
fn apply_bound(sock: &Socket, family: IpFamily, iface: &str) -> io::Result<()> {
	use std::num::NonZeroU32;
	let idx = interface_index(iface).ok_or_else(|| {
		io::Error::new(
			io::ErrorKind::NotFound,
			format!("tunproxy: find egress interface {iface}"),
		)
	})?;
	let idx = NonZeroU32::new(idx).unwrap();
	match family {
		IpFamily::V4 => sock.bind_device_by_index_v4(Some(idx)),
		IpFamily::V6 => sock.bind_device_by_index_v6(Some(idx)),
	}
	.map_err(|e| io::Error::other(format!("bind socket to interface {iface}: {e}")))?;
	tracing::info!(
		target: "tunproxy",
		"egress socket bound: iface={iface} idx={idx} family={:?} fd={:?}",
		family,
		sock.as_raw_fd()
	);
	Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn apply_bound(_sock: &Socket, _family: IpFamily, _iface: &str) -> io::Result<()> {
	Err(io::Error::other(
		"tunproxy: bound egress not supported on this platform",
	))
}

// Unix-only trait needed to convert `socket2::Socket` into a raw fd.
#[cfg(unix)]
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd};

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn select_interface_forces_v4() {
		let (name, family) =
			select_interface("tcp4", "1.2.3.4:80", Some("eth0"), Some("eth1")).unwrap();
		assert_eq!(name, "eth0");
		assert_eq!(family, IpFamily::V4);
	}

	#[test]
	fn select_interface_forces_v6() {
		let (name, family) =
			select_interface("tcp6", "[2001:db8::1]:80", Some("eth0"), Some("eth1")).unwrap();
		assert_eq!(name, "eth1");
		assert_eq!(family, IpFamily::V6);
	}

	#[test]
	fn select_interface_ipv4_literal() {
		let (name, family) =
			select_interface("tcp", "192.0.2.1:443", Some("eth0"), Some("eth1")).unwrap();
		assert_eq!(name, "eth0");
		assert_eq!(family, IpFamily::V4);
	}

	#[test]
	fn select_interface_ipv6_literal() {
		let (name, family) =
			select_interface("udp", "[2001:db8::1]:53", Some("eth0"), Some("eth1")).unwrap();
		assert_eq!(name, "eth1");
		assert_eq!(family, IpFamily::V6);
	}

	#[test]
	fn select_interface_hostname_prefers_v4() {
		let (name, family) =
			select_interface("tcp", "example.com:443", Some("eth0"), Some("eth1")).unwrap();
		assert_eq!(name, "eth0");
		assert_eq!(family, IpFamily::V4);
	}

	#[test]
	fn select_interface_hostname_ipv6_only() {
		let (name, family) =
			select_interface("tcp", "example.com:443", None, Some("eth1")).unwrap();
		assert_eq!(name, "eth1");
		assert_eq!(family, IpFamily::V6);
	}

	#[test]
	fn select_interface_missing_v4_errors() {
		let err = select_interface("tcp4", "1.2.3.4:80", None, Some("eth1")).unwrap_err();
		assert!(err.to_string().contains("no IPv4 egress interface"));
	}

	#[test]
	fn select_interface_missing_v6_errors() {
		let err = select_interface("tcp6", "[2001:db8::1]:80", Some("eth0"), None).unwrap_err();
		assert!(err.to_string().contains("no IPv6 egress interface"));
	}

	#[test]
	fn select_interface_no_egress_errors() {
		let err = select_interface("tcp", "example.com:443", None, None).unwrap_err();
		assert!(err.to_string().contains("no egress interface"));
	}

	#[test]
	fn split_host_plain() {
		assert_eq!(split_host("1.2.3.4:80"), Some("1.2.3.4"));
	}

	#[test]
	fn split_host_ipv6() {
		assert_eq!(split_host("[2001:db8::1]:80"), Some("2001:db8::1"));
	}

	#[test]
	fn split_host_no_port() {
		assert_eq!(split_host("hostname"), None);
	}

	#[test]
	fn verify_interface_empty_ok() {
		assert!(verify_interface("").is_ok());
	}

	#[test]
	fn verify_interface_unknown_errors() {
		let err = verify_interface("definitely-not-an-iface").unwrap_err();
		assert!(err.to_string().contains("find egress interface"));
	}

	#[test]
	fn interface_index_loopback_present() {
		// `lo0` (macOS) or `lo` (Linux) always exists on a developer machine;
		// CI sandboxes may differ.
		if let Some(idx) = interface_index("lo0").or_else(|| interface_index("lo")) {
			assert!(idx > 0);
		}
	}

	#[test]
	fn bound_dialer_unknown_iface_fails_construction() {
		let err = BoundDialer::new("definitely-not-an-iface", "").unwrap_err();
		assert!(err.to_string().contains("find egress interface"));
	}

	#[test]
	fn bound_dialer_empty_args_ok() {
		assert!(BoundDialer::new("", "").is_ok());
	}

	#[tokio::test]
	async fn bound_dialer_dial_without_egress_errors() {
		let dialer = BoundDialer::new("", "").unwrap();
		let result = dialer.dial_context("tcp", "example.com:443").await;
		match result {
			Ok(_) => panic!("expected error, got Ok"),
			Err(err) => assert!(err.to_string().contains("no egress interface")),
		}
	}
}
