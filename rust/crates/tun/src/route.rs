//! Host network manager: owns the host-side TUN addresses, routes, and
//! backend egress path.
//!
//! Mirrors Go `pkg/tunproxy/route.go` and the per-platform
//! `route_{darwin,linux,other}.go` files. `Apply` is transactional; `Restore`
//! is safe to call more than once.

use std::io;

use async_trait::async_trait;
use puppy_core::backend::{BoxedStream, Dialer};

/// DNS interception handler invoked by the Linux netfilter DNAT path.
///
/// Mirrors Go `dnsInterceptHandler` (pkg/tunproxy/route.go:9).
#[async_trait]
pub trait DnsInterceptHandler: Send + Sync {
	/// Handles a redirected DNS-over-TCP stream. The proxy spawns a fresh
	/// task per accepted connection, so this method may block until EOF.
	async fn serve_intercepted_dns_stream(&self, stream: BoxedStream);

	/// Resolves a redirected DNS-over-UDP datagram, returning the response
	/// bytes to send back to the client.
	fn resolve_intercepted_dns_datagram(&self, query: &[u8]) -> io::Result<Vec<u8>>;
}

/// Host network manager: applies TUN addresses, split routes, and backend
/// egress binding. Apply is transactional; Restore is idempotent.
///
/// Mirrors Go `hostNetworkManager` (pkg/tunproxy/route.go:16).
#[async_trait]
pub trait HostNetworkManager: Send + Sync {
	/// Brings up the TUN, assigns addresses, installs split routes, and
	/// returns a dialer pinned to the captured egress interfaces.
	async fn apply(&mut self) -> io::Result<Arc<dyn Dialer>>;

	/// Installs DNS interception (Linux systemd-resolved only). No-op on
	/// other platforms.
	async fn enable_dns_interception(
		&mut self,
		handler: Arc<dyn DnsInterceptHandler>,
	) -> io::Result<()>;

	/// Reverts every mutation made by `apply` and `enable_dns_interception`.
	/// Safe to call multiple times.
	async fn restore(&mut self) -> io::Result<()>;

	/// Returns the captured egress interface names `(ipv4, ipv6)`. Empty
	/// until `apply` succeeds.
	fn egress_interfaces(&self) -> (String, String);
}

use std::sync::Arc;

/// Constructs a platform-specific host network manager.
///
/// Mirrors Go `newHostNetworkManager` (pkg/tunproxy/route_{darwin,linux,other}.go).
pub fn new_host_network_manager(
	device: &str,
	ipv4_addr: &str,
	ipv6_addr: &str,
	auto_route: bool,
	intercept_systemd_resolved: bool,
) -> Box<dyn HostNetworkManager> {
	#[cfg(target_os = "macos")]
	{
		let _ = intercept_systemd_resolved;
		Box::new(crate::route_darwin::DarwinHostNetworkManager::new(
			device, ipv4_addr, ipv6_addr, auto_route,
		))
	}
	#[cfg(target_os = "linux")]
	{
		Box::new(crate::route_linux::LinuxHostNetworkManager::new(
			device,
			ipv4_addr,
			ipv6_addr,
			auto_route,
			intercept_systemd_resolved,
		))
	}
	#[cfg(not(any(target_os = "linux", target_os = "macos")))]
	{
		let _ = (
			device,
			ipv4_addr,
			ipv6_addr,
			auto_route,
			intercept_systemd_resolved,
		);
		Box::new(crate::route_other::UnsupportedHostNetworkManager)
	}
}

/// Returns `true` if systemd-resolved DNS interception would be enabled for
/// the given configuration on the current platform. Always `false` on
/// non-Linux platforms.
///
/// Mirrors Go `systemdResolvedInterceptionEnabled`
/// (pkg/tunproxy/route_{darwin,linux,other}.go).
pub fn systemd_resolved_interception_enabled(
	auto_route: bool,
	dns_configured: bool,
	ipv4_configured: bool,
) -> bool {
	#[cfg(target_os = "linux")]
	{
		auto_route && dns_configured && ipv4_configured
	}
	#[cfg(not(target_os = "linux"))]
	{
		let _ = (auto_route, dns_configured, ipv4_configured);
		false
	}
}
