//! TUN proxy server: orchestrates device, netstack, dispatcher, host network
//! manager, and pumps.
//!
//! Mirrors Go `pkg/tunproxy/server.go`. `Server::new` applies defaults;
//! `Server::run` opens the TUN device, configures host routing, starts the
//! netstack + dispatcher + pumps, and serves until shutdown or a pump error.
//! Routing state is always restored before returning.

use std::sync::Arc;

use puppy_core::backend::Dialer;
use tokio_util::sync::CancellationToken;

use crate::config::{parse_dns_server, ConfigError, ServerConfiguration};
use crate::device::{open_device, Device};
use crate::dispatch::{Dispatcher, DispatcherConfiguration};
use crate::pumps::run_pumps;
use crate::route::{
	new_host_network_manager, systemd_resolved_interception_enabled, DnsInterceptHandler,
};
use crate::stack::NetworkStack;

/// TUN proxy server.
///
/// Mirrors Go `tunproxy.Server` (pkg/tunproxy/server.go:73). Owns the runtime
/// configuration; `run` consumes the server and drives it to completion.
pub struct Server {
	config: ServerConfiguration,
	dns: Option<puppy_core::backend::Target>,
}

impl std::fmt::Debug for Server {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("Server")
			.field("config", &self.config)
			.field("dns", &self.dns)
			.finish()
	}
}

impl Server {
	/// Applies defaults and returns a ready-to-run server.
	///
	/// Mirrors Go `tunproxy.NewServer` (pkg/tunproxy/server.go:82). The
	/// caller must have validated the configuration via
	/// [`ServerConfiguration::validate`] (typically through
	/// [`ServerConfiguration::from_file_config`]) before calling `new`.
	pub fn new(mut config: ServerConfiguration) -> Result<Self, ConfigError> {
		let dns = parse_dns_server(&config.dns_server)
			.map_err(|e| ConfigError::Validation(format!("tunproxy: {e}")))?;
		if config.udp_idle_timeout.as_secs() == 0 {
			config.udp_idle_timeout = crate::config::DEFAULT_UDP_IDLE;
		}
		if config.protocol_detect_timeout.as_secs() == 0 {
			config.protocol_detect_timeout = crate::config::DEFAULT_PROTOCOL_DETECT_TIMEOUT;
		}
		if config.protocol_detect_max_bytes == 0 {
			config.protocol_detect_max_bytes = crate::config::DEFAULT_PROTOCOL_DETECT_MAX_BYTES;
		}
		Ok(Self { config, dns })
	}

	/// Returns a reference to the runtime configuration.
	pub fn config(&self) -> &ServerConfiguration {
		&self.config
	}

	/// Opens the TUN device, configures routing, and serves until `shutdown`
	/// resolves or a pump errors. Always restores routing state before
	/// returning.
	///
	/// Mirrors Go `(*Server).Run` (pkg/tunproxy/server.go:105).
	pub async fn run<F>(self, shutdown: F) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
	where
		F: std::future::Future<Output = ()> + Send + 'static,
	{
		// Root check: TUN devices require privileges on all platforms.
		#[cfg(unix)]
		{
			unsafe {
				if libc::geteuid() != 0 {
					return Err("tunproxy: TUN mode requires root privileges"
						.to_string()
						.into());
				}
			}
		}

		let Self { config, dns } = self;

		// Open the TUN device.
		let device: Box<dyn Device> = open_device(&config.device_name, config.mtu)
			.map_err(|e| format!("tunproxy: open device: {e}"))?;
		let device_name = device.name().to_string();
		let device_mtu = device.mtu();
		tracing::info!(name = %device_name, mtu = device_mtu, "tunproxy: device opened");

		// Build the netstack with the dispatcher as the session handler.
		// The dispatcher is constructed after `network_mgr.apply()` so it
		// can use the egress-bound dialer returned by the host network
		// manager (mirroring Go's `(*Server).Run` ordering).
		let addresses: Vec<String> = config
			.ipv4_address
			.split(',')
			.chain(config.ipv6_address.split(','))
			.filter(|s| !s.is_empty())
			.map(|s| s.trim().to_string())
			.collect();

		// Apply host network configuration (addresses, routes, egress dialer).
		let intercept_systemd_resolved = systemd_resolved_interception_enabled(
			config.auto_route,
			dns.is_some(),
			!config.ipv4_address.is_empty(),
		);
		let mut network_mgr = new_host_network_manager(
			&device_name,
			&config.ipv4_address,
			&config.ipv6_address,
			config.auto_route,
			intercept_systemd_resolved,
		);
		let egress_dialer: Arc<dyn Dialer> = network_mgr
			.apply()
			.await
			.map_err(|e| format!("tunproxy: configure host network: {e}"))?;

		// Now build the dispatcher with the egress-bound dialer.
		let dispatcher_cancel = CancellationToken::new();
		let dispatcher = Dispatcher::new(
			build_dispatcher_config(&config, dns.clone(), &egress_dialer),
			dispatcher_cancel.clone(),
		);

		let stack = Arc::new(
			NetworkStack::new(config.mtu, addresses, Dispatcher::clone(&dispatcher))
				.map_err(|e| format!("tunproxy: netstack: {e}"))?,
		);

		// Enable DNS interception (Linux systemd-resolved only). The handler
		// is the dispatcher itself.
		let handler: Arc<dyn DnsInterceptHandler> = Dispatcher::clone(&dispatcher);
		network_mgr
			.enable_dns_interception(handler)
			.await
			.map_err(|e| format!("tunproxy: enable systemd-resolved interception: {e}"))?;

		let (egress4, egress6) = network_mgr.egress_interfaces();
		tracing::info!(
			device = %device_name,
			ipv4 = %config.ipv4_address,
			ipv6 = %config.ipv6_address,
			egress_ipv4_interface = %egress4,
			egress_ipv6_interface = %egress6,
			systemd_resolved_intercept = intercept_systemd_resolved,
			auto_route = config.auto_route,
			"tunproxy: serving"
		);

		// Run the pumps and the shutdown signal concurrently. We keep the
		// device alive (via `run_pumps`) until shutdown or a pump error.
		let pump_cancel = CancellationToken::new();
		let pumps_stack = Arc::clone(&stack);
		let pumps_cancel = pump_cancel.clone();
		let mut pumps_task =
			tokio::spawn(async move { run_pumps(device, pumps_stack, pumps_cancel).await });

		tokio::pin!(shutdown);
		let mut run_result: Result<(), String> = tokio::select! {
			biased;
			_ = &mut shutdown => {
				tracing::info!("tunproxy: shutting down");
				Ok(())
			},
			res = &mut pumps_task => {
				pump_cancel.cancel();
				match res {
					Ok(Ok(())) => Ok(()),
					Ok(Err(e)) => Err(format!("tunproxy: pump: {e}")),
					Err(e) => Err(format!("tunproxy: pump task: {e}")),
				}
			},
		};

		// Cleanup: cancel dispatcher, restore host routing, stop netstack,
		// wait for in-flight sessions. Mirrors the deferred cleanup in Go's
		// `(*Server).Run` (pkg/tunproxy/server.go:167-179). Restore routing
		// BEFORE waiting for sessions so UDP relays don't black-hole host
		// traffic while the split routes are still in place.
		dispatcher_cancel.cancel();
		if let Err(e) = network_mgr.restore().await {
			tracing::error!(error = %e, "tunproxy: restore host network failed");
			run_result = match run_result {
				Ok(()) => Err(format!("tunproxy: restore host network: {e}")),
				Err(prior) => Err(format!("{prior}; tunproxy: restore host network: {e}")),
			};
		}
		stack
			.stop()
			.map_err(|e| format!("tunproxy: stop netstack: {e}"))?;
		dispatcher.wait().await;

		run_result.map_err(|e| e.into())
	}
}

/// Builds the dispatcher configuration from the server config.
///
/// Mirrors the `DispatcherConfiguration{...}` literal in Go's
/// `(*Server).Run` (pkg/tunproxy/server.go:150).
fn build_dispatcher_config(
	config: &ServerConfiguration,
	dns: Option<puppy_core::backend::Target>,
	egress_dialer: &Arc<dyn Dialer>,
) -> DispatcherConfiguration {
	DispatcherConfiguration {
		backends: config.backends.clone(),
		fallback: config.fallback.clone(),
		dialer: Arc::clone(egress_dialer),
		dns,
		shim_buf: config.shim_buffer_size,
		udp_idle: config.udp_idle_timeout,
		detect_timeout: config.protocol_detect_timeout,
		detect_max_bytes: config.protocol_detect_max_bytes,
		name: config.name.clone(),
		stats: config.stats.clone(),
		conn_reg: config.conn_reg.clone(),
		bus: config.bus.clone(),
	}
}

impl Dispatcher {
	/// Convenience for cloning an `Arc<Dispatcher>` without importing `Arc`.
	fn clone(this: &Arc<Self>) -> Arc<Self> {
		Arc::clone(this)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use puppy_core::backend::{Capability, Protocol};

	/// A backend that advertises configurable capabilities and never dials.
	struct StubBackend {
		caps: Vec<Capability>,
	}

	#[async_trait::async_trait]
	impl puppy_core::backend::Backend for StubBackend {
		fn capabilities(&self) -> Vec<Capability> {
			self.caps.clone()
		}
		async fn dial(
			&self,
			_target: puppy_core::backend::Target,
			_dialer: &dyn Dialer,
		) -> Result<puppy_core::backend::BoxedStream, puppy_core::backend::BackendError> {
			Err(puppy_core::backend::BackendError::Other("stub".to_string()))
		}
	}

	fn dual_stack_backend() -> Arc<dyn puppy_core::backend::Backend> {
		Arc::new(StubBackend {
			caps: vec![
				Capability {
					network: "tcp".to_string(),
					protocol: Protocol::Any,
				},
				Capability {
					network: "udp".to_string(),
					protocol: Protocol::Any,
				},
			],
		})
	}

	fn base_config() -> ServerConfiguration {
		ServerConfiguration {
			device_name: String::new(),
			ipv4_address: "10.0.0.1/24".to_string(),
			ipv6_address: String::new(),
			mtu: 0,
			auto_route: false,
			udp_idle_timeout: Duration::ZERO,
			dns_server: String::new(),
			backends: vec![dual_stack_backend()],
			fallback: dual_stack_backend(),
			egress_dialer: None,
			protocol_detect_timeout: Duration::ZERO,
			protocol_detect_max_bytes: 0,
			shim_buffer_size: 1024,
			name: "test".to_string(),
			stats: None,
			conn_reg: None,
			bus: None,
		}
	}

	use std::time::Duration;

	#[test]
	fn new_server_applies_udp_idle_default() {
		let cfg = base_config();
		let server = Server::new(cfg).expect("new server");
		assert_eq!(
			server.config().udp_idle_timeout,
			crate::config::DEFAULT_UDP_IDLE
		);
	}

	#[test]
	fn new_server_respects_explicit_udp_idle() {
		let mut cfg = base_config();
		cfg.udp_idle_timeout = Duration::from_secs(10);
		let server = Server::new(cfg).expect("new server");
		assert_eq!(server.config().udp_idle_timeout, Duration::from_secs(10));
	}

	#[test]
	fn new_server_applies_detect_defaults() {
		let cfg = base_config();
		let server = Server::new(cfg).expect("new server");
		assert_eq!(
			server.config().protocol_detect_timeout,
			crate::config::DEFAULT_PROTOCOL_DETECT_TIMEOUT
		);
		assert_eq!(
			server.config().protocol_detect_max_bytes,
			crate::config::DEFAULT_PROTOCOL_DETECT_MAX_BYTES
		);
	}

	#[test]
	fn new_server_parses_dns_target() {
		let mut cfg = base_config();
		cfg.dns_server = "1.1.1.1:53".to_string();
		let server = Server::new(cfg).expect("new server");
		assert!(server.dns.is_some());
		let dns = server.dns.as_ref().unwrap();
		assert_eq!(dns.host, "1.1.1.1");
		assert_eq!(dns.port, 53);
	}

	#[test]
	fn new_server_rejects_invalid_dns() {
		let mut cfg = base_config();
		cfg.dns_server = "resolver.example:53".to_string();
		let err = Server::new(cfg).unwrap_err();
		assert!(err
			.to_string()
			.contains("dns_server must be an IP address with port"));
	}

	#[tokio::test]
	async fn run_requires_root_when_not_root() {
		// Skip when running as root (CI may run as root).
		#[cfg(unix)]
		unsafe {
			if libc::geteuid() == 0 {
				return;
			}
		}
		let cfg = base_config();
		let server = Server::new(cfg).expect("new server");
		let (_tx, rx) = tokio::sync::oneshot::channel::<()>();
		let result = server
			.run(async {
				let _ = rx.await;
			})
			.await;
		assert!(result.is_err(), "run should error when not root");
		let err = result.unwrap_err().to_string();
		assert!(err.contains("root"), "error should mention root: {err}");
	}

	#[tokio::test]
	async fn run_returns_on_shutdown_when_not_root() {
		#[cfg(unix)]
		unsafe {
			if libc::geteuid() == 0 {
				return;
			}
		}
		let cfg = base_config();
		let server = Server::new(cfg).expect("new server");
		let (tx, rx) = tokio::sync::oneshot::channel::<()>();
		let handle = tokio::spawn(async move {
			server
				.run(async {
					let _ = rx.await;
				})
				.await
		});
		// Give the server a moment to start, then fire shutdown.
		tokio::time::sleep(Duration::from_millis(50)).await;
		let _ = tx.send(());
		let result = tokio::time::timeout(Duration::from_secs(2), handle)
			.await
			.expect("run should return within 2s after shutdown")
			.expect("task should not panic");
		// When not root, `run` returns the root error before reaching the
		// shutdown select. The error must mention "root" (the root check
		// fires first), OR be clean if shutdown raced ahead.
		match result {
			Ok(()) => {}
			Err(e) => {
				let msg = e.to_string();
				assert!(msg.contains("root"), "unexpected error: {msg}");
			}
		}
	}
}
