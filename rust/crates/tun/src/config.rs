//! Runtime configuration for the TUN frontend.
//!
//! Translated from `pkg/tunproxy/config.go` and the configuration portions of
//! `pkg/tunproxy/server.go`. The TOML-decoded file configuration lives in the
//! `config` crate as `TunFrontendConfiguration`; this crate owns the runtime
//! form (`ServerConfiguration`) which adds the backends, fallback, dialer,
//! stats, and timing parameters.

use std::sync::Arc;
use std::time::Duration;

use puppy_core::backend::{supports_any_protocol, Backend, Dialer, Target};
use puppy_core::stats::{ConnectionRegistry, Deps, EventBus, StatsRegistry};

pub use config::TunFrontendConfiguration;

/// Discriminant identifying the TUN proxy frontend in a named configuration
/// group. Mirrors Go `tunproxy.Type = "tun"` (pkg/tunproxy/config.go:17).
pub const TYPE: &str = "tun";

/// Default UDP idle timeout when `udp_idle_timeout` is unset or non-positive.
/// Mirrors Go `defaultUDPIdle = 30 * time.Second`.
pub const DEFAULT_UDP_IDLE: Duration = Duration::from_secs(30);

/// Default protocol-detect timeout. Mirrors Go
/// `defaultProtocolDetectTimeout = time.Second`.
pub const DEFAULT_PROTOCOL_DETECT_TIMEOUT: Duration = Duration::from_secs(1);

/// Default protocol-detect byte cap. Mirrors Go
/// `defaultProtocolDetectMaxBytes = 16 * 1024`.
pub const DEFAULT_PROTOCOL_DETECT_MAX_BYTES: usize = 16 * 1024;

/// Runtime configuration for the TUN proxy frontend.
///
/// Mirrors Go `tunproxy.ServerConfiguration` (pkg/tunproxy/server.go:16). The
/// TOML-decoded [`TunFrontendConfiguration`] is converted into this runtime
/// form via [`ServerConfiguration::from_file_config`].
#[derive(Clone)]
pub struct ServerConfiguration {
	pub device_name: String,
	pub ipv4_address: String,
	pub ipv6_address: String,
	pub mtu: u32,
	pub auto_route: bool,
	pub udp_idle_timeout: Duration,
	pub dns_server: String,
	/// Ordered backend candidates; the first that accepts the flow is used.
	pub backends: Vec<Arc<dyn Backend>>,
	/// Catch-all backend used when no candidate accepts the flow. Must support
	/// both TCP and UDP with `Any` protocol.
	pub fallback: Arc<dyn Backend>,
	/// Bound dialer for backend egress. When `None`, the system default
	/// (`SystemDialer`) is used.
	pub egress_dialer: Option<Arc<dyn Dialer>>,
	pub protocol_detect_timeout: Duration,
	pub protocol_detect_max_bytes: usize,
	pub shim_buffer_size: usize,
	pub name: String,
	pub stats: Option<Arc<StatsRegistry>>,
	pub conn_reg: Option<Arc<ConnectionRegistry>>,
	pub bus: Option<Arc<EventBus>>,
}

impl std::fmt::Debug for ServerConfiguration {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("ServerConfiguration")
			.field("device_name", &self.device_name)
			.field("ipv4_address", &self.ipv4_address)
			.field("ipv6_address", &self.ipv6_address)
			.field("mtu", &self.mtu)
			.field("auto_route", &self.auto_route)
			.field("udp_idle_timeout", &self.udp_idle_timeout)
			.field("dns_server", &self.dns_server)
			.field("backends_len", &self.backends.len())
			.field("protocol_detect_timeout", &self.protocol_detect_timeout)
			.field("protocol_detect_max_bytes", &self.protocol_detect_max_bytes)
			.field("shim_buffer_size", &self.shim_buffer_size)
			.field("name", &self.name)
			.finish()
	}
}

/// Errors returned by configuration validation.
#[derive(thiserror::Error, Debug)]
pub enum ConfigError {
	#[error("{0}")]
	Validation(String),
}

impl ServerConfiguration {
	/// Validates the runtime configuration fields.
	///
	/// Mirrors Go `ServerConfiguration.Validate` (pkg/tunproxy/server.go:44).
	/// Error strings are prefixed with `"tunproxy: "` to match the Go source
	/// byte-for-byte.
	pub fn validate(&self) -> Result<(), ConfigError> {
		validate_addresses(&self.ipv4_address, &self.ipv6_address)
			.map_err(ConfigError::Validation)?;
		if self.backends.is_empty() {
			return Err(ConfigError::Validation(
				"tunproxy: at least one backend is required".to_string(),
			));
		}
		// parseDNSServer is enforced at file-config time; runtime invariant
		// only checks backends/fallback.
		for backend in &self.backends {
			let _ = backend;
			// Go checks `backend == nil`; in Rust `Arc<dyn Backend>` is always
			// non-null, so there is nothing to do here beyond iteration.
		}
		for network in ["tcp", "udp"] {
			if !supports_any_protocol(&self.fallback.capabilities(), network) {
				return Err(ConfigError::Validation(format!(
					"tunproxy: fallback must support {network} with any application protocol"
				)));
			}
		}
		Ok(())
	}

	/// Adds runtime dependencies to the frontend's file configuration and
	/// validates the resulting runtime configuration.
	///
	/// Mirrors Go `Configuration.ServerConfig` (pkg/tunproxy/config.go:137).
	/// Defaults are applied exactly as in Go: `udp_idle_timeout` ≤ 0 → 30s;
	/// `protocol_detect_timeout` 0 → 1s; `protocol_detect_max_bytes` 0 → 16
	/// KiB; `auto_route` defaults to true unless explicitly set false.
	#[allow(clippy::too_many_arguments)]
	pub fn from_file_config(
		file: &TunFrontendConfiguration,
		backends: Vec<Arc<dyn Backend>>,
		fallback: Arc<dyn Backend>,
		egress_dialer: Option<Arc<dyn Dialer>>,
		shim_buffer_size: usize,
		stats_deps: Deps,
	) -> Result<Self, ConfigError> {
		let mtu = file.mtu.max(0) as u32;
		let udp_idle = if file.udp_idle_timeout <= 0 {
			DEFAULT_UDP_IDLE
		} else {
			Duration::from_secs(file.udp_idle_timeout as u64)
		};
		let auto_route = file.auto_route.unwrap_or(true);
		let detect_timeout = if file.protocol_detect_timeout <= 0 {
			DEFAULT_PROTOCOL_DETECT_TIMEOUT
		} else {
			Duration::from_secs(file.protocol_detect_timeout as u64)
		};
		let detect_max_bytes = if file.protocol_detect_max_bytes <= 0 {
			DEFAULT_PROTOCOL_DETECT_MAX_BYTES
		} else {
			file.protocol_detect_max_bytes as usize
		};
		let sc = ServerConfiguration {
			device_name: file.device_name.clone(),
			ipv4_address: file.ipv4_address.clone(),
			ipv6_address: file.ipv6_address.clone(),
			mtu,
			auto_route,
			udp_idle_timeout: udp_idle,
			dns_server: file.dns_server.clone(),
			backends,
			fallback,
			egress_dialer,
			protocol_detect_timeout: detect_timeout,
			protocol_detect_max_bytes: detect_max_bytes,
			shim_buffer_size,
			name: stats_deps.name,
			stats: stats_deps.stats.map(Arc::new),
			conn_reg: stats_deps.conn_reg.map(Arc::new),
			bus: stats_deps.bus.map(Arc::new),
		};
		sc.validate()?;
		Ok(sc)
	}
}

/// Validates that at least one of `ipv4`/`ipv6` is set, and each is a CIDR of
/// the correct family. Mirrors Go `validateAddresses` (pkg/tunproxy/config.go:110).
///
/// Error strings are prefixed with `"tunproxy: "` to match Go's
/// `ServerConfiguration.Validate` which wraps the address error with
/// `fmt.Errorf("tunproxy: %w", err)`.
fn validate_addresses(ipv4: &str, ipv6: &str) -> Result<(), String> {
	if ipv4.is_empty() && ipv6.is_empty() {
		return Err("tunproxy: ipv4_address or ipv6_address is required".to_string());
	}
	if !ipv4.is_empty() {
		let (ip, prefix_len) = parse_cidr(ipv4)
			.map_err(|e| format!("tunproxy: ipv4_address must be in CIDR form: {e}"))?;
		if !is_ipv4(&ip) {
			return Err("tunproxy: ipv4_address must contain an IPv4 address".to_string());
		}
		if prefix_len.is_none() {
			return Err("tunproxy: ipv4_address must be in CIDR form: missing prefix".to_string());
		}
	}
	if !ipv6.is_empty() {
		let (ip, prefix_len) = parse_cidr(ipv6)
			.map_err(|e| format!("tunproxy: ipv6_address must be in CIDR form: {e}"))?;
		if is_ipv4(&ip) {
			return Err("tunproxy: ipv6_address must contain an IPv6 address".to_string());
		}
		if prefix_len.is_none() {
			return Err("tunproxy: ipv6_address must be in CIDR form: missing prefix".to_string());
		}
	}
	Ok(())
}

/// Parses `addr/prefix` returning the IP and optional prefix length.
fn parse_cidr(s: &str) -> Result<(std::net::IpAddr, Option<u8>), String> {
	let (ip_part, prefix_part) = match s.rsplit_once('/') {
		Some((ip, p)) => (ip, Some(p)),
		None => (s, None),
	};
	let ip: std::net::IpAddr = ip_part
		.parse()
		.map_err(|e: std::net::AddrParseError| e.to_string())?;
	let prefix = match prefix_part {
		Some(p) => Some(
			p.parse::<u8>()
				.map_err(|e: std::num::ParseIntError| e.to_string())?,
		),
		None => None,
	};
	Ok((ip, prefix))
}

fn is_ipv4(addr: &std::net::IpAddr) -> bool {
	matches!(addr, std::net::IpAddr::V4(_))
}

/// Validates a DNS server address (IP:port). Empty disables interception.
///
/// Mirrors Go `parseDNSServer` (pkg/tunproxy/config.go:201). Returns the
/// parsed target so the dispatcher can use it directly.
pub fn parse_dns_server(value: &str) -> Result<Option<Target>, String> {
	if value.is_empty() {
		return Ok(None);
	}
	let (host, port_str) = split_host_port(value)
		.map_err(|e| format!("tunproxy: dns_server must be an IP address with port: {e}"))?;
	if host.is_empty() {
		return Err(
			"tunproxy: dns_server must be an IP address with port: missing host".to_string(),
		);
	}
	let ip: std::net::IpAddr = host.parse().map_err(|e: std::net::AddrParseError| {
		format!("tunproxy: dns_server must be an IP address with port: {e}")
	})?;
	if host.starts_with('[') && host.contains('%') {
		return Err("tunproxy: dns_server must not contain an IPv6 zone".to_string());
	}
	let port: u16 = port_str.parse().map_err(|e: std::num::ParseIntError| {
		format!("tunproxy: dns_server must be an IP address with port: {e}")
	})?;
	if port == 0 {
		return Err("tunproxy: dns_server port must not be zero".to_string());
	}
	Ok(Some(Target {
		network: "tcp".to_string(),
		protocol: puppy_core::backend::Protocol::Dns,
		host: ip.to_string(),
		port,
	}))
}

/// Splits `host:port` or `[ipv6]:port` like Go's `net.SplitHostPort`.
fn split_host_port(s: &str) -> Result<(String, String), String> {
	if let Some(stripped) = s.strip_prefix('[') {
		// [ipv6]:port
		let end = stripped
			.find(']')
			.ok_or_else(|| "missing ']'".to_string())?;
		let host = &stripped[..end];
		let rest = &stripped[end + 1..];
		let port = rest
			.strip_prefix(':')
			.ok_or_else(|| "missing port".to_string())?;
		Ok((host.to_string(), port.to_string()))
	} else {
		let (host, port) = s
			.rsplit_once(':')
			.ok_or_else(|| "missing port".to_string())?;
		Ok((host.to_string(), port.to_string()))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use puppy_core::backend::{Capability, Protocol};
	use puppy_core::stats::Deps;
	use std::sync::Arc;

	/// A backend that advertises a configurable set of capabilities and never
	/// actually dials. Used only for validation tests.
	struct StubBackend {
		caps: Vec<Capability>,
	}

	#[async_trait::async_trait]
	impl Backend for StubBackend {
		fn capabilities(&self) -> Vec<Capability> {
			self.caps.clone()
		}
		async fn dial(
			&self,
			_target: Target,
			_dialer: &dyn Dialer,
		) -> Result<puppy_core::backend::BoxedStream, puppy_core::backend::BackendError> {
			Err(puppy_core::backend::BackendError::Other("stub".to_string()))
		}
	}

	fn dual_stack_backend() -> Arc<dyn Backend> {
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

	fn tcp_only_backend() -> Arc<dyn Backend> {
		Arc::new(StubBackend {
			caps: vec![Capability {
				network: "tcp".to_string(),
				protocol: Protocol::Any,
			}],
		})
	}

	fn base_file() -> TunFrontendConfiguration {
		TunFrontendConfiguration {
			ipv4_address: "10.0.0.1/24".to_string(),
			backend: "b".to_string(),
			shim: "s".to_string(),
			..Default::default()
		}
	}

	#[test]
	fn from_file_config_applies_defaults() {
		let file = base_file();
		let sc = ServerConfiguration::from_file_config(
			&file,
			vec![dual_stack_backend()],
			dual_stack_backend(),
			None,
			0,
			Deps::default(),
		)
		.expect("valid config");
		assert_eq!(sc.udp_idle_timeout, DEFAULT_UDP_IDLE);
		assert!(sc.auto_route);
		assert_eq!(sc.protocol_detect_timeout, DEFAULT_PROTOCOL_DETECT_TIMEOUT);
		assert_eq!(
			sc.protocol_detect_max_bytes,
			DEFAULT_PROTOCOL_DETECT_MAX_BYTES
		);
	}

	#[test]
	fn from_file_config_respects_explicit_values() {
		let mut file = base_file();
		file.udp_idle_timeout = 10;
		file.protocol_detect_timeout = 3;
		file.protocol_detect_max_bytes = 4096;
		file.auto_route = Some(false);
		let sc = ServerConfiguration::from_file_config(
			&file,
			vec![dual_stack_backend()],
			dual_stack_backend(),
			None,
			0,
			Deps::default(),
		)
		.expect("valid config");
		assert_eq!(sc.udp_idle_timeout, Duration::from_secs(10));
		assert!(!sc.auto_route);
		assert_eq!(sc.protocol_detect_timeout, Duration::from_secs(3));
		assert_eq!(sc.protocol_detect_max_bytes, 4096);
	}

	#[test]
	fn validate_missing_addresses() {
		let file = TunFrontendConfiguration {
			backend: "b".to_string(),
			shim: "s".to_string(),
			..Default::default()
		};
		let err = ServerConfiguration::from_file_config(
			&file,
			vec![dual_stack_backend()],
			dual_stack_backend(),
			None,
			0,
			Deps::default(),
		)
		.unwrap_err();
		assert!(err
			.to_string()
			.contains("ipv4_address or ipv6_address is required"));
	}

	#[test]
	fn validate_no_backends() {
		let file = base_file();
		let err = ServerConfiguration::from_file_config(
			&file,
			Vec::new(),
			dual_stack_backend(),
			None,
			0,
			Deps::default(),
		)
		.unwrap_err();
		assert!(err.to_string().contains("at least one backend is required"));
	}

	#[test]
	fn validate_fallback_must_support_udp() {
		let file = base_file();
		let err = ServerConfiguration::from_file_config(
			&file,
			vec![dual_stack_backend()],
			tcp_only_backend(),
			None,
			0,
			Deps::default(),
		)
		.unwrap_err();
		assert!(err
			.to_string()
			.contains("fallback must support udp with any application protocol"));
	}

	#[test]
	fn validate_dns_server_in_runtime_is_not_rechecked() {
		// File-level validation already enforced dns_server. Runtime config
		// does not re-parse it.
		let mut file = base_file();
		file.dns_server = "1.1.1.1:53".to_string();
		let sc = ServerConfiguration::from_file_config(
			&file,
			vec![dual_stack_backend()],
			dual_stack_backend(),
			None,
			0,
			Deps::default(),
		);
		assert!(sc.is_ok());
	}

	#[test]
	fn parse_dns_server_v4() {
		let t = parse_dns_server("1.1.1.1:53").unwrap().unwrap();
		assert_eq!(t.network, "tcp");
		assert_eq!(t.protocol, Protocol::Dns);
		assert_eq!(t.host, "1.1.1.1");
		assert_eq!(t.port, 53);
	}

	#[test]
	fn parse_dns_server_v6() {
		let t = parse_dns_server("[2606:4700:4700::1111]:5353")
			.unwrap()
			.unwrap();
		assert_eq!(t.host, "2606:4700:4700::1111");
		assert_eq!(t.port, 5353);
	}

	#[test]
	fn parse_dns_server_empty() {
		assert!(parse_dns_server("").unwrap().is_none());
	}

	#[test]
	fn parse_dns_server_zero_port() {
		let err = parse_dns_server("1.1.1.1:0").unwrap_err();
		assert!(err.contains("dns_server port must not be zero"));
	}

	#[test]
	fn parse_dns_server_missing_port() {
		let err = parse_dns_server("1.1.1.1").unwrap_err();
		assert!(err.contains("dns_server must be an IP address with port"));
	}

	#[test]
	fn parse_dns_server_hostname() {
		let err = parse_dns_server("resolver.example:53").unwrap_err();
		assert!(err.contains("dns_server must be an IP address with port"));
	}
}
