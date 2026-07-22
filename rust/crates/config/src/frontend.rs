//! Frontend configuration: tagged enum over HTTP / SOCKS5 / TUN variants.
//!
//! - HTTP CONNECT (`type = "httpproxy"`)
//! - SOCKS5 (`type = "socksproxy"`)
//! - gRPC tunnel (`type = "grpcproxy"`)
//! - TUN (`type = "tun"`)

use std::net::IpAddr;

use serde::Deserialize;

/// A frontend entry under `[frontends.<name>]`, tagged by `type`.
#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
pub enum FrontendConfiguration {
	#[serde(rename = "httpproxy")]
	Http(HttpFrontendConfiguration),
	#[serde(rename = "socksproxy")]
	Socks(SocksFrontendConfiguration),
	#[serde(rename = "grpcproxy")]
	Grpc(GrpcFrontendConfiguration),
	#[serde(rename = "tun")]
	Tun(TunFrontendConfiguration),
}

/// Discriminant accessor used by tests and the server factory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrontendKind {
	Http,
	Socks,
	Grpc,
	Tun,
}

impl FrontendConfiguration {
	pub fn kind(&self) -> FrontendKind {
		match self {
			FrontendConfiguration::Http(_) => FrontendKind::Http,
			FrontendConfiguration::Socks(_) => FrontendKind::Socks,
			FrontendConfiguration::Grpc(_) => FrontendKind::Grpc,
			FrontendConfiguration::Tun(_) => FrontendKind::Tun,
		}
	}
}

/// HTTP CONNECT frontend configuration.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpFrontendConfiguration {
	#[serde(default)]
	pub listen_address: String,
	#[serde(default)]
	pub listen_port: u16,
	#[serde(default)]
	pub tls_cert_file: String,
	#[serde(default)]
	pub tls_key_file: String,
	#[serde(default)]
	pub username: String,
	#[serde(default)]
	pub password: String,
	#[serde(default)]
	pub camouflage: bool,
	#[serde(default)]
	pub camouflage_method: String,
	#[serde(default)]
	pub backend: String,
	#[serde(default)]
	pub shim: String,
}

impl HttpFrontendConfiguration {
	pub fn validate(&self) -> Result<(), String> {
		if self.listen_address.is_empty() {
			return Err("listen_address is required".to_string());
		}
		if self.listen_port == 0 {
			return Err("listen_port is required".to_string());
		}
		if (self.tls_cert_file.is_empty()) != (self.tls_key_file.is_empty()) {
			return Err(
				"tls_cert_file and tls_key_file must both be set or both be empty".to_string(),
			);
		}
		if (self.username.is_empty()) != (self.password.is_empty()) {
			return Err("username and password must both be set or both be empty".to_string());
		}
		if normalize_camouflage_method(&self.camouflage_method) != RETURN_404 {
			return Err("camouflage_method must be return-404 or empty".to_string());
		}
		if self.backend.is_empty() {
			return Err("backend reference is required".to_string());
		}
		if self.shim.is_empty() {
			return Err("shim reference is required".to_string());
		}
		Ok(())
	}
}

/// SOCKS5 frontend configuration.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SocksFrontendConfiguration {
	#[serde(default)]
	pub listen_address: String,
	#[serde(default)]
	pub listen_port: u16,
	#[serde(default)]
	pub tls_cert_file: String,
	#[serde(default)]
	pub tls_key_file: String,
	#[serde(default)]
	pub username: String,
	#[serde(default)]
	pub password: String,
	#[serde(default)]
	pub backend: String,
	#[serde(default)]
	pub shim: String,
}

impl SocksFrontendConfiguration {
	pub fn validate(&self) -> Result<(), String> {
		if self.listen_address.is_empty() {
			return Err("listen_address is required".to_string());
		}
		if self.listen_port == 0 {
			return Err("listen_port is required".to_string());
		}
		if (self.tls_cert_file.is_empty()) != (self.tls_key_file.is_empty()) {
			return Err(
				"tls_cert_file and tls_key_file must both be set or both be empty".to_string(),
			);
		}
		if (self.username.is_empty()) != (self.password.is_empty()) {
			return Err("username and password must both be set or both be empty".to_string());
		}
		if self.backend.is_empty() {
			return Err("backend reference is required".to_string());
		}
		if self.shim.is_empty() {
			return Err("shim reference is required".to_string());
		}
		Ok(())
	}
}

/// gRPC tunnel frontend configuration.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrpcFrontendConfiguration {
	#[serde(default)]
	pub listen_address: String,
	#[serde(default)]
	pub listen_port: u16,
	#[serde(default)]
	pub tls_cert_file: String,
	#[serde(default)]
	pub tls_key_file: String,
	#[serde(default)]
	pub token: String,
	#[serde(default)]
	pub backend: String,
	#[serde(default)]
	pub shim: String,
}

impl GrpcFrontendConfiguration {
	pub fn validate(&self) -> Result<(), String> {
		if self.listen_address.is_empty() {
			return Err("listen_address is required".to_string());
		}
		if self.listen_port == 0 {
			return Err("listen_port is required".to_string());
		}
		if (self.tls_cert_file.is_empty()) != (self.tls_key_file.is_empty()) {
			return Err(
				"tls_cert_file and tls_key_file must both be set or both be empty".to_string(),
			);
		}
		if self.backend.is_empty() {
			return Err("backend reference is required".to_string());
		}
		if self.shim.is_empty() {
			return Err("shim reference is required".to_string());
		}
		Ok(())
	}
}

/// TUN frontend configuration.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunFrontendConfiguration {
	#[serde(default)]
	pub device_name: String,
	#[serde(default)]
	pub ipv4_address: String,
	#[serde(default)]
	pub ipv6_address: String,
	#[serde(default)]
	pub mtu: i64,
	#[serde(default)]
	pub auto_route: Option<bool>,
	#[serde(default)]
	pub udp_idle_timeout: i64,
	#[serde(default)]
	pub dns_server: String,
	#[serde(default)]
	pub backend: String,
	#[serde(default)]
	pub backends: Vec<String>,
	#[serde(default)]
	pub fallback: String,
	#[serde(default)]
	pub protocol_detect_timeout: i64,
	#[serde(default)]
	pub protocol_detect_max_bytes: i64,
	#[serde(default)]
	pub shim: String,
}

impl TunFrontendConfiguration {
	pub fn validate(&self) -> Result<(), String> {
		validate_addresses(&self.ipv4_address, &self.ipv6_address)?;
		if self.mtu < 0 {
			return Err("mtu must not be negative".to_string());
		}
		parse_dns_server(&self.dns_server)?;
		if !self.backend.is_empty() && !self.backends.is_empty() {
			return Err("backend and backends are mutually exclusive".to_string());
		}
		if self.backend.is_empty() && self.backends.is_empty() {
			return Err("backend or backends reference is required".to_string());
		}
		let mut seen = std::collections::HashSet::new();
		for name in &self.backends {
			if name.is_empty() {
				return Err("backends must not contain an empty reference".to_string());
			}
			if !seen.insert(name.clone()) {
				return Err(format!("backends contains duplicate reference {name:?}"));
			}
		}
		if self.protocol_detect_timeout < 0 {
			return Err("protocol_detect_timeout must not be negative".to_string());
		}
		if self.protocol_detect_max_bytes < 0 {
			return Err("protocol_detect_max_bytes must not be negative".to_string());
		}
		if self.shim.is_empty() {
			return Err("shim reference is required".to_string());
		}
		Ok(())
	}

	/// Returns the configured candidate backend names in routing order.
	pub fn backend_references(&self) -> Vec<String> {
		if !self.backends.is_empty() {
			self.backends.clone()
		} else if !self.backend.is_empty() {
			vec![self.backend.clone()]
		} else {
			Vec::new()
		}
	}
}

fn validate_addresses(ipv4: &str, ipv6: &str) -> Result<(), String> {
	if ipv4.is_empty() && ipv6.is_empty() {
		return Err("ipv4_address or ipv6_address is required".to_string());
	}
	if !ipv4.is_empty() {
		let (ip, prefix_len) =
			parse_cidr(ipv4).map_err(|e| format!("ipv4_address must be in CIDR form: {e}"))?;
		if !is_ipv4(&ip) {
			return Err("ipv4_address must contain an IPv4 address".to_string());
		}
		if prefix_len.is_none() {
			return Err("ipv4_address must be in CIDR form: missing prefix".to_string());
		}
	}
	if !ipv6.is_empty() {
		let (ip, prefix_len) =
			parse_cidr(ipv6).map_err(|e| format!("ipv6_address must be in CIDR form: {e}"))?;
		if is_ipv4(&ip) {
			return Err("ipv6_address must contain an IPv6 address".to_string());
		}
		if prefix_len.is_none() {
			return Err("ipv6_address must be in CIDR form: missing prefix".to_string());
		}
	}
	Ok(())
}

/// Parses `addr/prefix` returning the IP and optional prefix length.
fn parse_cidr(s: &str) -> Result<(IpAddr, Option<u8>), String> {
	let (ip_part, prefix_part) = match s.rsplit_once('/') {
		Some((ip, p)) => (ip, Some(p)),
		None => (s, None),
	};
	let ip: IpAddr = ip_part
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

fn is_ipv4(addr: &IpAddr) -> bool {
	matches!(addr, IpAddr::V4(_))
}

/// Validates a DNS server address (IP:port). Empty disables interception.
///
/// Error strings are kept stable so tests can `contains`-match.
fn parse_dns_server(value: &str) -> Result<(), String> {
	if value.is_empty() {
		return Ok(());
	}
	let (host, port_str) = split_host_port(value)
		.map_err(|e| format!("dns_server must be an IP address with port: {e}"))?;
	if host.is_empty() {
		return Err("dns_server must be an IP address with port: missing host".to_string());
	}
	let _ip: IpAddr = host.parse().map_err(|e: std::net::AddrParseError| {
		format!("dns_server must be an IP address with port: {e}")
	})?;
	// IPv6 zones are rejected.
	if host.starts_with('[') && host.contains('%') {
		return Err("dns_server must not contain an IPv6 zone".to_string());
	}
	let port: u16 = port_str.parse().map_err(|e: std::num::ParseIntError| {
		format!("dns_server must be an IP address with port: {e}")
	})?;
	if port == 0 {
		return Err("dns_server port must not be zero".to_string());
	}
	Ok(())
}

/// Splits `host:port` or `[ipv6]:port`.
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

pub const RETURN_404: &str = "return-404";

fn normalize_camouflage_method(method: &str) -> &str {
	if method.is_empty() {
		RETURN_404
	} else {
		method
	}
}
