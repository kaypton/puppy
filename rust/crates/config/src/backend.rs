//! Backend configuration: tagged enum over direct / HTTP / SOCKS5 variants.
//!
//! - direct (`type = "direct"`)
//! - HTTP CONNECT (`type = "httpproxy"`)
//! - SOCKS5 (`type = "socksproxy"`)
//! - gRPC tunnel (`type = "grpcproxy"`)

use serde::Deserialize;

/// A backend entry under `[backends.<name>]`, tagged by `type`.
#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
pub enum BackendConfiguration {
	#[serde(rename = "direct")]
	Direct(DirectBackendConfiguration),
	#[serde(rename = "httpproxy")]
	Http(HttpBackendConfiguration),
	#[serde(rename = "socksproxy")]
	Socks(SocksBackendConfiguration),
	#[serde(rename = "grpcproxy")]
	Grpc(GrpcBackendConfiguration),
}

/// Discriminant accessor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendKind {
	Direct,
	Http,
	Socks,
	Grpc,
}

impl BackendConfiguration {
	pub fn kind(&self) -> BackendKind {
		match self {
			BackendConfiguration::Direct(_) => BackendKind::Direct,
			BackendConfiguration::Http(_) => BackendKind::Http,
			BackendConfiguration::Socks(_) => BackendKind::Socks,
			BackendConfiguration::Grpc(_) => BackendKind::Grpc,
		}
	}

	pub fn validate(&self) -> Result<(), String> {
		match self {
			BackendConfiguration::Direct(c) => c.validate(),
			BackendConfiguration::Http(c) => c.validate(),
			BackendConfiguration::Socks(c) => c.validate(),
			BackendConfiguration::Grpc(c) => c.validate(),
		}
	}
}

/// Direct backend: no implementation-specific settings.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectBackendConfiguration {}

impl DirectBackendConfiguration {
	pub fn validate(&self) -> Result<(), String> {
		Ok(())
	}
}

/// Upstream HTTP CONNECT backend configuration.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpBackendConfiguration {
	#[serde(default)]
	pub proxy_address: String,
	#[serde(default)]
	pub username: String,
	#[serde(default)]
	pub password: String,
	#[serde(default)]
	pub tls: bool,
	#[serde(default)]
	pub tls_ca_file: String,
	#[serde(default)]
	pub tls_server_name: String,
	#[serde(default)]
	pub tls_insecure_skip_verify: bool,
}

/// Upstream SOCKS5 backend configuration.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SocksBackendConfiguration {
	#[serde(default)]
	pub proxy_address: String,
	#[serde(default)]
	pub username: String,
	#[serde(default)]
	pub password: String,
	#[serde(default)]
	pub tls: bool,
	#[serde(default)]
	pub tls_ca_file: String,
	#[serde(default)]
	pub tls_server_name: String,
	#[serde(default)]
	pub tls_insecure_skip_verify: bool,
}

/// Upstream gRPC tunnel backend configuration.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrpcBackendConfiguration {
	#[serde(default)]
	pub server_address: String,
	#[serde(default)]
	pub tls: bool,
	#[serde(default)]
	pub tls_ca_file: String,
	#[serde(default)]
	pub tls_server_name: String,
	#[serde(default)]
	pub tls_insecure_skip_verify: bool,
	#[serde(default)]
	pub token: String,
}

impl HttpBackendConfiguration {
	pub fn validate(&self) -> Result<(), String> {
		validate_proxy_backend(
			&self.proxy_address,
			&self.username,
			&self.password,
			self.tls,
			&self.tls_ca_file,
			&self.tls_server_name,
			self.tls_insecure_skip_verify,
		)
	}
}

impl SocksBackendConfiguration {
	pub fn validate(&self) -> Result<(), String> {
		validate_proxy_backend(
			&self.proxy_address,
			&self.username,
			&self.password,
			self.tls,
			&self.tls_ca_file,
			&self.tls_server_name,
			self.tls_insecure_skip_verify,
		)
	}
}

impl GrpcBackendConfiguration {
	pub fn validate(&self) -> Result<(), String> {
		if self.server_address.is_empty() {
			return Err("server_address is required".to_string());
		}
		let (host, port_str) = split_host_port(&self.server_address)
			.map_err(|e| format!("server_address must be in host:port form: {e}"))?;
		if host.is_empty() {
			return Err("server_address host is required".to_string());
		}
		let port: u16 = port_str.parse().map_err(|e: std::num::ParseIntError| {
			format!("server_address must be in host:port form: {e}")
		})?;
		if port == 0 {
			return Err("server_address port must be between 1 and 65535".to_string());
		}
		if !self.tls
			&& (!self.tls_ca_file.is_empty()
				|| !self.tls_server_name.is_empty()
				|| self.tls_insecure_skip_verify)
		{
			return Err(
				"tls_ca_file, tls_server_name, and tls_insecure_skip_verify require tls = true"
					.to_string(),
			);
		}
		if self.tls_insecure_skip_verify && !self.tls_ca_file.is_empty() {
			return Err(
				"tls_insecure_skip_verify and tls_ca_file are mutually exclusive".to_string(),
			);
		}
		Ok(())
	}
}

fn validate_proxy_backend(
	proxy_address: &str,
	username: &str,
	password: &str,
	tls: bool,
	tls_ca_file: &str,
	tls_server_name: &str,
	tls_insecure_skip_verify: bool,
) -> Result<(), String> {
	if proxy_address.is_empty() {
		return Err("proxy_address is required".to_string());
	}
	let (host, port_str) = split_host_port(proxy_address)
		.map_err(|e| format!("proxy_address must be in host:port form: {e}"))?;
	if host.is_empty() {
		return Err("proxy_address host is required".to_string());
	}
	let port: u16 = port_str.parse().map_err(|e: std::num::ParseIntError| {
		format!("proxy_address must be in host:port form: {e}")
	})?;
	if port == 0 {
		return Err("proxy_address port must be between 1 and 65535".to_string());
	}
	if (username.is_empty()) != (password.is_empty()) {
		return Err("username and password must both be set or both be empty".to_string());
	}
	if !tls && (!tls_ca_file.is_empty() || !tls_server_name.is_empty() || tls_insecure_skip_verify)
	{
		return Err(
			"tls_ca_file, tls_server_name, and tls_insecure_skip_verify require tls = true"
				.to_string(),
		);
	}
	if tls_insecure_skip_verify && !tls_ca_file.is_empty() {
		return Err("tls_insecure_skip_verify and tls_ca_file are mutually exclusive".to_string());
	}
	Ok(())
}

fn split_host_port(s: &str) -> Result<(String, String), String> {
	if let Some(stripped) = s.strip_prefix('[') {
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
