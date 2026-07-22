//! TOML configuration owned by the gRPC tunnel proxy backend.

use serde::Deserialize;

/// Discriminant identifying the gRPC tunnel proxy backend in a named
/// configuration group.
pub const TYPE: &str = "grpcproxy";

/// TOML configuration for the gRPC tunnel proxy backend.
///
/// Strict TOML decoding (`deny_unknown_fields`) rejects unknown fields at
/// startup so configuration mistakes surface immediately.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Configuration {
	/// Address of the remote gRPC tunnel server (`host:port`).
	#[serde(default)]
	pub server_address: String,
	/// Enables TLS to the tunnel server when `true`.
	#[serde(default)]
	pub tls: bool,
	/// PEM file of additional CA certificates used to verify the tunnel
	/// server's certificate. Only meaningful when `tls` is `true`.
	#[serde(default)]
	pub tls_ca_file: String,
	/// Overrides the TLS SNI and certificate verification name. When empty,
	/// the host portion of `server_address` is used. Only meaningful when
	/// `tls` is `true`.
	#[serde(default)]
	pub tls_server_name: String,
	/// Disables certificate verification. Only meaningful when `tls` is
	/// `true`, and mutually exclusive with `tls_ca_file`.
	#[serde(default)]
	pub tls_insecure_skip_verify: bool,
	/// Bearer token sent as the `authorization` metadata header. Empty
	/// disables authentication metadata.
	#[serde(default)]
	pub token: String,
}

impl Configuration {
	/// Validates the gRPC tunnel proxy backend's own configuration fields.
	pub fn validate(&self) -> Result<(), ConfigError> {
		if self.server_address.is_empty() {
			return Err(ConfigError::Validation(
				"server_address is required".to_string(),
			));
		}
		let (host, port_text) = split_host_port(&self.server_address).ok_or_else(|| {
			ConfigError::Validation(format!(
				"server_address must be in host:port form: missing port in address {}",
				self.server_address
			))
		})?;
		if host.is_empty() {
			return Err(ConfigError::Validation(
				"server_address host is required".to_string(),
			));
		}
		let port: u64 = port_text.parse().map_err(|_| {
			ConfigError::Validation("server_address port must be between 1 and 65535".to_string())
		})?;
		if port == 0 || port > 65535 {
			return Err(ConfigError::Validation(
				"server_address port must be between 1 and 65535".to_string(),
			));
		}
		if !self.tls
			&& (!self.tls_ca_file.is_empty()
				|| !self.tls_server_name.is_empty()
				|| self.tls_insecure_skip_verify)
		{
			return Err(ConfigError::Validation(
				"tls_ca_file, tls_server_name, and tls_insecure_skip_verify require tls = true"
					.to_string(),
			));
		}
		if self.tls_insecure_skip_verify && !self.tls_ca_file.is_empty() {
			return Err(ConfigError::Validation(
				"tls_insecure_skip_verify and tls_ca_file are mutually exclusive".to_string(),
			));
		}
		Ok(())
	}
}

/// Splits `host:port` into `(host, port_text)`. Returns `None` when no port
/// delimiter is present. Handles IPv6 literals in the `server_address` shape
/// (no zone-id handling needed for our tests).
fn split_host_port(s: &str) -> Option<(&str, &str)> {
	// IPv6 literals contain colons; look for the last ':' that follows the
	// closing ']' of an IPv6 host, otherwise the last ':' in the string.
	if let Some(rest) = s.strip_prefix('[') {
		let close = rest.find(']')?;
		// `close` is the index of ']' in `rest`, which is one past the '[' in
		// `s`. So ']' sits at index `close + 1` in `s`, and the host slice
		// (including brackets) ends at `close + 2`.
		let host_end = close + 2;
		let after = &s[host_end..];
		let port_text = after.strip_prefix(':')?;
		Some((&s[..host_end], port_text))
	} else {
		let idx = s.rfind(':')?;
		Some((&s[..idx], &s[idx + 1..]))
	}
}

/// Errors returned by [`Configuration::validate`].
#[derive(thiserror::Error, Debug)]
pub enum ConfigError {
	#[error("{0}")]
	Validation(String),
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn split_host_port_simple() {
		assert_eq!(
			split_host_port("tunnel.example.com:443"),
			Some(("tunnel.example.com", "443"))
		);
	}

	#[test]
	fn split_host_port_ipv6() {
		assert_eq!(split_host_port("[::1]:443"), Some(("[::1]", "443")));
	}

	#[test]
	fn split_host_port_no_port() {
		assert_eq!(split_host_port("tunnel.example.com"), None);
	}
}
