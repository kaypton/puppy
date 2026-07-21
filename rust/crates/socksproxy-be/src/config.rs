//! TOML configuration owned by the SOCKS5 proxy backend.
//!
//! Error strings are kept stable so tests can match on substrings.

use std::net::ToSocketAddrs;

use serde::Deserialize;

/// Discriminant identifying the SOCKS5 proxy backend in a named configuration
/// group.
pub const TYPE: &str = "socksproxy";

/// TOML configuration for the SOCKS5 proxy backend.
///
/// Strict TOML decoding (`deny_unknown_fields`) rejects unknown fields at
/// startup so configuration mistakes fail fast.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Configuration {
	/// Upstream SOCKS5 proxy address (`host:port`).
	pub proxy_address: String,
	/// Username for RFC 1929 username/password sub-negotiation. Required to be
	/// paired with `password`.
	pub username: String,
	/// Password for RFC 1929 username/password sub-negotiation. Required to be
	/// paired with `username`.
	pub password: String,
	/// Enables TLS to the upstream proxy when `true`.
	#[serde(default)]
	pub tls: bool,
	/// PEM file of additional CA certificates used to verify the upstream
	/// proxy's server certificate. Only meaningful when `tls` is `true`.
	#[serde(default)]
	pub tls_ca_file: String,
	/// Overrides the TLS SNI and certificate verification name. When empty,
	/// the host portion of `proxy_address` is used. Only meaningful when
	/// `tls` is `true`.
	#[serde(default)]
	pub tls_server_name: String,
	/// Disables certificate verification. Only meaningful when `tls` is
	/// `true`, and mutually exclusive with `tls_ca_file`.
	#[serde(default)]
	pub tls_insecure_skip_verify: bool,
}

impl Configuration {
	/// Validates the SOCKS5 proxy backend's own configuration fields.
	pub fn validate(&self) -> Result<(), ConfigError> {
		if self.proxy_address.is_empty() {
			return Err(ConfigError::Validation(
				"proxy_address is required".to_string(),
			));
		}
		let (host, port_text) = split_host_port(&self.proxy_address).ok_or_else(|| {
			ConfigError::Validation(format!(
				"proxy_address must be in host:port form: missing port in address {}",
				self.proxy_address
			))
		})?;
		if host.is_empty() {
			return Err(ConfigError::Validation(
				"proxy_address host is required".to_string(),
			));
		}
		let port: u64 = port_text.parse().map_err(|_| {
			ConfigError::Validation("proxy_address port must be between 1 and 65535".to_string())
		})?;
		if port == 0 || port > 65535 {
			return Err(ConfigError::Validation(
				"proxy_address port must be between 1 and 65535".to_string(),
			));
		}
		if (self.username.is_empty()) != (self.password.is_empty()) {
			return Err(ConfigError::Validation(
				"username and password must both be set or both be empty".to_string(),
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
		// `ToSocketAddrs` is used as a sanity check; we only care that the
		// host part is syntactically valid. The unused result is intentional.
		let _ = (self.proxy_address.as_str(), 0u16).to_socket_addrs();
		Ok(())
	}
}

/// Splits `host:port` into `(host, port_text)`. Returns `None` when no port
/// delimiter is present. Handles bracketed IPv6 literals.
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

	/// Verifies `split_host_port` parses a plain `host:port` string into the
	/// `(host, port_text)` pair.
	#[test]
	fn split_host_port_simple() {
		assert_eq!(
			split_host_port("proxy.example.com:1080"),
			Some(("proxy.example.com", "1080"))
		);
	}

	/// Verifies `split_host_port` correctly handles a bracketed IPv6 literal
	/// (`[::1]:443`) and returns the bracketed host verbatim.
	#[test]
	fn split_host_port_ipv6() {
		assert_eq!(split_host_port("[::1]:443"), Some(("[::1]", "443")));
	}

	/// Verifies `split_host_port` returns `None` when no port delimiter is
	/// present.
	#[test]
	fn split_host_port_no_port() {
		assert_eq!(split_host_port("proxy.example.com"), None);
	}
}
