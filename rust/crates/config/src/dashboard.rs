//! Dashboard configuration.
//!
//! The dashboard itself is **not implemented**; the struct exists only so
//! `config.toml`'s `[dashboard]` section parses and can be validated. The
//! server bin ignores the dashboard at startup (no listener is spawned).

use serde::Deserialize;

/// `[dashboard]` section. Fields and validation are kept in sync with
/// `config.toml` so the example round-trips and validation errors stay
/// stable.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DashboardConfiguration {
	#[serde(default)]
	pub enabled: bool,
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
}

impl DashboardConfiguration {
	/// Validates the dashboard configuration. Validation is skipped when the
	/// dashboard is disabled.
	pub fn validate(&self) -> Result<(), String> {
		if !self.enabled {
			return Ok(());
		}
		if self.listen_address.is_empty() {
			return Err("dashboard: listen_address is required when enabled".to_string());
		}
		if self.listen_port == 0 {
			return Err("dashboard: listen_port is required when enabled".to_string());
		}
		if (self.tls_cert_file.is_empty()) != (self.tls_key_file.is_empty()) {
			return Err(
				"dashboard: tls_cert_file and tls_key_file must both be set or both be empty"
					.to_string(),
			);
		}
		Ok(())
	}
}
