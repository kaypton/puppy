//! gRPC management endpoint configuration.

use serde::Deserialize;

/// Strict `[grpc]` configuration for the read-only observability API.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrpcConfiguration {
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

impl GrpcConfiguration {
	pub fn validate(&self) -> Result<(), String> {
		if !self.enabled {
			return Ok(());
		}
		if self.listen_address.is_empty() {
			return Err("grpc: listen_address is required when enabled".to_string());
		}
		if self.listen_port == 0 {
			return Err("grpc: listen_port is required when enabled".to_string());
		}
		if self.tls_cert_file.is_empty() != self.tls_key_file.is_empty() {
			return Err(
				"grpc: tls_cert_file and tls_key_file must both be set or both be empty"
					.to_string(),
			);
		}
		Ok(())
	}
}
