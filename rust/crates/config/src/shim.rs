//! Shim configuration.

use serde::Deserialize;

/// Shim entry under `[shims.<name>]`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShimConfiguration {
	#[serde(default)]
	pub buffer_size: i64,
}

impl ShimConfiguration {
	pub fn validate(&self) -> Result<(), String> {
		if self.buffer_size < 0 {
			return Err("buffer_size must not be negative".to_string());
		}
		Ok(())
	}
}
