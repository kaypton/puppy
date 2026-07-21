//! TOML configuration owned by the direct backend.
//!
//! Direct connections currently have no implementation-specific settings, so
//! the configuration is an empty struct that always validates.

use serde::Deserialize;

/// Discriminant identifying the direct backend in a named configuration
/// group.
pub const TYPE: &str = "direct";

/// TOML configuration for the direct backend.
///
/// Direct connections currently have no implementation-specific settings.
/// Strict TOML decoding (`deny_unknown_fields`) rejects unknown fields at
/// startup.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Configuration {}

impl Configuration {
	/// Validates the direct backend configuration. Always succeeds because
	/// direct connections have no settings.
	pub fn validate(&self) -> Result<(), ConfigError> {
		Ok(())
	}
}

/// Errors returned by [`Configuration::validate`]. Currently no variants are
/// emitted; the type exists for forward compatibility.
#[derive(thiserror::Error, Debug)]
pub enum ConfigError {}
