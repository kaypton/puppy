//! Durable observability storage configuration.

use serde::Deserialize;

fn default_checkpoint_interval_ms() -> u64 {
	1_000
}

/// Strict `[observability]` configuration.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservabilityConfiguration {
	#[serde(default)]
	pub database_path: String,
	#[serde(default)]
	pub log_directory: String,
	#[serde(default = "default_checkpoint_interval_ms")]
	pub checkpoint_interval_ms: u64,
	#[serde(default)]
	pub connection_retention_days: u64,
	#[serde(default)]
	pub connection_max_rows: u64,
	#[serde(default)]
	pub log_retention_days: u64,
	#[serde(default)]
	pub log_max_total_bytes: u64,
}

impl Default for ObservabilityConfiguration {
	fn default() -> Self {
		Self {
			database_path: String::new(),
			log_directory: String::new(),
			checkpoint_interval_ms: default_checkpoint_interval_ms(),
			connection_retention_days: 0,
			connection_max_rows: 0,
			log_retention_days: 0,
			log_max_total_bytes: 0,
		}
	}
}

impl ObservabilityConfiguration {
	pub fn validate(&self) -> Result<(), String> {
		if self.database_path.is_empty() {
			return Err("observability: database_path is required".to_string());
		}
		if self.log_directory.is_empty() {
			return Err("observability: log_directory is required".to_string());
		}
		if !(100..=60_000).contains(&self.checkpoint_interval_ms) {
			return Err(
				"observability: checkpoint_interval_ms must be between 100 and 60000".to_string(),
			);
		}
		Ok(())
	}
}
