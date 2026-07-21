//! Configuration error types.
//!
//! - parse failures wrap as `load configuration <path>: <err>`
//! - validation failures wrap as `validate configuration <path>: <err>`

use std::path::PathBuf;

/// Top-level error raised by [`crate::load`].
#[derive(thiserror::Error, Debug)]
pub enum ConfigError {
	/// Could not read the file from disk.
	#[error("load configuration {0:?}: {1}")]
	Load(PathBuf, std::io::Error),

	/// TOML parse failure (includes unknown-field errors emitted by serde).
	#[error("load configuration {0}")]
	Parse(#[source] toml::de::Error),

	/// Top-level unknown TOML field, rewritten to the strict-decoder error
	/// string `configuration contains unknown field(s): <name>`.
	#[error("load configuration {0}")]
	ParseUnknownTopLevel(String),

	/// Cross-field validation failure.
	#[error("validate configuration {0:?}: {1}")]
	Validation(PathBuf, ValidationError),
}

/// A validation error carrying the error message string.
#[derive(thiserror::Error, Debug)]
#[error("{0}")]
pub struct ValidationError(pub String);

impl ValidationError {
	pub fn new(message: impl Into<String>) -> Self {
		Self(message.into())
	}
}

impl From<String> for ValidationError {
	fn from(s: String) -> Self {
		Self(s)
	}
}
