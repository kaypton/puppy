//! Configuration parsing and validation for puppy-server.
//!
//! The `Configuration` shape is built around named frontend/backend/shim maps
//! plus a `frontend` selector and an optional `[dashboard]` section.
//!
//! All serde structs use `#[serde(deny_unknown_fields)]` so unknown fields
//! fail at startup. Error strings are stable so the test suite can lock them
//! down with `assert_eq!` / `contains` checks.

mod backend;
mod dashboard;
mod error;
mod frontend;
mod shim;

pub use backend::{
	BackendConfiguration, BackendKind, DirectBackendConfiguration, HttpBackendConfiguration,
	SocksBackendConfiguration,
};
pub use dashboard::DashboardConfiguration;
pub use error::{ConfigError, ValidationError};
pub use frontend::{
	FrontendConfiguration, FrontendKind, HttpFrontendConfiguration, SocksFrontendConfiguration,
	TunFrontendConfiguration,
};
pub use shim::ShimConfiguration;

use std::collections::HashMap;
use std::path::Path;

use serde::Deserialize;

/// Top-level configuration as decoded from TOML.
///
/// All nested component maps are keyed by name; `frontend` selects which entry
/// in `frontends` to start.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Configuration {
	/// Name of the `[frontends.<name>]` entry to start. Required.
	#[serde(default)]
	pub frontend: String,
	#[serde(default)]
	pub frontends: HashMap<String, FrontendConfiguration>,
	#[serde(default)]
	pub backends: HashMap<String, BackendConfiguration>,
	#[serde(default)]
	pub shims: HashMap<String, ShimConfiguration>,
	#[serde(default)]
	pub dashboard: Option<DashboardConfiguration>,
}

impl Configuration {
	/// Validates the configuration, producing the same errors in the same
	/// order as a deterministic left-to-right traversal of the component maps.
	pub fn validate(&self) -> Result<(), ValidationError> {
		if self.frontend.is_empty() {
			return Err(ValidationError::new("frontend selection is required"));
		}
		if !self.frontends.contains_key(&self.frontend) {
			return Err(ValidationError::new(format!(
				"selected frontend {:?} does not exist",
				self.frontend
			)));
		}

		for name in sorted_keys(&self.frontends) {
			self.validate_frontend(&name)?;
		}
		for name in sorted_keys(&self.backends) {
			self.validate_backend(&name)?;
		}
		for name in sorted_keys(&self.shims) {
			if name.is_empty() {
				return Err(ValidationError::new("shim name must not be empty"));
			}
			self.shims[&name]
				.validate()
				.map_err(|e| ValidationError::new(format!("shim {name:?}: {e}")))?;
		}

		if let Some(dash) = &self.dashboard {
			dash.validate().map_err(ValidationError::from)?;
		}
		Ok(())
	}

	fn validate_frontend(&self, name: &str) -> Result<(), ValidationError> {
		if name.is_empty() {
			return Err(ValidationError::new("frontend name must not be empty"));
		}
		let group = &self.frontends[name];
		match &group.kind() {
			FrontendKind::Http => {
				let FrontendConfiguration::Http(cfg) = group else {
					return Err(ValidationError::new(format!(
						"frontend {name:?}: configuration does not match type {:?}",
						"httpproxy"
					)));
				};
				cfg.validate()
					.map_err(|e| ValidationError::new(format!("frontend {name:?}: {e}")))?;
				if !self.backends.contains_key(&cfg.backend) {
					return Err(ValidationError::new(format!(
						"frontend {name:?}: backend {:?} does not exist",
						cfg.backend
					)));
				}
				if !self.shims.contains_key(&cfg.shim) {
					return Err(ValidationError::new(format!(
						"frontend {name:?}: shim {:?} does not exist",
						cfg.shim
					)));
				}
			}
			FrontendKind::Socks => {
				let FrontendConfiguration::Socks(cfg) = group else {
					return Err(ValidationError::new(format!(
						"frontend {name:?}: configuration does not match type {:?}",
						"socksproxy"
					)));
				};
				cfg.validate()
					.map_err(|e| ValidationError::new(format!("frontend {name:?}: {e}")))?;
				if !self.backends.contains_key(&cfg.backend) {
					return Err(ValidationError::new(format!(
						"frontend {name:?}: backend {:?} does not exist",
						cfg.backend
					)));
				}
				if !self.shims.contains_key(&cfg.shim) {
					return Err(ValidationError::new(format!(
						"frontend {name:?}: shim {:?} does not exist",
						cfg.shim
					)));
				}
			}
			FrontendKind::Tun => {
				let FrontendConfiguration::Tun(cfg) = group else {
					return Err(ValidationError::new(format!(
						"frontend {name:?}: configuration does not match type {:?}",
						"tun"
					)));
				};
				cfg.validate()
					.map_err(|e| ValidationError::new(format!("frontend {name:?}: {e}")))?;
				for backend_name in cfg.backend_references() {
					if !self.backends.contains_key(&backend_name) {
						return Err(ValidationError::new(format!(
							"frontend {name:?}: backend {:?} does not exist",
							backend_name
						)));
					}
				}
				if !cfg.fallback.is_empty() && !self.backends.contains_key(&cfg.fallback) {
					return Err(ValidationError::new(format!(
						"frontend {name:?}: fallback backend {:?} does not exist",
						cfg.fallback
					)));
				}
				if !self.shims.contains_key(&cfg.shim) {
					return Err(ValidationError::new(format!(
						"frontend {name:?}: shim {:?} does not exist",
						cfg.shim
					)));
				}
			}
		}
		Ok(())
	}

	fn validate_backend(&self, name: &str) -> Result<(), ValidationError> {
		if name.is_empty() {
			return Err(ValidationError::new("backend name must not be empty"));
		}
		let group = &self.backends[name];
		group
			.validate()
			.map_err(|e| ValidationError::new(format!("backend {name:?}: {e}")))?;
		Ok(())
	}
}

/// Loads a `Configuration` from a TOML file.
///
/// Loading is non-strict in a controlled way: every undecoded key is collected
/// and reported together at the end as
/// `configuration contains unknown field(s): <dotted>, <dotted>, ...`. Unknown
/// `type` discriminants are caught earlier, during the per-group decode loop,
/// and produce `frontend "<name>": unknown type "<type>"` (or `backend ...`).
///
/// This function implements that two-pass behavior:
///  1. Parse to `toml::Value`.
///  2. Walk frontends/backends in sorted name order; if any has an unknown
///     `type`, return the `unknown type` error (the early return).
///  3. Walk the full tree and collect every unknown field as a dotted path;
///     if any, return `configuration contains unknown field(s): <joined>`.
///  4. Deserialize into `Configuration` and run `validate`.
///
/// Error strings are stable so the test suite can lock them down with
/// `contains` checks.
pub fn load(path: &Path) -> Result<Configuration, ConfigError> {
	let text =
		std::fs::read_to_string(path).map_err(|e| ConfigError::Load(path.to_path_buf(), e))?;
	let value: toml::Value = toml::from_str(&text).map_err(ConfigError::Parse)?;

	if let Some(msg) = find_unknown_type(&value) {
		return Err(ConfigError::ParseUnknownTopLevel(msg));
	}

	if let Some(keys) = collect_unknown_fields(&value) {
		return Err(ConfigError::ParseUnknownTopLevel(format!(
			"configuration contains unknown field(s): {}",
			keys.join(", ")
		)));
	}

	let cfg: Configuration = value.try_into().map_err(ConfigError::Parse)?;
	cfg.validate()
		.map_err(|e| ConfigError::Validation(path.to_path_buf(), e))?;
	Ok(cfg)
}

/// Frontend/backend `type` discriminants recognised by the schema.
const FRONTEND_KINDS: &[&str] = &["httpproxy", "socksproxy", "tun"];
const BACKEND_KINDS: &[&str] = &["direct", "httpproxy", "socksproxy"];

/// Pass 1: walk frontends then backends in sorted name order and return the
/// first group whose `type` is not a recognised discriminant. This mirrors
/// the per-group decode loop, which returns early on unknown `type` before the
/// full unknown-field check.
fn find_unknown_type(value: &toml::Value) -> Option<String> {
	let table = value.as_table()?;
	if let Some(frontends) = table.get("frontends").and_then(|v| v.as_table()) {
		let mut names: Vec<&String> = frontends.keys().collect();
		names.sort();
		for name in names {
			if let Some(group) = frontends.get(name).and_then(|v| v.as_table()) {
				let kind = group.get("type").and_then(|v| v.as_str()).unwrap_or("");
				if !FRONTEND_KINDS.contains(&kind) {
					return Some(format!(r#"frontend "{name}": unknown type "{kind}""#));
				}
			}
		}
	}
	if let Some(backends) = table.get("backends").and_then(|v| v.as_table()) {
		let mut names: Vec<&String> = backends.keys().collect();
		names.sort();
		for name in names {
			if let Some(group) = backends.get(name).and_then(|v| v.as_table()) {
				let kind = group.get("type").and_then(|v| v.as_str()).unwrap_or("");
				if !BACKEND_KINDS.contains(&kind) {
					return Some(format!(r#"backend "{name}": unknown type "{kind}""#));
				}
			}
		}
	}
	None
}

/// Pass 2: walk the full TOML tree and collect every unknown field as a dotted
/// path. Both top-level unknowns and nested unknowns (inside
/// frontends/backends/shims/dashboard) are reported with the same
/// `configuration contains unknown field(s): ...` envelope.
///
/// Keys are collected in BTreeMap (sorted) order, not file order; tests use
/// `contains`, so a single matching path substring suffices.
fn collect_unknown_fields(value: &toml::Value) -> Option<Vec<String>> {
	let table = value.as_table()?;
	let mut keys: Vec<String> = Vec::new();

	for (top, val) in table {
		match top.as_str() {
			"frontend" => {}
			"frontends" => {
				if let Some(groups) = val.as_table() {
					collect_unknown_in_tagged_groups(
						groups,
						"frontends",
						frontend_known_fields,
						FRONTEND_KINDS,
						&mut keys,
					);
				}
			}
			"backends" => {
				if let Some(groups) = val.as_table() {
					collect_unknown_in_tagged_groups(
						groups,
						"backends",
						backend_known_fields,
						BACKEND_KINDS,
						&mut keys,
					);
				}
			}
			"shims" => {
				if let Some(groups) = val.as_table() {
					collect_unknown_in_groups(groups, "shims", shim_known_fields, &mut keys);
				}
			}
			"dashboard" => {
				if let Some(dash) = val.as_table() {
					collect_unknown_in_table(
						dash,
						"dashboard",
						dashboard_known_fields(),
						&mut keys,
					);
				}
			}
			other => {
				keys.push(format!("configuration contains unknown field(s): {other}"));
			}
		}
	}

	if keys.is_empty() {
		None
	} else {
		Some(keys)
	}
}

/// Collects unknown fields across `[<section>.<group>]` entries where the
/// allowed field set depends on the `type` discriminant. Groups with an
/// unrecognised `type` are skipped here (Pass 1 already reported them).
fn collect_unknown_in_tagged_groups(
	groups: &toml::value::Table,
	section: &str,
	known: fn(&str) -> &'static [&'static str],
	known_kinds: &'static [&'static str],
	keys: &mut Vec<String>,
) {
	for (group_name, group_val) in groups {
		let Some(group_table) = group_val.as_table() else {
			continue;
		};
		let kind = group_table
			.get("type")
			.and_then(|v| v.as_str())
			.unwrap_or("");
		if !known_kinds.contains(&kind) {
			continue;
		}
		let allowed = known(kind);
		for (field, _) in group_table {
			if field == "type" {
				continue;
			}
			if !allowed.contains(&field.as_str()) {
				keys.push(format!("{section}.{group_name}.{field}"));
			}
		}
	}
}

/// Collects unknown fields across `[<section>.<group>]` entries where every
/// group shares the same allowed field set (shims).
fn collect_unknown_in_groups(
	groups: &toml::value::Table,
	section: &str,
	known: fn(&str) -> &'static [&'static str],
	keys: &mut Vec<String>,
) {
	for (group_name, group_val) in groups {
		let Some(group_table) = group_val.as_table() else {
			continue;
		};
		let allowed = known("");
		for (field, _) in group_table {
			if !allowed.contains(&field.as_str()) {
				keys.push(format!("{section}.{group_name}.{field}"));
			}
		}
	}
}

/// Collects unknown fields in a flat table (dashboard).
fn collect_unknown_in_table(
	table: &toml::value::Table,
	prefix: &str,
	known: &'static [&'static str],
	keys: &mut Vec<String>,
) {
	for (field, _) in table {
		if !known.contains(&field.as_str()) {
			keys.push(format!("{prefix}.{field}"));
		}
	}
}

fn frontend_known_fields(kind: &str) -> &'static [&'static str] {
	match kind {
		"httpproxy" => &[
			"listen_address",
			"listen_port",
			"tls_cert_file",
			"tls_key_file",
			"username",
			"password",
			"camouflage",
			"camouflage_method",
			"backend",
			"shim",
		],
		"socksproxy" => &[
			"listen_address",
			"listen_port",
			"tls_cert_file",
			"tls_key_file",
			"username",
			"password",
			"backend",
			"shim",
		],
		"tun" => &[
			"device_name",
			"ipv4_address",
			"ipv6_address",
			"mtu",
			"auto_route",
			"udp_idle_timeout",
			"dns_server",
			"backend",
			"backends",
			"fallback",
			"protocol_detect_timeout",
			"protocol_detect_max_bytes",
			"shim",
		],
		_ => &[],
	}
}

fn backend_known_fields(kind: &str) -> &'static [&'static str] {
	match kind {
		"direct" => &[],
		"httpproxy" | "socksproxy" => &[
			"proxy_address",
			"username",
			"password",
			"tls",
			"tls_ca_file",
			"tls_server_name",
			"tls_insecure_skip_verify",
		],
		_ => &[],
	}
}

fn shim_known_fields(_kind: &str) -> &'static [&'static str] {
	&["buffer_size"]
}

fn dashboard_known_fields() -> &'static [&'static str] {
	&[
		"enabled",
		"listen_address",
		"listen_port",
		"tls_cert_file",
		"tls_key_file",
		"token",
	]
}

fn sorted_keys<T>(map: &HashMap<String, T>) -> Vec<String> {
	let mut keys: Vec<String> = map.keys().cloned().collect();
	keys.sort();
	keys
}
