//! Tests for `config.rs`.
//!
//! Two test groups:
//! - `configuration_validate_*`: 14 table-driven validation cases asserting
//!   substring matches on error messages.
//! - `configuration_backend_config_copies_fields`: the `BackendConfig`
//!   field-copy test.

use socksproxy_be::{BackendConfiguration, Configuration};

fn cfg(
	proxy_address: &str,
	username: &str,
	password: &str,
	tls: bool,
	tls_ca_file: &str,
	tls_server_name: &str,
	tls_insecure_skip_verify: bool,
) -> Configuration {
	Configuration {
		proxy_address: proxy_address.to_string(),
		username: username.to_string(),
		password: password.to_string(),
		tls,
		tls_ca_file: tls_ca_file.to_string(),
		tls_server_name: tls_server_name.to_string(),
		tls_insecure_skip_verify,
	}
}

/// Verifies a baseline open config (proxy address only, no auth, no TLS)
/// validates successfully.
#[test]
fn configuration_validate_valid() {
	let c = cfg("proxy.example.com:1080", "", "", false, "", "", false);
	assert!(c.validate().is_ok(), "unexpected error");
}

/// Verifies a config with a paired username/password validates successfully.
#[test]
fn configuration_validate_valid_auth() {
	let c = cfg(
		"proxy.example.com:1080",
		"alice",
		"secret",
		false,
		"",
		"",
		false,
	);
	assert!(c.validate().is_ok(), "unexpected error");
}

/// Verifies a config with TLS enabled (and no CA/server-name/insecure
/// overrides) validates successfully.
#[test]
fn configuration_validate_valid_tls() {
	let c = cfg("proxy.example.com:1080", "", "", true, "", "", false);
	assert!(c.validate().is_ok(), "unexpected error");
}

/// Verifies a config with TLS enabled and a CA file path validates
/// successfully.
#[test]
fn configuration_validate_valid_tls_with_ca() {
	let c = cfg(
		"proxy.example.com:1080",
		"",
		"",
		true,
		"./certs/ca-cert.pem",
		"",
		false,
	);
	assert!(c.validate().is_ok(), "unexpected error");
}

/// Verifies a config with TLS enabled and a custom server name validates
/// successfully.
#[test]
fn configuration_validate_valid_tls_with_server_name() {
	let c = cfg(
		"proxy.example.com:1080",
		"",
		"",
		true,
		"",
		"proxy.internal",
		false,
	);
	assert!(c.validate().is_ok(), "unexpected error");
}

/// Verifies a config with TLS enabled and `tls_insecure_skip_verify`
/// validates successfully.
#[test]
fn configuration_validate_valid_tls_insecure() {
	let c = cfg("proxy.example.com:1080", "", "", true, "", "", true);
	assert!(c.validate().is_ok(), "unexpected error");
}

/// Verifies `validate` rejects an empty `proxy_address` with an error
/// containing "proxy_address is required".
#[test]
fn configuration_validate_missing_address() {
	let c = cfg("", "", "", false, "", "", false);
	let err = c.validate().expect_err("expected error");
	assert!(
		err.to_string().contains("proxy_address is required"),
		"error = {err}"
	);
}

/// Verifies `validate` rejects a `proxy_address` without a port (no `:`
/// delimiter) with an error containing "host:port".
#[test]
fn configuration_validate_missing_port() {
	let c = cfg("proxy.example.com", "", "", false, "", "", false);
	let err = c.validate().expect_err("expected error");
	assert!(err.to_string().contains("host:port"), "error = {err}");
}

/// Verifies `validate` rejects a `proxy_address` with port `0` with an
/// error containing "between 1 and 65535".
#[test]
fn configuration_validate_zero_port() {
	let c = cfg("proxy.example.com:0", "", "", false, "", "", false);
	let err = c.validate().expect_err("expected error");
	assert!(
		err.to_string().contains("between 1 and 65535"),
		"error = {err}"
	);
}

/// Verifies `validate` rejects a config with a username but no password
/// (and vice versa) with an error containing "username and password".
#[test]
fn configuration_validate_unpaired_credentials() {
	let c = cfg("proxy.example.com:1080", "alice", "", false, "", "", false);
	let err = c.validate().expect_err("expected error");
	assert!(
		err.to_string().contains("username and password"),
		"error = {err}"
	);
}

/// Verifies `validate` rejects a `tls_ca_file` set without `tls = true`
/// with an error containing "require tls = true".
#[test]
fn configuration_validate_ca_file_without_tls() {
	let c = cfg(
		"proxy.example.com:1080",
		"",
		"",
		false,
		"./certs/ca-cert.pem",
		"",
		false,
	);
	let err = c.validate().expect_err("expected error");
	assert!(
		err.to_string().contains("require tls = true"),
		"error = {err}"
	);
}

/// Verifies `validate` rejects a `tls_server_name` set without `tls = true`
/// with an error containing "require tls = true".
#[test]
fn configuration_validate_server_name_without_tls() {
	let c = cfg(
		"proxy.example.com:1080",
		"",
		"",
		false,
		"",
		"proxy.internal",
		false,
	);
	let err = c.validate().expect_err("expected error");
	assert!(
		err.to_string().contains("require tls = true"),
		"error = {err}"
	);
}

/// Verifies `validate` rejects `tls_insecure_skip_verify` set without
/// `tls = true` with an error containing "require tls = true".
#[test]
fn configuration_validate_insecure_without_tls() {
	let c = cfg("proxy.example.com:1080", "", "", false, "", "", true);
	let err = c.validate().expect_err("expected error");
	assert!(
		err.to_string().contains("require tls = true"),
		"error = {err}"
	);
}

/// Verifies `validate` rejects a config that sets both `tls_ca_file` and
/// `tls_insecure_skip_verify` (mutually exclusive: trust a CA vs. skip
/// verification) with an error containing "mutually exclusive".
#[test]
fn configuration_validate_insecure_with_ca_file() {
	let c = cfg(
		"proxy.example.com:1080",
		"",
		"",
		true,
		"./certs/ca-cert.pem",
		"",
		true,
	);
	let err = c.validate().expect_err("expected error");
	assert!(
		err.to_string().contains("mutually exclusive"),
		"error = {err}"
	);
}

/// Verifies `backend_config` copies every field from the file
/// `Configuration` into the runtime `BackendConfiguration` (proxy address,
/// credentials, TLS flag, CA file, server name, and the inverted
/// `tls_insecure_skip_verify`).
#[test]
fn configuration_backend_config_copies_fields() {
	let c = cfg(
		"proxy.example.com:1080",
		"alice",
		"secret",
		true,
		"./certs/ca-cert.pem",
		"proxy.internal",
		false,
	);
	let bc: BackendConfiguration = c.backend_config().expect("BackendConfig");
	assert_eq!(bc.proxy_address, "proxy.example.com:1080");
	assert_eq!(bc.username, "alice");
	assert_eq!(bc.password, "secret");
	assert!(bc.tls);
	assert_eq!(bc.tls_ca_file, "./certs/ca-cert.pem");
	assert_eq!(bc.tls_server_name, "proxy.internal");
	assert!(!bc.tls_insecure_skip_verify);
}
