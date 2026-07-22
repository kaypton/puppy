//! Tests for `config.rs`.
//!
//! Three test groups:
//! - `configuration_default*`: serde defaults.
//! - `configuration_validate_*`: validation cases, asserting substring
//!   matches on error messages.
//! - `configuration_backend_config_*`: the `backend_config` field-copy test.

use grpcproxy_be::{BackendConfiguration, Configuration};

fn cfg(
	server_address: &str,
	tls: bool,
	tls_ca_file: &str,
	tls_server_name: &str,
	tls_insecure_skip_verify: bool,
	token: &str,
) -> Configuration {
	Configuration {
		server_address: server_address.to_string(),
		tls,
		tls_ca_file: tls_ca_file.to_string(),
		tls_server_name: tls_server_name.to_string(),
		tls_insecure_skip_verify,
		token: token.to_string(),
	}
}

#[test]
fn configuration_default_from_empty_toml() {
	let c: Configuration = toml::from_str("").expect("empty TOML decodes with defaults");
	assert_eq!(c, Configuration::default());
	assert_eq!(c.server_address, "");
	assert!(!c.tls);
	assert_eq!(c.tls_ca_file, "");
	assert_eq!(c.tls_server_name, "");
	assert!(!c.tls_insecure_skip_verify);
	assert_eq!(c.token, "");
}

#[test]
fn configuration_rejects_unknown_fields() {
	let err = toml::from_str::<Configuration>(
		"server_address = \"tunnel.example.com:443\"\nbogus_field = 1\n",
	)
	.expect_err("unknown field must be rejected");
	assert!(err.to_string().contains("unknown field"), "error = {err}");
}

#[test]
fn configuration_validate_valid_no_tls() {
	let c = cfg("tunnel.example.com:443", false, "", "", false, "");
	assert!(c.validate().is_ok(), "unexpected error");
}

#[test]
fn configuration_validate_valid_token() {
	let c = cfg("tunnel.example.com:443", false, "", "", false, "secret");
	assert!(c.validate().is_ok(), "unexpected error");
}

#[test]
fn configuration_validate_valid_tls() {
	let c = cfg("tunnel.example.com:443", true, "", "", false, "");
	assert!(c.validate().is_ok(), "unexpected error");
}

#[test]
fn configuration_validate_valid_tls_with_ca() {
	let c = cfg(
		"tunnel.example.com:443",
		true,
		"./certs/ca-cert.pem",
		"",
		false,
		"",
	);
	assert!(c.validate().is_ok(), "unexpected error");
}

#[test]
fn configuration_validate_valid_tls_with_server_name() {
	let c = cfg(
		"tunnel.example.com:443",
		true,
		"",
		"tunnel.internal",
		false,
		"",
	);
	assert!(c.validate().is_ok(), "unexpected error");
}

#[test]
fn configuration_validate_valid_tls_insecure() {
	let c = cfg("tunnel.example.com:443", true, "", "", true, "");
	assert!(c.validate().is_ok(), "unexpected error");
}

#[test]
fn configuration_validate_missing_address() {
	let c = cfg("", false, "", "", false, "");
	let err = c.validate().expect_err("expected error");
	assert!(
		err.to_string().contains("server_address is required"),
		"error = {err}"
	);
}

#[test]
fn configuration_validate_missing_port() {
	let c = cfg("tunnel.example.com", false, "", "", false, "");
	let err = c.validate().expect_err("expected error");
	assert!(err.to_string().contains("host:port"), "error = {err}");
}

#[test]
fn configuration_validate_zero_port() {
	let c = cfg("tunnel.example.com:0", false, "", "", false, "");
	let err = c.validate().expect_err("expected error");
	assert!(
		err.to_string().contains("between 1 and 65535"),
		"error = {err}"
	);
}

#[test]
fn configuration_validate_ca_file_without_tls() {
	let c = cfg(
		"tunnel.example.com:443",
		false,
		"./certs/ca-cert.pem",
		"",
		false,
		"",
	);
	let err = c.validate().expect_err("expected error");
	assert!(
		err.to_string().contains("require tls = true"),
		"error = {err}"
	);
}

#[test]
fn configuration_validate_server_name_without_tls() {
	let c = cfg(
		"tunnel.example.com:443",
		false,
		"",
		"tunnel.internal",
		false,
		"",
	);
	let err = c.validate().expect_err("expected error");
	assert!(
		err.to_string().contains("require tls = true"),
		"error = {err}"
	);
}

#[test]
fn configuration_validate_insecure_without_tls() {
	let c = cfg("tunnel.example.com:443", false, "", "", true, "");
	let err = c.validate().expect_err("expected error");
	assert!(
		err.to_string().contains("require tls = true"),
		"error = {err}"
	);
}

#[test]
fn configuration_validate_insecure_with_ca_file() {
	let c = cfg(
		"tunnel.example.com:443",
		true,
		"./certs/ca-cert.pem",
		"",
		true,
		"",
	);
	let err = c.validate().expect_err("expected error");
	assert!(
		err.to_string().contains("mutually exclusive"),
		"error = {err}"
	);
}

#[test]
fn configuration_backend_config_copies_fields() {
	let c = cfg(
		"tunnel.example.com:443",
		true,
		"./certs/ca-cert.pem",
		"tunnel.internal",
		false,
		"secret",
	);
	let bc: BackendConfiguration = c.backend_config().expect("backend_config");
	assert_eq!(bc.server_address, "tunnel.example.com:443");
	assert!(bc.tls);
	assert_eq!(bc.tls_ca_file, "./certs/ca-cert.pem");
	assert_eq!(bc.tls_server_name, "tunnel.internal");
	assert!(!bc.tls_insecure_skip_verify);
	assert_eq!(bc.token, "secret");
}

#[test]
fn configuration_backend_config_validates() {
	let c = Configuration::default();
	let err = match c.backend_config() {
		Err(e) => e,
		Ok(_) => panic!("expected error, got Ok"),
	};
	assert!(
		err.to_string().contains("server address is required"),
		"error = {err}"
	);
}
