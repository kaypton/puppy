//! Tests for `config.rs`.
//!
//! Two test groups:
//! - `configuration_validate_*`: table-driven validation cases, asserting
//!   substring matches on error messages.
//! - `configuration_backend_config_*`: the `backend_config` field-copy test.

use httpproxy_be::{BackendConfiguration, Configuration};

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

#[test]
fn configuration_validate_valid_no_auth() {
	let c = cfg("proxy.example.com:3128", "", "", false, "", "", false);
	assert!(c.validate().is_ok(), "unexpected error");
}

#[test]
fn configuration_validate_valid_auth() {
	let c = cfg(
		"proxy.example.com:3128",
		"alice",
		"secret",
		false,
		"",
		"",
		false,
	);
	assert!(c.validate().is_ok(), "unexpected error");
}

#[test]
fn configuration_validate_valid_tls() {
	let c = cfg("proxy.example.com:3128", "", "", true, "", "", false);
	assert!(c.validate().is_ok(), "unexpected error");
}

#[test]
fn configuration_validate_valid_tls_with_ca() {
	let c = cfg(
		"proxy.example.com:3128",
		"",
		"",
		true,
		"./certs/ca-cert.pem",
		"",
		false,
	);
	assert!(c.validate().is_ok(), "unexpected error");
}

#[test]
fn configuration_validate_valid_tls_with_server_name() {
	let c = cfg(
		"proxy.example.com:3128",
		"",
		"",
		true,
		"",
		"proxy.internal",
		false,
	);
	assert!(c.validate().is_ok(), "unexpected error");
}

#[test]
fn configuration_validate_valid_tls_insecure() {
	let c = cfg("proxy.example.com:3128", "", "", true, "", "", true);
	assert!(c.validate().is_ok(), "unexpected error");
}

#[test]
fn configuration_validate_missing_address() {
	let c = cfg("", "", "", false, "", "", false);
	let err = c.validate().expect_err("expected error");
	assert!(
		err.to_string().contains("proxy_address is required"),
		"error = {err}"
	);
}

#[test]
fn configuration_validate_missing_port() {
	let c = cfg("proxy.example.com", "", "", false, "", "", false);
	let err = c.validate().expect_err("expected error");
	assert!(err.to_string().contains("host:port"), "error = {err}");
}

#[test]
fn configuration_validate_zero_port() {
	let c = cfg("proxy.example.com:0", "", "", false, "", "", false);
	let err = c.validate().expect_err("expected error");
	assert!(
		err.to_string().contains("between 1 and 65535"),
		"error = {err}"
	);
}

#[test]
fn configuration_validate_unpaired_credentials() {
	let c = cfg("proxy.example.com:3128", "alice", "", false, "", "", false);
	let err = c.validate().expect_err("expected error");
	assert!(
		err.to_string().contains("username and password"),
		"error = {err}"
	);
}

#[test]
fn configuration_validate_ca_file_without_tls() {
	let c = cfg(
		"proxy.example.com:3128",
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

#[test]
fn configuration_validate_server_name_without_tls() {
	let c = cfg(
		"proxy.example.com:3128",
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

#[test]
fn configuration_validate_insecure_without_tls() {
	let c = cfg("proxy.example.com:3128", "", "", false, "", "", true);
	let err = c.validate().expect_err("expected error");
	assert!(
		err.to_string().contains("require tls = true"),
		"error = {err}"
	);
}

#[test]
fn configuration_validate_insecure_with_ca_file() {
	let c = cfg(
		"proxy.example.com:3128",
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

#[test]
fn configuration_backend_config_copies_fields() {
	let c = cfg(
		"proxy.example.com:3128",
		"alice",
		"secret",
		true,
		"./certs/ca-cert.pem",
		"proxy.internal",
		false,
	);
	let bc: BackendConfiguration = c.backend_config().expect("backend_config");
	assert_eq!(bc.proxy_address, "proxy.example.com:3128");
	assert_eq!(bc.username, "alice");
	assert_eq!(bc.password, "secret");
	assert!(bc.tls);
	assert_eq!(bc.tls_ca_file, "./certs/ca-cert.pem");
	assert_eq!(bc.tls_server_name, "proxy.internal");
	assert!(!bc.tls_insecure_skip_verify);
}
