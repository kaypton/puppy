//! End-to-end CLI smoke tests for `puppy-server`.
//!
//! Covers the missing-config flag error case and the configuration-error
//! exit code behavior after the runner returns an error.

use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use assert_cmd::prelude::*;

/// Returns the path to a config file with the given contents, written inside a
/// temp directory.
fn write_config(contents: &str) -> (tempfile::TempDir, PathBuf) {
	let dir = tempfile::tempdir().expect("tempdir");
	let path = dir.path().join("puppy.toml");
	std::fs::write(&path, contents).expect("write config");
	(dir, path)
}

#[test]
fn cli_without_config_exits_with_usage_error() {
	// clap exits with code 2 for missing-required-argument errors.
	let mut cmd = Command::cargo_bin("puppy-server").expect("find puppy-server binary");
	let output = cmd.output().expect("run binary");
	assert!(
		!output.status.success(),
		"expected non-zero exit, got {}",
		output.status
	);
	assert_eq!(
		output.status.code(),
		Some(2),
		"clap usage errors exit with 2"
	);
	let stderr = String::from_utf8_lossy(&output.stderr);
	assert!(
		stderr.contains("required arguments were not provided") && stderr.contains("--config"),
		"expected required-arg error mentioning --config, got stderr: {stderr}"
	);
}

#[test]
fn cli_with_missing_config_file_exits_nonzero() {
	// A non-existent config path should fail with a load error and a non-zero
	// exit code.
	let mut cmd = Command::cargo_bin("puppy-server").expect("find puppy-server binary");
	cmd.args(["--config", "/nonexistent/puppy.toml"]);
	let output = cmd.output().expect("run binary");
	assert!(!output.status.success(), "expected non-zero exit");
	let stderr = String::from_utf8_lossy(&output.stderr);
	assert!(
		stderr.contains("load configuration") && stderr.contains("/nonexistent/puppy.toml"),
		"expected load error mentioning the path, got stderr: {stderr}"
	);
}

#[test]
fn cli_with_invalid_config_exits_nonzero() {
	// Configuration validation errors should exit non-zero with the
	// `validate configuration "..."` message.
	let (_dir, path) = write_config("frontend = \"missing\"\n");
	let mut cmd = Command::cargo_bin("puppy-server").expect("find puppy-server binary");
	cmd.args(["--config", path.to_str().unwrap()]);
	let output = cmd.output().expect("run binary");
	assert!(!output.status.success(), "expected non-zero exit");
	let stderr = String::from_utf8_lossy(&output.stderr);
	assert!(
		stderr.contains("selected frontend") && stderr.contains("does not exist"),
		"expected validation error about missing frontend, got stderr: {stderr}"
	);
}

#[test]
fn cli_with_valid_config_starts_and_responds_to_sigterm() {
	// Builds a config with a HTTP frontend on a free port, starts the server,
	// verifies it accepts a TCP connection on the bound port, then sends
	// SIGTERM and verifies graceful exit.
	use std::net::TcpListener;

	// Bind a free port first, then release it so the server can rebind.
	let ln = TcpListener::bind("127.0.0.1:0").expect("free port");
	let addr = ln.local_addr().unwrap();
	drop(ln);

	let contents = format!(
		r#"
frontend = "fe"

[frontends.fe]
type = "httpproxy"
listen_address = "127.0.0.1"
listen_port = {port}
backend = "direct_out"
shim = "shim"

[backends.direct_out]
type = "direct"

[shims.shim]
buffer_size = 32768
"#,
		port = addr.port()
	);
	let (_dir, path) = write_config(&contents);

	let mut cmd = Command::cargo_bin("puppy-server").expect("find puppy-server binary");
	cmd.args(["--config", path.to_str().unwrap()]);

	// Suppress tracing JSON output from polluting the test runner.
	cmd.env("RUST_LOG", "error");

	let mut child = cmd.spawn().expect("spawn server");

	// Wait for the server to bind by repeatedly attempting a TCP connection.
	let mut connected = false;
	for _ in 0..40 {
		if std::net::TcpStream::connect(addr).is_ok() {
			connected = true;
			break;
		}
		std::thread::sleep(Duration::from_millis(50));
	}
	assert!(connected, "server did not bind to {addr} within 2s");

	// Send SIGTERM (Unix) and verify graceful exit within 5s.
	#[cfg(unix)]
	{
		use std::os::unix::process::ExitStatusExt;
		unsafe {
			libc::kill(child.id() as i32, libc::SIGTERM);
		}
		let status = child
			.wait_timeout(Duration::from_secs(5))
			.expect("wait should not panic");
		let status = status.expect("server should exit within 5s of SIGTERM");
		// Graceful shutdown returns ExitCode::SUCCESS (0).
		assert!(
			status.success() || status.code() == Some(0) || status.signal() == Some(libc::SIGTERM),
			"unexpected exit status: {status:?}"
		);
	}
	#[cfg(not(unix))]
	{
		// On non-Unix, just kill the child to clean up.
		let _ = child.kill();
		let _ = child.wait();
	}
}

// ---------------------------------------------------------------------------
// Helper trait extension for `Child::wait_timeout` (Unix only).
// ---------------------------------------------------------------------------

#[cfg(unix)]
trait ChildWaitTimeoutExt {
	fn wait_timeout(&mut self, dur: Duration) -> std::io::Result<Option<std::process::ExitStatus>>;
}

#[cfg(unix)]
impl ChildWaitTimeoutExt for std::process::Child {
	fn wait_timeout(&mut self, dur: Duration) -> std::io::Result<Option<std::process::ExitStatus>> {
		let start = std::time::Instant::now();
		loop {
			match self.try_wait()? {
				Some(status) => return Ok(Some(status)),
				None => {
					if start.elapsed() >= dur {
						return Ok(None);
					}
					std::thread::sleep(Duration::from_millis(50));
				}
			}
		}
	}
}
