//! Linux host network manager: assigns TUN addresses and installs split
//! routes via `ip`, and (optionally) installs an nft table that redirects
//! systemd-resolved DNS traffic to a local interceptor.
//!
//! Mirrors Go `pkg/tunproxy/route_linux.go`.

use std::io;
use std::process::Command;
use std::sync::Arc;

use async_trait::async_trait;

use crate::dns_intercept_linux::LinuxDnsProxy;
use crate::egress::BoundDialer;
use crate::nft::{linux_nft_table_name, nft_apply_script, LINUX_BYPASS_MARK};
use crate::route::{DnsInterceptHandler, HostNetworkManager};
use crate::routes::{is_tunnel_interface, split_routes};

use puppy_core::backend::Dialer;

/// Linux host network manager.
///
/// Mirrors Go `linuxHostNetworkManager` (pkg/tunproxy/route_linux.go:15).
pub struct LinuxHostNetworkManager {
	device: String,
	ipv4_addr: String,
	ipv6_addr: String,
	auto_route: bool,
	intercept_systemd_resolved: bool,

	egress4: String,
	egress6: String,
	configured4: bool,
	configured6: bool,
	routes: Vec<LinuxRoute>,
	nft_table: String,
	nft_applied: bool,
	dns_proxy: Option<Arc<LinuxDnsProxy>>,
	applied: bool,

	/// Injectable `ip` runner; defaults to `run_linux_ip`.
	run: RunFn,
	/// Injectable `nft --check` runner; defaults to `check_linux_nft`.
	check_nft: NftFn,
	/// Injectable `nft --file -` runner; defaults to `run_linux_nft`.
	run_nft: NftFn,
	/// Injectable default-route lookup; defaults to `linux_default_route`.
	default_route: DefaultRouteFn,
	/// Injectable per-destination route lookup; defaults to
	/// `linux_route_interface`.
	route_iface: RouteIfaceFn,
}

type RunFn = Box<dyn Fn(&[&str]) -> io::Result<()> + Send + Sync>;
type NftFn = Box<dyn Fn(&str) -> io::Result<()> + Send + Sync>;
type DefaultRouteFn = Box<dyn Fn(&str) -> io::Result<(String, String)> + Send + Sync>;
type RouteIfaceFn = Box<dyn Fn(&str, &str) -> io::Result<String> + Send + Sync>;

#[derive(Debug, Clone)]
struct LinuxRoute {
	family: &'static str,
	prefix: &'static str,
}

impl LinuxHostNetworkManager {
	/// Creates a new manager. Mirrors Go `newHostNetworkManager`
	/// (pkg/tunproxy/route_linux.go:43).
	pub fn new(
		device: &str,
		ipv4_addr: &str,
		ipv6_addr: &str,
		auto_route: bool,
		intercept_systemd_resolved: bool,
	) -> Self {
		Self {
			device: device.to_string(),
			ipv4_addr: ipv4_addr.to_string(),
			ipv6_addr: ipv6_addr.to_string(),
			auto_route,
			intercept_systemd_resolved,
			egress4: String::new(),
			egress6: String::new(),
			configured4: false,
			configured6: false,
			routes: Vec::new(),
			nft_table: linux_nft_table_name(device),
			nft_applied: false,
			dns_proxy: None,
			applied: false,
			run: Box::new(run_linux_ip),
			check_nft: Box::new(check_linux_nft),
			run_nft: Box::new(run_linux_nft),
			default_route: Box::new(linux_default_route),
			route_iface: Box::new(linux_route_interface),
		}
	}

	/// Creates a manager with the given command runners. Used by tests.
	#[cfg(test)]
	#[allow(clippy::type_complexity)]
	pub fn with_runners(
		device: &str,
		ipv4_addr: &str,
		ipv6_addr: &str,
		auto_route: bool,
		intercept_systemd_resolved: bool,
		run: RunFn,
		check_nft: NftFn,
		run_nft: NftFn,
		default_route: DefaultRouteFn,
		route_iface: RouteIfaceFn,
	) -> Self {
		let mut m = Self::new(
			device,
			ipv4_addr,
			ipv6_addr,
			auto_route,
			intercept_systemd_resolved,
		);
		m.run = run;
		m.check_nft = check_nft;
		m.run_nft = run_nft;
		m.default_route = default_route;
		m.route_iface = route_iface;
		m
	}

	/// Validates that the captured default egress interface is not a tunnel
	/// and that probe destinations route via the same interface.
	///
	/// Mirrors Go `linuxHostNetworkManager.validateEgress`
	/// (pkg/tunproxy/route_linux.go:156).
	fn validate_egress(
		&self,
		family: &str,
		default_iface: &str,
		probes: &[&str],
	) -> io::Result<()> {
		if is_tunnel_interface(default_iface) {
			return Err(io::Error::other(format!(
				"tunproxy: default egress interface {default_iface} is already a tunnel; disable the existing VPN or set auto_route = false"
			)));
		}
		for destination in probes {
			let iface = (self.route_iface)(family, destination).map_err(|e| {
				io::Error::other(format!("tunproxy: inspect route to {destination}: {e}"))
			})?;
			if iface != default_iface {
				return Err(io::Error::other(format!(
					"tunproxy: route to {destination} uses {iface} instead of default egress {default_iface}; disable the existing VPN or set auto_route = false"
				)));
			}
		}
		Ok(())
	}

	/// Builds the nft apply script with the current DNS proxy ports.
	fn build_nft_apply_script(&self, udp_port: u16, tcp_port: u16) -> String {
		nft_apply_script(&self.nft_table, LINUX_BYPASS_MARK, udp_port, tcp_port)
	}

	/// Restores addresses and routes; helper that does NOT touch `applied`,
	/// used during rollback from a failed `apply`.
	fn restore_inner(&mut self) -> io::Result<()> {
		let mut errs: Vec<io::Error> = Vec::new();
		if self.nft_applied {
			let script = format!("delete table ip {}\n", self.nft_table);
			if let Err(e) = (self.run_nft)(&script) {
				errs.push(io::Error::other(format!(
					"delete nft DNS interception table {}: {e}",
					self.nft_table
				)));
			} else {
				self.nft_applied = false;
			}
		}
		// dns_proxy is closed when the Arc is dropped by the caller; we
		// simply clear our reference here.
		self.dns_proxy = None;
		for route in self.routes.iter().rev() {
			let args: Vec<&str> = vec![
				route.family,
				"route",
				"del",
				route.prefix,
				"dev",
				&self.device,
			];
			if let Err(e) = (self.run)(&args) {
				errs.push(io::Error::other(format!(
					"delete route {}: {e}",
					route.prefix
				)));
			}
		}
		self.routes.clear();
		if self.configured6 {
			let args: Vec<&str> = vec!["-6", "addr", "del", &self.ipv6_addr, "dev", &self.device];
			if let Err(e) = (self.run)(&args) {
				errs.push(io::Error::other(format!(
					"delete IPv6 address {}: {e}",
					self.ipv6_addr
				)));
			}
			self.configured6 = false;
		}
		if self.configured4 {
			let args: Vec<&str> = vec!["-4", "addr", "del", &self.ipv4_addr, "dev", &self.device];
			if let Err(e) = (self.run)(&args) {
				errs.push(io::Error::other(format!(
					"delete IPv4 address {}: {e}",
					self.ipv4_addr
				)));
			}
			self.configured4 = false;
		}
		join_errors(errs)
	}
}

#[async_trait]
impl HostNetworkManager for LinuxHostNetworkManager {
	async fn apply(&mut self) -> io::Result<Arc<dyn Dialer>> {
		if self.applied {
			return Err(io::Error::other(
				"tunproxy: host network already configured",
			));
		}
		self.applied = true;

		// nft preflight: validate the script we *would* install using dummy
		// ports, so we fail early if nft is missing or a stale table exists.
		if self.auto_route && self.intercept_systemd_resolved {
			let preflight = self.build_nft_apply_script(1, 1);
			if let Err(e) = (self.check_nft)(&preflight) {
				self.applied = false;
				return Err(io::Error::other(format!(
					"tunproxy: validate nft DNS interception table {} (ensure nft is installed and remove any stale Puppy table): {e}",
					self.nft_table
				)));
			}
		}

		let mut iface4 = String::new();
		let mut iface6 = String::new();
		let mut validate_err: Option<io::Error> = None;

		if self.auto_route {
			if !self.ipv4_addr.is_empty() {
				match (self.default_route)("-4") {
					Ok((_gw, iface)) => {
						iface4 = iface.clone();
						if let Err(e) = self.validate_egress("-4", &iface, &["1.1.1.1", "8.8.8.8"])
						{
							validate_err = Some(e);
						}
					}
					Err(e) => {
						validate_err = Some(io::Error::other(format!(
							"tunproxy: discover IPv4 default route: {e}"
						)));
					}
				}
			}
			if validate_err.is_none() && !self.ipv6_addr.is_empty() {
				match (self.default_route)("-6") {
					Ok((_gw, iface)) => {
						iface6 = iface.clone();
						if let Err(e) = self.validate_egress(
							"-6",
							&iface,
							&["2606:4700:4700::1111", "2001:4860:4860::8888"],
						) {
							validate_err = Some(e);
						}
					}
					Err(e) => {
						validate_err = Some(io::Error::other(format!(
							"tunproxy: discover IPv6 default route: {e}"
						)));
					}
				}
			}
		}

		if let Some(e) = validate_err {
			let restore_err = self.restore_inner();
			self.applied = false;
			return Err(join_two(e, restore_err));
		}

		self.egress4 = iface4.clone();
		self.egress6 = iface6.clone();

		// Bring up the device.
		let up_args: Vec<&str> = vec!["link", "set", "dev", &self.device, "up"];
		if let Err(e) = (self.run)(&up_args) {
			let err = io::Error::other(format!("tunproxy: bring up {}: {e}", self.device));
			let restore_err = self.restore_inner();
			self.applied = false;
			return Err(join_two(err, restore_err));
		}

		if !self.ipv4_addr.is_empty() {
			let args: Vec<&str> = vec!["-4", "addr", "add", &self.ipv4_addr, "dev", &self.device];
			if let Err(e) = (self.run)(&args) {
				let err = io::Error::other(format!(
					"tunproxy: add IPv4 address {}: {e}",
					self.ipv4_addr
				));
				let restore_err = self.restore_inner();
				self.applied = false;
				return Err(join_two(err, restore_err));
			}
			self.configured4 = true;
		}
		if !self.ipv6_addr.is_empty() {
			let args: Vec<&str> = vec!["-6", "addr", "add", &self.ipv6_addr, "dev", &self.device];
			if let Err(e) = (self.run)(&args) {
				let err = io::Error::other(format!(
					"tunproxy: add IPv6 address {}: {e}",
					self.ipv6_addr
				));
				let restore_err = self.restore_inner();
				self.applied = false;
				return Err(join_two(err, restore_err));
			}
			self.configured6 = true;
		}
		if !self.auto_route {
			return Ok(Arc::new(puppy_core::backend::SystemDialer));
		}

		let v4 = !self.ipv4_addr.is_empty();
		let v6 = !self.ipv6_addr.is_empty();
		for route in split_routes(v4, v6) {
			let args: Vec<&str> = vec![
				route.family,
				"route",
				"add",
				route.prefix,
				"dev",
				&self.device,
			];
			if let Err(e) = (self.run)(&args) {
				let err = io::Error::other(format!("tunproxy: add route {}: {e}", route.prefix));
				let restore_err = self.restore_inner();
				self.applied = false;
				return Err(join_two(err, restore_err));
			}
			self.routes.push(LinuxRoute {
				family: route.family,
				prefix: route.prefix,
			});
		}

		Ok(Arc::new(BoundDialer::new(&iface4, &iface6).map_err(
			|e| io::Error::other(format!("tunproxy: bind egress: {e}")),
		)?))
	}

	async fn enable_dns_interception(
		&mut self,
		handler: Arc<dyn DnsInterceptHandler>,
	) -> io::Result<()> {
		if !self.auto_route || !self.intercept_systemd_resolved {
			return Ok(());
		}
		if !self.applied {
			return Err(io::Error::other(
				"host network must be configured before DNS interception",
			));
		}
		if self.dns_proxy.is_some() || self.nft_applied {
			return Err(io::Error::other("DNS interception is already enabled"));
		}
		let proxy = Arc::new(
			LinuxDnsProxy::new(handler)
				.await
				.map_err(|e| io::Error::other(format!("tunproxy: start DNS interceptor: {e}")))?,
		);
		let script = self.build_nft_apply_script(proxy.udp_port(), proxy.tcp_port());
		if let Err(e) = (self.check_nft)(&script) {
			return Err(io::Error::other(format!(
				"validate nft DNS interception: {e}"
			)));
		}
		if let Err(e) = (self.run_nft)(&script) {
			return Err(io::Error::other(format!(
				"install nft DNS interception: {e}"
			)));
		}
		self.nft_applied = true;
		proxy.start();
		self.dns_proxy = Some(proxy);
		Ok(())
	}

	async fn restore(&mut self) -> io::Result<()> {
		if !self.applied {
			return Ok(());
		}
		self.applied = false;
		self.egress4.clear();
		self.egress6.clear();
		self.restore_inner()
	}

	fn egress_interfaces(&self) -> (String, String) {
		(self.egress4.clone(), self.egress6.clone())
	}
}

/// Joins multiple errors into a single error with newlines between them.
/// Mirrors Go `errors.Join`.
fn join_errors(errs: Vec<io::Error>) -> io::Result<()> {
	if errs.is_empty() {
		return Ok(());
	}
	let msgs: Vec<String> = errs.iter().map(|e| e.to_string()).collect();
	Err(io::Error::other(msgs.join("\n")))
}

/// Joins two errors, omitting the second if it is `Ok`.
fn join_two(a: io::Error, b: io::Result<()>) -> io::Error {
	match b {
		Ok(()) => a,
		Err(be) => io::Error::other(format!("{}\n{}", a, be)),
	}
}

/// Runs `ip args...` and wraps the error with combined stdout/stderr.
/// Mirrors Go `runLinuxIP` (pkg/tunproxy/route_linux.go:255).
fn run_linux_ip(args: &[&str]) -> io::Result<()> {
	let output = Command::new("ip").args(args).output()?;
	if !output.status.success() {
		let combined = format!(
			"{}{} {}",
			String::from_utf8_lossy(&output.stdout),
			String::from_utf8_lossy(&output.stderr),
			output.status
		);
		return Err(io::Error::other(format!(
			"ip {}: {}",
			args.join(" "),
			combined.trim_end()
		)));
	}
	Ok(())
}

/// Runs `nft --check --file -` with `script` on stdin.
/// Mirrors Go `checkLinuxNFT` (pkg/tunproxy/route_linux.go:233).
fn check_linux_nft(script: &str) -> io::Result<()> {
	run_linux_nft_command(&["--check", "--file", "-"], script)
}

/// Runs `nft --file -` with `script` on stdin.
/// Mirrors Go `runLinuxNFT` (pkg/tunproxy/route_linux.go:237).
fn run_linux_nft(script: &str) -> io::Result<()> {
	run_linux_nft_command(&["--file", "-"], script)
}

/// Shared helper for nft invocations.
/// Mirrors Go `runLinuxNFTCommand` (pkg/tunproxy/route_linux.go:241).
fn run_linux_nft_command(args: &[&str], script: &str) -> io::Result<()> {
	use std::io::Write;
	let path = which_nft()?;
	let mut command = Command::new(path);
	command.args(args);
	command.stdin(std::process::Stdio::piped());
	command.stdout(std::process::Stdio::piped());
	command.stderr(std::process::Stdio::piped());
	let mut child = command.spawn()?;
	if let Some(mut stdin) = child.stdin.take() {
		stdin.write_all(script.as_bytes())?;
	}
	let output = child.wait_with_output()?;
	if !output.status.success() {
		let combined = format!(
			"{}{} {}",
			String::from_utf8_lossy(&output.stdout),
			String::from_utf8_lossy(&output.stderr),
			output.status
		);
		return Err(io::Error::other(format!(
			"nft {}: {}",
			args.join(" "),
			combined.trim_end()
		)));
	}
	Ok(())
}

/// Locates the `nft` binary on `PATH`. Mirrors Go `exec.LookPath("nft")`.
fn which_nft() -> io::Result<String> {
	let output = Command::new("which").arg("nft").output()?;
	if !output.status.success() {
		return Err(io::Error::other("find nft command: command not found"));
	}
	let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
	if path.is_empty() {
		return Err(io::Error::other("find nft command: command not found"));
	}
	Ok(path)
}

/// Returns the default `(gateway, interface)` for `family` via
/// `ip <family> route show default`. Mirrors Go `linuxDefaultRoute`
/// (pkg/tunproxy/route_linux.go:263).
fn linux_default_route(family: &str) -> io::Result<(String, String)> {
	let output = Command::new("ip")
		.args([family, "route", "show", "default"])
		.output()?;
	if !output.status.success() {
		let combined = format!(
			"{}{} {}",
			String::from_utf8_lossy(&output.stdout),
			String::from_utf8_lossy(&output.stderr),
			output.status
		);
		return Err(io::Error::other(format!(
			"ip {family} route show default: {}",
			combined.trim_end()
		)));
	}
	crate::nft::parse_default_route(&String::from_utf8_lossy(&output.stdout))
		.map(|(gw, iface)| (gw.unwrap_or_default(), iface))
		.map_err(io::Error::other)
}

/// Returns the interface used to reach `destination` in `family`.
/// Mirrors Go `linuxRouteInterface` (pkg/tunproxy/route_linux.go:271).
fn linux_route_interface(family: &str, destination: &str) -> io::Result<String> {
	let output = Command::new("ip")
		.args([family, "route", "get", destination])
		.output()?;
	if !output.status.success() {
		let combined = format!(
			"{}{} {}",
			String::from_utf8_lossy(&output.stdout),
			String::from_utf8_lossy(&output.stderr),
			output.status
		);
		return Err(io::Error::other(format!(
			"ip {family} route get {destination}: {}",
			combined.trim_end()
		)));
	}
	let text = String::from_utf8_lossy(&output.stdout);
	for (i, field) in text.split_whitespace().enumerate() {
		if field == "dev" {
			if let Some(next) = text.split_whitespace().nth(i + 1) {
				return Ok(next.to_string());
			}
		}
	}
	Err(io::Error::other("route has no output interface"))
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::sync::{Arc, Mutex};

	fn capture() -> Arc<Mutex<Vec<String>>> {
		Arc::new(Mutex::new(Vec::new()))
	}

	#[tokio::test]
	async fn linux_apply_and_restore() {
		let commands = capture();
		let cmds = commands.clone();
		let run = Box::new(move |args: &[&str]| {
			cmds.lock().unwrap().push(args.join(" "));
			Ok(())
		});
		let check_nft = Box::new(|_s: &str| Ok(()));
		let run_nft = Box::new(|_s: &str| Ok(()));
		let default_route = Box::new(|_f: &str| Ok(("192.0.2.1".to_string(), "lo".to_string())));
		let route_iface = Box::new(|_f: &str, _d: &str| Ok("lo".to_string()));

		let mut m = LinuxHostNetworkManager::with_runners(
			"tun9",
			"10.0.0.1/24",
			"fd00::1/64",
			true,
			false,
			run,
			check_nft,
			run_nft,
			default_route,
			route_iface,
		);
		m.apply().await.unwrap();
		m.restore().await.unwrap();

		let want = [
			"link set dev tun9 up",
			"-4 addr add 10.0.0.1/24 dev tun9",
			"-6 addr add fd00::1/64 dev tun9",
			"-4 route add 0.0.0.0/1 dev tun9",
			"-4 route add 128.0.0.0/1 dev tun9",
			"-6 route add ::/1 dev tun9",
			"-6 route add 8000::/1 dev tun9",
			"-6 route del 8000::/1 dev tun9",
			"-6 route del ::/1 dev tun9",
			"-4 route del 128.0.0.0/1 dev tun9",
			"-4 route del 0.0.0.0/1 dev tun9",
			"-6 addr del fd00::1/64 dev tun9",
			"-4 addr del 10.0.0.1/24 dev tun9",
		];
		let got: Vec<String> = commands.lock().unwrap().clone();
		assert_eq!(got.join("\n"), want.join("\n"));
	}

	#[tokio::test]
	async fn linux_rolls_back_partial_apply() {
		let commands = capture();
		let cmds = commands.clone();
		let run = Box::new(move |args: &[&str]| {
			let command = args.join(" ");
			cmds.lock().unwrap().push(command.clone());
			if command == "-4 route add 128.0.0.0/1 dev tun9" {
				return Err(io::Error::other("injected failure"));
			}
			Ok(())
		});
		let check_nft = Box::new(|_| Ok(()));
		let run_nft = Box::new(|_| Ok(()));
		let default_route = Box::new(|_| Ok(("192.0.2.1".to_string(), "lo".to_string())));
		let route_iface = Box::new(|_, _| Ok("lo".to_string()));

		let mut m = LinuxHostNetworkManager::with_runners(
			"tun9",
			"10.0.0.1/24",
			"",
			true,
			false,
			run,
			check_nft,
			run_nft,
			default_route,
			route_iface,
		);
		match m.apply().await {
			Ok(_) => panic!("expected error, got Ok"),
			Err(err) => assert!(err.to_string().contains("injected failure")),
		}
		assert!(!m.applied);
		let want_tail = [
			"-4 route del 0.0.0.0/1 dev tun9",
			"-4 addr del 10.0.0.1/24 dev tun9",
		];
		let got: Vec<String> = commands.lock().unwrap().clone();
		let got_tail = &got[got.len() - want_tail.len()..];
		assert_eq!(got_tail.join("\n"), want_tail.join("\n"));
	}

	#[tokio::test]
	async fn linux_rejects_existing_vpn_before_mutation() {
		let mutated = Arc::new(Mutex::new(false));
		let m_flag = mutated.clone();
		let run = Box::new(move |_args: &[&str]| {
			*m_flag.lock().unwrap() = true;
			Ok(())
		});
		let check_nft = Box::new(|_| Ok(()));
		let run_nft = Box::new(|_| Ok(()));
		let default_route = Box::new(|_| Ok(("192.0.2.1".to_string(), "eth0".to_string())));
		let route_iface = Box::new(|_, _| Ok("tun8".to_string()));

		let mut m = LinuxHostNetworkManager::with_runners(
			"tun9",
			"10.0.0.1/24",
			"",
			true,
			false,
			run,
			check_nft,
			run_nft,
			default_route,
			route_iface,
		);
		match m.apply().await {
			Ok(_) => panic!("expected error, got Ok"),
			Err(err) => assert!(err.to_string().contains("existing VPN")),
		}
		assert!(!*mutated.lock().unwrap());
	}

	#[tokio::test]
	async fn linux_nft_preflight_fails_before_mutation() {
		let mutated = Arc::new(Mutex::new(false));
		let m_flag = mutated.clone();
		let run = Box::new(move |_args: &[&str]| {
			*m_flag.lock().unwrap() = true;
			Ok(())
		});
		let check_nft = Box::new(|_s: &str| Err(io::Error::other("nft unavailable")));
		let run_nft = Box::new(move |_s: &str| {
			*m_flag.lock().unwrap() = true;
			Ok(())
		});
		let default_route = Box::new(|_| Ok(("192.0.2.1".to_string(), "lo".to_string())));
		let route_iface = Box::new(|_, _| Ok("lo".to_string()));

		let mut m = LinuxHostNetworkManager::with_runners(
			"tun9",
			"10.0.0.1/24",
			"",
			true,
			true,
			run,
			check_nft,
			run_nft,
			default_route,
			route_iface,
		);
		match m.apply().await {
			Ok(_) => panic!("expected error, got Ok"),
			Err(err) => assert!(err.to_string().contains("validate nft DNS interception")),
		}
		assert!(!*mutated.lock().unwrap());
	}

	#[tokio::test]
	async fn linux_apply_no_auto_route_returns_system_dialer() {
		let cmds = capture();
		let cmds_c = cmds.clone();
		let run = Box::new(move |args: &[&str]| {
			cmds_c.lock().unwrap().push(args.join(" "));
			Ok(())
		});
		let mut m = LinuxHostNetworkManager::with_runners(
			"tun9",
			"10.0.0.1/24",
			"",
			false,
			false,
			run,
			Box::new(|_| Ok(())),
			Box::new(|_| Ok(())),
			Box::new(|_| Ok(("gw".into(), "en0".into()))),
			Box::new(|_, _| Ok("en0".into())),
		);
		m.apply().await.unwrap();
		// link set up + addr add only.
		assert_eq!(cmds.lock().unwrap().len(), 2);
	}

	#[tokio::test]
	async fn linux_apply_twice_errors() {
		let mut m = LinuxHostNetworkManager::new("tun9", "", "", false, false);
		m.apply().await.unwrap();
		match m.apply().await {
			Ok(_) => panic!("expected error, got Ok"),
			Err(err) => assert!(err.to_string().contains("already configured")),
		}
	}

	#[tokio::test]
	async fn linux_restore_without_apply_is_noop() {
		let mut m = LinuxHostNetworkManager::new("tun9", "", "", false, false);
		m.restore().await.unwrap();
		assert!(!m.applied);
	}

	#[tokio::test]
	async fn linux_egress_interfaces_empty_before_apply() {
		let m = LinuxHostNetworkManager::new("tun9", "10.0.0.1/24", "", false, false);
		assert_eq!(m.egress_interfaces(), ("".to_string(), "".to_string()));
	}
}
