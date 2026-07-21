//! macOS host network manager: assigns TUN addresses and installs split
//! routes via `ifconfig` and `route`. Discovers default egress interfaces
//! via `route -n get` before mutating the host network.
//!
//! Mirrors Go `pkg/tunproxy/route_darwin.go`.

use std::io;
use std::net::IpAddr;
use std::process::Command;

use async_trait::async_trait;

use crate::egress::BoundDialer;
use crate::route::{DnsInterceptHandler, HostNetworkManager};
use crate::routes::SplitRoute;
use crate::routes::{is_tunnel_interface, split_routes};

use puppy_core::backend::Dialer;
use std::sync::Arc;

/// macOS host network manager.
///
/// Mirrors Go `darwinHostNetworkManager` (pkg/tunproxy/route_darwin.go:16),
/// with one macOS-specific extension: in addition to the split routes through
/// the TUN device, it installs scoped default routes (`-ifscope`) through the
/// original physical egress interface. On macOS, `IP_BOUND_IF` scopes the
/// route lookup to the bound interface but does NOT bypass the routing table;
/// without a matching scoped route, `connect()` returns `ENETUNRECH` when the
/// split routes divert traffic to the TUN. The scoped default routes give the
/// kernel a route to use for `IP_BOUND_IF`-bound sockets.
pub struct DarwinHostNetworkManager {
	device: String,
	ipv4_addr: String,
	ipv6_addr: String,
	auto_route: bool,

	egress4: String,
	egress6: String,
	/// Original default-route gateways, captured before split routes are
	/// installed. Used to add scoped default routes on the egress interface.
	gateway4: String,
	gateway6: String,
	configured4: bool,
	configured6: bool,
	/// Split routes through the TUN device (deleted in reverse on restore).
	routes: Vec<DarwinRoute>,
	/// Scoped default routes on the physical egress interface (deleted in
	/// reverse on restore). Each entry records the family, scope interface,
	/// and gateway.
	scoped_routes: Vec<DarwinScopedRoute>,
	applied: bool,

	/// Injectable command runner; defaults to `run_darwin`.
	run: RunFn,
	/// Injectable default-route lookup; defaults to `darwin_default_route`.
	default_route: DefaultRouteFn,
	/// Injectable per-destination route lookup; defaults to
	/// `darwin_route_interface`.
	route_iface: RouteIfaceFn,
}

type RunFn = Box<dyn Fn(&str, &[&str]) -> io::Result<()> + Send + Sync>;
type DefaultRouteFn = Box<dyn Fn(&str) -> io::Result<(String, String)> + Send + Sync>;
type RouteIfaceFn = Box<dyn Fn(&str, &str) -> io::Result<String> + Send + Sync>;

#[derive(Debug, Clone)]
struct DarwinRoute {
	family: &'static str,
	prefix: &'static str,
}

/// A scoped default route (`-ifscope <iface>`) on a physical egress
/// interface. Mirrors the `route -n add -inet -ifscope en0 -net default <gw>`
/// command. Required so `IP_BOUND_IF`-bound sockets can resolve a route when
/// split routes have diverted the unscoped default to the TUN.
#[derive(Debug, Clone)]
struct DarwinScopedRoute {
	family: &'static str,
	iface: String,
	gateway: String,
}

impl DarwinHostNetworkManager {
	/// Creates a new manager. Mirrors Go `newHostNetworkManager`
	/// (pkg/tunproxy/route_darwin.go:38).
	pub fn new(device: &str, ipv4_addr: &str, ipv6_addr: &str, auto_route: bool) -> Self {
		Self {
			device: device.to_string(),
			ipv4_addr: ipv4_addr.to_string(),
			ipv6_addr: ipv6_addr.to_string(),
			auto_route,
			egress4: String::new(),
			egress6: String::new(),
			gateway4: String::new(),
			gateway6: String::new(),
			configured4: false,
			configured6: false,
			routes: Vec::new(),
			scoped_routes: Vec::new(),
			applied: false,
			run: Box::new(run_darwin),
			default_route: Box::new(darwin_default_route),
			route_iface: Box::new(darwin_route_interface),
		}
	}

	/// Creates a manager with the given command runners. Used by tests to
	/// capture commands without invoking `ifconfig`/`route`.
	#[cfg(test)]
	pub fn with_runners(
		device: &str,
		ipv4_addr: &str,
		ipv6_addr: &str,
		auto_route: bool,
		run: RunFn,
		default_route: DefaultRouteFn,
		route_iface: RouteIfaceFn,
	) -> Self {
		let mut m = Self::new(device, ipv4_addr, ipv6_addr, auto_route);
		m.run = run;
		m.default_route = default_route;
		m.route_iface = route_iface;
		m
	}

	/// Validates that the captured default egress interface is not a tunnel
	/// and that probe destinations route via the same interface.
	///
	/// Mirrors Go `darwinHostNetworkManager.validateEgress`
	/// (pkg/tunproxy/route_darwin.go:121).
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

	/// Splits `ipv4/24` into `(ip, netmask)`. Mirrors Go `darwinIPv4Parts`
	/// (pkg/tunproxy/route_darwin.go:176).
	fn darwin_ipv4_parts(cidr: &str) -> io::Result<(String, String)> {
		let (ip, prefix_len) = parse_cidr_v4(cidr)?;
		let mask = ipv4_mask_string(prefix_len);
		Ok((ip, mask))
	}

	/// Adds a scoped default route (`-ifscope <iface>`) through `gateway`.
	///
	/// This is a macOS-specific extension with no Go counterpart. On macOS,
	/// `IP_BOUND_IF` scopes the route lookup to the bound interface but does
	/// NOT bypass the routing table. When split routes divert the unscoped
	/// default to the TUN, `IP_BOUND_IF`-bound sockets have no route and
	/// `connect()` returns `ENETUNREACH`. The scoped default route gives the
	/// kernel a matching `RTF_IFSCOPE` route on the physical egress interface.
	fn add_scoped_default(
		&mut self,
		family: &'static str,
		iface: &str,
		gateway: &str,
	) -> io::Result<()> {
		let args: Vec<&str> = vec![
			"-n", "add", family, "-ifscope", iface, "-net", "default", gateway,
		];
		tracing::info!(
			target: "tunproxy",
			"installing scoped default route: route {} (iface={}, gw={})",
			args.join(" "),
			iface,
			gateway
		);
		(self.run)("route", &args).map_err(|e| {
			io::Error::other(format!(
				"tunproxy: add scoped default route on {iface}: {e}"
			))
		})?;
		tracing::info!(
			target: "tunproxy",
			"scoped default route installed: family={} iface={} gw={}", family, iface, gateway
		);
		self.scoped_routes.push(DarwinScopedRoute {
			family,
			iface: iface.to_string(),
			gateway: gateway.to_string(),
		});
		Ok(())
	}

	/// Restores addresses; helper that does NOT touch `applied`, used during
	/// rollback from a failed `apply`.
	fn restore_inner(&mut self) -> io::Result<()> {
		let mut errs: Vec<io::Error> = Vec::new();
		// Delete scoped default routes first (they were added last).
		for route in self.scoped_routes.iter().rev() {
			let args: Vec<&str> = vec![
				"-n",
				"delete",
				route.family,
				"-ifscope",
				&route.iface,
				"-net",
				"default",
				&route.gateway,
			];
			if let Err(e) = (self.run)("route", &args) {
				errs.push(io::Error::other(format!(
					"delete scoped default route on {}: {e}",
					route.iface
				)));
			}
		}
		self.scoped_routes.clear();
		for route in self.routes.iter().rev() {
			let args: Vec<&str> = vec![
				"-n",
				"delete",
				route.family,
				"-net",
				&route.prefix,
				"-interface",
				&self.device,
			];
			if let Err(e) = (self.run)("route", &args) {
				errs.push(io::Error::other(format!(
					"delete route {}: {e}",
					route.prefix
				)));
			}
		}
		self.routes.clear();
		if self.configured6 {
			if let Ok((ip, _)) = parse_cidr(&self.ipv6_addr) {
				let args: Vec<&str> = vec!["inet6", &ip, "-alias"];
				let mut full = vec![self.device.as_str()];
				full.extend_from_slice(&args);
				if let Err(e) = (self.run)("ifconfig", &full) {
					errs.push(io::Error::other(format!(
						"delete IPv6 address {}: {e}",
						self.ipv6_addr
					)));
				}
			}
			self.configured6 = false;
		}
		if self.configured4 {
			if let Ok((ip, _)) = parse_cidr(&self.ipv4_addr) {
				let args: Vec<&str> = vec!["inet", &ip, "-alias"];
				let mut full = vec![self.device.as_str()];
				full.extend_from_slice(&args);
				if let Err(e) = (self.run)("ifconfig", &full) {
					errs.push(io::Error::other(format!(
						"delete IPv4 address {}: {e}",
						self.ipv4_addr
					)));
				}
			}
			self.configured4 = false;
		}
		join_errors(errs)
	}
}

#[async_trait]
impl HostNetworkManager for DarwinHostNetworkManager {
	async fn apply(&mut self) -> io::Result<Arc<dyn Dialer>> {
		if self.applied {
			return Err(io::Error::other(
				"tunproxy: host network already configured",
			));
		}
		self.applied = true;

		let mut iface4 = String::new();
		let mut iface6 = String::new();
		let mut gw4 = String::new();
		let mut gw6 = String::new();
		let mut validate_err: Option<io::Error> = None;

		if self.auto_route {
			if !self.ipv4_addr.is_empty() {
				match (self.default_route)("-inet") {
					Ok((gw, iface)) => {
						iface4 = iface.clone();
						gw4 = gw;
						if let Err(e) =
							self.validate_egress("-inet", &iface, &["1.1.1.1", "8.8.8.8"])
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
				match (self.default_route)("-inet6") {
					Ok((gw, iface)) => {
						iface6 = iface.clone();
						gw6 = gw;
						if let Err(e) = self.validate_egress(
							"-inet6",
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
		self.gateway4 = gw4.clone();
		self.gateway6 = gw6.clone();

		if !self.ipv4_addr.is_empty() {
			let (ip, mask) = match Self::darwin_ipv4_parts(&self.ipv4_addr) {
				Ok(parts) => parts,
				Err(e) => {
					let restore_err = self.restore_inner();
					self.applied = false;
					return Err(join_two(e, restore_err));
				}
			};
			let args: Vec<&str> = vec![
				self.device.as_str(),
				"inet",
				ip.as_str(),
				ip.as_str(),
				"netmask",
				mask.as_str(),
				"up",
			];
			if let Err(e) = (self.run)("ifconfig", &args) {
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
			let (ip, prefix) = match parse_cidr(&self.ipv6_addr) {
				Ok((ip, p)) => (ip, p),
				Err(e) => {
					let err = io::Error::other(format!(
						"tunproxy: parse IPv6 address {}: {e}",
						self.ipv6_addr
					));
					let restore_err = self.restore_inner();
					self.applied = false;
					return Err(join_two(err, restore_err));
				}
			};
			let prefix_str = prefix.to_string();
			let args: Vec<&str> = vec![
				self.device.as_str(),
				"inet6",
				ip.as_str(),
				"prefixlen",
				prefix_str.as_str(),
				"alias",
			];
			if let Err(e) = (self.run)("ifconfig", &args) {
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
			let family = family_for_split(&route);
			let args: Vec<&str> = vec![
				"-n",
				"add",
				family,
				"-net",
				route.prefix,
				"-interface",
				self.device.as_str(),
			];
			if let Err(e) = (self.run)("route", &args) {
				let err = io::Error::other(format!("tunproxy: add route {}: {e}", route.prefix));
				let restore_err = self.restore_inner();
				self.applied = false;
				return Err(join_two(err, restore_err));
			}
			self.routes.push(DarwinRoute {
				family,
				prefix: route.prefix,
			});
		}

		// Install scoped default routes on the physical egress interfaces.
		// On macOS, `IP_BOUND_IF` scopes the route lookup to the bound
		// interface but does NOT bypass the routing table. Without a matching
		// scoped route, `connect()` returns ENETUNREACH because the only
		// routes to the destination are the split routes on the TUN device.
		// The scoped default routes (`-ifscope <iface>`) give the kernel a
		// route to use for `IP_BOUND_IF`-bound sockets.
		if !iface4.is_empty() && !gw4.is_empty() {
			if let Err(e) = self.add_scoped_default("-inet", &iface4, &gw4) {
				let restore_err = self.restore_inner();
				self.applied = false;
				return Err(join_two(e, restore_err));
			}
		}
		if !iface6.is_empty() && !gw6.is_empty() {
			if let Err(e) = self.add_scoped_default("-inet6", &iface6, &gw6) {
				let restore_err = self.restore_inner();
				self.applied = false;
				return Err(join_two(e, restore_err));
			}
		}

		Ok(Arc::new(BoundDialer::new(&iface4, &iface6).map_err(
			|e| io::Error::other(format!("tunproxy: bind egress: {e}")),
		)?))
	}

	async fn enable_dns_interception(
		&mut self,
		_handler: Arc<dyn DnsInterceptHandler>,
	) -> io::Result<()> {
		// No systemd-resolved on macOS.
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

/// Maps a `SplitRoute` to the darwin `route` family flag (`-inet` or `-inet6`).
fn family_for_split(route: &SplitRoute) -> &'static str {
	if route.family == "-6" {
		"-inet6"
	} else {
		"-inet"
	}
}

/// Parses `ip/prefix` and returns `(ip_string, prefix_len)`.
fn parse_cidr(cidr: &str) -> io::Result<(String, u8)> {
	let (ip, p) = cidr
		.split_once('/')
		.ok_or_else(|| io::Error::other(format!("tunproxy: parse CIDR {cidr}")))?;
	let prefix: u8 = p
		.parse()
		.map_err(|_| io::Error::other(format!("tunproxy: parse CIDR {cidr}")))?;
	let ip_parsed: IpAddr = ip
		.parse()
		.map_err(|_| io::Error::other(format!("tunproxy: parse CIDR {cidr}")))?;
	Ok((ip_parsed.to_string(), prefix))
}

/// Parses an IPv4 `ip/prefix` CIDR, returning `(ip_string, prefix_len)`.
fn parse_cidr_v4(cidr: &str) -> io::Result<(String, u8)> {
	let (ip, prefix) = parse_cidr(cidr)?;
	if ip.parse::<std::net::Ipv4Addr>().is_err() {
		return Err(io::Error::other(format!(
			"tunproxy: parse IPv4 address {cidr}"
		)));
	}
	Ok((ip, prefix))
}

/// Formats an IPv4 netmask from a prefix length. E.g. `24` -> `255.255.255.0`.
fn ipv4_mask_string(prefix: u8) -> String {
	let bits: u32 = if prefix == 0 {
		0
	} else if prefix >= 32 {
		0xffff_ffff
	} else {
		0xffff_ffff_u32.wrapping_shl(32 - prefix as u32)
	};
	format!(
		"{}.{}.{}.{}",
		(bits >> 24) & 0xff,
		(bits >> 16) & 0xff,
		(bits >> 8) & 0xff,
		bits & 0xff
	)
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

/// Runs `name args...` and wraps the error with combined stdout/stderr.
/// Mirrors Go `runDarwin` (pkg/tunproxy/route_darwin.go:185).
fn run_darwin(name: &str, args: &[&str]) -> io::Result<()> {
	let output = Command::new(name).args(args).output()?;
	if !output.status.success() {
		let combined = format!(
			"{}{} {}",
			String::from_utf8_lossy(&output.stdout),
			String::from_utf8_lossy(&output.stderr),
			output.status
		);
		return Err(io::Error::other(format!(
			"{} {}: {}",
			name,
			args.join(" "),
			combined.trim_end()
		)));
	}
	Ok(())
}

/// Returns the default `(gateway, interface)` for `family` via
/// `route -n get <family> default`. Mirrors Go `darwinDefaultRoute`
/// (pkg/tunproxy/route_darwin.go:193).
fn darwin_default_route(family: &str) -> io::Result<(String, String)> {
	let output = Command::new("route")
		.args(["-n", "get", family, "default"])
		.output()?;
	if !output.status.success() {
		let combined = format!(
			"{}{} {}",
			String::from_utf8_lossy(&output.stdout),
			String::from_utf8_lossy(&output.stderr),
			output.status
		);
		return Err(io::Error::other(format!(
			"route get {family} default: {}",
			combined.trim_end()
		)));
	}
	parse_darwin_default_route(&String::from_utf8_lossy(&output.stdout))
}

/// Returns the interface used to reach `destination` in `family`.
/// Mirrors Go `darwinRouteInterface` (pkg/tunproxy/route_darwin.go:201).
fn darwin_route_interface(family: &str, destination: &str) -> io::Result<String> {
	let output = Command::new("route")
		.args(["-n", "get", family, destination])
		.output()?;
	if !output.status.success() {
		let combined = format!(
			"{}{} {}",
			String::from_utf8_lossy(&output.stdout),
			String::from_utf8_lossy(&output.stderr),
			output.status
		);
		return Err(io::Error::other(format!(
			"route get {family} {destination}: {}",
			combined.trim_end()
		)));
	}
	let (_gw, iface) = parse_darwin_default_route(&String::from_utf8_lossy(&output.stdout))?;
	Ok(iface)
}

/// Parses the output of `route -n get` to extract the gateway and interface.
/// Mirrors Go `parseDarwinDefaultRoute`
/// (pkg/tunproxy/route_darwin.go:210).
pub fn parse_darwin_default_route(output: &str) -> io::Result<(String, String)> {
	let mut gateway = String::new();
	let mut iface = String::new();
	for line in output.lines() {
		let line = line.trim();
		if let Some(rest) = line.strip_prefix("gateway:") {
			gateway = rest.trim().to_string();
		}
		if let Some(rest) = line.strip_prefix("interface:") {
			iface = rest.trim().to_string();
		}
	}
	if iface.is_empty() {
		return Err(io::Error::other("no default route interface"));
	}
	Ok((gateway, iface))
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::sync::{Arc, Mutex};

	#[test]
	fn parse_darwin_default_route_basic() {
		let output = "
   route to: default
destination: default
       mask: default
    gateway: 192.0.2.1
  interface: en0
";
		let (gw, iface) = parse_darwin_default_route(output).unwrap();
		assert_eq!(gw, "192.0.2.1");
		assert_eq!(iface, "en0");
	}

	#[test]
	fn parse_darwin_default_route_missing_iface() {
		let err = parse_darwin_default_route("route to: default\n").unwrap_err();
		assert!(err.to_string().contains("no default route interface"));
	}

	#[test]
	fn ipv4_mask_string_known_prefixes() {
		assert_eq!(ipv4_mask_string(0), "0.0.0.0");
		assert_eq!(ipv4_mask_string(8), "255.0.0.0");
		assert_eq!(ipv4_mask_string(16), "255.255.0.0");
		assert_eq!(ipv4_mask_string(24), "255.255.255.0");
		assert_eq!(ipv4_mask_string(32), "255.255.255.255");
	}

	#[test]
	fn parse_cidr_v4_ok() {
		let (ip, p) = parse_cidr_v4("10.0.0.1/24").unwrap();
		assert_eq!(ip, "10.0.0.1");
		assert_eq!(p, 24);
	}

	#[test]
	fn parse_cidr_v6_ok() {
		let (ip, p) = parse_cidr("fd00::1/64").unwrap();
		assert_eq!(ip, "fd00::1");
		assert_eq!(p, 64);
	}

	#[test]
	fn parse_cidr_v4_rejects_v6() {
		let err = parse_cidr_v4("fd00::1/64").unwrap_err();
		assert!(err.to_string().contains("parse IPv4 address"));
	}

	#[test]
	fn family_for_split_v4() {
		let r = SplitRoute {
			family: "-4",
			prefix: "0.0.0.0/1",
		};
		assert_eq!(family_for_split(&r), "-inet");
	}

	#[test]
	fn family_for_split_v6() {
		let r = SplitRoute {
			family: "-6",
			prefix: "::/1",
		};
		assert_eq!(family_for_split(&r), "-inet6");
	}

	fn capture() -> Arc<Mutex<Vec<String>>> {
		Arc::new(Mutex::new(Vec::new()))
	}

	#[tokio::test]
	async fn darwin_apply_and_restore() {
		let commands = capture();
		let cmds = commands.clone();
		let run = Box::new(move |name: &str, args: &[&str]| {
			let mut full = vec![name.to_string()];
			full.extend(args.iter().map(|s| s.to_string()));
			cmds.lock().unwrap().push(full.join(" "));
			Ok(())
		});
		let default_route = Box::new(|_f: &str| Ok(("192.0.2.1".to_string(), "lo0".to_string())));
		let route_iface = Box::new(|_f: &str, _d: &str| Ok("lo0".to_string()));

		let mut m = DarwinHostNetworkManager::with_runners(
			"utun9",
			"10.0.0.1/24",
			"fd00::1/64",
			true,
			run,
			default_route,
			route_iface,
		);
		m.apply().await.unwrap();
		m.restore().await.unwrap();

		let want = [
			"ifconfig utun9 inet 10.0.0.1 10.0.0.1 netmask 255.255.255.0 up",
			"ifconfig utun9 inet6 fd00::1 prefixlen 64 alias",
			"route -n add -inet -net 0.0.0.0/1 -interface utun9",
			"route -n add -inet -net 128.0.0.0/1 -interface utun9",
			"route -n add -inet6 -net ::/1 -interface utun9",
			"route -n add -inet6 -net 8000::/1 -interface utun9",
			"route -n add -inet -ifscope lo0 -net default 192.0.2.1",
			"route -n add -inet6 -ifscope lo0 -net default 192.0.2.1",
			"route -n delete -inet6 -ifscope lo0 -net default 192.0.2.1",
			"route -n delete -inet -ifscope lo0 -net default 192.0.2.1",
			"route -n delete -inet6 -net 8000::/1 -interface utun9",
			"route -n delete -inet6 -net ::/1 -interface utun9",
			"route -n delete -inet -net 128.0.0.0/1 -interface utun9",
			"route -n delete -inet -net 0.0.0.0/1 -interface utun9",
			"ifconfig utun9 inet6 fd00::1 -alias",
			"ifconfig utun9 inet 10.0.0.1 -alias",
		];
		let got: Vec<String> = commands.lock().unwrap().clone();
		assert_eq!(got.join("\n"), want.join("\n"));
	}

	#[tokio::test]
	async fn darwin_rejects_existing_vpn_before_mutation() {
		let mutated = Arc::new(Mutex::new(false));
		let m_flag = mutated.clone();
		let run = Box::new(move |_n: &str, _a: &[&str]| {
			*m_flag.lock().unwrap() = true;
			Ok(())
		});
		let default_route = Box::new(|_f: &str| Ok(("192.0.2.1".to_string(), "en0".to_string())));
		let route_iface = Box::new(|_f: &str, _d: &str| Ok("utun8".to_string()));

		let mut m = DarwinHostNetworkManager::with_runners(
			"utun9",
			"10.0.0.1/24",
			"",
			true,
			run,
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
	async fn darwin_apply_no_auto_route_returns_system_dialer() {
		let cmds = capture();
		let cmds_c = cmds.clone();
		let run = Box::new(move |name: &str, args: &[&str]| {
			let mut full = vec![name.to_string()];
			full.extend(args.iter().map(|s| s.to_string()));
			cmds_c.lock().unwrap().push(full.join(" "));
			Ok(())
		});
		let mut m = DarwinHostNetworkManager::with_runners(
			"utun9",
			"10.0.0.1/24",
			"",
			false,
			run,
			Box::new(|_| Ok(("gw".into(), "en0".into()))),
			Box::new(|_, _| Ok("en0".into())),
		);
		m.apply().await.unwrap();
		// Only ifconfig up — no route commands.
		assert_eq!(cmds.lock().unwrap().len(), 1);
	}

	#[tokio::test]
	async fn darwin_apply_twice_errors() {
		let mut m = DarwinHostNetworkManager::new("utun9", "", "", false);
		m.apply().await.unwrap();
		match m.apply().await {
			Ok(_) => panic!("expected error, got Ok"),
			Err(err) => assert!(err.to_string().contains("already configured")),
		}
	}

	#[tokio::test]
	async fn darwin_restore_without_apply_is_noop() {
		let mut m = DarwinHostNetworkManager::new("utun9", "", "", false);
		m.restore().await.unwrap();
		assert!(!m.applied);
	}

	#[tokio::test]
	async fn darwin_egress_interfaces_empty_before_apply() {
		let m = DarwinHostNetworkManager::new("utun9", "10.0.0.1/24", "", false);
		assert_eq!(m.egress_interfaces(), ("".to_string(), "".to_string()));
	}
}
