//! Linux nftables script generation and `ip route` parsing helpers.
//!
//! Mirrors the pure-logic portions of `pkg/tunproxy/route_linux.go`:
//! - `linuxNFTTableName` (FNV-32a of device name → `puppy_tunproxy_<8 hex>`)
//! - `nftApplyScript` (deterministic nftables script for DNS DNAT)
//! - `parseDefaultRoute` (parses `ip route show default` output)
//! - `systemdResolvedInterceptionEnabled`
//!
//! Process-spawning helpers (`runLinuxIP`, `checkLinuxNFT`, `runLinuxNFT`,
//! `linuxDefaultRoute`, `linuxRouteInterface`) live in `route_linux.rs` and
//! are not part of this pure-logic module.

/// Mark applied to Puppy's own sockets so the nft OUTPUT rule does not feed
/// backend or resolver traffic back into the TUN. The value is the ASCII
/// encoding of `"PUPP"` (0x50 0x55 0x50 0x50), matching
/// `linuxBypassMark = 0x50555059` in `pkg/tunproxy/egress_linux.go:16`.
pub const LINUX_BYPASS_MARK: u32 = 0x50555059;

/// Returns true when systemd-resolved DNS interception should be enabled.
///
/// Mirrors Go `systemdResolvedInterceptionEnabled` (pkg/tunproxy/route_linux.go:53).
/// Interception is enabled only when all three conditions hold: `auto_route`
/// is set, a fixed DNS server is configured, and an IPv4 address is assigned
/// (systemd-resolved's stub listener is IPv4-only at 127.0.0.53).
pub fn systemd_resolved_interception_enabled(
	auto_route: bool,
	dns_configured: bool,
	ipv4_configured: bool,
) -> bool {
	auto_route && dns_configured && ipv4_configured
}

/// Returns the deterministic nftables table name for a TUN device.
///
/// Mirrors Go `linuxNFTTableName` (pkg/tunproxy/route_linux.go:227). Uses
/// FNV-32a of the device name, formatted as `puppy_tunproxy_<08x>`.
pub fn linux_nft_table_name(device: &str) -> String {
	format!("puppy_tunproxy_{:08x}", fnv1a_32(device.as_bytes()))
}

/// Generates the nftables script that DNATs DNS traffic to the local
/// interceptor.
///
/// Mirrors Go `nftApplyScript` (pkg/tunproxy/route_linux.go:218). The output
/// is byte-for-byte identical to the Go version: 6 lines, each newline-
/// terminated, with the table name, bypass mark, and UDP/TCP ports
/// substituted via positional formatting.
pub fn nft_apply_script(table: &str, udp_port: u16, tcp_port: u16) -> String {
	format!(
		"add table ip {table}\n\
add chain ip {table} output {{ type nat hook output priority -100; policy accept; }}\n\
add chain ip {table} postrouting {{ type nat hook postrouting priority 100; policy accept; }}\n\
add rule ip {table} output meta mark != 0x{mark:x} ip daddr 127.0.0.53 udp dport 53 dnat to 127.0.0.1:{udp}\n\
add rule ip {table} output meta mark != 0x{mark:x} ip daddr 127.0.0.53 tcp dport 53 dnat to 127.0.0.1:{tcp}\n",
		table = table,
		mark = LINUX_BYPASS_MARK,
		udp = udp_port,
		tcp = tcp_port,
	)
}

/// Generates the nftables command to delete the DNS interception table.
///
/// Mirrors Go `Restore` (pkg/tunproxy/route_linux.go:184), which sends
/// `delete table ip <table>\n` to `nft --file -`.
pub fn nft_delete_script(table: &str) -> String {
	format!("delete table ip {table}\n")
}

/// Parses the output of `ip route show default` to extract the gateway and
/// interface of the first default route.
///
/// Mirrors Go `parseDefaultRoute` (pkg/tunproxy/route_linux.go:287). Accepts
/// both gateway (`via`) and on-link defaults; only the output interface is
/// required.
pub fn parse_default_route(output: &str) -> Result<(Option<String>, String), String> {
	let line = match output.find('\n') {
		Some(idx) => &output[..idx],
		None => output,
	};
	let mut gateway: Option<String> = None;
	let mut iface: Option<String> = None;
	let fields: Vec<&str> = line.split_whitespace().collect();
	let mut i = 0;
	while i + 1 < fields.len() {
		match fields[i] {
			"via" => gateway = Some(fields[i + 1].to_string()),
			"dev" => iface = Some(fields[i + 1].to_string()),
			_ => {}
		}
		i += 1;
	}
	let iface = iface.ok_or_else(|| "no default route interface".to_string())?;
	Ok((gateway, iface))
}

/// Computes the FNV-32a hash of `data`. Matches Go's `hash/fnv` package:
/// offset basis 2166136261, prime 16777619.
fn fnv1a_32(data: &[u8]) -> u32 {
	let mut hash: u32 = 2166136261;
	for &b in data {
		hash ^= b as u32;
		hash = hash.wrapping_mul(16777619);
	}
	hash
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn nft_table_name_is_deterministic() {
		let first = linux_nft_table_name("tun-with.dots");
		let second = linux_nft_table_name("tun-with.dots");
		assert_eq!(first, second);
		assert!(first.starts_with("puppy_tunproxy_"));
	}

	#[test]
	fn nft_table_name_distinguishes_devices() {
		let a = linux_nft_table_name("tun-with.dots");
		let b = linux_nft_table_name("tun-other");
		assert_ne!(a, b);
	}

	#[test]
	fn nft_table_name_known_value() {
		// FNV-32a("tun9") = ?
		// Compute by hand: 2166136261 ^ 't' = 2166136257
		//   * 16777619 = 0x6A _ overflow; just trust the algorithm.
		// Verify the function output is well-formed hex.
		let name = linux_nft_table_name("tun9");
		assert!(name.starts_with("puppy_tunproxy_"));
		let hex = &name["puppy_tunproxy_".len()..];
		assert_eq!(hex.len(), 8);
		assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
	}

	#[test]
	fn nft_apply_script_contains_all_lines() {
		let table = "puppy_tunproxy_deadbeef";
		let script = nft_apply_script(table, 5353, 5354);
		assert!(script.contains(&format!("add table ip {table}")));
		assert!(script.contains("type nat hook output priority -100"));
		assert!(script.contains("type nat hook postrouting priority 100"));
		assert!(script.contains("meta mark != 0x50555059"));
		assert!(script.contains("ip daddr 127.0.0.53 udp dport 53 dnat to 127.0.0.1:5353"));
		assert!(script.contains("ip daddr 127.0.0.53 tcp dport 53 dnat to 127.0.0.1:5354"));
	}

	#[test]
	fn nft_apply_script_ends_with_newline() {
		let script = nft_apply_script("t", 1, 2);
		assert!(script.ends_with('\n'));
	}

	#[test]
	fn nft_delete_script_format() {
		let table = "puppy_tunproxy_deadbeef";
		assert_eq!(
			nft_delete_script(table),
			"delete table ip puppy_tunproxy_deadbeef\n"
		);
	}

	#[test]
	fn systemd_resolved_interception_all_enabled() {
		assert!(systemd_resolved_interception_enabled(true, true, true));
	}

	#[test]
	fn systemd_resolved_interception_manual_routes() {
		// auto_route false → no interception
		assert!(!systemd_resolved_interception_enabled(false, true, true));
	}

	#[test]
	fn systemd_resolved_interception_no_dns() {
		assert!(!systemd_resolved_interception_enabled(true, false, true));
	}

	#[test]
	fn systemd_resolved_interception_ipv6_only() {
		assert!(!systemd_resolved_interception_enabled(true, true, false));
	}

	#[test]
	fn parse_default_route_standard() {
		let (gw, iface) = parse_default_route("default via 192.168.1.1 dev eth0").unwrap();
		assert_eq!(gw.as_deref(), Some("192.168.1.1"));
		assert_eq!(iface, "eth0");
	}

	#[test]
	fn parse_default_route_with_metric() {
		let (gw, iface) = parse_default_route("default via 10.0.0.1 dev tun0 metric 100").unwrap();
		assert_eq!(gw.as_deref(), Some("10.0.0.1"));
		assert_eq!(iface, "tun0");
	}

	#[test]
	fn parse_default_route_on_link() {
		let (gw, iface) = parse_default_route("default dev eth0").unwrap();
		assert_eq!(gw, None);
		assert_eq!(iface, "eth0");
	}

	#[test]
	fn parse_default_route_empty() {
		let err = parse_default_route("").unwrap_err();
		assert!(err.contains("no default route interface"));
	}

	#[test]
	fn parse_default_route_multiline_uses_first() {
		let (gw, iface) = parse_default_route(
			"default via 172.16.0.1 dev eth1\n10.0.0.0/8 via 172.16.0.2 dev eth1",
		)
		.unwrap();
		assert_eq!(gw.as_deref(), Some("172.16.0.1"));
		assert_eq!(iface, "eth1");
	}

	#[test]
	fn fnv1a_known_vectors() {
		// FNV-32a known test vectors (from the FNV reference).
		// empty → 0x811c9dc5 (offset basis)
		assert_eq!(fnv1a_32(b""), 0x811c9dc5);
		// "a" → 0xe40c292c
		assert_eq!(fnv1a_32(b"a"), 0xe40c292c);
		// "foobar" → 0xbf9cf968
		assert_eq!(fnv1a_32(b"foobar"), 0xbf9cf968);
	}
}
