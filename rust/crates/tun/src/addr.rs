//! CIDR address parsing helpers.
//!
//! Mirrors Go `pkg/tunproxy/addr.go`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Parsed CIDR: address (normalized) and prefix length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddrWithPrefix {
	/// IPv4 addresses are stored as 4-byte; IPv6 as 16-byte (no IPv4-in-IPv6 mapping).
	pub bytes: Vec<u8>,
	/// 0..=32 for IPv4, 0..=128 for IPv6.
	pub prefix_len: i32,
}

/// Parses an "IP/prefix" string (e.g. "10.0.0.1/24" or "fd00::1/64") and
/// returns the address as a 4- or 16-byte slice plus the prefix length.
/// IPv4-mapped IPv6 addresses are normalized to IPv4.
///
/// Mirrors Go `parseAddrWithPrefix` (pkg/tunproxy/addr.go:13). Error strings
/// are byte-for-byte identical to Go.
pub fn parse_addr_with_prefix(s: &str) -> Result<AddrWithPrefix, String> {
	let (ip_str, prefix_str) = match s.split_once('/') {
		Some((ip, prefix)) => (ip, prefix),
		None => return Err("missing prefix length".to_string()),
	};
	let ip: IpAddr = ip_str
		.parse()
		.map_err(|_| format!("invalid IP {ip_str:?}"))?;
	let prefix_len: i32 = prefix_str
		.parse::<i32>()
		.map_err(|e| format!("invalid prefix {prefix_str:?}: {e}"))?;
	match ip {
		IpAddr::V4(v4) => {
			if !(0..=32).contains(&prefix_len) {
				return Err(format!("ipv4 prefix {prefix_len} out of range [0,32]"));
			}
			Ok(AddrWithPrefix {
				bytes: v4.octets().to_vec(),
				prefix_len,
			})
		}
		IpAddr::V6(v6) => {
			if let Some(v4) = v6.to_ipv4_mapped() {
				if !(0..=32).contains(&prefix_len) {
					return Err(format!("ipv4 prefix {prefix_len} out of range [0,32]"));
				}
				return Ok(AddrWithPrefix {
					bytes: v4.octets().to_vec(),
					prefix_len,
				});
			}
			if !(0..=128).contains(&prefix_len) {
				return Err(format!("ipv6 prefix {prefix_len} out of range [0,128]"));
			}
			Ok(AddrWithPrefix {
				bytes: v6.octets().to_vec(),
				prefix_len,
			})
		}
	}
}

/// Converts an IPv4 address from 4-octet form to `IpAddr`.
pub fn ipv4_from_bytes(b: &[u8]) -> Option<Ipv4Addr> {
	if b.len() == 4 {
		Some(Ipv4Addr::new(b[0], b[1], b[2], b[3]))
	} else {
		None
	}
}

/// Converts an IPv6 address from 16-octet form to `IpAddr`.
pub fn ipv6_from_bytes(b: &[u8]) -> Option<Ipv6Addr> {
	if b.len() == 16 {
		let mut octets = [0u8; 16];
		octets.copy_from_slice(b);
		Some(Ipv6Addr::from(octets))
	} else {
		None
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn parse_v4() {
		let r = parse_addr_with_prefix("10.0.0.1/24").unwrap();
		assert_eq!(r.bytes, vec![10, 0, 0, 1]);
		assert_eq!(r.prefix_len, 24);
	}

	#[test]
	fn parse_v6() {
		let r = parse_addr_with_prefix("fd00::1/64").unwrap();
		assert_eq!(r.bytes.len(), 16);
		assert_eq!(r.prefix_len, 64);
	}

	#[test]
	fn parse_v4_mapped_normalizes() {
		// ::ffff:10.0.0.1 is IPv4-mapped; should normalize to 4-byte v4.
		let r = parse_addr_with_prefix("::ffff:10.0.0.1/24").unwrap();
		assert_eq!(r.bytes, vec![10, 0, 0, 1]);
		assert_eq!(r.prefix_len, 24);
	}

	#[test]
	fn missing_prefix() {
		let err = parse_addr_with_prefix("10.0.0.1").unwrap_err();
		assert_eq!(err, "missing prefix length");
	}

	#[test]
	fn invalid_ip() {
		let err = parse_addr_with_prefix("not_an_ip/24").unwrap_err();
		assert_eq!(err, "invalid IP \"not_an_ip\"");
	}

	#[test]
	fn invalid_prefix_non_numeric() {
		let err = parse_addr_with_prefix("10.0.0.1/abc").unwrap_err();
		assert!(err.starts_with("invalid prefix \"abc\""));
	}

	#[test]
	fn v4_prefix_out_of_range() {
		let err = parse_addr_with_prefix("10.0.0.1/33").unwrap_err();
		assert_eq!(err, "ipv4 prefix 33 out of range [0,32]");
	}

	#[test]
	fn v4_prefix_negative() {
		let err = parse_addr_with_prefix("10.0.0.1/-1").unwrap_err();
		assert_eq!(err, "ipv4 prefix -1 out of range [0,32]");
	}

	#[test]
	fn v6_prefix_out_of_range() {
		let err = parse_addr_with_prefix("fd00::1/129").unwrap_err();
		assert_eq!(err, "ipv6 prefix 129 out of range [0,128]");
	}
}
