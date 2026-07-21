//! Split-default route table generation.
//!
//! Mirrors Go `pkg/tunproxy/routes.go`.

/// One half of a split-default route, targeted at a single address family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitRoute {
	/// `"-4"` for IPv4, `"-6"` for IPv6 (matching `route -4`/`route -6` flags).
	pub family: &'static str,
	/// CIDR prefix, e.g. `"0.0.0.0/1"`.
	pub prefix: &'static str,
}

/// Returns true if the interface name looks like a tunnel device that should
/// be skipped when picking egress interfaces.
///
/// Mirrors Go `isTunnelInterface` (pkg/tunproxy/routes.go:10).
pub fn is_tunnel_interface(name: &str) -> bool {
	name.starts_with("tun") || name.starts_with("utun") || name.starts_with("wg")
}

/// Returns the split-default routes used to override the system default route
/// without removing it: 0.0.0.0/1 + 128.0.0.0/1 for IPv4, ::/1 + 8000::/1 for
/// IPv6. Each half covers half of the IPv4/IPv6 unicast space; together they
/// cover everything but leave the original default route untouched for backend
/// egress.
///
/// Mirrors Go `splitRoutes` (pkg/tunproxy/routes.go:16).
pub fn split_routes(ipv4: bool, ipv6: bool) -> Vec<SplitRoute> {
	let mut routes = Vec::with_capacity(4);
	if ipv4 {
		routes.push(SplitRoute {
			family: "-4",
			prefix: "0.0.0.0/1",
		});
		routes.push(SplitRoute {
			family: "-4",
			prefix: "128.0.0.0/1",
		});
	}
	if ipv6 {
		routes.push(SplitRoute {
			family: "-6",
			prefix: "::/1",
		});
		routes.push(SplitRoute {
			family: "-6",
			prefix: "8000::/1",
		});
	}
	routes
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn split_routes_v4_v6() {
		let routes = split_routes(true, true);
		let want = vec![
			SplitRoute {
				family: "-4",
				prefix: "0.0.0.0/1",
			},
			SplitRoute {
				family: "-4",
				prefix: "128.0.0.0/1",
			},
			SplitRoute {
				family: "-6",
				prefix: "::/1",
			},
			SplitRoute {
				family: "-6",
				prefix: "8000::/1",
			},
		];
		assert_eq!(routes, want);
	}

	#[test]
	fn split_routes_v4_only() {
		let routes = split_routes(true, false);
		assert_eq!(routes.len(), 2);
		assert!(routes.iter().all(|r| r.family == "-4"));
	}

	#[test]
	fn split_routes_v6_only() {
		let routes = split_routes(false, true);
		assert_eq!(routes.len(), 2);
		assert!(routes.iter().all(|r| r.family == "-6"));
	}

	#[test]
	fn split_routes_none() {
		let routes = split_routes(false, false);
		assert!(routes.is_empty());
	}

	#[test]
	fn is_tunnel_interface_true() {
		assert!(is_tunnel_interface("tun0"));
		assert!(is_tunnel_interface("utun4"));
		assert!(is_tunnel_interface("wg0"));
	}

	#[test]
	fn is_tunnel_interface_false() {
		assert!(!is_tunnel_interface("en0"));
		assert!(!is_tunnel_interface("eth0"));
		assert!(!is_tunnel_interface("lo0"));
		assert!(!is_tunnel_interface(""));
	}
}
