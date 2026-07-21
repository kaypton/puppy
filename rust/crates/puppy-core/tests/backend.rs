//! Tests for `backend.rs`.

use puppy_core::backend::{
	supports, supports_any_protocol, supports_network, Capability, Protocol, Target,
};

/// Verifies the capability-matching helpers (`supports_network`,
/// `supports_any_protocol`, `supports`) select backends per the documented
/// rules: exact network match, the `Any` (`*`) protocol wildcard, exact
/// protocol match, and normalization of an empty/`Unknown` target protocol
/// to `Unknown` (which never matches a non-wildcard capability).
#[test]
fn capabilities_match_spec_semantics() {
	let capabilities = vec![
		Capability {
			network: "tcp".to_string(),
			protocol: Protocol::Http,
		},
		Capability {
			network: "tcp".to_string(),
			protocol: Protocol::Dns,
		},
		Capability {
			network: "udp".to_string(),
			protocol: Protocol::Any,
		},
	];

	assert!(supports_network(&capabilities, "tcp"));
	assert!(!supports_network(&capabilities, "icmp"));

	// `SupportsAnyProtocol` returns true when a capability has the wildcard
	// `*` (Any) protocol — the udp entry qualifies, the tcp entries do not.
	assert!(!supports_any_protocol(&capabilities, "tcp"));
	assert!(supports_any_protocol(&capabilities, "udp"));

	assert!(supports(
		&capabilities,
		&Target {
			network: "tcp".to_string(),
			protocol: Protocol::Http,
			host: String::new(),
			port: 0,
		}
	));
	assert!(!supports(
		&capabilities,
		&Target {
			network: "tcp".to_string(),
			protocol: Protocol::Tls,
			host: String::new(),
			port: 0,
		}
	));
	assert!(supports(
		&capabilities,
		&Target {
			network: "tcp".to_string(),
			protocol: Protocol::Dns,
			host: String::new(),
			port: 0,
		}
	));
	// The udp wildcard accepts any application protocol marker.
	assert!(supports(
		&capabilities,
		&Target {
			network: "udp".to_string(),
			protocol: Protocol::Tls,
			host: String::new(),
			port: 0,
		}
	));
	// Empty protocol normalizes to Unknown, not Http, so no tcp capability
	// matches (only the udp wildcard would, on a different network).
	assert!(!supports(
		&capabilities,
		&Target {
			network: "tcp".to_string(),
			protocol: Protocol::Unknown,
			host: String::new(),
			port: 0,
		}
	));
}
