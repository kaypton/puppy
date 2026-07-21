//! Unsupported-platform stub for the host network manager.
//!
//! Mirrors Go `pkg/tunproxy/route_other.go`.

use std::io;

use async_trait::async_trait;

use crate::route::{DnsInterceptHandler, HostNetworkManager};
use puppy_core::backend::Dialer;
use std::sync::Arc;

/// Host network manager for platforms without native route support.
///
/// Mirrors Go `unsupportedHostNetworkManager` (pkg/tunproxy/route_other.go:11).
pub struct UnsupportedHostNetworkManager;

#[async_trait]
impl HostNetworkManager for UnsupportedHostNetworkManager {
	async fn apply(&mut self) -> io::Result<Arc<dyn Dialer>> {
		Err(io::Error::other(
			"tunproxy: host network configuration not supported on this platform",
		))
	}

	async fn enable_dns_interception(
		&mut self,
		_handler: Arc<dyn DnsInterceptHandler>,
	) -> io::Result<()> {
		Ok(())
	}

	async fn restore(&mut self) -> io::Result<()> {
		Ok(())
	}

	fn egress_interfaces(&self) -> (String, String) {
		(String::new(), String::new())
	}
}
