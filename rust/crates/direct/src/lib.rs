//! Direct backend: connects to the target via the frontend-provided dialer
//! with no intermediary proxy.

pub mod config;

use async_trait::async_trait;
use puppy_core::backend::{
	Backend, BackendError, BoxedStream, Capability, Dialer, Protocol, SystemDialer, Target,
};

/// Direct backend: dials the target via the supplied dialer.
///
/// Direct backend: dials the target via the supplied dialer. The struct is a
/// unit — there are no implementation-specific settings.
#[derive(Default)]
pub struct DirectBackend;

impl DirectBackend {
	/// Returns a direct backend with default settings.
	pub fn new() -> Self {
		Self
	}
}

#[async_trait]
impl Backend for DirectBackend {
	/// Capabilities report that direct connections accept TCP and UDP
	/// regardless of application protocol.
	fn capabilities(&self) -> Vec<Capability> {
		vec![
			Capability {
				network: "tcp".to_string(),
				protocol: Protocol::Any,
			},
			Capability {
				network: "udp".to_string(),
				protocol: Protocol::Any,
			},
		]
	}

	/// Dials `target` via `dialer`. If `dialer` is `SystemDialer` (the unit
	/// struct), uses a fresh `SystemDialer` instance.
	async fn dial(&self, target: Target, dialer: &dyn Dialer) -> Result<BoxedStream, BackendError> {
		let network = target.net().to_string();
		let address = target.address();
		dialer
			.dial_context(&network, &address)
			.await
			.map_err(BackendError::Io)
	}
}

/// Convenience wrapper for callers that want the system default dialer.
pub async fn dial_system(target: Target) -> Result<BoxedStream, BackendError> {
	DirectBackend::new().dial(target, &SystemDialer).await
}
