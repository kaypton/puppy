//! Per-connection info and the active-connection registry.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use parking_lot::RwLock;

use crate::backend::{Protocol, Target};

/// Describes a single active tunnel observed by a frontend.
///
/// Byte counters are atomic so the shim's two copy tasks can update them
/// concurrently without external locking.
#[derive(Debug)]
pub struct ConnectionInfo {
	/// Unique identifier assigned when the connection is registered.
	pub id: String,
	/// Name of the frontend that accepted the connection.
	pub frontend: String,
	/// Client address (`host:port`).
	pub remote_addr: String,
	/// Destination the backend dialed on behalf of the client.
	pub target: Target,
	/// Detected application protocol (may be `Unknown`).
	pub protocol: Protocol,
	/// Transport network (`"tcp"` or `"udp"`).
	pub network: String,
	/// When the connection was accepted.
	pub started_at: Instant,
	/// Set when the connection is removed from the registry. Shared via
	/// `RwLock<Option<Instant>>` so `Remove` can mutate it through an `Arc`.
	pub closed_at: RwLock<Option<Instant>>,

	bytes_in: AtomicU64,
	bytes_out: AtomicU64,
}

impl ConnectionInfo {
	/// Creates a new `ConnectionInfo` with zeroed byte counters and
	/// `started_at = Instant::now()`.
	pub fn new(
		id: impl Into<String>,
		frontend: impl Into<String>,
		remote_addr: impl Into<String>,
	) -> Self {
		Self {
			id: id.into(),
			frontend: frontend.into(),
			remote_addr: remote_addr.into(),
			target: Target {
				network: String::new(),
				protocol: Protocol::Unknown,
				host: String::new(),
				port: 0,
			},
			protocol: Protocol::Unknown,
			network: String::new(),
			started_at: Instant::now(),
			closed_at: RwLock::new(None),
			bytes_in: AtomicU64::new(0),
			bytes_out: AtomicU64::new(0),
		}
	}

	/// Creates a new `ConnectionInfo` with the given target/protocol/network
	/// and zeroed byte counters.
	pub fn with_target(
		id: impl Into<String>,
		frontend: impl Into<String>,
		remote_addr: impl Into<String>,
		target: Target,
		protocol: Protocol,
		network: impl Into<String>,
	) -> Self {
		Self {
			id: id.into(),
			frontend: frontend.into(),
			remote_addr: remote_addr.into(),
			protocol,
			network: network.into(),
			target,
			started_at: Instant::now(),
			closed_at: RwLock::new(None),
			bytes_in: AtomicU64::new(0),
			bytes_out: AtomicU64::new(0),
		}
	}

	/// Cumulative bytes read from the client.
	pub fn bytes_in(&self) -> u64 {
		self.bytes_in.load(Ordering::Relaxed)
	}

	/// Cumulative bytes written to the client.
	pub fn bytes_out(&self) -> u64 {
		self.bytes_out.load(Ordering::Relaxed)
	}

	/// Atomically adds `n` to the inbound byte counter. No-op for `n == 0`.
	pub fn add_bytes_in(&self, n: usize) {
		if n == 0 {
			return;
		}
		self.bytes_in.fetch_add(n as u64, Ordering::Relaxed);
	}

	/// Atomically adds `n` to the outbound byte counter. No-op for `n == 0`.
	pub fn add_bytes_out(&self, n: usize) {
		if n == 0 {
			return;
		}
		self.bytes_out.fetch_add(n as u64, Ordering::Relaxed);
	}

	/// Returns `true` if `closed_at` has been set.
	pub fn is_closed(&self) -> bool {
		self.closed_at.read().is_some()
	}
}

/// Tracks active connections across all frontends.
///
/// Connections are stored as `Arc<ConnectionInfo>` so external holders
/// (counting wrapper, tests) observe `Remove`'s `closed_at` mutation.
pub struct ConnectionRegistry {
	active: RwLock<std::collections::HashMap<String, Arc<ConnectionInfo>>>,
}

impl ConnectionRegistry {
	/// Returns a ready-to-use registry.
	pub fn new() -> Self {
		Self {
			active: RwLock::new(std::collections::HashMap::new()),
		}
	}

	/// Records a new active connection. The registry stores the `Arc` clone so
	/// external holders and the registry share the same `ConnectionInfo`.
	pub fn register(&self, info: Arc<ConnectionInfo>) -> Arc<ConnectionInfo> {
		let id = info.id.clone();
		self.active.write().insert(id, info.clone());
		info
	}

	/// Deletes a connection from the active set and marks `closed_at`.
	pub fn remove(&self, id: &str) {
		if let Some(info) = self.active.write().remove(id) {
			*info.closed_at.write() = Some(Instant::now());
		}
	}

	/// Returns the connection with the given id, or `None` if not found.
	pub fn get(&self, id: &str) -> Option<Arc<ConnectionInfo>> {
		self.active.read().get(id).cloned()
	}

	/// Returns a snapshot of all currently active connections.
	pub fn active(&self) -> Vec<Arc<ConnectionInfo>> {
		self.active.read().values().cloned().collect()
	}

	/// Returns active connections for a specific frontend name.
	pub fn active_by_frontend(&self, frontend: &str) -> Vec<Arc<ConnectionInfo>> {
		self.active
			.read()
			.values()
			.filter(|info| info.frontend == frontend)
			.cloned()
			.collect()
	}

	/// Returns the number of currently active connections.
	pub fn count(&self) -> usize {
		self.active.read().len()
	}
}

impl Default for ConnectionRegistry {
	fn default() -> Self {
		Self::new()
	}
}
