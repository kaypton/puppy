//! Global atomic counters shared across all frontends.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use crate::stats::ConnectionRegistry;
use crate::stats::EventBus;

/// Bundles the observability dependencies injected into a frontend's
/// `ServerConfiguration`. Any field may be `None` to disable that aspect of
/// instrumentation.
#[derive(Default)]
pub struct Deps {
	/// Frontend name used for attribution in stats and events.
	pub name: String,
	/// Global counter updates. `None` disables global counting.
	pub stats: Option<StatsRegistry>,
	/// Active connection tracking. `None` disables per-connection tracking.
	pub conn_reg: Option<ConnectionRegistry>,
	/// Lifecycle event broadcasting. `None` disables event publishing.
	pub bus: Option<EventBus>,
}

/// Immutable point-in-time view of global counters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatsSnapshot {
	pub total_connections: u64,
	pub active_connections: u64,
	pub dial_successes: u64,
	pub dial_failures: u64,
	pub bytes_in: u64,
	pub bytes_out: u64,
	pub started_at: Instant,
}

impl Default for StatsSnapshot {
	fn default() -> Self {
		Self {
			total_connections: 0,
			active_connections: 0,
			dial_successes: 0,
			dial_failures: 0,
			bytes_in: 0,
			bytes_out: 0,
			started_at: Instant::now(),
		}
	}
}

/// Atomic global counters shared across all frontends.
pub struct StatsRegistry {
	total_connections: AtomicU64,
	active_connections: AtomicU64,
	dial_successes: AtomicU64,
	dial_failures: AtomicU64,
	bytes_in: AtomicU64,
	bytes_out: AtomicU64,
	started_at: Instant,
}

impl Default for StatsRegistry {
	fn default() -> Self {
		Self::new()
	}
}

impl StatsRegistry {
	/// Returns a ready-to-use registry with `started_at` set to now.
	pub fn new() -> Self {
		Self {
			total_connections: AtomicU64::new(0),
			active_connections: AtomicU64::new(0),
			dial_successes: AtomicU64::new(0),
			dial_failures: AtomicU64::new(0),
			bytes_in: AtomicU64::new(0),
			bytes_out: AtomicU64::new(0),
			started_at: Instant::now(),
		}
	}

	/// Atomically increments the total connection counter.
	pub fn inc_total(&self) {
		self.total_connections.fetch_add(1, Ordering::Relaxed);
	}

	/// Atomically increments the active connection counter.
	pub fn inc_active(&self) {
		self.active_connections.fetch_add(1, Ordering::Relaxed);
	}

	/// Atomically decrements the active connection counter.
	pub fn dec_active(&self) {
		self.active_connections.fetch_sub(1, Ordering::Relaxed);
	}

	/// Atomically increments the dial success counter.
	pub fn inc_dial_success(&self) {
		self.dial_successes.fetch_add(1, Ordering::Relaxed);
	}

	/// Atomically increments the dial failure counter.
	pub fn inc_dial_failure(&self) {
		self.dial_failures.fetch_add(1, Ordering::Relaxed);
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

	/// Returns an immutable copy of all counters.
	pub fn snapshot(&self) -> StatsSnapshot {
		StatsSnapshot {
			total_connections: self.total_connections.load(Ordering::Relaxed),
			active_connections: self.active_connections.load(Ordering::Relaxed),
			dial_successes: self.dial_successes.load(Ordering::Relaxed),
			dial_failures: self.dial_failures.load(Ordering::Relaxed),
			bytes_in: self.bytes_in.load(Ordering::Relaxed),
			bytes_out: self.bytes_out.load(Ordering::Relaxed),
			started_at: self.started_at,
		}
	}
}
