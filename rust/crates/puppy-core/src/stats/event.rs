//! Broadcast runtime events to multiple subscribers.
//!
//! Subscribers receive events on a buffered channel; when the buffer fills,
//! events are dropped to keep the publisher non-blocking.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use parking_lot::Mutex;
use tokio::sync::mpsc;

/// Categorizes a runtime event published on the `EventBus`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventType {
	/// A tunnel was established.
	Connect,
	/// A tunnel closed.
	Disconnect,
	/// A backend dial failed.
	DialFailed,
	/// A hot reload succeeded.
	ConfigReloaded,
	/// A hot reload failed.
	ConfigReloadFailed,
	/// A graceful shutdown was requested.
	Shutdown,
}

impl EventType {
	/// Returns the string form (`"connect"`, `"dial_failed"`, ...).
	pub fn as_str(self) -> &'static str {
		match self {
			EventType::Connect => "connect",
			EventType::Disconnect => "disconnect",
			EventType::DialFailed => "dial_failed",
			EventType::ConfigReloaded => "config_reloaded",
			EventType::ConfigReloadFailed => "config_reload_failed",
			EventType::Shutdown => "shutdown",
		}
	}
}

/// A runtime observation broadcast to all subscribers.
#[derive(Debug, Clone)]
pub struct Event {
	pub event_type: EventType,
	pub time: Instant,
	pub frontend: String,
	pub connection_id: String,
	pub target: String,
	pub remote_addr: String,
	pub message: String,
}

impl Event {
	/// Creates a new event with the given type and empty fields. `time` is
	/// stamped by `EventBus::publish` if left as `Instant::now()` here.
	pub fn new(event_type: EventType) -> Self {
		Self {
			event_type,
			time: Instant::now(),
			frontend: String::new(),
			connection_id: String::new(),
			target: String::new(),
			remote_addr: String::new(),
			message: String::new(),
		}
	}
}

/// Per-subscriber channel buffer. Events beyond this are dropped to prevent a
/// slow consumer from blocking publishers.
pub const SUBSCRIBER_BUFFER_SIZE: usize = 256;

struct Subscriber {
	sender: mpsc::Sender<Event>,
	filter: Option<HashMap<EventType, ()>>,
}

/// Broadcasts `Event`s to multiple subscribers.
pub struct EventBus {
	subscribers: Mutex<HashMap<u64, Subscriber>>,
	next_id: Mutex<u64>,
}

impl EventBus {
	/// Returns a ready-to-use event bus.
	pub fn new() -> Self {
		Self {
			subscribers: Mutex::new(HashMap::new()),
			next_id: Mutex::new(0),
		}
	}

	/// Subscribes to events. When `types` is non-empty, only events whose type
	/// matches one of the given types are delivered. When `types` is empty, all
	/// events are delivered. Returns a receiver and a guard that unsubscribes
	/// on drop.
	///
	/// The returned guard must be held alive for the subscription to remain
	/// active; dropping it removes the subscriber.
	pub fn subscribe(&self, types: &[EventType]) -> (mpsc::Receiver<Event>, SubscriptionGuard<'_>) {
		let (tx, rx) = mpsc::channel(SUBSCRIBER_BUFFER_SIZE);
		let filter = if types.is_empty() {
			None
		} else {
			Some(types.iter().copied().map(|t| (t, ())).collect())
		};
		let mut next = self.next_id.lock();
		let id = *next;
		*next += 1;
		self.subscribers
			.lock()
			.insert(id, Subscriber { sender: tx, filter });
		(
			rx,
			SubscriptionGuard {
				bus: self,
				id,
				cancelled: false,
			},
		)
	}

	/// Broadcasts an event to all subscribers whose filter matches the event
	/// type. If a subscriber's buffer is full the event is dropped for that
	/// subscriber. Publish never blocks.
	pub fn publish(&self, mut ev: Event) {
		// Stamp the time here so all subscribers see the same instant.
		ev.time = Instant::now();
		let subs = self.subscribers.lock();
		for sub in subs.values() {
			if let Some(filter) = &sub.filter {
				if !filter.contains_key(&ev.event_type) {
					continue;
				}
			}
			let _ = sub.sender.try_send(ev.clone());
		}
	}

	/// Returns the current number of active subscribers.
	pub fn subscriber_count(&self) -> usize {
		self.subscribers.lock().len()
	}

	/// Removes a subscriber by id (used by `SubscriptionGuard::cancel`).
	fn remove_subscriber(&self, id: u64) {
		self.subscribers.lock().remove(&id);
	}
}

impl Default for EventBus {
	fn default() -> Self {
		Self::new()
	}
}

/// RAII guard that unsubscribes from the `EventBus` on drop.
pub struct SubscriptionGuard<'a> {
	bus: &'a EventBus,
	id: u64,
	cancelled: bool,
}

impl SubscriptionGuard<'_> {
	/// Cancels the subscription explicitly.
	pub fn cancel(&mut self) {
		if !self.cancelled {
			self.bus.remove_subscriber(self.id);
			self.cancelled = true;
		}
	}
}

impl Drop for SubscriptionGuard<'_> {
	fn drop(&mut self) {
		self.cancel();
	}
}

/// `Arc<EventBus>` is the typical shared form.
pub type SharedEventBus = Arc<EventBus>;
