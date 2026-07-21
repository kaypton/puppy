//! Runtime observability primitives: atomic global counters, an active
//! connection registry, and an event bus for broadcasting lifecycle events.
//!
//! All types are safe for concurrent use. A `None` `StatsRegistry` /
//! `ConnectionRegistry` / `EventBus` is treated as a no-op by the helpers in
//! this module, allowing frontends to opt out of instrumentation at zero cost.

pub mod connection;
pub mod event;
pub mod id;
pub mod registry;

pub use connection::{ConnectionInfo, ConnectionRegistry};
pub use event::{Event, EventBus, EventType, SubscriptionGuard, SUBSCRIBER_BUFFER_SIZE};
pub use id::generate_connection_id;
pub use registry::{Deps, StatsRegistry, StatsSnapshot};
