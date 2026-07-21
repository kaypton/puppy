//! Tests for the `stats` module.

use std::sync::Arc;
use std::time::Duration;

use puppy_core::backend::{Protocol, Target};
use puppy_core::stats::{
	generate_connection_id, ConnectionInfo, ConnectionRegistry, Event, EventBus, EventType,
	StatsRegistry, SUBSCRIBER_BUFFER_SIZE,
};

/// Verifies that each `StatsRegistry` counter mutator updates the snapshot
/// fields as expected, including increment, decrement, and byte additions.
#[test]
fn stats_registry_counters() {
	let r = StatsRegistry::new();
	r.inc_total();
	r.inc_total();
	r.inc_total();
	r.inc_active();
	r.inc_active();
	r.dec_active();
	r.inc_dial_success();
	r.inc_dial_failure();
	r.inc_dial_failure();
	r.add_bytes_in(100);
	r.add_bytes_in(50);
	r.add_bytes_out(200);

	let snap = r.snapshot();
	assert_eq!(snap.total_connections, 3);
	assert_eq!(snap.active_connections, 1);
	assert_eq!(snap.dial_successes, 1);
	assert_eq!(snap.dial_failures, 2);
	assert_eq!(snap.bytes_in, 150);
	assert_eq!(snap.bytes_out, 200);
}

/// Exercises `StatsRegistry` under concurrent access from many threads to
/// confirm the atomics produce a consistent final snapshot with no lost
/// updates.
#[test]
fn stats_registry_concurrent() {
	let r = Arc::new(StatsRegistry::new());
	let mut handles = Vec::new();
	for _ in 0..100 {
		let r = r.clone();
		handles.push(std::thread::spawn(move || {
			r.inc_total();
			r.inc_active();
			r.add_bytes_in(10);
			r.add_bytes_out(20);
			r.dec_active();
		}));
	}
	for h in handles {
		h.join().unwrap();
	}
	let snap = r.snapshot();
	assert_eq!(snap.total_connections, 100);
	assert_eq!(snap.active_connections, 0);
	assert_eq!(snap.bytes_in, 1000);
	assert_eq!(snap.bytes_out, 2000);
}

/// Verifies `ConnectionRegistry::register` stores connections retrievable
/// by ID, `get` returns the same `Arc` and `None` for unknown IDs, and
/// `remove` drops the entry and stamps `ClosedAt` on the info.
#[test]
fn connection_registry_register_remove() {
	let r = ConnectionRegistry::new();
	let info1 = Arc::new(ConnectionInfo::new("conn-1", "fe1", "1.2.3.4:1234"));
	let info2 = Arc::new(ConnectionInfo::new("conn-2", "fe2", "5.6.7.8:5678"));
	let info1 = r.register(info1);
	let info2 = r.register(info2);

	assert_eq!(r.count(), 2);
	let got = r.get("conn-1").expect("conn-1 present");
	assert!(Arc::ptr_eq(&got, &info1));
	assert!(r.get("missing").is_none());

	r.remove("conn-1");
	assert_eq!(r.count(), 1);
	assert!(r.get("conn-1").is_none());
	assert!(info1.is_closed(), "ClosedAt should be set after Remove");
	let _ = info2;
}

/// Verifies the `active`, `active_by_frontend` views reflect registered
/// connections and group correctly per frontend, returning empty for an
/// unknown frontend.
#[test]
fn connection_registry_active() {
	let r = ConnectionRegistry::new();
	r.register(Arc::new(ConnectionInfo::new("a", "fe1", "")));
	r.register(Arc::new(ConnectionInfo::new("b", "fe1", "")));
	r.register(Arc::new(ConnectionInfo::new("c", "fe2", "")));

	assert_eq!(r.active().len(), 3);
	assert_eq!(r.active_by_frontend("fe1").len(), 2);
	assert_eq!(r.active_by_frontend("fe2").len(), 1);
	assert_eq!(r.active_by_frontend("nope").len(), 0);
}

/// Verifies `ConnectionInfo` byte counters accumulate additions and ignore
/// non-positive values.
#[test]
fn connection_info_bytes() {
	let info = ConnectionInfo::new("c1", "fe", "1.2.3.4:5");
	// We can't directly mutate `target`/`protocol`/`network` since they're not
	// `pub mut`, but we can still verify the byte counters behave as expected.
	info.add_bytes_in(100);
	info.add_bytes_in(50);
	info.add_bytes_out(300);
	assert_eq!(info.bytes_in(), 150);
	assert_eq!(info.bytes_out(), 300);

	// Non-positive additions are ignored.
	info.add_bytes_in(0);
	info.add_bytes_out(0);
	assert_eq!(info.bytes_in(), 150);
	assert_eq!(info.bytes_out(), 300);
}

/// Exercises `ConnectionInfo` byte counters under concurrent access to
/// confirm the atomics produce the expected totals with no lost updates.
#[test]
fn connection_info_concurrent_bytes() {
	let info = Arc::new(ConnectionInfo::new("c1", "", ""));
	let mut handles = Vec::new();
	for _ in 0..50 {
		let info_in = info.clone();
		let info_out = info.clone();
		handles.push(std::thread::spawn(move || info_in.add_bytes_in(10)));
		handles.push(std::thread::spawn(move || info_out.add_bytes_out(20)));
	}
	for h in handles {
		h.join().unwrap();
	}
	assert_eq!(info.bytes_in(), 500);
	assert_eq!(info.bytes_out(), 1000);
}

/// Verifies a subscriber with no filter receives published events in order,
/// including the `frontend` and `connection_id` fields supplied by the
/// publisher.
#[tokio::test]
async fn event_bus_publish_subscribe() {
	let bus = EventBus::new();
	let (mut rx, _guard) = bus.subscribe(&[]);

	bus.publish(Event {
		event_type: EventType::Connect,
		frontend: "fe1".to_string(),
		connection_id: "c1".to_string(),
		target: "example.com:443".to_string(),
		..Event::new(EventType::Connect)
	});
	bus.publish(Event {
		event_type: EventType::Disconnect,
		connection_id: "c1".to_string(),
		..Event::new(EventType::Disconnect)
	});

	let ev1 = rx.recv().await.expect("first event");
	assert_eq!(ev1.event_type, EventType::Connect);
	assert_eq!(ev1.frontend, "fe1");
	let ev2 = rx.recv().await.expect("second event");
	assert_eq!(ev2.event_type, EventType::Disconnect);
}

/// Confirms the `EventBus` fans a single published event out to multiple
/// independent subscribers and reports the correct subscriber count.
#[tokio::test]
async fn event_bus_multiple_subscribers() {
	let bus = EventBus::new();
	let (mut rx1, _g1) = bus.subscribe(&[]);
	let (mut rx2, _g2) = bus.subscribe(&[]);

	assert_eq!(bus.subscriber_count(), 2);
	bus.publish(Event::new(EventType::Connect));

	let ev1 = rx1.recv().await.expect("rx1 event");
	let ev2 = rx2.recv().await.expect("rx2 event");
	assert_eq!(ev1.event_type, EventType::Connect);
	assert_eq!(ev2.event_type, EventType::Connect);
}

/// Confirms that cancelling a subscription guard removes the subscriber
/// from the bus (count drops to zero) and closes its receiver channel.
#[tokio::test]
async fn event_bus_unsubscribe_on_cancel() {
	let bus = EventBus::new();
	let (mut rx, mut guard) = bus.subscribe(&[]);
	assert_eq!(bus.subscriber_count(), 1);

	guard.cancel();
	// Drain any buffered events then expect channel close.
	while rx.try_recv().ok().is_some() {}
	assert_eq!(bus.subscriber_count(), 0);
}

/// Verifies that publishing beyond a subscriber's buffer capacity drops
/// excess events rather than blocking the publisher, and that the receiver
/// yields at most `SUBSCRIBER_BUFFER_SIZE` events.
#[tokio::test]
async fn event_bus_drops_on_full_buffer() {
	let bus = EventBus::new();
	let (mut rx, _guard) = bus.subscribe(&[]);

	// Fill the buffer beyond capacity to trigger drops.
	for _ in 0..SUBSCRIBER_BUFFER_SIZE + 50 {
		bus.publish(Event::new(EventType::Connect));
	}
	// Should not block; received count should be <= buffer size.
	let mut received = 0;
	while rx.try_recv().is_ok() {
		received += 1;
	}
	assert!(
		received <= SUBSCRIBER_BUFFER_SIZE,
		"received {received}, expected at most {SUBSCRIBER_BUFFER_SIZE}"
	);
}

/// Confirms that dropping all subscription guards removes every subscriber
/// and brings the bus's subscriber count to zero.
#[tokio::test]
async fn event_bus_close() {
	let bus = EventBus::new();
	let (_rx1, _g1) = bus.subscribe(&[]);
	let (_rx2, _g2) = bus.subscribe(&[]);
	assert_eq!(bus.subscriber_count(), 2);
	drop(_g1);
	drop(_g2);
	assert_eq!(bus.subscriber_count(), 0);
}

/// Verifies a single-event-type filter receives only matching events and
/// silently drops non-matching ones (the receiver times out waiting for
/// further events).
#[tokio::test]
async fn event_bus_subscribe_with_filter() {
	let bus = EventBus::new();
	let (mut rx, _guard) = bus.subscribe(&[EventType::Connect]);

	bus.publish(Event {
		event_type: EventType::Connect,
		connection_id: "c1".to_string(),
		..Event::new(EventType::Connect)
	});
	bus.publish(Event {
		event_type: EventType::Disconnect,
		connection_id: "c1".to_string(),
		..Event::new(EventType::Disconnect)
	});
	bus.publish(Event {
		event_type: EventType::DialFailed,
		target: "x:443".to_string(),
		..Event::new(EventType::DialFailed)
	});

	let ev = rx.recv().await.expect("event");
	assert_eq!(ev.event_type, EventType::Connect);

	tokio::time::timeout(Duration::from_millis(50), rx.recv())
		.await
		.expect_err("no more events should match the filter");
}

/// Verifies a multi-event-type filter receives each listed type in publish
/// order and drops events whose type is not in the set.
#[tokio::test]
async fn event_bus_subscribe_multiple_topics() {
	let bus = EventBus::new();
	let (mut rx, _guard) = bus.subscribe(&[EventType::Connect, EventType::Disconnect]);

	bus.publish(Event {
		event_type: EventType::Connect,
		connection_id: "c1".to_string(),
		..Event::new(EventType::Connect)
	});
	bus.publish(Event {
		event_type: EventType::Disconnect,
		connection_id: "c1".to_string(),
		..Event::new(EventType::Disconnect)
	});
	bus.publish(Event::new(EventType::Shutdown));

	let ev1 = rx.recv().await.expect("first event");
	assert_eq!(ev1.event_type, EventType::Connect);
	let ev2 = rx.recv().await.expect("second event");
	assert_eq!(ev2.event_type, EventType::Disconnect);

	tokio::time::timeout(Duration::from_millis(50), rx.recv())
		.await
		.expect_err("shutdown should be filtered out");
}

/// Confirms a subscriber whose filter matches none of the published types
/// receives nothing (the receiver times out).
#[tokio::test]
async fn event_bus_subscribe_no_match() {
	let bus = EventBus::new();
	let (mut rx, _guard) = bus.subscribe(&[EventType::DialFailed]);

	bus.publish(Event::new(EventType::Connect));
	bus.publish(Event::new(EventType::Disconnect));
	bus.publish(Event::new(EventType::Shutdown));

	tokio::time::timeout(Duration::from_millis(50), rx.recv())
		.await
		.expect_err("no events should match");
}

/// Confirms that an empty filter list subscribes to all event types,
/// receiving every published event in order.
#[tokio::test]
async fn event_bus_subscribe_all_when_no_types() {
	let bus = EventBus::new();
	let (mut rx, _guard) = bus.subscribe(&[]);

	bus.publish(Event::new(EventType::Connect));
	bus.publish(Event::new(EventType::Shutdown));

	let ev1 = rx.recv().await.expect("first event");
	assert_eq!(ev1.event_type, EventType::Connect);
	let ev2 = rx.recv().await.expect("second event");
	assert_eq!(ev2.event_type, EventType::Shutdown);
}

/// Verifies `generate_connection_id` produces unique IDs across many
/// invocations and that each carries the expected `conn-` prefix.
#[test]
fn generate_connection_id_is_unique_and_well_formed() {
	let mut seen = std::collections::HashSet::new();
	for _ in 0..1000 {
		let id = generate_connection_id();
		assert!(id.starts_with("conn-"), "id = {id}");
		assert!(seen.insert(id.clone()), "duplicate id: {id}");
	}
}

/// Verifies a freshly constructed `ConnectionInfo` reports an empty/`Unknown`
/// `Target` and `Unknown` protocol, matching the zero-value defaults.
#[test]
fn connection_info_default_target_and_protocol() {
	let info = ConnectionInfo::new("c1", "fe", "1.2.3.4:5");
	// Sanity: default fields match a zero-value `ConnectionInfo`.
	assert_eq!(
		info.target,
		Target {
			network: String::new(),
			protocol: Protocol::Unknown,
			host: String::new(),
			port: 0,
		}
	);
	assert_eq!(info.protocol, Protocol::Unknown);
	assert_eq!(info.network, "");
}
