package stats

import (
	"context"
	"sync"
	"time"
)

// EventType categorizes a runtime event published on the EventBus.
type EventType string

const (
	// EventConnect is published when a tunnel is established.
	EventConnect EventType = "connect"
	// EventDisconnect is published when a tunnel closes.
	EventDisconnect EventType = "disconnect"
	// EventDialFailed is published when a backend dial fails.
	EventDialFailed EventType = "dial_failed"
	// EventConfigReloaded is published after a successful hot reload.
	EventConfigReloaded EventType = "config_reloaded"
	// EventConfigReloadFailed is published when a hot reload fails.
	EventConfigReloadFailed EventType = "config_reload_failed"
	// EventShutdown is published when a graceful shutdown is requested.
	EventShutdown EventType = "shutdown"
)

// Event is a runtime observation broadcast to all subscribers.
type Event struct {
	// Type is the event category.
	Type EventType
	// Time is when the event occurred.
	Time time.Time
	// Frontend is the frontend name associated with the event, if any.
	Frontend string
	// ConnectionID is the connection id for connect/disconnect events.
	ConnectionID string
	// Target is the destination associated with the event, if any.
	Target string
	// RemoteAddr is the client address, if applicable.
	RemoteAddr string
	// Message is a human-readable detail string, if any.
	Message string
}

// subscriberBufferSize is the per-subscriber channel buffer. Events beyond
// this are dropped to prevent a slow consumer from blocking publishers.
const subscriberBufferSize = 256

type subscriber struct {
	ch     chan Event
	cancel context.CancelFunc
	filter map[EventType]struct{}
}

// EventBus broadcasts Events to multiple subscribers. Subscribers receive
// events on a buffered channel; when the buffer fills, events are dropped to
// keep the publisher non-blocking.
type EventBus struct {
	mu          sync.Mutex
	subscribers map[*subscriber]struct{}
}

// NewEventBus returns a ready-to-use event bus.
func NewEventBus() *EventBus {
	return &EventBus{subscribers: make(map[*subscriber]struct{})}
}

// Subscribe returns a channel that receives events until ctx is cancelled or
// the bus is closed. When types is non-empty, only events whose Type matches
// one of the given types are delivered. When types is empty, all events are
// delivered. The caller should drain the channel promptly; a full buffer
// causes events to be dropped (not blocked).
func (b *EventBus) Subscribe(ctx context.Context, types ...EventType) <-chan Event {
	if b == nil {
		ch := make(chan Event)
		close(ch)
		return ch
	}
	ctx, cancel := context.WithCancel(ctx)
	sub := &subscriber{ch: make(chan Event, subscriberBufferSize), cancel: cancel}
	if len(types) > 0 {
		sub.filter = make(map[EventType]struct{}, len(types))
		for _, t := range types {
			sub.filter[t] = struct{}{}
		}
	}
	b.mu.Lock()
	b.subscribers[sub] = struct{}{}
	b.mu.Unlock()
	go func() {
		<-ctx.Done()
		b.mu.Lock()
		if _, ok := b.subscribers[sub]; ok {
			delete(b.subscribers, sub)
			close(sub.ch)
		}
		b.mu.Unlock()
	}()
	return sub.ch
}

// Publish broadcasts an event to all subscribers whose filter matches the
// event type. If a subscriber's buffer is full the event is dropped for that
// subscriber. Publish never blocks.
func (b *EventBus) Publish(ev Event) {
	if b == nil {
		return
	}
	if ev.Time.IsZero() {
		ev.Time = time.Now()
	}
	b.mu.Lock()
	for sub := range b.subscribers {
		if sub.filter != nil {
			if _, ok := sub.filter[ev.Type]; !ok {
				continue
			}
		}
		select {
		case sub.ch <- ev:
		default:
			// drop event for slow subscriber
		}
	}
	b.mu.Unlock()
}

// Close shuts down all subscribers. After Close, Subscribe returns a closed
// channel and Publish is a no-op.
func (b *EventBus) Close() {
	if b == nil {
		return
	}
	b.mu.Lock()
	for sub := range b.subscribers {
		sub.cancel()
		delete(b.subscribers, sub)
	}
	b.mu.Unlock()
}

// SubscriberCount returns the current number of active subscribers.
func (b *EventBus) SubscriberCount() int {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	n := len(b.subscribers)
	b.mu.Unlock()
	return n
}
