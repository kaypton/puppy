// Package stats provides runtime observability primitives for puppy's
// frontends. It exposes atomic counters for global traffic, a registry of
// active connections, and an event bus for broadcasting lifecycle events to
// subscribers such as the dashboard SSE endpoint.
//
// All types are safe for concurrent use. A nil *StatsRegistry,
// *ConnectionRegistry, or *EventBus is treated as a no-op by the helpers in
// this package, allowing frontends to opt out of instrumentation at zero
// cost.
package stats

import (
	"sync/atomic"
	"time"
)

// Deps bundles the observability dependencies injected into a frontend's
// ServerConfiguration. Any field may be nil to disable that aspect of
// instrumentation.
type Deps struct {
	// Name is the frontend name used for attribution in stats and events.
	Name string
	// Stats receives global counter updates. Nil disables global counting.
	Stats *StatsRegistry
	// ConnReg tracks active connections. Nil disables per-connection tracking.
	ConnReg *ConnectionRegistry
	// Bus broadcasts lifecycle events. Nil disables event publishing.
	Bus *EventBus
}

// StatsSnapshot is an immutable point-in-time view of global counters.
type StatsSnapshot struct {
	// TotalConnections is the cumulative number of connections accepted by
	// all instrumented frontends since startup.
	TotalConnections uint64
	// ActiveConnections is the current number of open tunnels.
	ActiveConnections uint64
	// DialSuccesses is the cumulative number of successful backend dials.
	DialSuccesses uint64
	// DialFailures is the cumulative number of failed backend dials.
	DialFailures uint64
	// BytesIn is the cumulative number of bytes read from clients (frontend
	// to backend direction).
	BytesIn uint64
	// BytesOut is the cumulative number of bytes written to clients (backend
	// to frontend direction).
	BytesOut uint64
	// StartedAt is when the StatsRegistry was created (process start).
	StartedAt time.Time
}

// StatsRegistry holds atomic global counters shared across all frontends.
type StatsRegistry struct {
	totalConnections  atomic.Uint64
	activeConnections atomic.Uint64
	dialSuccesses     atomic.Uint64
	dialFailures      atomic.Uint64
	bytesIn           atomic.Uint64
	bytesOut          atomic.Uint64
	startedAt         time.Time
}

// NewStatsRegistry returns a ready-to-use registry with StartedAt set to now.
func NewStatsRegistry() *StatsRegistry {
	return &StatsRegistry{startedAt: time.Now()}
}

// IncTotal atomically increments the total connection counter.
func (s *StatsRegistry) IncTotal() {
	if s == nil {
		return
	}
	s.totalConnections.Add(1)
}

// IncActive atomically increments the active connection counter.
func (s *StatsRegistry) IncActive() {
	if s == nil {
		return
	}
	s.activeConnections.Add(1)
}

// DecActive atomically decrements the active connection counter.
func (s *StatsRegistry) DecActive() {
	if s == nil {
		return
	}
	s.activeConnections.Add(^uint64(0))
}

// IncDialSuccess atomically increments the dial success counter.
func (s *StatsRegistry) IncDialSuccess() {
	if s == nil {
		return
	}
	s.dialSuccesses.Add(1)
}

// IncDialFailure atomically increments the dial failure counter.
func (s *StatsRegistry) IncDialFailure() {
	if s == nil {
		return
	}
	s.dialFailures.Add(1)
}

// AddBytesIn atomically adds n to the inbound byte counter.
func (s *StatsRegistry) AddBytesIn(n int) {
	if s == nil || n <= 0 {
		return
	}
	s.bytesIn.Add(uint64(n))
}

// AddBytesOut atomically adds n to the outbound byte counter.
func (s *StatsRegistry) AddBytesOut(n int) {
	if s == nil || n <= 0 {
		return
	}
	s.bytesOut.Add(uint64(n))
}

// Snapshot returns an immutable copy of all counters.
func (s *StatsRegistry) Snapshot() StatsSnapshot {
	if s == nil {
		return StatsSnapshot{}
	}
	return StatsSnapshot{
		TotalConnections:  s.totalConnections.Load(),
		ActiveConnections: s.activeConnections.Load(),
		DialSuccesses:     s.dialSuccesses.Load(),
		DialFailures:      s.dialFailures.Load(),
		BytesIn:           s.bytesIn.Load(),
		BytesOut:          s.bytesOut.Load(),
		StartedAt:         s.startedAt,
	}
}
