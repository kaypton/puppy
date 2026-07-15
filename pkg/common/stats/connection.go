package stats

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/puppy/pkg/common"
)

// ConnectionInfo describes a single active tunnel observed by a frontend.
type ConnectionInfo struct {
	// ID is a unique identifier assigned when the connection is registered.
	ID string
	// Frontend is the name of the frontend that accepted the connection.
	Frontend string
	// RemoteAddr is the client address (host:port).
	RemoteAddr string
	// Target is the destination the backend dialed on behalf of the client.
	Target common.Target
	// Protocol is the detected application protocol (may be ProtocolUnknown).
	Protocol common.Protocol
	// Network is the transport network ("tcp" or "udp").
	Network string
	// StartedAt is when the connection was accepted.
	StartedAt time.Time
	// ClosedAt is set when the connection is removed from the registry.
	ClosedAt time.Time

	// bytesIn/bytesOut are mutated atomically via AddBytesIn/AddBytesOut by
	// the counting wrapper and are read atomically by BytesIn/BytesOut, so no
	// external locking is required even while the shim's two copy goroutines
	// run concurrently.
	bytesIn  atomic.Uint64
	bytesOut atomic.Uint64
}

// BytesIn returns the cumulative number of bytes read from the client.
func (c *ConnectionInfo) BytesIn() uint64 { return c.bytesIn.Load() }

// BytesOut returns the cumulative number of bytes written to the client.
func (c *ConnectionInfo) BytesOut() uint64 { return c.bytesOut.Load() }

// AddBytesIn atomically adds n to the connection's inbound byte counter. It
// is called by the counting connection wrapper; callers do not need external
// locking.
func (c *ConnectionInfo) AddBytesIn(n int) {
	if n <= 0 {
		return
	}
	c.bytesIn.Add(uint64(n))
}

// AddBytesOut atomically adds n to the connection's outbound byte counter.
func (c *ConnectionInfo) AddBytesOut(n int) {
	if n <= 0 {
		return
	}
	c.bytesOut.Add(uint64(n))
}

// ConnectionRegistry tracks active connections across all frontends. The set
// of active connections is expected to be small relative to total throughput,
// so a single RWMutex-guarded map is sufficient.
type ConnectionRegistry struct {
	mu     sync.RWMutex
	active map[string]*ConnectionInfo
}

// NewConnectionRegistry returns a ready-to-use registry.
func NewConnectionRegistry() *ConnectionRegistry {
	return &ConnectionRegistry{active: make(map[string]*ConnectionInfo)}
}

// Register records a new active connection and returns a pointer to the
// stored ConnectionInfo. The caller should use the returned pointer with a
// counting connection wrapper and call Remove when the connection closes.
func (r *ConnectionRegistry) Register(info *ConnectionInfo) *ConnectionInfo {
	if r == nil || info == nil {
		return nil
	}
	if info.StartedAt.IsZero() {
		info.StartedAt = time.Now()
	}
	r.mu.Lock()
	r.active[info.ID] = info
	r.mu.Unlock()
	return info
}

// Remove deletes a connection from the active set and marks ClosedAt.
func (r *ConnectionRegistry) Remove(id string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	if info, ok := r.active[id]; ok {
		info.ClosedAt = time.Now()
		delete(r.active, id)
	}
	r.mu.Unlock()
}

// Get returns the connection with the given id, or nil if not found.
func (r *ConnectionRegistry) Get(id string) *ConnectionInfo {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	info := r.active[id]
	r.mu.RUnlock()
	return info
}

// Active returns a snapshot slice of all currently active connections. The
// slice is a copy; callers may iterate it without holding the lock.
func (r *ConnectionRegistry) Active() []*ConnectionInfo {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	out := make([]*ConnectionInfo, 0, len(r.active))
	for _, info := range r.active {
		out = append(out, info)
	}
	r.mu.RUnlock()
	return out
}

// ActiveByFrontend returns active connections for a specific frontend name.
func (r *ConnectionRegistry) ActiveByFrontend(frontend string) []*ConnectionInfo {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	out := make([]*ConnectionInfo, 0)
	for _, info := range r.active {
		if info.Frontend == frontend {
			out = append(out, info)
		}
	}
	r.mu.RUnlock()
	return out
}

// Count returns the number of currently active connections.
func (r *ConnectionRegistry) Count() int {
	if r == nil {
		return 0
	}
	r.mu.RLock()
	n := len(r.active)
	r.mu.RUnlock()
	return n
}
