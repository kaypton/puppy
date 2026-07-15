// Package counting provides an io.ReadWriteCloser wrapper that tallies bytes
// transferred through a connection into a stats.ConnectionInfo and a global
// StatsRegistry. A CountingConn is inserted between the frontend (client)
// connection and the shim so that per-connection and global byte counters
// stay in sync without modifying the shim itself.
//
// Only the client-side connection is wrapped. Bytes read from the client are
// counted as inbound (BytesIn) and bytes written to the client are counted as
// outbound (BytesOut). The backend connection is not wrapped, which avoids
// double-counting the same bytes.
package counting

import (
	"io"

	"github.com/puppy/pkg/common/stats"
)

// CountingConn wraps an io.ReadWriteCloser and records bytes passing through
// Read and Write into the associated ConnectionInfo (per-connection) and
// StatsRegistry (global). Either may be nil, in which case counting is
// skipped for that level.
type CountingConn struct {
	conn     io.ReadWriteCloser
	info     *stats.ConnectionInfo
	registry *stats.StatsRegistry
}

// NewConn returns a CountingConn that wraps conn. Read bytes are recorded as
// inbound (client to proxy) and Write bytes as outbound (proxy to client).
func NewConn(conn io.ReadWriteCloser, info *stats.ConnectionInfo, registry *stats.StatsRegistry) *CountingConn {
	return &CountingConn{conn: conn, info: info, registry: registry}
}

// Read reads from the underlying connection and records the number of bytes
// read as inbound traffic.
func (c *CountingConn) Read(p []byte) (int, error) {
	n, err := c.conn.Read(p)
	if n > 0 {
		if c.info != nil {
			c.info.AddBytesIn(n)
		}
		if c.registry != nil {
			c.registry.AddBytesIn(n)
		}
	}
	return n, err
}

// Write writes to the underlying connection and records the number of bytes
// written as outbound traffic.
func (c *CountingConn) Write(p []byte) (int, error) {
	n, err := c.conn.Write(p)
	if n > 0 {
		if c.info != nil {
			c.info.AddBytesOut(n)
		}
		if c.registry != nil {
			c.registry.AddBytesOut(n)
		}
	}
	return n, err
}

// Close closes the underlying connection. It does not remove the connection
// from the registry; the frontend is responsible for calling
// ConnectionRegistry.Remove after the shim returns.
func (c *CountingConn) Close() error {
	return c.conn.Close()
}
