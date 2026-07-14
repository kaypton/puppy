// Package direct implements a common.Backend that connects directly to the
// target via net.Dialer (no intermediary proxy).
package direct

import (
	"context"
	"io"
	"net"

	"github.com/puppy/pkg/common"
)

// Backend dials targets directly over TCP (or the target's requested network).
type Backend struct {
	// Dialer overrides the default dialer. When nil, &net.Dialer{} is used.
	Dialer *net.Dialer
}

// NewBackend returns a direct backend with default settings.
func NewBackend() *Backend {
	return &Backend{}
}

// Dial connects directly to the target and returns the resulting connection.
func (b *Backend) Dial(ctx context.Context, target common.Target) (io.ReadWriteCloser, error) {
	d := b.Dialer
	if d == nil {
		d = &net.Dialer{}
	}
	return d.DialContext(ctx, target.Net(), target.Address())
}
