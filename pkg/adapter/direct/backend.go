// Package direct implements a common.Backend that connects directly to the
// target via net.Dialer (no intermediary proxy).
package direct

import (
	"context"
	"io"

	"github.com/puppy/pkg/common"
)

// Backend dials targets directly over TCP (or the target's requested network).
type Backend struct{}

// NewBackend returns a direct backend with default settings.
func NewBackend() *Backend {
	return &Backend{}
}

// Dial connects directly to the target and returns the resulting connection.
func (b *Backend) Dial(ctx context.Context, target common.Target, dialer common.Dialer) (io.ReadWriteCloser, error) {
	if dialer == nil {
		dialer = common.SystemDialer()
	}
	return dialer.DialContext(ctx, target.Net(), target.Address())
}
