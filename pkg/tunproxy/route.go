package tunproxy

import (
	"io"

	"github.com/puppy/pkg/common"
)

type dnsInterceptHandler interface {
	serveInterceptedDNSStream(io.ReadWriteCloser)
	resolveInterceptedDNSDatagram([]byte) ([]byte, error)
}

// hostNetworkManager owns the host-side TUN addresses, routes, and backend
// egress path. Apply is transactional; Restore is safe to call more than once.
type hostNetworkManager interface {
	Apply() (common.Dialer, error)
	EnableDNSInterception(dnsInterceptHandler) error
	Restore() error
	EgressInterfaces() (ipv4, ipv6 string)
}
