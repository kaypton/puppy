package tunproxy

import "github.com/puppy/pkg/common"

// hostNetworkManager owns the host-side TUN addresses, routes, and backend
// egress path. Apply is transactional; Restore is safe to call more than once.
type hostNetworkManager interface {
	Apply() (common.Dialer, error)
	Restore() error
	EgressInterfaces() (ipv4, ipv6 string)
}
