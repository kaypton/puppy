package tunproxy

import (
	"context"
	"fmt"
	"net"
	"strings"
	"syscall"

	"github.com/puppy/pkg/common"
)

type socketControl func(ctx context.Context, network, address string, c syscall.RawConn) error

// newBoundDialer creates a host dialer whose application and DNS sockets are
// both pinned to the physical interfaces captured before split routes exist.
func newBoundDialer(iface4, iface6 string) (common.Dialer, error) {
	control, err := newSocketControl(iface4, iface6)
	if err != nil {
		return nil, err
	}
	dnsDialer := &net.Dialer{ControlContext: control}
	return &net.Dialer{
		ControlContext: control,
		Resolver: &net.Resolver{
			PreferGo: true,
			Dial:     dnsDialer.DialContext,
		},
	}, nil
}

func selectInterface(network, address, iface4, iface6 string) (string, int, error) {
	if strings.HasSuffix(network, "4") {
		if iface4 == "" {
			return "", 0, fmt.Errorf("tunproxy: no IPv4 egress interface")
		}
		return iface4, 4, nil
	}
	if strings.HasSuffix(network, "6") {
		if iface6 == "" {
			return "", 0, fmt.Errorf("tunproxy: no IPv6 egress interface")
		}
		return iface6, 6, nil
	}
	host, _, err := net.SplitHostPort(address)
	if err == nil {
		if ip := net.ParseIP(host); ip != nil {
			if ip.To4() != nil {
				if iface4 == "" {
					return "", 0, fmt.Errorf("tunproxy: no IPv4 egress interface")
				}
				return iface4, 4, nil
			}
			if iface6 == "" {
				return "", 0, fmt.Errorf("tunproxy: no IPv6 egress interface")
			}
			return iface6, 6, nil
		}
	}
	if iface4 != "" {
		return iface4, 4, nil
	}
	if iface6 != "" {
		return iface6, 6, nil
	}
	return "", 0, fmt.Errorf("tunproxy: no egress interface")
}
