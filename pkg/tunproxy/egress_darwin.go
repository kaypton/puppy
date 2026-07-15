//go:build darwin

package tunproxy

import (
	"context"
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func newSocketControl(iface4, iface6 string) (socketControl, error) {
	indexes := make(map[string]int, 2)
	for _, name := range []string{iface4, iface6} {
		if name == "" {
			continue
		}
		iface, err := net.InterfaceByName(name)
		if err != nil {
			return nil, fmt.Errorf("tunproxy: find egress interface %s: %w", name, err)
		}
		indexes[name] = iface.Index
	}
	return func(ctx context.Context, network, address string, c syscall.RawConn) error {
		iface, family, err := selectInterface(network, address, iface4, iface6)
		if err != nil {
			return err
		}
		level, option := unix.IPPROTO_IP, unix.IP_BOUND_IF
		if family == 6 {
			level, option = unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF
		}
		var controlErr error
		if err := c.Control(func(fd uintptr) {
			controlErr = unix.SetsockoptInt(int(fd), level, option, indexes[iface])
		}); err != nil {
			return fmt.Errorf("tunproxy: access socket for interface binding: %w", err)
		}
		if controlErr != nil {
			return fmt.Errorf("tunproxy: bind socket to interface %s: %w", iface, controlErr)
		}
		return nil
	}, nil
}
