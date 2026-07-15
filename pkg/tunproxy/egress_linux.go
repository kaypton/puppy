//go:build linux

package tunproxy

import (
	"context"
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func newSocketControl(iface4, iface6 string) (socketControl, error) {
	for _, name := range []string{iface4, iface6} {
		if name == "" {
			continue
		}
		if _, err := net.InterfaceByName(name); err != nil {
			return nil, fmt.Errorf("tunproxy: find egress interface %s: %w", name, err)
		}
	}
	return func(ctx context.Context, network, address string, c syscall.RawConn) error {
		iface, _, err := selectInterface(network, address, iface4, iface6)
		if err != nil {
			return err
		}
		var controlErr error
		if err := c.Control(func(fd uintptr) {
			controlErr = unix.BindToDevice(int(fd), iface)
		}); err != nil {
			return fmt.Errorf("tunproxy: access socket for interface binding: %w", err)
		}
		if controlErr != nil {
			return fmt.Errorf("tunproxy: bind socket to interface %s: %w", iface, controlErr)
		}
		return nil
	}, nil
}
