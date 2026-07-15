//go:build linux

package tunproxy

import (
	"context"
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// linuxBypassMark identifies sockets created by Puppy itself so the nft
// OUTPUT rule does not feed backend or resolver traffic back into the TUN.
const linuxBypassMark = 0x50555059

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
			controlErr = configureLinuxSocket(
				int(fd), iface,
				unix.BindToDevice,
				func(fd, mark int) error {
					return unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, mark)
				},
			)
		}); err != nil {
			return fmt.Errorf("tunproxy: access socket for interface binding: %w", err)
		}
		if controlErr != nil {
			return fmt.Errorf("tunproxy: configure egress socket: %w", controlErr)
		}
		return nil
	}, nil
}

func configureLinuxSocket(fd int, iface string, bind func(int, string) error, mark func(int, int) error) error {
	if err := bind(fd, iface); err != nil {
		return fmt.Errorf("bind socket to interface %s: %w", iface, err)
	}
	if err := mark(fd, linuxBypassMark); err != nil {
		return fmt.Errorf("mark socket for TUN bypass: %w", err)
	}
	return nil
}
