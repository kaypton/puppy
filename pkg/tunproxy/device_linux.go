//go:build linux

package tunproxy

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// linuxDevice wraps an open /dev/net/tun file descriptor.
type linuxDevice struct {
	fd   *os.File
	name string
	mtu  uint32
}

// openDevice opens a TUN device on Linux. If name is empty the kernel assigns
// the next free tunN. The device is created without a packet information
// header (IFF_NO_PI) so reads/writes carry raw IP packets.
func openDevice(name string, mtu uint32) (Device, error) {
	if mtu == 0 {
		mtu = defaultMTU
	}
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("tunproxy: open /dev/net/tun: %w", err)
	}

	ifr, err := unix.NewIfreq(name)
	if err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("tunproxy: build ifreq: %w", err)
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("tunproxy: TUNSETIFF: %w", err)
	}
	assigned := ifr.Name()

	if err := unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("tunproxy: set nonblock: %w", err)
	}

	if mtu != 0 {
		if err := setLinkMTU(assigned, int(mtu)); err != nil {
			_ = unix.Close(fd)
			return nil, fmt.Errorf("tunproxy: set MTU: %w", err)
		}
	}

	return &linuxDevice{
		fd:   os.NewFile(uintptr(fd), "/dev/net/tun"),
		name: assigned,
		mtu:  mtu,
	}, nil
}

func (d *linuxDevice) Name() string { return d.name }
func (d *linuxDevice) MTU() uint32  { return d.mtu }

func (d *linuxDevice) Read(p []byte) (int, error) {
	n, err := d.fd.Read(p)
	if err != nil && errors.Is(err, os.ErrClosed) {
		return 0, ErrDeviceClosed
	}
	return n, err
}

func (d *linuxDevice) Write(p []byte) (int, error) {
	n, err := d.fd.Write(p)
	if err != nil && errors.Is(err, os.ErrClosed) {
		return 0, ErrDeviceClosed
	}
	return n, err
}

func (d *linuxDevice) Close() error { return d.fd.Close() }

// setLinkMTU sets the MTU of the named interface via the SIOCSIFMTU ioctl on a
// dummy datagram socket.
func setLinkMTU(name string, mtu int) error {
	s, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(s)

	ifr, err := unix.NewIfreq(name)
	if err != nil {
		return err
	}
	ifr.SetUint32(uint32(mtu))
	return unix.IoctlIfreq(s, unix.SIOCSIFMTU, ifr)
}

// Compile-time assertion.
var _ Device = (*linuxDevice)(nil)
