//go:build darwin

package tunproxy

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// macOS kernel control constants not exposed by golang.org/x/sys/unix.
const (
	afSystem        = 32 // AF_SYSTEM
	sysprotoControl = 2  // SYSPROTO_CONTROL
	afSysControl    = 2  // AF_SYS_CONTROL (sub-address for kernel control)
	ctlIOCGInfo     = 0xc0644e03
	utunOptIfname   = 2 // UTUN_OPT_IFNAME
	utunControlName = "com.apple.net.utun_control"
	maxKctlName     = 96
)

// ctlInfo mirrors struct ctl_info from <sys/kern_control.h>.
type ctlInfo struct {
	ID   uint32
	Name [maxKctlName]byte
}

// sockaddrCtl mirrors struct sockaddr_ctl from <sys/kern_control.h>.
type sockaddrCtl struct {
	Len      uint8
	Family   uint8
	SysAddr  uint16
	ID       uint32
	Unit     uint32
	Reserved [5]uint32
}

func (s *sockaddrCtl) sockaddr() rawSockaddrCtl {
	return rawSockaddrCtl{
		Len:      s.Len,
		Family:   s.Family,
		SysAddr:  s.SysAddr,
		ID:       s.ID,
		Unit:     s.Unit,
		Reserved: s.Reserved,
	}
}

// rawSockaddrCtl is the wire-format sockaddr_ctl used with the connect syscall.
type rawSockaddrCtl struct {
	Len      uint8
	Family   uint8
	SysAddr  uint16
	ID       uint32
	Unit     uint32
	Reserved [5]uint32
}

// darwinDevice wraps an open utun control socket.
type darwinDevice struct {
	fd   int
	name string
	mtu  uint32
}

// openDevice opens a utunN device on macOS. If name is empty or "utun" the
// kernel assigns the next free unit; "utunN" requests a specific unit.
func openDevice(name string, mtu uint32) (Device, error) {
	if mtu == 0 {
		mtu = defaultMTU
	}

	unit, err := parseUtunUnit(name)
	if err != nil {
		return nil, err
	}

	fd, err := syscall.Socket(afSystem, syscall.SOCK_DGRAM, sysprotoControl)
	if err != nil {
		return nil, fmt.Errorf("tunproxy: socket(AF_SYSTEM_CONTROL): %w", err)
	}

	var info ctlInfo
	copy(info.Name[:], utunControlName)
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(ctlIOCGInfo), uintptr(unsafe.Pointer(&info)))
	if errno != 0 {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("tunproxy: CTLIOCGINFO: %w", errno)
	}

	addr := rawSockaddrCtl{
		Len:     uint8(unsafe.Sizeof(rawSockaddrCtl{})),
		Family:  afSystem,
		SysAddr: afSysControl,
		ID:      info.ID,
		Unit:    uint32(unit),
	}
	_, _, errno = syscall.Syscall(syscall.SYS_CONNECT, uintptr(fd), uintptr(unsafe.Pointer(&addr)), uintptr(unsafe.Sizeof(addr)))
	if errno != 0 {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("tunproxy: connect utun unit %d: %w", unit, errno)
	}

	assigned, err := utunName(fd)
	if err != nil {
		_ = syscall.Close(fd)
		return nil, err
	}

	if err := setLinkMTU(assigned, int(mtu)); err != nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("tunproxy: set MTU: %w", err)
	}

	if err := syscall.SetNonblock(fd, true); err != nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("tunproxy: set nonblock: %w", err)
	}

	return &darwinDevice{fd: fd, name: assigned, mtu: mtu}, nil
}

func (d *darwinDevice) Name() string { return d.name }
func (d *darwinDevice) MTU() uint32  { return d.mtu }

func (d *darwinDevice) Read(p []byte) (int, error) {
	// utun reads prepend a 4-byte protocol family header on macOS.
	if len(p) < 4 {
		return 0, fmt.Errorf("tunproxy: read buffer too small")
	}
	n, err := syscall.Read(d.fd, p)
	if err != nil {
		if errors.Is(err, os.ErrClosed) || err == syscall.EBADF {
			return 0, ErrDeviceClosed
		}
		return 0, err
	}
	if n < 4 {
		return 0, fmt.Errorf("tunproxy: short utun read (%d bytes)", n)
	}
	// Strip the protocol family header in place.
	copy(p, p[4:n])
	return n - 4, nil
}

func (d *darwinDevice) Write(p []byte) (int, error) {
	// utun writes require a 4-byte protocol family header. AF_INET/AF_INET6
	// is chosen by inspecting the first nibble of the IP packet.
	var hdr [4]byte
	proto := syscall.AF_INET
	if len(p) > 0 && p[0]>>4 == 6 {
		proto = syscall.AF_INET6
	}
	hdr[0] = byte(proto)
	hdr[1] = byte(proto >> 8)
	hdr[2] = byte(proto >> 16)
	hdr[3] = byte(proto >> 24)

	w := make([]byte, 0, 4+len(p))
	w = append(w, hdr[:]...)
	w = append(w, p...)
	_, err := syscall.Write(d.fd, w)
	if err != nil {
		if errors.Is(err, os.ErrClosed) || err == syscall.EBADF {
			return 0, ErrDeviceClosed
		}
		return 0, err
	}
	return len(p), nil
}

func (d *darwinDevice) Close() error { return syscall.Close(d.fd) }

// utunName retrieves the interface name assigned by the kernel via getsockopt.
func utunName(fd int) (string, error) {
	buf := make([]byte, 16+1)
	oLen := len(buf)
	_, _, errno := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		uintptr(fd),
		uintptr(sysprotoControl),
		uintptr(utunOptIfname),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&oLen)),
		0,
	)
	if errno != 0 {
		return "", fmt.Errorf("tunproxy: getsockopt UTUN_OPT_IFNAME: %w", errno)
	}
	for i, c := range buf {
		if c == 0 {
			return string(buf[:i]), nil
		}
	}
	return string(buf), nil
}

// parseUtunUnit accepts "", "utun", or "utunN" and returns the unit number
// (0 means kernel-assigned).
func parseUtunUnit(name string) (int, error) {
	if name == "" || name == "utun" {
		return 0, nil
	}
	if len(name) < 4 || name[:4] != "utun" {
		return 0, fmt.Errorf("tunproxy: device name must be empty or utunN, got %q", name)
	}
	var unit int
	for _, c := range name[4:] {
		if c < '0' || c > '9' {
			return 0, fmt.Errorf("tunproxy: device name must be empty or utunN, got %q", name)
		}
		unit = unit*10 + int(c-'0')
	}
	return unit, nil
}

// ifreqMTU mirrors the ifreq layout used by SIOCSIFMTU.
type ifreqMTU struct {
	Name [16]byte
	MTU  int32
	_    [20]byte // padding to match struct ifreq size on darwin
}

// setLinkMTU sets the MTU of the named interface via SIOCSIFMTU on a routing
// socket.
func setLinkMTU(name string, mtu int) error {
	s, err := syscall.Socket(unix.AF_ROUTE, syscall.SOCK_RAW, 0)
	if err != nil {
		return err
	}
	defer syscall.Close(s)

	var ifr ifreqMTU
	copy(ifr.Name[:], name)
	ifr.MTU = int32(mtu)
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(s), uintptr(unix.SIOCSIFMTU), uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		return errno
	}
	return nil
}

// Compile-time assertion.
var _ Device = (*darwinDevice)(nil)
