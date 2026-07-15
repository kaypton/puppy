// Package tunproxy implements a TUN-mode proxy frontend. It opens a virtual
// TUN device, feeds IP packets into a userspace network stack (gVisor
// netstack), and forwards accepted TCP/UDP connections to a common.Backend
// (direct, upstream HTTP proxy, ...) via pkg/shim.
//
// Supported platforms: macOS (utun) and Linux (/dev/net/tun). Both require
// elevated privileges to create the device and modify routing tables. In
// automatic routing mode, backend sockets are pinned to the physical interface
// that owned the default route before the TUN routes were installed.
package tunproxy
