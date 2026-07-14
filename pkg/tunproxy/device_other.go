//go:build !darwin && !linux

package tunproxy

import "fmt"

// openDevice is the unsupported-platform stub.
func openDevice(name string, mtu uint32) (Device, error) {
	return nil, fmt.Errorf("tunproxy: TUN device not supported on this platform")
}
