package tunproxy

import (
	"errors"
	"io"
)

// Device is the platform-agnostic TUN device abstraction used by tunproxy.
// Read and Write operate on raw IP packets (no Layer-2 framing, no packet
// information header).
type Device interface {
	// Name returns the OS-assigned interface name (e.g. "utun4", "tun0").
	Name() string
	// MTU returns the device maximum transmission unit in bytes.
	MTU() uint32
	// Read pulls the next inbound IP packet from the device into p.
	Read(p []byte) (int, error)
	// Write pushes an outbound IP packet to the device.
	Write(p []byte) (int, error)
	// Close releases the device. Subsequent Read/Write return an error.
	io.Closer
}

// ErrDeviceClosed is returned by Read/Write after Close has been called.
var ErrDeviceClosed = errors.New("tunproxy: device closed")

// defaultMTU is used when the configuration does not specify an MTU.
const defaultMTU uint32 = 1500
