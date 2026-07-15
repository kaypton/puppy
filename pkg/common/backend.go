package common

import (
	"context"
	"io"
	"net"
	"strconv"
)

// Target describes the destination a backend connects to on behalf of a client.
type Target struct {
	// Network is the transport network ("tcp", "udp"). When empty, Net()
	// defaults to "tcp".
	Network string
	// Protocol is the detected application protocol. An empty value is treated
	// as ProtocolUnknown.
	Protocol Protocol
	// Host is the destination hostname or IP address literal.
	Host string
	// Port is the destination port.
	Port uint16
}

// Protocol identifies an application protocol observed by a frontend.
type Protocol string

const (
	// ProtocolAny is a capability wildcard and must not be used as a detected
	// Target protocol.
	ProtocolAny Protocol = "*"
	// ProtocolUnknown means the frontend could not identify the application
	// protocol.
	ProtocolUnknown Protocol = "unknown"
	// ProtocolHTTP identifies HTTP/1 or the HTTP/2 client connection preface.
	ProtocolHTTP Protocol = "http"
	// ProtocolTLS identifies a TLS client handshake.
	ProtocolTLS Protocol = "tls"
	// ProtocolDNS identifies DNS carried over TCP.
	ProtocolDNS Protocol = "dns"
)

// Capability describes one network/application-protocol combination accepted
// by a Backend. ProtocolAny matches every application protocol.
type Capability struct {
	Network  string
	Protocol Protocol
}

// SupportsNetwork reports whether capabilities contain the network.
func SupportsNetwork(capabilities []Capability, network string) bool {
	for _, capability := range capabilities {
		if capability.Network == network {
			return true
		}
	}
	return false
}

// SupportsAnyProtocol reports whether capabilities contain a wildcard entry
// for the network.
func SupportsAnyProtocol(capabilities []Capability, network string) bool {
	for _, capability := range capabilities {
		if capability.Network == network && capability.Protocol == ProtocolAny {
			return true
		}
	}
	return false
}

// Supports reports whether capabilities accept the target's network and
// application protocol.
func Supports(capabilities []Capability, target Target) bool {
	protocol := target.Protocol
	if protocol == "" {
		protocol = ProtocolUnknown
	}
	for _, capability := range capabilities {
		if capability.Network == target.Net() && (capability.Protocol == ProtocolAny || capability.Protocol == protocol) {
			return true
		}
	}
	return false
}

// Dialer establishes the transport connection used by a Backend. Frontends
// provide the dialer so they can control which network path backend traffic
// takes (for example, bypassing a TUN interface).
type Dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// DialFunc adapts a function to Dialer.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// DialContext calls f.
func (f DialFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}

// SystemDialer returns a dialer that uses the host's normal routing table.
func SystemDialer() Dialer { return &net.Dialer{} }

// Address returns the "host:port" form suitable for net.Dial and HTTP CONNECT.
func (t Target) Address() string {
	return net.JoinHostPort(t.Host, strconv.Itoa(int(t.Port)))
}

// Net returns the network, defaulting to "tcp" when empty.
func (t Target) Net() string {
	if t.Network == "" {
		return "tcp"
	}
	return t.Network
}

// Backend dials a tunneled connection to a Target using the frontend-provided
// transport dialer. Implementations live in pkg/adapter/* (direct,
// httpproxy, socksproxy, ...). The returned io.ReadWriteCloser is handed to a
// ShimServer as its Backend.
type Backend interface {
	// Capabilities returns the network and application protocol combinations
	// that the backend can accept.
	Capabilities() []Capability
	Dial(ctx context.Context, target Target, dialer Dialer) (io.ReadWriteCloser, error)
}
