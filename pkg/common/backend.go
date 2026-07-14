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
	// Host is the destination hostname or IP address literal.
	Host string
	// Port is the destination port.
	Port uint16
}

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

// Backend dials a tunneled connection to a Target. Implementations live in
// pkg/adapter/* (direct, httpproxy, socksproxy, ...). The returned
// io.ReadWriteCloser is handed to a ShimServer as its Backend.
type Backend interface {
	Dial(ctx context.Context, target Target) (io.ReadWriteCloser, error)
}
