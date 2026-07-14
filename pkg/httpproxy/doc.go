// Package httpproxy implements an HTTP CONNECT proxy with optional TLS and
// username/password authentication. It is designed as a frontend for pkg/shim:
// after the optional TLS handshake and a successful CONNECT handshake, the
// client connection and a backend connection (obtained via a common.Backend)
// are handed to a ShimServer for bidirectional byte piping.
//
// The backend is configurable: callers supply a common.Backend implementation
// from pkg/adapter/* (e.g. direct for direct connections, httpproxy for
// chaining through an upstream HTTP proxy).
package httpproxy
