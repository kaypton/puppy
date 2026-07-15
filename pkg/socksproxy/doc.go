// Package socksproxy implements a SOCKS5 proxy frontend (RFC 1928) with optional
// TLS transport and RFC 1929 username/password authentication. It is designed
// as a frontend for pkg/shim: after the optional TLS handshake and a successful
// SOCKS5 CONNECT handshake, the client connection and a backend connection
// (obtained via a common.Backend) are handed to a ShimServer for bidirectional
// byte piping.
//
// Only the CONNECT command is supported. The backend is configurable: callers
// supply a common.Backend implementation from pkg/adapter/* (e.g. direct for
// direct connections, httpproxy for chaining through an upstream HTTP proxy,
// socksproxy for chaining through an upstream SOCKS5 proxy).
package socksproxy
