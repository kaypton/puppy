// Package httpproxy implements a common.Backend that forwards traffic to a
// target through an upstream HTTP proxy using the CONNECT method (proxy
// chaining). It is the outbound counterpart to pkg/httpproxy's inbound
// frontend.
package httpproxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/puppy/pkg/common"
)

// BackendConfiguration configures an HTTP CONNECT chaining backend.
type BackendConfiguration struct {
	// ProxyAddress is the upstream HTTP proxy address (host:port).
	ProxyAddress string
	// Username and Password authenticate to the upstream proxy via HTTP Basic
	// Proxy-Authorization when both are non-empty.
	Username string
	Password string
	// Dial reaches the upstream proxy. When nil, a net.Dialer is used.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// Logger receives structured log events. When nil, slog.Default() is used.
	Logger *slog.Logger
}

// Backend chains connections through an upstream HTTP proxy via CONNECT.
type Backend struct {
	config BackendConfiguration
	logger *slog.Logger
	dial   func(ctx context.Context, network, addr string) (net.Conn, error)
}

// NewBackend validates the configuration and returns a chaining backend.
func NewBackend(config BackendConfiguration) (*Backend, error) {
	if config.ProxyAddress == "" {
		return nil, errors.New("httpproxy: proxy address is required")
	}
	if (config.Username == "") != (config.Password == "") {
		return nil, errors.New("httpproxy: username and password must both be set or both be empty")
	}
	dial := config.Dial
	if dial == nil {
		var d net.Dialer
		dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return d.DialContext(ctx, network, addr)
		}
	}
	logger := config.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Backend{config: config, logger: logger, dial: dial}, nil
}

// Dial connects to the upstream proxy, issues a CONNECT to target, and returns
// the tunneled connection.
func (b *Backend) Dial(ctx context.Context, target common.Target) (io.ReadWriteCloser, error) {
	conn, err := b.dial(ctx, "tcp", b.config.ProxyAddress)
	if err != nil {
		return nil, fmt.Errorf("httpproxy: dial upstream proxy: %w", err)
	}

	targetAddr := target.Address()
	var req strings.Builder
	fmt.Fprintf(&req, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", targetAddr, targetAddr)
	if b.config.Username != "" {
		creds := base64.StdEncoding.EncodeToString([]byte(b.config.Username + ":" + b.config.Password))
		fmt.Fprintf(&req, "Proxy-Authorization: Basic %s\r\n", creds)
	}
	req.WriteString("\r\n")

	if _, err := io.WriteString(conn, req.String()); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("httpproxy: write CONNECT: %w", err)
	}

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("httpproxy: read CONNECT response: %w", err)
	}
	_ = resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		_ = conn.Close()
		return nil, fmt.Errorf("httpproxy: upstream proxy returned %s", resp.Status)
	}

	return &bufferedConn{r: reader, Conn: conn}, nil
}

// bufferedConn preserves bytes that bufio.Reader pulled past the CONNECT
// response header, in case the upstream proxy sent early tunnel data.
type bufferedConn struct {
	r *bufio.Reader
	net.Conn
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.r.Read(p) }

// Compile-time assertion that Backend implements common.Backend.
var _ common.Backend = (*Backend)(nil)
