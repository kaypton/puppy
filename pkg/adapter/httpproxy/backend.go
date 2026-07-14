// Package httpproxy implements a common.Backend that forwards traffic to a
// target through an upstream HTTP proxy using the CONNECT method (proxy
// chaining). It is the outbound counterpart to pkg/httpproxy's inbound
// frontend.
package httpproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
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
	// TLS enables TLS to the upstream proxy when true. The TCP connection to
	// ProxyAddress is wrapped with tls.Client before issuing CONNECT.
	TLS bool
	// TLSCAFile is a PEM file of additional CA certificates used to verify the
	// upstream proxy's certificate. When empty, the system roots are used.
	// Ignored when TLSConfig is non-nil.
	TLSCAFile string
	// TLSServerName overrides the TLS SNI and verification name. When empty,
	// the host portion of ProxyAddress is used. Ignored when TLSConfig is
	// non-nil.
	TLSServerName string
	// TLSInsecureSkipVerify disables certificate verification. Mutually
	// exclusive with TLSCAFile. Ignored when TLSConfig is non-nil.
	TLSInsecureSkipVerify bool
	// TLSConfig, when non-nil, is used as-is for the TLS client connection to
	// the upstream proxy. When nil and TLS is true, a *tls.Config is built
	// from the fields above. Mainly intended for test injection.
	TLSConfig *tls.Config
	// Dial reaches the upstream proxy. When nil, a net.Dialer is used.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// Logger receives structured log events. When nil, slog.Default() is used.
	Logger *slog.Logger
}

// Backend chains connections through an upstream HTTP proxy via CONNECT.
type Backend struct {
	config    BackendConfiguration
	logger    *slog.Logger
	dial      func(ctx context.Context, network, addr string) (net.Conn, error)
	tlsConfig *tls.Config
}

// NewBackend validates the configuration and returns a chaining backend.
func NewBackend(config BackendConfiguration) (*Backend, error) {
	if config.ProxyAddress == "" {
		return nil, errors.New("httpproxy: proxy address is required")
	}
	if (config.Username == "") != (config.Password == "") {
		return nil, errors.New("httpproxy: username and password must both be set or both be empty")
	}
	if !config.TLS {
		if config.TLSCAFile != "" || config.TLSServerName != "" || config.TLSInsecureSkipVerify {
			return nil, errors.New("httpproxy: tls_ca_file, tls_server_name, and tls_insecure_skip_verify require tls = true")
		}
	}
	if config.TLSInsecureSkipVerify && config.TLSCAFile != "" {
		return nil, errors.New("httpproxy: tls_insecure_skip_verify and tls_ca_file are mutually exclusive")
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
	tlsConfig := config.TLSConfig
	if tlsConfig == nil && config.TLS {
		built, err := buildClientTLSConfig(config.ProxyAddress, config.TLSServerName, config.TLSCAFile, config.TLSInsecureSkipVerify)
		if err != nil {
			return nil, err
		}
		tlsConfig = built
	}
	return &Backend{config: config, logger: logger, dial: dial, tlsConfig: tlsConfig}, nil
}

// buildClientTLSConfig constructs a *tls.Config for the upstream proxy
// connection.
func buildClientTLSConfig(proxyAddress, serverName, caFile string, insecure bool) (*tls.Config, error) {
	host := serverName
	if host == "" {
		var err error
		host, _, err = net.SplitHostPort(proxyAddress)
		if err != nil {
			return nil, fmt.Errorf("httpproxy: parse proxy address for TLS: %w", err)
		}
	}
	cfg := &tls.Config{
		ServerName:         host,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: insecure,
	}
	if caFile != "" {
		roots, err := x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("httpproxy: read TLS CA file: %w", err)
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("httpproxy: no certificates parsed from %s", caFile)
		}
		cfg.RootCAs = roots
	}
	return cfg, nil
}

// Dial connects to the upstream proxy, issues a CONNECT to target, and returns
// the tunneled connection.
func (b *Backend) Dial(ctx context.Context, target common.Target) (io.ReadWriteCloser, error) {
	conn, err := b.dial(ctx, "tcp", b.config.ProxyAddress)
	if err != nil {
		return nil, fmt.Errorf("httpproxy: dial upstream proxy: %w", err)
	}

	if b.tlsConfig != nil {
		tlsConn := tls.Client(conn, b.tlsConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("httpproxy: TLS handshake with upstream proxy: %w", err)
		}
		conn = tlsConn
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
