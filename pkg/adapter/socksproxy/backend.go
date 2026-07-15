// Package socksproxy implements a common.Backend that forwards traffic to a
// target through an upstream SOCKS5 proxy (proxy chaining). It is the outbound
// counterpart to pkg/httpproxy's inbound frontend for SOCKS5 upstreams.
package socksproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strconv"

	"github.com/puppy/pkg/common"
)

// SOCKS5 protocol constants (RFC 1928 and RFC 1929).
const (
	socks5Version byte = 0x05

	socks5MethodNoAuth           byte = 0x00
	socks5MethodUsernamePassword byte = 0x02
	socks5MethodNoAcceptable     byte = 0xFF

	socks5AuthVersion byte = 0x01

	socks5CmdConnect byte = 0x01

	socks5AtypIPv4   byte = 0x01
	socks5AtypDomain byte = 0x03
	socks5AtypIPv6   byte = 0x04

	socks5RepSuccess byte = 0x00
)

// BackendConfiguration configures a SOCKS5 chaining backend.
type BackendConfiguration struct {
	// ProxyAddress is the upstream SOCKS5 proxy address (host:port).
	ProxyAddress string
	// Username and Password authenticate to the upstream proxy via RFC 1929
	// username/password sub-negotiation when both are non-empty. When both are
	// empty, the backend negotiates no authentication.
	Username string
	Password string
	// TLS enables TLS to the upstream proxy when true. The TCP connection to
	// ProxyAddress is wrapped with tls.Client before issuing the SOCKS5
	// handshake.
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
	// Logger receives structured log events. When nil, slog.Default() is used.
	Logger *slog.Logger
}

// Backend chains connections through an upstream SOCKS5 proxy via CONNECT.
type Backend struct {
	config    BackendConfiguration
	logger    *slog.Logger
	tlsConfig *tls.Config
}

// NewBackend validates the configuration and returns a chaining backend.
func NewBackend(config BackendConfiguration) (*Backend, error) {
	if config.ProxyAddress == "" {
		return nil, errors.New("socksproxy: proxy address is required")
	}
	if (config.Username == "") != (config.Password == "") {
		return nil, errors.New("socksproxy: username and password must both be set or both be empty")
	}
	if !config.TLS {
		if config.TLSCAFile != "" || config.TLSServerName != "" || config.TLSInsecureSkipVerify {
			return nil, errors.New("socksproxy: tls_ca_file, tls_server_name, and tls_insecure_skip_verify require tls = true")
		}
	}
	if config.TLSInsecureSkipVerify && config.TLSCAFile != "" {
		return nil, errors.New("socksproxy: tls_insecure_skip_verify and tls_ca_file are mutually exclusive")
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
	return &Backend{config: config, logger: logger, tlsConfig: tlsConfig}, nil
}

// Capabilities reports that SOCKS5 CONNECT can tunnel any TCP application
// protocol, but cannot carry UDP.
func (b *Backend) Capabilities() []common.Capability {
	return []common.Capability{{Network: "tcp", Protocol: common.ProtocolAny}}
}

// buildClientTLSConfig constructs a *tls.Config for the upstream proxy
// connection.
func buildClientTLSConfig(proxyAddress, serverName, caFile string, insecure bool) (*tls.Config, error) {
	host := serverName
	if host == "" {
		var err error
		host, _, err = net.SplitHostPort(proxyAddress)
		if err != nil {
			return nil, fmt.Errorf("socksproxy: parse proxy address for TLS: %w", err)
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
			return nil, fmt.Errorf("socksproxy: read TLS CA file: %w", err)
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("socksproxy: no certificates parsed from %s", caFile)
		}
		cfg.RootCAs = roots
	}
	return cfg, nil
}

// Dial connects to the upstream SOCKS5 proxy, negotiates authentication,
// issues a CONNECT to target, and returns the tunneled connection.
func (b *Backend) Dial(ctx context.Context, target common.Target, dialer common.Dialer) (io.ReadWriteCloser, error) {
	if dialer == nil {
		dialer = common.SystemDialer()
	}
	conn, err := dialer.DialContext(ctx, "tcp", b.config.ProxyAddress)
	if err != nil {
		return nil, fmt.Errorf("socksproxy: dial upstream proxy: %w", err)
	}

	if b.tlsConfig != nil {
		tlsConn := tls.Client(conn, b.tlsConfig)
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("socksproxy: TLS handshake with upstream proxy: %w", err)
		}
		conn = tlsConn
	}

	reader := bufio.NewReader(conn)

	if err := b.negotiateMethod(reader, conn); err != nil {
		_ = conn.Close()
		return nil, err
	}

	if err := socks5Connect(reader, conn, target); err != nil {
		_ = conn.Close()
		return nil, err
	}

	return &bufferedConn{r: reader, Conn: conn}, nil
}

// negotiateMethod performs the SOCKS5 method selection handshake. When the
// backend has credentials it offers username/password auth alongside
// no-auth; otherwise it offers only no-auth.
func (b *Backend) negotiateMethod(reader *bufio.Reader, conn net.Conn) error {
	methods := []byte{socks5MethodNoAuth}
	if b.config.Username != "" {
		methods = []byte{socks5MethodNoAuth, socks5MethodUsernamePassword}
	}
	req := make([]byte, 0, 2+len(methods))
	req = append(req, socks5Version, byte(len(methods)))
	req = append(req, methods...)
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("socksproxy: write method negotiation: %w", err)
	}

	var header [2]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return fmt.Errorf("socksproxy: read method negotiation: %w", err)
	}
	if header[0] != socks5Version {
		return fmt.Errorf("socksproxy: unexpected SOCKS version 0x%02x during method negotiation", header[0])
	}
	method := header[1]
	switch method {
	case socks5MethodNoAuth:
		return nil
	case socks5MethodUsernamePassword:
		return b.usernamePasswordAuth(reader, conn)
	case socks5MethodNoAcceptable:
		return errors.New("socksproxy: upstream proxy rejected connection (no acceptable method)")
	default:
		return fmt.Errorf("socksproxy: upstream proxy selected unsupported method 0x%02x", method)
	}
}

// usernamePasswordAuth performs the RFC 1929 username/password sub-negotiation.
func (b *Backend) usernamePasswordAuth(reader *bufio.Reader, conn net.Conn) error {
	if len(b.config.Username) > 255 || len(b.config.Password) > 255 {
		return errors.New("socksproxy: username and password must each be at most 255 bytes")
	}
	req := make([]byte, 0, 3+len(b.config.Username)+len(b.config.Password))
	req = append(req, socks5AuthVersion, byte(len(b.config.Username)))
	req = append(req, b.config.Username...)
	req = append(req, byte(len(b.config.Password)))
	req = append(req, b.config.Password...)
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("socksproxy: write username/password auth: %w", err)
	}

	var resp [2]byte
	if _, err := io.ReadFull(reader, resp[:]); err != nil {
		return fmt.Errorf("socksproxy: read username/password auth: %w", err)
	}
	if resp[0] != socks5AuthVersion {
		return fmt.Errorf("socksproxy: unexpected auth version 0x%02x", resp[0])
	}
	if resp[1] != 0x00 {
		return errors.New("socksproxy: upstream proxy rejected credentials")
	}
	return nil
}

// socks5Connect issues a SOCKS5 CONNECT request for target and consumes the
// reply, leaving the connection ready for tunnel data.
func socks5Connect(reader *bufio.Reader, conn net.Conn, target common.Target) error {
	req, err := encodeSOCKS5Request(target)
	if err != nil {
		return err
	}
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("socksproxy: write CONNECT request: %w", err)
	}

	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return fmt.Errorf("socksproxy: read CONNECT response: %w", err)
	}
	if header[0] != socks5Version {
		return fmt.Errorf("socksproxy: unexpected SOCKS version 0x%02x in CONNECT response", header[0])
	}
	if header[1] != socks5RepSuccess {
		return fmt.Errorf("socksproxy: upstream proxy returned %s", socks5ReplyText(header[1]))
	}

	// Skip BND.ADDR based on the address type.
	switch header[3] {
	case socks5AtypIPv4:
		var addr [4]byte
		if _, err := io.ReadFull(reader, addr[:]); err != nil {
			return fmt.Errorf("socksproxy: read CONNECT bind address: %w", err)
		}
	case socks5AtypIPv6:
		var addr [16]byte
		if _, err := io.ReadFull(reader, addr[:]); err != nil {
			return fmt.Errorf("socksproxy: read CONNECT bind address: %w", err)
		}
	case socks5AtypDomain:
		var lenByte [1]byte
		if _, err := io.ReadFull(reader, lenByte[:]); err != nil {
			return fmt.Errorf("socksproxy: read CONNECT bind address length: %w", err)
		}
		domain := make([]byte, lenByte[0])
		if _, err := io.ReadFull(reader, domain); err != nil {
			return fmt.Errorf("socksproxy: read CONNECT bind address: %w", err)
		}
	default:
		return fmt.Errorf("socksproxy: unknown address type 0x%02x in CONNECT response", header[3])
	}

	var port [2]byte
	if _, err := io.ReadFull(reader, port[:]); err != nil {
		return fmt.Errorf("socksproxy: read CONNECT bind port: %w", err)
	}
	return nil
}

// encodeSOCKS5Request builds the SOCKS5 CONNECT request bytes for target.
func encodeSOCKS5Request(target common.Target) ([]byte, error) {
	host := target.Host
	port := target.Port
	if host == "" {
		return nil, errors.New("socksproxy: target host is required")
	}
	if port == 0 {
		return nil, errors.New("socksproxy: target port is required")
	}

	req := []byte{socks5Version, socks5CmdConnect, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req = append(req, socks5AtypIPv4)
			req = append(req, v4...)
		} else {
			req = append(req, socks5AtypIPv6)
			req = append(req, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return nil, fmt.Errorf("socksproxy: target domain %q exceeds 255 bytes", host)
		}
		req = append(req, socks5AtypDomain, byte(len(host)))
		req = append(req, host...)
	}
	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], port)
	req = append(req, portBytes[:]...)
	return req, nil
}

// socks5ReplyText maps a SOCKS5 reply code to a human-readable description.
func socks5ReplyText(rep byte) string {
	switch rep {
	case 0x00:
		return "succeeded"
	case 0x01:
		return "general SOCKS server failure"
	case 0x02:
		return "connection not allowed by ruleset"
	case 0x03:
		return "network unreachable"
	case 0x04:
		return "host unreachable"
	case 0x05:
		return "connection refused"
	case 0x06:
		return "TTL expired"
	case 0x07:
		return "command not supported"
	case 0x08:
		return "address type not supported"
	default:
		return "unknown error (0x" + strconv.FormatUint(uint64(rep), 16) + ")"
	}
}

// bufferedConn preserves bytes that bufio.Reader pulled past the SOCKS5
// handshake, in case the upstream proxy sent early tunnel data.
type bufferedConn struct {
	r *bufio.Reader
	net.Conn
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.r.Read(p) }

// Compile-time assertion that Backend implements common.Backend.
var _ common.Backend = (*Backend)(nil)
