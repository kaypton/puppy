package socksproxy

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/puppy/pkg/adapter/direct"
	"github.com/puppy/pkg/common"
)

// errorBackend is a common.Backend whose Dial always returns err.
type errorBackend struct{ err error }

func (b *errorBackend) Capabilities() []common.Capability {
	return []common.Capability{{Network: "tcp", Protocol: common.ProtocolAny}}
}

func (b *errorBackend) Dial(ctx context.Context, target common.Target, dialer common.Dialer) (io.ReadWriteCloser, error) {
	return nil, b.err
}

type udpOnlyBackend struct{ errorBackend }

func (b *udpOnlyBackend) Capabilities() []common.Capability {
	return []common.Capability{{Network: "udp", Protocol: common.ProtocolAny}}
}

func testCertificateFiles(t *testing.T) (certFile, keyFile string, roots *x509.CertPool) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Puppy SOCKS Proxy Test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	dir := t.TempDir()
	certFile = filepath.Join(dir, "proxy-cert.pem")
	keyFile = filepath.Join(dir, "proxy-key.pem")
	if err := os.WriteFile(certFile, certificatePEM, 0o644); err != nil {
		t.Fatalf("write certificate: %v", err)
	}
	if err := os.WriteFile(keyFile, privateKeyPEM, 0o600); err != nil {
		t.Fatalf("write private key: %v", err)
	}
	roots = x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certificatePEM) {
		t.Fatal("append test certificate")
	}
	return certFile, keyFile, roots
}

func dialTLSSocksProxy(t *testing.T, proxyAddr string, roots *x509.CertPool) *tls.Conn {
	t.Helper()
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", proxyAddr, &tls.Config{
		RootCAs:    roots,
		ServerName: "localhost",
	})
	if err != nil {
		t.Fatalf("dial TLS SOCKS proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// startServer launches a Server on a random localhost port and returns the
// actual address plus a cancel function that stops the server. The Backend
// field is set to backend. runErr receives the value returned by Run.
func startServer(t *testing.T, cfg ServerConfiguration, backend common.Backend) (addr string, cancel context.CancelFunc, runErr <-chan error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	_ = ln.Close()

	cfg.ListenAddress = host
	cfg.ListenPort = uint16(port)
	cfg.Backend = backend
	cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))

	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- s.Run(ctx) }()

	addr = net.JoinHostPort(host, portStr)
	deadline := time.Now().Add(2 * time.Second)
	for {
		c, derr := net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if derr == nil {
			_ = c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not start: %v", derr)
		}
	}

	t.Cleanup(func() {
		cancel()
		<-errCh
	})

	return addr, cancel, errCh
}

// echoUpstream is a test upstream that mirrors bytes back to the writer.
func echoUpstream(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	return ln.Addr().String()
}

// socksConnect performs a full SOCKS5 CONNECT handshake through the proxy at
// proxyAddr (no auth) and returns the tunneled connection.
func socksConnect(t *testing.T, proxyAddr, targetHost string, targetPort uint16) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := socksHandshake(conn, "", "", targetHost, targetPort); err != nil {
		t.Fatalf("socks handshake: %v", err)
	}
	return conn
}

// socksHandshake performs the SOCKS5 method negotiation, optional auth, and
// CONNECT request on conn. Returns an error if any step fails or the reply
// is not success.
func socksHandshake(conn net.Conn, username, password, targetHost string, targetPort uint16) error {
	// Method negotiation.
	methods := []byte{common.SOCKS5MethodNoAuth}
	if username != "" {
		methods = []byte{common.SOCKS5MethodUsernamePassword}
	}
	if _, err := conn.Write(append([]byte{common.SOCKS5Version, byte(len(methods))}, methods...)); err != nil {
		return err
	}
	var sel [2]byte
	if _, err := io.ReadFull(conn, sel[:]); err != nil {
		return err
	}
	if sel[1] == common.SOCKS5MethodNoAcceptable {
		return errors.New("no acceptable method")
	}
	if sel[1] == common.SOCKS5MethodUsernamePassword {
		creds := []byte{common.SOCKS5AuthVersion, byte(len(username))}
		creds = append(creds, username...)
		creds = append(creds, byte(len(password)))
		creds = append(creds, password...)
		if _, err := conn.Write(creds); err != nil {
			return err
		}
		var authResp [2]byte
		if _, err := io.ReadFull(conn, authResp[:]); err != nil {
			return err
		}
		if authResp[1] != 0x00 {
			return errors.New("auth rejected")
		}
	}

	// CONNECT request.
	req := []byte{common.SOCKS5Version, common.SOCKS5CmdConnect, 0x00}
	if ip := net.ParseIP(targetHost); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req = append(req, common.SOCKS5AtypIPv4)
			req = append(req, v4...)
		} else {
			req = append(req, common.SOCKS5AtypIPv6)
			req = append(req, ip.To16()...)
		}
	} else {
		req = append(req, common.SOCKS5AtypDomain, byte(len(targetHost)))
		req = append(req, targetHost...)
	}
	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], targetPort)
	req = append(req, portBytes[:]...)
	if _, err := conn.Write(req); err != nil {
		return err
	}

	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return err
	}
	if header[1] != common.SOCKS5RepSuccess {
		return fmt.Errorf("connect reply REP=0x%02x (%s)", header[1], common.SOCKS5ReplyText(header[1]))
	}
	if _, _, err := common.ReadSOCKS5Address(conn, header[3]); err != nil {
		return err
	}
	return nil
}

func TestNewServer_Validation(t *testing.T) {
	validBackend := direct.NewBackend()
	cases := []struct {
		name    string
		cfg     ServerConfiguration
		wantErr string
	}{
		{"missing address", ServerConfiguration{ListenPort: 1, Backend: validBackend}, "listen address"},
		{"missing port", ServerConfiguration{ListenAddress: "127.0.0.1", Backend: validBackend}, "listen port"},
		{"missing backend", ServerConfiguration{ListenAddress: "127.0.0.1", ListenPort: 1}, "backend is required"},
		{"backend lacks TCP unknown", ServerConfiguration{ListenAddress: "127.0.0.1", ListenPort: 1, Backend: &udpOnlyBackend{}}, "backend must support tcp"},
		{"certificate only", ServerConfiguration{ListenAddress: "127.0.0.1", ListenPort: 1, Backend: validBackend, TLSCertFile: "proxy-cert.pem"}, "certificate and key files"},
		{"key only", ServerConfiguration{ListenAddress: "127.0.0.1", ListenPort: 1, Backend: validBackend, TLSKeyFile: "proxy-key.pem"}, "certificate and key files"},
		{"username only", ServerConfiguration{ListenAddress: "127.0.0.1", ListenPort: 1, Backend: validBackend, Username: "u"}, "username and password"},
		{"password only", ServerConfiguration{ListenAddress: "127.0.0.1", ListenPort: 1, Backend: validBackend, Password: "p"}, "username and password"},
		{"valid open", ServerConfiguration{ListenAddress: "127.0.0.1", ListenPort: 1, Backend: validBackend}, ""},
		{"valid authed", ServerConfiguration{ListenAddress: "127.0.0.1", ListenPort: 1, Backend: validBackend, Username: "u", Password: "p"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewServer(tc.cfg)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %q, want substring %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestNewServer_TLSConfiguration(t *testing.T) {
	certFile, keyFile, _ := testCertificateFiles(t)
	s, err := NewServer(ServerConfiguration{
		ListenAddress: "127.0.0.1",
		ListenPort:    1080,
		TLSCertFile:   certFile,
		TLSKeyFile:    keyFile,
		Backend:       direct.NewBackend(),
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if s.tlsConfig == nil {
		t.Fatal("TLS configuration was not created")
	}
	if s.tlsConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("minimum TLS version = %x, want TLS 1.2", s.tlsConfig.MinVersion)
	}
	if len(s.tlsConfig.NextProtos) != 0 {
		t.Fatalf("ALPN protocols = %v, want none (SOCKS5 has no negotiated protocol)", s.tlsConfig.NextProtos)
	}

	_, err = NewServer(ServerConfiguration{
		ListenAddress: "127.0.0.1",
		ListenPort:    1080,
		TLSCertFile:   filepath.Join(t.TempDir(), "missing-cert.pem"),
		TLSKeyFile:    keyFile,
		Backend:       direct.NewBackend(),
	})
	if err == nil || !strings.Contains(err.Error(), "load TLS certificate and key") {
		t.Fatalf("missing certificate error = %v", err)
	}
}

func TestNewServer_PreservesShimBufferSize(t *testing.T) {
	s, err := NewServer(ServerConfiguration{
		ListenAddress:  "127.0.0.1",
		ListenPort:     1080,
		Backend:        direct.NewBackend(),
		ShimBufferSize: 64 * 1024,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if got := s.config.ShimBufferSize; got != 64*1024 {
		t.Fatalf("ShimBufferSize = %d, want %d", got, 64*1024)
	}
}

func TestServer_OpenProxyTunnel(t *testing.T) {
	upstreamAddr := echoUpstream(t)
	proxyAddr, _, _ := startServer(t, ServerConfiguration{}, direct.NewBackend())

	host, portStr, _ := net.SplitHostPort(upstreamAddr)
	port, _ := strconv.Atoi(portStr)
	conn := socksConnect(t, proxyAddr, host, uint16(port))
	msg := []byte("hello-tunnel")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != string(msg) {
		t.Fatalf("echo = %q, want %q", got, msg)
	}
}

func TestServer_AuthedProxyTunnel(t *testing.T) {
	upstreamAddr := echoUpstream(t)
	cfg := ServerConfiguration{Username: "alice", Password: "secret"}
	proxyAddr, _, _ := startServer(t, cfg, direct.NewBackend())

	host, portStr, _ := net.SplitHostPort(upstreamAddr)
	port, _ := strconv.Atoi(portStr)

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := socksHandshake(conn, "alice", "secret", host, uint16(port)); err != nil {
		t.Fatalf("socks handshake: %v", err)
	}
	msg := []byte("authed-tunnel")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != string(msg) {
		t.Fatalf("echo = %q, want %q", got, msg)
	}
}

func TestServer_AuthedProxyRejectsWrongCreds(t *testing.T) {
	upstreamAddr := echoUpstream(t)
	cfg := ServerConfiguration{Username: "alice", Password: "secret"}
	proxyAddr, _, _ := startServer(t, cfg, direct.NewBackend())

	host, portStr, _ := net.SplitHostPort(upstreamAddr)
	port, _ := strconv.Atoi(portStr)

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	err = socksHandshake(conn, "alice", "wrong", host, uint16(port))
	if err == nil || !strings.Contains(err.Error(), "auth rejected") {
		t.Fatalf("error = %v, want 'auth rejected'", err)
	}
}

func TestServer_TLSProxyTunnel(t *testing.T) {
	upstreamAddr := echoUpstream(t)
	certFile, keyFile, roots := testCertificateFiles(t)
	proxyAddr, _, _ := startServer(t, ServerConfiguration{
		TLSCertFile: certFile,
		TLSKeyFile:  keyFile,
	}, direct.NewBackend())

	conn := dialTLSSocksProxy(t, proxyAddr, roots)
	host, portStr, _ := net.SplitHostPort(upstreamAddr)
	port, _ := strconv.Atoi(portStr)
	if err := socksHandshake(conn, "", "", host, uint16(port)); err != nil {
		t.Fatalf("socks handshake: %v", err)
	}

	msg := []byte("hello-over-tls-socks")
	if _, err := conn.Write(msg); err != nil {
		t.Fatalf("write tunnel data: %v", err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read tunnel data: %v", err)
	}
	if string(got) != string(msg) {
		t.Fatalf("echo = %q, want %q", got, msg)
	}
}

func TestServer_TLSRejectsPlaintext(t *testing.T) {
	certFile, keyFile, _ := testCertificateFiles(t)
	proxyAddr, _, _ := startServer(t, ServerConfiguration{
		TLSCertFile: certFile,
		TLSKeyFile:  keyFile,
	}, direct.NewBackend())

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	// Send a SOCKS5 method negotiation in plaintext; the TLS listener must not
	// produce a valid SOCKS5 reply.
	if _, err := conn.Write([]byte{common.SOCKS5Version, 1, common.SOCKS5MethodNoAuth}); err != nil {
		t.Fatalf("write plaintext: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	resp := make([]byte, 16)
	n, _ := conn.Read(resp)
	// A valid SOCKS5 reply starts with 0x05; a TLS server returns a TLS handshake.
	if n >= 1 && resp[0] == common.SOCKS5Version {
		t.Fatalf("TLS proxy returned a plaintext SOCKS5 reply: %x", resp[:n])
	}
}

func TestServer_DialFailure_RepGeneralFailure(t *testing.T) {
	proxyAddr, _, _ := startServer(t, ServerConfiguration{}, &errorBackend{err: errors.New("upstream unreachable")})

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := conn.Write([]byte{common.SOCKS5Version, 1, common.SOCKS5MethodNoAuth}); err != nil {
		t.Fatalf("write method negotiation: %v", err)
	}
	var sel [2]byte
	if _, err := io.ReadFull(conn, sel[:]); err != nil {
		t.Fatalf("read method selection: %v", err)
	}
	if _, err := conn.Write([]byte{common.SOCKS5Version, common.SOCKS5CmdConnect, 0x00, common.SOCKS5AtypDomain, 11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 0x01, 0xBB}); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if header[1] != common.SOCKS5RepGeneralFailure {
		t.Fatalf("REP = 0x%02x, want 0x01 (general failure)", header[1])
	}
}

// refusedDialer is a common.Dialer whose DialContext always returns
// ECONNREFUSED, letting us verify the frontend's REP=0x05 mapping end-to-end.
type refusedDialer struct{}

func (refusedDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return nil, syscall.ECONNREFUSED
}

// dialerBackend is a common.Backend that uses an injected dialer to connect
// directly to the target, exercising the frontend's REP mapping on dial errors.
type dialerBackend struct {
	dialer common.Dialer
}

func (b *dialerBackend) Capabilities() []common.Capability {
	return []common.Capability{{Network: "tcp", Protocol: common.ProtocolAny}}
}

func (b *dialerBackend) Dial(ctx context.Context, target common.Target, _ common.Dialer) (io.ReadWriteCloser, error) {
	d := b.dialer
	if d == nil {
		d = common.SystemDialer()
	}
	return d.DialContext(ctx, target.Net(), target.Address())
}

func TestServer_DialFailure_RepConnectionRefused(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	_ = ln.Close()

	refusedBackend := &dialerBackend{dialer: refusedDialer{}}
	s, err := NewServer(ServerConfiguration{
		ListenAddress: host,
		ListenPort:    uint16(port),
		Backend:       refusedBackend,
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- s.Run(ctx) }()
	t.Cleanup(func() { cancel(); <-errCh })

	addr := net.JoinHostPort(host, portStr)
	deadline := time.Now().Add(2 * time.Second)
	for {
		c, derr := net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if derr == nil {
			_ = c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not start: %v", derr)
		}
	}

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := conn.Write([]byte{common.SOCKS5Version, 1, common.SOCKS5MethodNoAuth}); err != nil {
		t.Fatalf("write method negotiation: %v", err)
	}
	var sel [2]byte
	if _, err := io.ReadFull(conn, sel[:]); err != nil {
		t.Fatalf("read method selection: %v", err)
	}
	if _, err := conn.Write([]byte{common.SOCKS5Version, common.SOCKS5CmdConnect, 0x00, common.SOCKS5AtypIPv4, 127, 0, 0, 1, 0x1F, 0x90}); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		t.Fatalf("read reply: %v", err)
	}
	if header[1] != common.SOCKS5RepConnectionRefused {
		t.Fatalf("REP = 0x%02x, want 0x05 (connection refused)", header[1])
	}
}

func TestServer_ContextCancel(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	_ = ln.Close()

	cfg := ServerConfiguration{
		ListenAddress: host,
		ListenPort:    uint16(port),
		Backend:       direct.NewBackend(),
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- s.Run(ctx) }()

	addr := net.JoinHostPort(host, portStr)
	deadline := time.Now().Add(2 * time.Second)
	for {
		c, derr := net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if derr == nil {
			_ = c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not start: %v", derr)
		}
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Run returned error after cancel: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}
