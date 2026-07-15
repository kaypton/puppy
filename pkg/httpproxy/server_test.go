package httpproxy

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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
		Subject:      pkix.Name{CommonName: "Puppy HTTPS Proxy Test"},
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

func dialTLSProxy(t *testing.T, proxyAddr string, roots *x509.CertPool) *tls.Conn {
	t.Helper()
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", proxyAddr, &tls.Config{
		RootCAs:    roots,
		ServerName: "localhost",
		NextProtos: []string{"http/1.1"},
	})
	if err != nil {
		t.Fatalf("dial HTTPS proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// startServer launches a Server on a random localhost port and returns the
// actual address plus a cancel function that stops the server. The Backend
// field is set to backend. runErr receives the value returned by Run.
func startServer(t *testing.T, cfg ServerConfiguration, backend common.Backend) (addr string, cancel context.CancelFunc, runErr <-chan error) {
	t.Helper()
	// Grab a free port from the OS, then release it so Server.Run can rebind.
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

	// Wait until Run has bound the listener by retrying a dial briefly.
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
		{"unknown camouflage method", ServerConfiguration{ListenAddress: "127.0.0.1", ListenPort: 1, Backend: validBackend, CamouflageMethod: "unknown"}, "unsupported camouflage method"},
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
		ListenPort:    8080,
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
	if len(s.tlsConfig.NextProtos) != 1 || s.tlsConfig.NextProtos[0] != "http/1.1" {
		t.Fatalf("ALPN protocols = %v, want [http/1.1]", s.tlsConfig.NextProtos)
	}

	_, err = NewServer(ServerConfiguration{
		ListenAddress: "127.0.0.1",
		ListenPort:    8080,
		TLSCertFile:   filepath.Join(t.TempDir(), "missing-cert.pem"),
		TLSKeyFile:    keyFile,
		Backend:       direct.NewBackend(),
	})
	if err == nil || !strings.Contains(err.Error(), "load TLS certificate and key") {
		t.Fatalf("missing certificate error = %v", err)
	}

	invalidCert := filepath.Join(t.TempDir(), "invalid-cert.pem")
	if err := os.WriteFile(invalidCert, []byte("not a certificate"), 0o600); err != nil {
		t.Fatalf("write invalid certificate: %v", err)
	}
	_, err = NewServer(ServerConfiguration{
		ListenAddress: "127.0.0.1",
		ListenPort:    8080,
		TLSCertFile:   invalidCert,
		TLSKeyFile:    keyFile,
		Backend:       direct.NewBackend(),
	})
	if err == nil || !strings.Contains(err.Error(), "load TLS certificate and key") {
		t.Fatalf("invalid certificate error = %v", err)
	}

	_, otherKeyFile, _ := testCertificateFiles(t)
	_, err = NewServer(ServerConfiguration{
		ListenAddress: "127.0.0.1",
		ListenPort:    8080,
		TLSCertFile:   certFile,
		TLSKeyFile:    otherKeyFile,
		Backend:       direct.NewBackend(),
	})
	if err == nil || !strings.Contains(err.Error(), "load TLS certificate and key") {
		t.Fatalf("mismatched certificate and key error = %v", err)
	}
}

func TestNewServer_DefaultsCamouflageMethod(t *testing.T) {
	s, err := NewServer(ServerConfiguration{
		ListenAddress: "127.0.0.1",
		ListenPort:    8080,
		Backend:       direct.NewBackend(),
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if s.config.CamouflageMethod != Return404 {
		t.Fatalf("CamouflageMethod = %q, want %q", s.config.CamouflageMethod, Return404)
	}
}

func TestNewServer_PreservesShimBufferSize(t *testing.T) {
	s, err := NewServer(ServerConfiguration{
		ListenAddress:  "127.0.0.1",
		ListenPort:     8080,
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

// dialThroughProxy performs a CONNECT handshake through the proxy at proxyAddr
// and returns the tunneled connection. auth may be empty for no auth.
func dialThroughProxy(t *testing.T, proxyAddr, target, auth string) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	req := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n"
	if auth != "" {
		creds := base64.StdEncoding.EncodeToString([]byte(auth))
		req += "Proxy-Authorization: Basic " + creds + "\r\n"
	}
	req += "\r\n"
	if _, err := io.WriteString(conn, req); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	return conn
}

func TestServer_OpenProxyTunnel(t *testing.T) {
	upstreamAddr := echoUpstream(t)
	proxyAddr, _, _ := startServer(t, ServerConfiguration{}, direct.NewBackend())

	conn := dialThroughProxy(t, proxyAddr, upstreamAddr, "")
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

func TestServer_TLSProxyTunnel(t *testing.T) {
	upstreamAddr := echoUpstream(t)
	certFile, keyFile, roots := testCertificateFiles(t)
	proxyAddr, _, _ := startServer(t, ServerConfiguration{
		TLSCertFile: certFile,
		TLSKeyFile:  keyFile,
	}, direct.NewBackend())

	conn := dialTLSProxy(t, proxyAddr, roots)
	if got := conn.ConnectionState().NegotiatedProtocol; got != "http/1.1" {
		t.Fatalf("negotiated protocol = %q, want http/1.1", got)
	}

	request := "CONNECT " + upstreamAddr + " HTTP/1.1\r\nHost: " + upstreamAddr + "\r\n\r\n"
	if _, err := io.WriteString(conn, request); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.StatusCode)
	}

	message := []byte("hello-over-https-proxy")
	if _, err := conn.Write(message); err != nil {
		t.Fatalf("write tunnel data: %v", err)
	}
	got := make([]byte, len(message))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read tunnel data: %v", err)
	}
	if string(got) != string(message) {
		t.Fatalf("echo = %q, want %q", got, message)
	}
}

func TestServer_TLSAuthenticationAndCamouflage(t *testing.T) {
	upstreamAddr := echoUpstream(t)
	certFile, keyFile, roots := testCertificateFiles(t)
	proxyAddr, _, _ := startServer(t, ServerConfiguration{
		TLSCertFile: certFile,
		TLSKeyFile:  keyFile,
		Username:    "alice",
		Password:    "secret",
	}, direct.NewBackend())

	conn := dialTLSProxy(t, proxyAddr, roots)
	if _, err := io.WriteString(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want 407", response.StatusCode)
	}

	authedConn := dialTLSProxy(t, proxyAddr, roots)
	credentials := base64.StdEncoding.EncodeToString([]byte("alice:secret"))
	request := "CONNECT " + upstreamAddr + " HTTP/1.1\r\nHost: " + upstreamAddr + "\r\nProxy-Authorization: Basic " + credentials + "\r\n\r\n"
	if _, err := io.WriteString(authedConn, request); err != nil {
		t.Fatalf("write authenticated CONNECT: %v", err)
	}
	authedResponse, err := http.ReadResponse(bufio.NewReader(authedConn), nil)
	if err != nil {
		t.Fatalf("read authenticated CONNECT response: %v", err)
	}
	defer authedResponse.Body.Close()
	if authedResponse.StatusCode != http.StatusOK {
		t.Fatalf("authenticated status = %d, want 200", authedResponse.StatusCode)
	}

	camouflageAddr, _, _ := startServer(t, ServerConfiguration{
		TLSCertFile: certFile,
		TLSKeyFile:  keyFile,
		Username:    "alice",
		Password:    "secret",
		Camouflage:  true,
	}, direct.NewBackend())
	camouflageConn := dialTLSProxy(t, camouflageAddr, roots)
	if _, err := io.WriteString(camouflageConn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"); err != nil {
		t.Fatalf("write camouflage CONNECT: %v", err)
	}
	camouflageResponse, err := http.ReadResponse(bufio.NewReader(camouflageConn), nil)
	if err != nil {
		t.Fatalf("read camouflage response: %v", err)
	}
	defer camouflageResponse.Body.Close()
	if camouflageResponse.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("camouflage status = %d, want 405", camouflageResponse.StatusCode)
	}
	if got := camouflageResponse.Header.Get("Proxy-Authenticate"); got != "" {
		t.Fatalf("Proxy-Authenticate = %q, want empty", got)
	}
}

func TestServer_TLSBackendFailure(t *testing.T) {
	certFile, keyFile, roots := testCertificateFiles(t)
	proxyAddr, _, _ := startServer(t, ServerConfiguration{
		TLSCertFile: certFile,
		TLSKeyFile:  keyFile,
	}, &errorBackend{err: errors.New("upstream unreachable")})

	conn := dialTLSProxy(t, proxyAddr, roots)
	if _, err := io.WriteString(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", response.StatusCode)
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
	if _, err := io.WriteString(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"); err != nil {
		t.Fatalf("write plaintext CONNECT: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	response := make([]byte, 16)
	n, _ := conn.Read(response)
	if strings.HasPrefix(string(response[:n]), "HTTP/") {
		t.Fatalf("HTTPS proxy returned a plaintext HTTP response: %q", response[:n])
	}
}

func TestServer_AuthedProxyTunnel(t *testing.T) {
	upstreamAddr := echoUpstream(t)
	cfg := ServerConfiguration{Username: "alice", Password: "secret"}
	proxyAddr, _, _ := startServer(t, cfg, direct.NewBackend())

	conn := dialThroughProxy(t, proxyAddr, upstreamAddr, "alice:secret")
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

func TestServer_DialFailure(t *testing.T) {
	proxyAddr, _, _ := startServer(t, ServerConfiguration{}, &errorBackend{err: errors.New("upstream unreachable")})

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := io.WriteString(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", resp.StatusCode)
	}
}

func TestServer_AuthRequired_407(t *testing.T) {
	cfg := ServerConfiguration{Username: "alice", Password: "secret"}
	proxyAddr, _, _ := startServer(t, cfg, direct.NewBackend())

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := io.WriteString(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want 407", resp.StatusCode)
	}
	if got := resp.Header.Get("Proxy-Authenticate"); !strings.Contains(got, "Basic") {
		t.Fatalf("Proxy-Authenticate = %q, want Basic", got)
	}
}

func TestServer_CamouflageAuthFailure_405(t *testing.T) {
	cfg := ServerConfiguration{
		Username:   "alice",
		Password:   "secret",
		Camouflage: true,
	}
	proxyAddr, _, _ := startServer(t, cfg, direct.NewBackend())

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := io.WriteString(conn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", resp.StatusCode)
	}
	if got := resp.Header.Get("Allow"); got != "GET, HEAD" {
		t.Fatalf("Allow = %q, want GET, HEAD", got)
	}
	if got := resp.Header.Get("Proxy-Authenticate"); got != "" {
		t.Fatalf("Proxy-Authenticate = %q, want empty", got)
	}
}

func TestServer_ContextCancel(t *testing.T) {
	// Override the default cleanup so we can assert Run returns nil on cancel.
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

	// Wait for the listener to be ready.
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
