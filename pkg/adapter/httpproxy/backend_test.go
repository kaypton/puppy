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
	"strings"
	"testing"
	"time"

	"github.com/puppy/pkg/common"
)

// miniProxy starts a minimal HTTP CONNECT upstream proxy that accepts CONNECT
// requests (optionally requiring Basic auth) and tunnels to the requested
// target. It returns the proxy address and a cleanup function.
func miniProxy(t *testing.T, requireUser, requirePass string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handleMiniProxyConn(t, c, requireUser, requirePass)
		}
	}()
	return ln.Addr().String()
}

func handleMiniProxyConn(t *testing.T, conn net.Conn, requireUser, requirePass string) {
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if req.Method != http.MethodConnect {
		_, _ = io.WriteString(conn, "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
		return
	}
	if requireUser != "" {
		v := req.Header.Get("Proxy-Authorization")
		creds := base64.StdEncoding.EncodeToString([]byte(requireUser + ":" + requirePass))
		if v != "Basic "+creds {
			_, _ = io.WriteString(conn, "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
			return
		}
	}
	target := req.URL.Host
	if target == "" {
		target = req.Host
	}
	upstream, err := net.Dial("tcp", target)
	if err != nil {
		_, _ = io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	defer upstream.Close()
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	// Tunnel bytes. Preserve any buffered bytes the bufio.Reader holds.
	done := make(chan struct{})
	go func() {
		bc := &bufferedConn{r: br, Conn: conn}
		_, _ = io.Copy(upstream, bc)
		_ = upstream.Close()
		close(done)
	}()
	_, _ = io.Copy(conn, upstream)
	<-done
}

// echoServer is a local TCP listener that mirrors bytes back.
func echoServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
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

func parseTarget(addr string) common.Target {
	host, portStr, _ := net.SplitHostPort(addr)
	port := uint16(0)
	for _, r := range portStr {
		port = port*10 + uint16(r-'0')
	}
	return common.Target{Network: "tcp", Host: host, Port: port}
}

func TestNewBackend_Validation(t *testing.T) {
	cases := []struct {
		name    string
		cfg     BackendConfiguration
		wantErr string
	}{
		{"missing proxy address", BackendConfiguration{}, "proxy address"},
		{"username only", BackendConfiguration{ProxyAddress: "127.0.0.1:1", Username: "u"}, "username and password"},
		{"password only", BackendConfiguration{ProxyAddress: "127.0.0.1:1", Password: "p"}, "username and password"},
		{"valid open", BackendConfiguration{ProxyAddress: "127.0.0.1:1"}, ""},
		{"valid authed", BackendConfiguration{ProxyAddress: "127.0.0.1:1", Username: "u", Password: "p"}, ""},
		{"valid tls", BackendConfiguration{ProxyAddress: "127.0.0.1:1", TLS: true}, ""},
		{"ca file without tls", BackendConfiguration{ProxyAddress: "127.0.0.1:1", TLSCAFile: "ca.pem"}, "require tls = true"},
		{"server name without tls", BackendConfiguration{ProxyAddress: "127.0.0.1:1", TLSServerName: "proxy.internal"}, "require tls = true"},
		{"insecure without tls", BackendConfiguration{ProxyAddress: "127.0.0.1:1", TLSInsecureSkipVerify: true}, "require tls = true"},
		{"insecure with ca file", BackendConfiguration{ProxyAddress: "127.0.0.1:1", TLS: true, TLSCAFile: "ca.pem", TLSInsecureSkipVerify: true}, "mutually exclusive"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewBackend(tc.cfg)
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

func TestBackend_ChainThroughHTTPProxy(t *testing.T) {
	echoAddr := echoServer(t)
	proxyAddr := miniProxy(t, "", "")

	b, err := NewBackend(BackendConfiguration{
		ProxyAddress: proxyAddr,
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("NewBackend: %v", err)
	}

	conn, err := b.Dial(context.Background(), parseTarget(echoAddr), nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	msg := []byte("chained-echo")
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

func TestBackend_AuthedUpstream(t *testing.T) {
	echoAddr := echoServer(t)
	proxyAddr := miniProxy(t, "alice", "secret")

	b, err := NewBackend(BackendConfiguration{
		ProxyAddress: proxyAddr,
		Username:     "alice",
		Password:     "secret",
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("NewBackend: %v", err)
	}

	conn, err := b.Dial(context.Background(), parseTarget(echoAddr), nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	msg := []byte("authed-chain")
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

func TestBackend_AuthedUpstreamWrongCreds(t *testing.T) {
	echoAddr := echoServer(t)
	proxyAddr := miniProxy(t, "alice", "secret")

	b, err := NewBackend(BackendConfiguration{
		ProxyAddress: proxyAddr,
		Username:     "alice",
		Password:     "wrong",
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("NewBackend: %v", err)
	}

	_, err = b.Dial(context.Background(), parseTarget(echoAddr), nil)
	if err == nil {
		t.Fatal("expected error for wrong credentials, got nil")
	}
	if !strings.Contains(err.Error(), "407") {
		t.Fatalf("error = %q, want 407", err.Error())
	}
}

func TestBackend_UpstreamRejects(t *testing.T) {
	// Point the backend at a server that always refuses CONNECT with 403.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
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
				br := bufio.NewReader(c)
				_, _ = http.ReadRequest(br)
				_, _ = io.WriteString(c, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
			}(c)
		}
	}()

	b, err := NewBackend(BackendConfiguration{
		ProxyAddress: ln.Addr().String(),
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("NewBackend: %v", err)
	}

	_, err = b.Dial(context.Background(), common.Target{Network: "tcp", Host: "example.com", Port: 443}, nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "403") {
		t.Fatalf("error = %q, want 403", err.Error())
	}
}

func TestBackend_DialFailure(t *testing.T) {
	b, err := NewBackend(BackendConfiguration{
		ProxyAddress: "127.0.0.1:1", // nothing listening
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("NewBackend: %v", err)
	}

	failingDialer := common.DialFunc(func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, errors.New("unreachable")
	})
	_, err = b.Dial(context.Background(), common.Target{Network: "tcp", Host: "example.com", Port: 443}, failingDialer)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "dial upstream proxy") {
		t.Fatalf("error = %q, want 'dial upstream proxy'", err.Error())
	}
}

// testTLSCertificate generates a self-signed certificate keyed to localhost /
// 127.0.0.1 and returns the cert file, key file, a cert pool trusting it, and
// the certificate PEM bytes (suitable for writing to a CA file).
func testTLSCertificate(t *testing.T) (certFile, keyFile string, roots *x509.CertPool, certPEM []byte) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate private key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Puppy Upstream Proxy Test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	dir := t.TempDir()
	certFile = filepath.Join(dir, "proxy-cert.pem")
	keyFile = filepath.Join(dir, "proxy-key.pem")
	if err := os.WriteFile(certFile, certPEM, 0o644); err != nil {
		t.Fatalf("write certificate: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatalf("write private key: %v", err)
	}
	roots = x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("append test certificate")
	}
	return certFile, keyFile, roots, certPEM
}

// miniTLSProxy is miniProxy wrapped in a TLS listener using the provided cert
// files. The returned address is the TLS listener address.
func miniTLSProxy(t *testing.T, certFile, keyFile string, requireUser, requirePass string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("load key pair: %v", err)
	}
	tlsLn := tls.NewListener(ln, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	})
	t.Cleanup(func() { _ = tlsLn.Close() })
	go func() {
		for {
			c, err := tlsLn.Accept()
			if err != nil {
				return
			}
			go handleMiniProxyConn(t, c, requireUser, requirePass)
		}
	}()
	return tlsLn.Addr().String()
}

func TestBackend_ChainThroughTLSProxy(t *testing.T) {
	echoAddr := echoServer(t)
	certFile, keyFile, _, _ := testTLSCertificate(t)
	proxyAddr := miniTLSProxy(t, certFile, keyFile, "", "")

	b, err := NewBackend(BackendConfiguration{
		ProxyAddress: proxyAddr,
		TLS:          true,
		TLSConfig: &tls.Config{
			ServerName:         "localhost",
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("NewBackend: %v", err)
	}

	conn, err := b.Dial(context.Background(), parseTarget(echoAddr), nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	msg := []byte("tls-chained-echo")
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

func TestBackend_AuthedTLSUpstream(t *testing.T) {
	echoAddr := echoServer(t)
	certFile, keyFile, _, _ := testTLSCertificate(t)
	proxyAddr := miniTLSProxy(t, certFile, keyFile, "alice", "secret")

	b, err := NewBackend(BackendConfiguration{
		ProxyAddress: proxyAddr,
		Username:     "alice",
		Password:     "secret",
		TLS:          true,
		TLSConfig: &tls.Config{
			ServerName:         "localhost",
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("NewBackend: %v", err)
	}

	conn, err := b.Dial(context.Background(), parseTarget(echoAddr), nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	msg := []byte("authed-tls-chain")
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

func TestBackend_AuthedTLSUpstreamWrongCreds(t *testing.T) {
	echoAddr := echoServer(t)
	certFile, keyFile, _, _ := testTLSCertificate(t)
	proxyAddr := miniTLSProxy(t, certFile, keyFile, "alice", "secret")

	b, err := NewBackend(BackendConfiguration{
		ProxyAddress: proxyAddr,
		Username:     "alice",
		Password:     "wrong",
		TLS:          true,
		TLSConfig: &tls.Config{
			ServerName:         "localhost",
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("NewBackend: %v", err)
	}

	_, err = b.Dial(context.Background(), parseTarget(echoAddr), nil)
	if err == nil {
		t.Fatal("expected error for wrong credentials, got nil")
	}
	if !strings.Contains(err.Error(), "407") {
		t.Fatalf("error = %q, want 407", err.Error())
	}
}

func TestBackend_TLSHandshakeFailure(t *testing.T) {
	// Plaintext miniProxy, but backend is configured for TLS; handshake fails.
	echoAddr := echoServer(t)
	proxyAddr := miniProxy(t, "", "")
	_ = echoAddr

	b, err := NewBackend(BackendConfiguration{
		ProxyAddress: proxyAddr,
		TLS:          true,
		TLSConfig: &tls.Config{
			ServerName:         "localhost",
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS12,
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("NewBackend: %v", err)
	}

	_, err = b.Dial(context.Background(), parseTarget(echoAddr), nil)
	if err == nil {
		t.Fatal("expected TLS handshake error, got nil")
	}
	if !strings.Contains(err.Error(), "TLS handshake") {
		t.Fatalf("error = %q, want 'TLS handshake'", err.Error())
	}
}

func TestBackend_TLSBuiltFromCAFile(t *testing.T) {
	echoAddr := echoServer(t)
	certFile, keyFile, _, certPEM := testTLSCertificate(t)
	proxyAddr := miniTLSProxy(t, certFile, keyFile, "", "")

	// Write the trust pool to a CA file so NewBackend builds the tls.Config
	// itself rather than receiving an injected TLSConfig.
	caFile := filepath.Join(filepath.Dir(certFile), "ca.pem")
	if err := os.WriteFile(caFile, certPEM, 0o644); err != nil {
		t.Fatalf("write CA file: %v", err)
	}

	b, err := NewBackend(BackendConfiguration{
		ProxyAddress:  proxyAddr,
		TLS:           true,
		TLSCAFile:     caFile,
		TLSServerName: "localhost",
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("NewBackend: %v", err)
	}

	conn, err := b.Dial(context.Background(), parseTarget(echoAddr), nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	msg := []byte("ca-file-chain")
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

func TestBackend_TLSCAValidationFailure(t *testing.T) {
	echoAddr := echoServer(t)
	certFile, keyFile, _, _ := testTLSCertificate(t)
	proxyAddr := miniTLSProxy(t, certFile, keyFile, "", "")
	_ = echoAddr

	// TLS enabled with no CA file and not skipping verification: the
	// self-signed test certificate is not in the system roots, so the
	// handshake must fail.
	b, err := NewBackend(BackendConfiguration{
		ProxyAddress:  proxyAddr,
		TLS:           true,
		TLSServerName: "localhost",
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("NewBackend: %v", err)
	}

	_, err = b.Dial(context.Background(), parseTarget(echoAddr), nil)
	if err == nil {
		t.Fatal("expected TLS verification error, got nil")
	}
	if !strings.Contains(err.Error(), "TLS handshake") {
		t.Fatalf("error = %q, want 'TLS handshake'", err.Error())
	}
}
