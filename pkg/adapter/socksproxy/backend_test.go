package socksproxy

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/puppy/pkg/common"
)

// Local aliases over the shared SOCKS5 constants keep the test fixtures
// readable while remaining in sync with pkg/common.
const (
	socks5Version                = common.SOCKS5Version
	socks5MethodNoAuth           = common.SOCKS5MethodNoAuth
	socks5MethodUsernamePassword = common.SOCKS5MethodUsernamePassword
	socks5MethodNoAcceptable     = common.SOCKS5MethodNoAcceptable
	socks5AuthVersion            = common.SOCKS5AuthVersion
	socks5CmdConnect             = common.SOCKS5CmdConnect
	socks5AtypIPv4               = common.SOCKS5AtypIPv4
	socks5AtypDomain             = common.SOCKS5AtypDomain
	socks5AtypIPv6               = common.SOCKS5AtypIPv6
	socks5RepSuccess             = common.SOCKS5RepSuccess
)

// miniSOCKS5 starts a minimal SOCKS5 upstream proxy that accepts CONNECT
// requests (optionally requiring username/password auth) and tunnels to the
// requested target. It returns the proxy address and registers cleanup.
func miniSOCKS5(t *testing.T, requireUser, requirePass string) string {
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
			go handleMiniSOCKS5Conn(t, c, requireUser, requirePass)
		}
	}()
	return ln.Addr().String()
}

func handleMiniSOCKS5Conn(t *testing.T, conn net.Conn, requireUser, requirePass string) {
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(conn)

	// Method negotiation: read VER + NMETHODS + METHODS.
	var header [2]byte
	if _, err := io.ReadFull(br, header[:]); err != nil {
		return
	}
	if header[0] != socks5Version {
		return
	}
	methods := make([]byte, header[1])
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}

	var selected byte = socks5MethodNoAcceptable
	for _, m := range methods {
		if requireUser != "" {
			if m == socks5MethodUsernamePassword {
				selected = m
				break
			}
		} else if m == socks5MethodNoAuth {
			selected = m
			break
		}
	}
	if _, err := conn.Write([]byte{socks5Version, selected}); err != nil {
		return
	}
	if selected == socks5MethodNoAcceptable {
		return
	}

	if selected == socks5MethodUsernamePassword {
		var authHeader [2]byte
		if _, err := io.ReadFull(br, authHeader[:]); err != nil {
			return
		}
		if authHeader[0] != socks5AuthVersion {
			return
		}
		ulen := int(authHeader[1])
		user := make([]byte, ulen)
		if _, err := io.ReadFull(br, user); err != nil {
			return
		}
		var plenByte [1]byte
		if _, err := io.ReadFull(br, plenByte[:]); err != nil {
			return
		}
		pass := make([]byte, plenByte[0])
		if _, err := io.ReadFull(br, pass); err != nil {
			return
		}
		if string(user) != requireUser || string(pass) != requirePass {
			_, _ = conn.Write([]byte{socks5AuthVersion, 0x01})
			return
		}
		if _, err := conn.Write([]byte{socks5AuthVersion, 0x00}); err != nil {
			return
		}
	}

	// CONNECT request.
	var reqHeader [4]byte
	if _, err := io.ReadFull(br, reqHeader[:]); err != nil {
		return
	}
	if reqHeader[0] != socks5Version || reqHeader[1] != socks5CmdConnect {
		_, _ = conn.Write([]byte{socks5Version, 0x07, 0x00, socks5AtypIPv4, 0, 0, 0, 0, 0, 0})
		return
	}
	host, err := readSOCKS5Addr(br, reqHeader[3])
	if err != nil {
		return
	}
	var portBytes [2]byte
	if _, err := io.ReadFull(br, portBytes[:]); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(portBytes[:])
	target := net.JoinHostPort(host, strconv.Itoa(int(port)))

	upstream, err := net.Dial("tcp", target)
	if err != nil {
		_, _ = conn.Write([]byte{socks5Version, 0x04, 0x00, socks5AtypIPv4, 0, 0, 0, 0, 0, 0}) // host unreachable
		return
	}
	defer upstream.Close()
	if _, err := conn.Write([]byte{socks5Version, socks5RepSuccess, 0x00, socks5AtypIPv4, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	// Tunnel bytes, preserving any buffered bytes the bufio.Reader holds.
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

func readSOCKS5Addr(br *bufio.Reader, atyp byte) (string, error) {
	// Reads only the DST.ADDR portion; DST.PORT is consumed separately by the
	// mini proxy so it can format the dial target.
	switch atyp {
	case socks5AtypIPv4:
		var addr [4]byte
		if _, err := io.ReadFull(br, addr[:]); err != nil {
			return "", err
		}
		return net.IP(addr[:]).String(), nil
	case socks5AtypIPv6:
		var addr [16]byte
		if _, err := io.ReadFull(br, addr[:]); err != nil {
			return "", err
		}
		return net.IP(addr[:]).String(), nil
	case socks5AtypDomain:
		var lenByte [1]byte
		if _, err := io.ReadFull(br, lenByte[:]); err != nil {
			return "", err
		}
		domain := make([]byte, lenByte[0])
		if _, err := io.ReadFull(br, domain); err != nil {
			return "", err
		}
		return string(domain), nil
	default:
		return "", errors.New("unknown address type")
	}
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

func TestBackendCapabilities(t *testing.T) {
	b := &Backend{}
	capabilities := b.Capabilities()
	if !common.SupportsAnyProtocol(capabilities, "tcp") {
		t.Fatal("SOCKS5 backend should support any TCP application protocol")
	}
	if common.SupportsNetwork(capabilities, "udp") {
		t.Fatal("SOCKS5 backend should not support UDP")
	}
}

func TestBackend_ChainThroughSOCKS5(t *testing.T) {
	echoAddr := echoServer(t)
	proxyAddr := miniSOCKS5(t, "", "")

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
	proxyAddr := miniSOCKS5(t, "alice", "secret")

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
	proxyAddr := miniSOCKS5(t, "alice", "secret")

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
	if !strings.Contains(err.Error(), "rejected credentials") {
		t.Fatalf("error = %q, want 'rejected credentials'", err.Error())
	}
}

func TestBackend_AuthRequiredButNoCreds(t *testing.T) {
	echoAddr := echoServer(t)
	proxyAddr := miniSOCKS5(t, "alice", "secret")

	b, err := NewBackend(BackendConfiguration{
		ProxyAddress: proxyAddr,
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("NewBackend: %v", err)
	}

	_, err = b.Dial(context.Background(), parseTarget(echoAddr), nil)
	if err == nil {
		t.Fatal("expected error when upstream requires auth but no creds offered, got nil")
	}
	if !strings.Contains(err.Error(), "no acceptable method") {
		t.Fatalf("error = %q, want 'no acceptable method'", err.Error())
	}
}

func TestBackend_UpstreamRejectsConnect(t *testing.T) {
	// An upstream that completes the method negotiation but always refuses
	// CONNECT with rep=0x05 (connection refused).
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
			go handleRejectingSOCKS5Conn(c)
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
	if !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("error = %q, want 'connection refused'", err.Error())
	}
}

// handleRejectingSOCKS5Conn completes method negotiation (no-auth) then replies
// to any CONNECT request with rep=0x05 (connection refused).
func handleRejectingSOCKS5Conn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(conn)
	var header [2]byte
	if _, err := io.ReadFull(br, header[:]); err != nil {
		return
	}
	methods := make([]byte, header[1])
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	if _, err := conn.Write([]byte{socks5Version, socks5MethodNoAuth}); err != nil {
		return
	}
	var reqHeader [4]byte
	if _, err := io.ReadFull(br, reqHeader[:]); err != nil {
		return
	}
	if _, err := readSOCKS5Addr(br, reqHeader[3]); err != nil {
		return
	}
	var portBytes [2]byte
	_, _ = io.ReadFull(br, portBytes[:])
	_, _ = conn.Write([]byte{socks5Version, 0x05, 0x00, socks5AtypIPv4, 0, 0, 0, 0, 0, 0})
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

func TestBackend_DomainTarget(t *testing.T) {
	echoAddr := echoServer(t)
	proxyAddr := miniSOCKS5(t, "", "")

	b, err := NewBackend(BackendConfiguration{
		ProxyAddress: proxyAddr,
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("NewBackend: %v", err)
	}

	// Use "localhost" so the mini proxy resolves it back to the loopback
	// echo server's port.
	host, portStr, _ := net.SplitHostPort(echoAddr)
	_ = host
	port := uint16(0)
	for _, r := range portStr {
		port = port*10 + uint16(r-'0')
	}
	conn, err := b.Dial(context.Background(), common.Target{Network: "tcp", Host: "localhost", Port: port}, nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	msg := []byte("domain-target-echo")
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

func TestBackend_IPv6Target(t *testing.T) {
	echoLn, err := net.Listen("tcp", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 not available: %v", err)
	}
	t.Cleanup(func() { _ = echoLn.Close() })
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()

	proxyAddr := miniSOCKS5(t, "", "")
	b, err := NewBackend(BackendConfiguration{
		ProxyAddress: proxyAddr,
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("NewBackend: %v", err)
	}

	target := parseTarget(echoLn.Addr().String())
	conn, err := b.Dial(context.Background(), target, nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	msg := []byte("ipv6-echo")
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
		Subject:      pkix.Name{CommonName: "Puppy SOCKS Upstream Test"},
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

// miniTLSSOCKS5 is miniSOCKS5 wrapped in a TLS listener using the provided
// cert files. The returned address is the TLS listener address.
func miniTLSSOCKS5(t *testing.T, certFile, keyFile string, requireUser, requirePass string) string {
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
			go handleMiniSOCKS5Conn(t, c, requireUser, requirePass)
		}
	}()
	return tlsLn.Addr().String()
}

func TestBackend_ChainThroughTLSProxy(t *testing.T) {
	echoAddr := echoServer(t)
	certFile, keyFile, _, _ := testTLSCertificate(t)
	proxyAddr := miniTLSSOCKS5(t, certFile, keyFile, "", "")

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
	proxyAddr := miniTLSSOCKS5(t, certFile, keyFile, "alice", "secret")

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
	proxyAddr := miniTLSSOCKS5(t, certFile, keyFile, "alice", "secret")

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
	if !strings.Contains(err.Error(), "rejected credentials") {
		t.Fatalf("error = %q, want 'rejected credentials'", err.Error())
	}
}

func TestBackend_TLSHandshakeFailure(t *testing.T) {
	// Plaintext miniSOCKS5, but backend is configured for TLS; handshake fails.
	echoAddr := echoServer(t)
	proxyAddr := miniSOCKS5(t, "", "")
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
	proxyAddr := miniTLSSOCKS5(t, certFile, keyFile, "", "")

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
	proxyAddr := miniTLSSOCKS5(t, certFile, keyFile, "", "")
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

func TestEncodeSOCKS5Request(t *testing.T) {
	cases := []struct {
		name     string
		target   common.Target
		wantErr  string
		wantAtyp byte
	}{
		{"ipv4", common.Target{Network: "tcp", Host: "127.0.0.1", Port: 80}, "", socks5AtypIPv4},
		{"ipv6", common.Target{Network: "tcp", Host: "::1", Port: 443}, "", socks5AtypIPv6},
		{"domain", common.Target{Network: "tcp", Host: "example.com", Port: 8080}, "", socks5AtypDomain},
		{"empty host", common.Target{Network: "tcp", Host: "", Port: 80}, "target host is required", 0},
		{"zero port", common.Target{Network: "tcp", Host: "example.com", Port: 0}, "target port is required", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := encodeSOCKS5Request(tc.target)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %v, want substring %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if req[0] != socks5Version || req[1] != socks5CmdConnect || req[2] != 0x00 {
				t.Fatalf("header = %x, want [05 01 00]", req[:3])
			}
			if req[3] != tc.wantAtyp {
				t.Fatalf("atyp = 0x%02x, want 0x%02x", req[3], tc.wantAtyp)
			}
		})
	}
}

func TestSOCKS5ReplyText_DelegatesToCommon(t *testing.T) {
	// The backend now reports reply text via common.SOCKS5ReplyText. Verify
	// the shared helper still produces the strings the backend relies on.
	if common.SOCKS5ReplyText(common.SOCKS5RepSuccess) != "succeeded" {
		t.Fatal("rep 0x00 should be succeeded")
	}
	if common.SOCKS5ReplyText(common.SOCKS5RepConnectionRefused) != "connection refused" {
		t.Fatal("rep 0x05 should be connection refused")
	}
	if !strings.Contains(common.SOCKS5ReplyText(0xFF), "unknown error") {
		t.Fatal("rep 0xFF should be unknown error")
	}
}
