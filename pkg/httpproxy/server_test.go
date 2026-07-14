package httpproxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/puppy/pkg/adapter/direct"
	"github.com/puppy/pkg/common"
)

// errorBackend is a common.Backend whose Dial always returns err.
type errorBackend struct{ err error }

func (b *errorBackend) Dial(ctx context.Context, target common.Target) (io.ReadWriteCloser, error) {
	return nil, b.err
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
