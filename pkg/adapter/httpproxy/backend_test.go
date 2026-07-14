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

	conn, err := b.Dial(context.Background(), parseTarget(echoAddr))
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

	conn, err := b.Dial(context.Background(), parseTarget(echoAddr))
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

	_, err = b.Dial(context.Background(), parseTarget(echoAddr))
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

	_, err = b.Dial(context.Background(), common.Target{Network: "tcp", Host: "example.com", Port: 443})
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
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return nil, errors.New("unreachable")
		},
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("NewBackend: %v", err)
	}

	_, err = b.Dial(context.Background(), common.Target{Network: "tcp", Host: "example.com", Port: 443})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "dial upstream proxy") {
		t.Fatalf("error = %q, want 'dial upstream proxy'", err.Error())
	}
}
