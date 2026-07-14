package httpproxy

import (
	"bufio"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/puppy/pkg/adapter/direct"
	"github.com/puppy/pkg/common"
)

// newPipeConns returns a pair of connected TCP conns on localhost. The server
// conn is passed to handshake; the client conn is used by the test to send the
// request and read any response. TCP (rather than net.Pipe) avoids synchronous
// write semantics that would deadlock the handshake's error-response writes.
func newPipeConns(t *testing.T) (clientConn, serverConn net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	accepted := make(chan net.Conn, 1)
	go func() {
		c, aerr := ln.Accept()
		if aerr != nil {
			close(accepted)
			return
		}
		accepted <- c
	}()

	clientConn, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	serverConn = <-accepted
	if serverConn == nil {
		t.Fatalf("accept failed")
	}
	t.Cleanup(func() { _ = clientConn.Close() })
	t.Cleanup(func() { _ = serverConn.Close() })
	return clientConn, serverConn
}

// dialHandshake runs s.handshake on serverConn in a goroutine and returns a
// function that waits for the result.
func dialHandshake(t *testing.T, s *Server, serverConn net.Conn) func() (common.Target, io.ReadWriteCloser, error) {
	t.Helper()
	var (
		target   common.Target
		frontend io.ReadWriteCloser
		err      error
		wg       sync.WaitGroup
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		target, frontend, err = s.handshake(serverConn)
	}()
	return func() (common.Target, io.ReadWriteCloser, error) {
		wg.Wait()
		return target, frontend, err
	}
}

// readResponse reads a full HTTP response (status line + headers + blank line)
// from clientConn. Used to inspect error responses written by the handshake.
func readResponse(t *testing.T, clientConn net.Conn) (statusLine string, headers http.Header) {
	t.Helper()
	br := bufio.NewReader(clientConn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	_ = resp.Body.Close()
	return resp.Status, resp.Header
}

func baseConfig() ServerConfiguration {
	return ServerConfiguration{ListenAddress: "127.0.0.1", ListenPort: 1, Backend: direct.NewBackend()}
}

func TestHandshake_ConnectSuccess(t *testing.T) {
	s, err := NewServer(baseConfig())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	clientConn, serverConn := newPipeConns(t)

	wait := dialHandshake(t, s, serverConn)

	// Send a bare CONNECT request. No trailing bytes this time.
	if _, err := io.WriteString(clientConn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}

	target, frontend, herr := wait()
	if herr != nil {
		t.Fatalf("handshake err: %v", herr)
	}
	if target.Host != "example.com" || target.Port != 443 {
		t.Fatalf("target = %+v, want example.com:443", target)
	}
	if frontend == nil {
		t.Fatal("frontend is nil")
	}
	_ = frontend.Close()
}

func TestHandshake_ConnectNoPortDefaults443(t *testing.T) {
	s, err := NewServer(baseConfig())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	clientConn, serverConn := newPipeConns(t)

	wait := dialHandshake(t, s, serverConn)

	if _, err := io.WriteString(clientConn, "CONNECT example.com HTTP/1.1\r\nHost: example.com\r\n\r\n"); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}

	target, frontend, herr := wait()
	if herr != nil {
		t.Fatalf("handshake err: %v", herr)
	}
	if target.Host != "example.com" || target.Port != 443 {
		t.Fatalf("target = %+v, want example.com:443", target)
	}
	_ = frontend.Close()
}

func TestHandshake_NonConnectMethod(t *testing.T) {
	s, err := NewServer(baseConfig())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	clientConn, serverConn := newPipeConns(t)

	wait := dialHandshake(t, s, serverConn)

	if _, err := io.WriteString(clientConn, "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"); err != nil {
		t.Fatalf("write GET: %v", err)
	}

	target, _, herr := wait()
	if herr == nil {
		t.Fatal("expected error, got nil")
	}
	if target.Host != "" {
		t.Fatalf("target = %+v, want empty", target)
	}
	status, _ := readResponse(t, clientConn)
	if !strings.Contains(status, "405") {
		t.Fatalf("status = %q, want 405", status)
	}
}

func TestHandshake_CamouflageNonConnectMethod(t *testing.T) {
	cfg := baseConfig()
	cfg.Camouflage = true
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	clientConn, serverConn := newPipeConns(t)
	wait := dialHandshake(t, s, serverConn)

	if _, err := io.WriteString(clientConn, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"); err != nil {
		t.Fatalf("write GET: %v", err)
	}
	if _, _, err := wait(); err == nil {
		t.Fatal("expected error, got nil")
	}
	status, headers := readResponse(t, clientConn)
	if !strings.Contains(status, "404") {
		t.Fatalf("status = %q, want 404", status)
	}
	if got := headers.Get("Proxy-Authenticate"); got != "" {
		t.Fatalf("Proxy-Authenticate = %q, want empty", got)
	}
}

func TestHandshake_MalformedRequest(t *testing.T) {
	s, err := NewServer(baseConfig())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	clientConn, serverConn := newPipeConns(t)

	wait := dialHandshake(t, s, serverConn)

	if _, err := io.WriteString(clientConn, "this is not http\r\n\r\n"); err != nil {
		t.Fatalf("write garbage: %v", err)
	}

	_, _, herr := wait()
	if herr == nil {
		t.Fatal("expected error, got nil")
	}
	status, _ := readResponse(t, clientConn)
	if !strings.Contains(status, "400") {
		t.Fatalf("status = %q, want 400", status)
	}
}

func TestHandshake_AuthMissing(t *testing.T) {
	cfg := baseConfig()
	cfg.Username = "alice"
	cfg.Password = "secret"
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	clientConn, serverConn := newPipeConns(t)

	wait := dialHandshake(t, s, serverConn)

	if _, err := io.WriteString(clientConn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}

	_, _, herr := wait()
	if herr == nil {
		t.Fatal("expected error, got nil")
	}
	status, headers := readResponse(t, clientConn)
	if !strings.Contains(status, "407") {
		t.Fatalf("status = %q, want 407", status)
	}
	if got := headers.Get("Proxy-Authenticate"); !strings.Contains(got, "Basic") {
		t.Fatalf("Proxy-Authenticate = %q, want Basic", got)
	}
}

func TestHandshake_AuthWrong(t *testing.T) {
	cfg := baseConfig()
	cfg.Username = "alice"
	cfg.Password = "secret"
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	clientConn, serverConn := newPipeConns(t)

	wait := dialHandshake(t, s, serverConn)

	creds := base64.StdEncoding.EncodeToString([]byte("alice:wrong"))
	if _, err := io.WriteString(clientConn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Basic "+creds+"\r\n\r\n"); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}

	_, _, herr := wait()
	if herr == nil {
		t.Fatal("expected error, got nil")
	}
	status, _ := readResponse(t, clientConn)
	if !strings.Contains(status, "407") {
		t.Fatalf("status = %q, want 407", status)
	}
}

func TestHandshake_CamouflageAuthFailures(t *testing.T) {
	tests := []struct {
		name   string
		header string
	}{
		{name: "missing"},
		{name: "malformed", header: "Proxy-Authorization: Basic not-base64!\r\n"},
		{name: "wrong", header: "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("alice:wrong")) + "\r\n"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := baseConfig()
			cfg.Username = "alice"
			cfg.Password = "secret"
			cfg.Camouflage = true
			s, err := NewServer(cfg)
			if err != nil {
				t.Fatalf("NewServer: %v", err)
			}
			clientConn, serverConn := newPipeConns(t)
			wait := dialHandshake(t, s, serverConn)

			request := "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n" + test.header + "\r\n"
			if _, err := io.WriteString(clientConn, request); err != nil {
				t.Fatalf("write CONNECT: %v", err)
			}
			if _, _, err := wait(); err == nil {
				t.Fatal("expected error, got nil")
			}
			status, headers := readResponse(t, clientConn)
			if !strings.Contains(status, "405") {
				t.Fatalf("status = %q, want 405", status)
			}
			if got := headers.Get("Allow"); got != "GET, HEAD" {
				t.Fatalf("Allow = %q, want GET, HEAD", got)
			}
			if got := headers.Get("Proxy-Authenticate"); got != "" {
				t.Fatalf("Proxy-Authenticate = %q, want empty", got)
			}
		})
	}
}

func TestHandshake_CamouflageMalformedRequest(t *testing.T) {
	cfg := baseConfig()
	cfg.Camouflage = true
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	clientConn, serverConn := newPipeConns(t)
	wait := dialHandshake(t, s, serverConn)

	if _, err := io.WriteString(clientConn, "this is not http\r\n\r\n"); err != nil {
		t.Fatalf("write garbage: %v", err)
	}
	if _, _, err := wait(); err == nil {
		t.Fatal("expected error, got nil")
	}
	status, _ := readResponse(t, clientConn)
	if !strings.Contains(status, "400") {
		t.Fatalf("status = %q, want 400", status)
	}
}

func TestHandshake_AuthCorrect(t *testing.T) {
	cfg := baseConfig()
	cfg.Username = "alice"
	cfg.Password = "secret"
	cfg.Camouflage = true
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	clientConn, serverConn := newPipeConns(t)

	wait := dialHandshake(t, s, serverConn)

	creds := base64.StdEncoding.EncodeToString([]byte("alice:secret"))
	if _, err := io.WriteString(clientConn, "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Basic "+creds+"\r\n\r\n"); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}

	target, frontend, herr := wait()
	if herr != nil {
		t.Fatalf("handshake err: %v", herr)
	}
	if target.Host != "example.com" || target.Port != 443 {
		t.Fatalf("target = %+v, want example.com:443", target)
	}
	_ = frontend.Close()
}

// TestHandshake_BufferedBytesPreserved verifies that bytes the client sends
// immediately after the CONNECT header (before the 200 response) are not lost:
// they must be readable from the returned frontend.
func TestHandshake_BufferedBytesPreserved(t *testing.T) {
	s, err := NewServer(baseConfig())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	clientConn, serverConn := newPipeConns(t)

	wait := dialHandshake(t, s, serverConn)

	// CONNECT header plus early tunnel bytes in a single write.
	request := "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n" + "early-tunnel-data"
	if _, err := io.WriteString(clientConn, request); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, frontend, herr := wait()
	if herr != nil {
		t.Fatalf("handshake err: %v", herr)
	}
	defer frontend.Close()

	want := "early-tunnel-data"
	got := make([]byte, len(want))
	if _, err := io.ReadFull(frontend, got); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if string(got) != want {
		t.Fatalf("buffered bytes = %q, want %q", string(got), want)
	}
}
