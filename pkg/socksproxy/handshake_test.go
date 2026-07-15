package socksproxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/puppy/pkg/adapter/direct"
	"github.com/puppy/pkg/common"
)

// newPipeConns returns a pair of connected TCP conns on localhost. The server
// conn is passed to handshake; the client conn is used by the test to send the
// request and read any reply. TCP (rather than net.Pipe) avoids synchronous
// write semantics that would deadlock the handshake's reply writes.
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

func baseConfig() ServerConfiguration {
	return ServerConfiguration{ListenAddress: "127.0.0.1", ListenPort: 1, Backend: direct.NewBackend()}
}

// sendMethodNegotiation writes VER+NMETHODS+METHODS to conn.
func sendMethodNegotiation(t *testing.T, conn net.Conn, methods ...byte) {
	t.Helper()
	req := []byte{common.SOCKS5Version, byte(len(methods))}
	req = append(req, methods...)
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write method negotiation: %v", err)
	}
}

// readMethodSelection reads the 2-byte method selection reply.
func readMethodSelection(t *testing.T, conn net.Conn) byte {
	t.Helper()
	var resp [2]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		t.Fatalf("read method selection: %v", err)
	}
	if resp[0] != common.SOCKS5Version {
		t.Fatalf("method selection version = 0x%02x, want 0x05", resp[0])
	}
	return resp[1]
}

// sendConnectRequest writes a SOCKS5 CONNECT request for host:port.
func sendConnectRequest(t *testing.T, conn net.Conn, host string, port uint16) {
	t.Helper()
	req := []byte{common.SOCKS5Version, common.SOCKS5CmdConnect, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req = append(req, common.SOCKS5AtypIPv4)
			req = append(req, v4...)
		} else {
			req = append(req, common.SOCKS5AtypIPv6)
			req = append(req, ip.To16()...)
		}
	} else {
		req = append(req, common.SOCKS5AtypDomain, byte(len(host)))
		req = append(req, host...)
	}
	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], port)
	req = append(req, portBytes[:]...)
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write CONNECT request: %v", err)
	}
}

// readReply reads a SOCKS5 reply and returns (REP, ATYP, rest). It reads the
// 4-byte header, then consumes BND.ADDR + BND.PORT based on ATYP.
func readReply(t *testing.T, conn net.Conn) (rep, atyp byte) {
	t.Helper()
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		t.Fatalf("read reply header: %v", err)
	}
	if header[0] != common.SOCKS5Version {
		t.Fatalf("reply version = 0x%02x, want 0x05", header[0])
	}
	// Consume BND.ADDR + BND.PORT so the connection is left in a clean state.
	if _, _, err := common.ReadSOCKS5Address(conn, header[3]); err != nil {
		t.Fatalf("read reply bind address: %v", err)
	}
	return header[1], header[3]
}

func TestHandshake_ConnectSuccess(t *testing.T) {
	s, err := NewServer(baseConfig())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	clientConn, serverConn := newPipeConns(t)

	wait := dialHandshake(t, s, serverConn)

	sendMethodNegotiation(t, clientConn, common.SOCKS5MethodNoAuth)
	if got := readMethodSelection(t, clientConn); got != common.SOCKS5MethodNoAuth {
		t.Fatalf("selected method = 0x%02x, want 0x00", got)
	}
	sendConnectRequest(t, clientConn, "example.com", 443)

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

func TestHandshake_ConnectIPv4(t *testing.T) {
	s, err := NewServer(baseConfig())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	clientConn, serverConn := newPipeConns(t)
	wait := dialHandshake(t, s, serverConn)

	sendMethodNegotiation(t, clientConn, common.SOCKS5MethodNoAuth)
	readMethodSelection(t, clientConn)
	sendConnectRequest(t, clientConn, "127.0.0.1", 8080)

	target, frontend, herr := wait()
	if herr != nil {
		t.Fatalf("handshake err: %v", herr)
	}
	if target.Host != "127.0.0.1" || target.Port != 8080 {
		t.Fatalf("target = %+v, want 127.0.0.1:8080", target)
	}
	_ = frontend.Close()
}

func TestHandshake_ConnectIPv6(t *testing.T) {
	s, err := NewServer(baseConfig())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	clientConn, serverConn := newPipeConns(t)
	wait := dialHandshake(t, s, serverConn)

	sendMethodNegotiation(t, clientConn, common.SOCKS5MethodNoAuth)
	readMethodSelection(t, clientConn)
	sendConnectRequest(t, clientConn, "::1", 443)

	target, frontend, herr := wait()
	if herr != nil {
		t.Fatalf("handshake err: %v", herr)
	}
	if target.Host != "::1" || target.Port != 443 {
		t.Fatalf("target = %+v, want ::1:443", target)
	}
	_ = frontend.Close()
}

func TestHandshake_AuthRequiredButNoAcceptable(t *testing.T) {
	cfg := baseConfig()
	cfg.Username = "alice"
	cfg.Password = "secret"
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	clientConn, serverConn := newPipeConns(t)
	wait := dialHandshake(t, s, serverConn)

	// Client offers only no-auth, but server requires username/password.
	sendMethodNegotiation(t, clientConn, common.SOCKS5MethodNoAuth)
	if got := readMethodSelection(t, clientConn); got != common.SOCKS5MethodNoAcceptable {
		t.Fatalf("selected method = 0x%02x, want 0xFF", got)
	}

	if _, _, herr := wait(); herr == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestHandshake_AuthSuccess(t *testing.T) {
	cfg := baseConfig()
	cfg.Username = "alice"
	cfg.Password = "secret"
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	clientConn, serverConn := newPipeConns(t)
	wait := dialHandshake(t, s, serverConn)

	sendMethodNegotiation(t, clientConn, common.SOCKS5MethodUsernamePassword)
	if got := readMethodSelection(t, clientConn); got != common.SOCKS5MethodUsernamePassword {
		t.Fatalf("selected method = 0x%02x, want 0x02", got)
	}

	// Send RFC 1929 credentials.
	creds := []byte{common.SOCKS5AuthVersion, 5, 'a', 'l', 'i', 'c', 'e', 6, 's', 'e', 'c', 'r', 'e', 't'}
	if _, err := clientConn.Write(creds); err != nil {
		t.Fatalf("write credentials: %v", err)
	}
	var authResp [2]byte
	if _, err := io.ReadFull(clientConn, authResp[:]); err != nil {
		t.Fatalf("read auth response: %v", err)
	}
	if authResp[0] != common.SOCKS5AuthVersion || authResp[1] != 0x00 {
		t.Fatalf("auth response = %x, want [01 00]", authResp)
	}

	sendConnectRequest(t, clientConn, "example.com", 443)

	target, frontend, herr := wait()
	if herr != nil {
		t.Fatalf("handshake err: %v", herr)
	}
	if target.Host != "example.com" || target.Port != 443 {
		t.Fatalf("target = %+v, want example.com:443", target)
	}
	_ = frontend.Close()
}

func TestHandshake_AuthWrongCredentials(t *testing.T) {
	cfg := baseConfig()
	cfg.Username = "alice"
	cfg.Password = "secret"
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	clientConn, serverConn := newPipeConns(t)
	wait := dialHandshake(t, s, serverConn)

	sendMethodNegotiation(t, clientConn, common.SOCKS5MethodUsernamePassword)
	readMethodSelection(t, clientConn)

	creds := []byte{common.SOCKS5AuthVersion, 5, 'a', 'l', 'i', 'c', 'e', 5, 'w', 'r', 'o', 'n', 'g'}
	if _, err := clientConn.Write(creds); err != nil {
		t.Fatalf("write credentials: %v", err)
	}
	var authResp [2]byte
	if _, err := io.ReadFull(clientConn, authResp[:]); err != nil {
		t.Fatalf("read auth response: %v", err)
	}
	if authResp[1] != 0x01 {
		t.Fatalf("auth status = 0x%02x, want 0x01 (failure)", authResp[1])
	}

	if _, _, herr := wait(); herr == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestHandshake_UnsupportedCommand(t *testing.T) {
	s, err := NewServer(baseConfig())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	clientConn, serverConn := newPipeConns(t)
	wait := dialHandshake(t, s, serverConn)

	sendMethodNegotiation(t, clientConn, common.SOCKS5MethodNoAuth)
	readMethodSelection(t, clientConn)

	// BIND command (0x02) is unsupported.
	req := []byte{common.SOCKS5Version, 0x02, 0x00, common.SOCKS5AtypIPv4, 127, 0, 0, 1, 0x1F, 0x90}
	if _, err := clientConn.Write(req); err != nil {
		t.Fatalf("write BIND request: %v", err)
	}

	if _, _, herr := wait(); herr == nil {
		t.Fatal("expected error, got nil")
	}
	rep, _ := readReply(t, clientConn)
	if rep != common.SOCKS5RepCmdNotSupported {
		t.Fatalf("REP = 0x%02x, want 0x07 (command not supported)", rep)
	}
}

func TestHandshake_UnknownAddressType(t *testing.T) {
	s, err := NewServer(baseConfig())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	clientConn, serverConn := newPipeConns(t)
	wait := dialHandshake(t, s, serverConn)

	sendMethodNegotiation(t, clientConn, common.SOCKS5MethodNoAuth)
	readMethodSelection(t, clientConn)

	// ATYP=0x09 is unknown.
	req := []byte{common.SOCKS5Version, common.SOCKS5CmdConnect, 0x00, 0x09, 0, 0, 0, 0, 0, 0}
	if _, err := clientConn.Write(req); err != nil {
		t.Fatalf("write request: %v", err)
	}

	if _, _, herr := wait(); herr == nil {
		t.Fatal("expected error, got nil")
	}
	rep, _ := readReply(t, clientConn)
	if rep != common.SOCKS5RepAddrTypeNotSupported {
		t.Fatalf("REP = 0x%02x, want 0x08 (address type not supported)", rep)
	}
}

func TestHandshake_BadVersion(t *testing.T) {
	s, err := NewServer(baseConfig())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	clientConn, serverConn := newPipeConns(t)
	wait := dialHandshake(t, s, serverConn)

	// SOCKS4 version byte 0x04.
	if _, err := clientConn.Write([]byte{0x04, 0x01, 0x00}); err != nil {
		t.Fatalf("write: %v", err)
	}
	_, _, herr := wait()
	if herr == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(herr.Error(), "unexpected SOCKS version") {
		t.Fatalf("error = %v, want substring 'unexpected SOCKS version'", herr)
	}
}

func TestHandshake_MalformedMethodNegotiation(t *testing.T) {
	s, err := NewServer(baseConfig())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	clientConn, serverConn := newPipeConns(t)
	wait := dialHandshake(t, s, serverConn)

	// Only the version byte, then EOF.
	if _, err := clientConn.Write([]byte{common.SOCKS5Version}); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = clientConn.Close()

	_, _, herr := wait()
	if herr == nil {
		t.Fatal("expected error, got nil")
	}
}

// TestHandshake_BufferedBytesPreserved verifies that bytes the client sends
// immediately after the CONNECT request (before the success reply) are not
// lost: they must be readable from the returned frontend.
func TestHandshake_BufferedBytesPreserved(t *testing.T) {
	s, err := NewServer(baseConfig())
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	clientConn, serverConn := newPipeConns(t)
	wait := dialHandshake(t, s, serverConn)

	sendMethodNegotiation(t, clientConn, common.SOCKS5MethodNoAuth)
	readMethodSelection(t, clientConn)

	// CONNECT request plus early tunnel bytes in a single write.
	req := []byte{common.SOCKS5Version, common.SOCKS5CmdConnect, 0x00, common.SOCKS5AtypDomain, 11}
	req = append(req, []byte("example.com")...)
	req = append(req, 0x01, 0xBB) // port 443
	req = append(req, []byte("early-tunnel-data")...)
	if _, err := clientConn.Write(req); err != nil {
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

func TestRepForDialError(t *testing.T) {
	wrapped := func(target error) error { return fmt.Errorf("wrap: %w", target) }
	cases := []struct {
		name string
		err  error
		want byte
	}{
		{"connection refused", wrapped(syscall.ECONNREFUSED), common.SOCKS5RepConnectionRefused},
		{"host unreachable", wrapped(syscall.EHOSTUNREACH), common.SOCKS5RepHostUnreachable},
		{"network unreachable", wrapped(syscall.ENETUNREACH), common.SOCKS5RepNetworkUnreachable},
		{"deadline exceeded", wrapped(context.DeadlineExceeded), common.SOCKS5RepTTLExpired},
		{"generic", errors.New("something else"), common.SOCKS5RepGeneralFailure},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := repForDialError(tc.err); got != tc.want {
				t.Fatalf("repForDialError = 0x%02x, want 0x%02x", got, tc.want)
			}
		})
	}
}
