package socksproxy

import (
	"bufio"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/puppy/pkg/common"
)

// bufferedConn preserves bytes that bufio.Reader has already pulled past the
// SOCKS5 request. Without it, any post-request bytes the client sent eagerly
// (common with TLS clients) would be lost before ShimServer takes over.
type bufferedConn struct {
	r *bufio.Reader
	net.Conn
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.r.Read(p) }

// handshake performs the SOCKS5 server-side handshake: method negotiation,
// optional RFC 1929 username/password authentication, and CONNECT request
// parsing. It returns the target plus a frontend reader that preserves
// buffered bytes. On failure it writes the appropriate SOCKS5 reply to conn
// and returns err.
func (s *Server) handshake(conn net.Conn) (target common.Target, frontend io.ReadWriteCloser, err error) {
	reader := bufio.NewReader(conn)

	method, err := s.negotiateMethod(reader, conn)
	if err != nil {
		return common.Target{}, nil, err
	}

	if method == common.SOCKS5MethodUsernamePassword {
		if err := s.authenticate(reader, conn); err != nil {
			return common.Target{}, nil, err
		}
	}

	target, err = s.readConnect(reader, conn)
	if err != nil {
		return common.Target{}, nil, err
	}

	return target, &bufferedConn{r: reader, Conn: conn}, nil
}

// negotiateMethod reads VER+NMETHODS+METHODS and selects the authentication
// method. When the server has credentials it accepts only username/password
// (0x02); otherwise it accepts only no-auth (0x00). On no acceptable method
// it writes 0xFF and returns an error.
func (s *Server) negotiateMethod(reader *bufio.Reader, conn net.Conn) (byte, error) {
	var header [2]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return 0, fmt.Errorf("read method negotiation: %w", err)
	}
	if header[0] != common.SOCKS5Version {
		return 0, fmt.Errorf("unexpected SOCKS version 0x%02x during method negotiation", header[0])
	}
	methods := make([]byte, header[1])
	if _, err := io.ReadFull(reader, methods); err != nil {
		return 0, fmt.Errorf("read methods: %w", err)
	}

	requireAuth := s.config.Username != ""
	want := common.SOCKS5MethodNoAuth
	if requireAuth {
		want = common.SOCKS5MethodUsernamePassword
	}
	accepted := byte(common.SOCKS5MethodNoAcceptable)
	for _, m := range methods {
		if m == want {
			accepted = m
			break
		}
	}
	if _, err := conn.Write([]byte{common.SOCKS5Version, accepted}); err != nil {
		return 0, fmt.Errorf("write method selection: %w", err)
	}
	if accepted == common.SOCKS5MethodNoAcceptable {
		return accepted, errors.New("no acceptable authentication method")
	}
	return accepted, nil
}

// authenticate performs the RFC 1929 username/password sub-negotiation,
// validating credentials with constant-time comparison. On failure it writes
// the auth failure reply and returns an error.
func (s *Server) authenticate(reader *bufio.Reader, conn net.Conn) error {
	var authHeader [2]byte
	if _, err := io.ReadFull(reader, authHeader[:]); err != nil {
		return fmt.Errorf("read auth version and username length: %w", err)
	}
	if authHeader[0] != common.SOCKS5AuthVersion {
		return fmt.Errorf("unexpected auth version 0x%02x", authHeader[0])
	}
	user := make([]byte, authHeader[1])
	if _, err := io.ReadFull(reader, user); err != nil {
		return fmt.Errorf("read username: %w", err)
	}
	var plenByte [1]byte
	if _, err := io.ReadFull(reader, plenByte[:]); err != nil {
		return fmt.Errorf("read password length: %w", err)
	}
	pass := make([]byte, plenByte[0])
	if _, err := io.ReadFull(reader, pass); err != nil {
		return fmt.Errorf("read password: %w", err)
	}

	uMatch := subtle.ConstantTimeCompare(user, []byte(s.config.Username)) == 1
	pMatch := subtle.ConstantTimeCompare(pass, []byte(s.config.Password)) == 1
	if !uMatch || !pMatch {
		_, _ = conn.Write([]byte{common.SOCKS5AuthVersion, 0x01})
		return errors.New("authentication failed")
	}
	if _, err := conn.Write([]byte{common.SOCKS5AuthVersion, 0x00}); err != nil {
		return fmt.Errorf("write auth success: %w", err)
	}
	return nil
}

// readConnect parses the SOCKS5 CONNECT request (VER+CMD+RSV+ATYP+DST.ADDR+
// DST.PORT) and returns the target. Only CONNECT (0x01) is supported. On
// failure it writes the appropriate SOCKS5 reply and returns an error.
func (s *Server) readConnect(reader *bufio.Reader, conn net.Conn) (common.Target, error) {
	var reqHeader [4]byte
	if _, err := io.ReadFull(reader, reqHeader[:]); err != nil {
		return common.Target{}, fmt.Errorf("read CONNECT request: %w", err)
	}
	if reqHeader[0] != common.SOCKS5Version {
		return common.Target{}, fmt.Errorf("unexpected SOCKS version 0x%02x in CONNECT request", reqHeader[0])
	}
	if reqHeader[1] != common.SOCKS5CmdConnect {
		_ = s.writeReply(conn, common.SOCKS5RepCmdNotSupported)
		return common.Target{}, fmt.Errorf("unsupported command 0x%02x", reqHeader[1])
	}

	host, port, err := common.ReadSOCKS5Address(reader, reqHeader[3])
	if err != nil {
		_ = s.writeReply(conn, common.SOCKS5RepAddrTypeNotSupported)
		return common.Target{}, fmt.Errorf("read target address: %w", err)
	}

	return common.Target{Network: "tcp", Protocol: common.ProtocolUnknown, Host: host, Port: port}, nil
}
