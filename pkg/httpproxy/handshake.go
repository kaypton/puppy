package httpproxy

import (
	"bufio"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/puppy/pkg/common"
)

// HTTP status codes used by the handshake. Defined locally to avoid importing
// net/http solely for constants in server.go.
const (
	httpStatusBadRequest        = http.StatusBadRequest
	httpStatusMethodNotAllowed  = http.StatusMethodNotAllowed
	httpStatusProxyAuthRequired = http.StatusProxyAuthRequired
	httpStatusBadGateway        = http.StatusBadGateway
)

// bufferedConn preserves bytes that bufio.Reader has already pulled past the
// HTTP request header. Without it, any post-header bytes the client sent
// eagerly (common with TLS clients) would be lost before ShimServer takes over.
type bufferedConn struct {
	r *bufio.Reader
	net.Conn
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.r.Read(p) }

// handshake reads the CONNECT request, validates auth, and returns the target
// plus a frontend reader that preserves buffered bytes. On failure it writes
// the appropriate HTTP error response to conn and returns err.
func (s *Server) handshake(conn net.Conn) (target common.Target, frontend io.ReadWriteCloser, err error) {
	reader := bufio.NewReader(conn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		s.writeError(conn, httpStatusBadRequest, nil)
		return common.Target{}, nil, fmt.Errorf("read request: %w", err)
	}

	if req.Method != http.MethodConnect {
		s.writeError(conn, httpStatusMethodNotAllowed, nil)
		return common.Target{}, nil, fmt.Errorf("method not allowed: %s", req.Method)
	}

	if s.config.Username != "" && !s.checkAuth(req) {
		s.writeError(conn, httpStatusProxyAuthRequired, map[string]string{
			"Proxy-Authenticate": `Basic realm="proxy"`,
		})
		return common.Target{}, nil, errors.New("authentication failed")
	}

	rawTarget := req.URL.Host
	if rawTarget == "" {
		rawTarget = req.Host
	}
	if rawTarget == "" {
		s.writeError(conn, httpStatusBadRequest, nil)
		return common.Target{}, nil, errors.New("missing target")
	}

	host, portStr, splitErr := net.SplitHostPort(rawTarget)
	if splitErr != nil {
		// No port: default to 443 (HTTPS).
		host = rawTarget
		portStr = "443"
	}
	port, perr := strconv.ParseUint(portStr, 10, 16)
	if perr != nil {
		s.writeError(conn, httpStatusBadRequest, nil)
		return common.Target{}, nil, fmt.Errorf("invalid port %q: %w", portStr, perr)
	}

	return common.Target{Network: "tcp", Host: host, Port: uint16(port)}, &bufferedConn{r: reader, Conn: conn}, nil
}

// checkAuth validates the Proxy-Authorization header against the configured
// credentials using constant-time comparison.
func (s *Server) checkAuth(req *http.Request) bool {
	user, pass, ok := proxyBasicAuth(req)
	if !ok {
		return false
	}
	uMatch := subtle.ConstantTimeCompare([]byte(user), []byte(s.config.Username)) == 1
	pMatch := subtle.ConstantTimeCompare([]byte(pass), []byte(s.config.Password)) == 1
	return uMatch && pMatch
}

// proxyBasicAuth extracts username/password from a Basic Proxy-Authorization
// header. ok is false when the header is absent or malformed.
func proxyBasicAuth(req *http.Request) (username, password string, ok bool) {
	v := req.Header.Get("Proxy-Authorization")
	if v == "" {
		return "", "", false
	}
	const prefix = "Basic "
	if !strings.HasPrefix(v, prefix) {
		return "", "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(v, prefix))
	if err != nil {
		return "", "", false
	}
	user, pass, found := strings.Cut(string(decoded), ":")
	if !found {
		return "", "", false
	}
	return user, pass, true
}

// writeError writes a minimal HTTP error response and closes the connection.
// Extra headers (e.g. Proxy-Authenticate) are optional.
func (s *Server) writeError(conn net.Conn, code int, headers map[string]string) {
	body := http.StatusText(code) + "\n"
	var sb strings.Builder
	fmt.Fprintf(&sb, "HTTP/1.1 %d %s\r\n", code, http.StatusText(code))
	for k, v := range headers {
		fmt.Fprintf(&sb, "%s: %s\r\n", k, v)
	}
	fmt.Fprintf(&sb, "Content-Length: %d\r\n", len(body))
	sb.WriteString("Connection: close\r\n")
	sb.WriteString("\r\n")
	sb.WriteString(body)
	_, _ = io.WriteString(conn, sb.String())
}
