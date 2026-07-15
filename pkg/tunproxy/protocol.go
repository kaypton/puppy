package tunproxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"time"

	"github.com/puppy/pkg/common"
)

var http2ClientPreface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

type replayConn struct {
	prefix *bytes.Reader
	io.ReadWriteCloser
}

func (c *replayConn) Read(p []byte) (int, error) {
	if c.prefix.Len() > 0 {
		return c.prefix.Read(p)
	}
	return c.ReadWriteCloser.Read(p)
}

// detectProtocol incrementally reads a client prefix. Bytes consumed during
// detection are returned through a wrapper so the shim sees the original
// stream unchanged.
func detectProtocol(ctx context.Context, conn net.Conn, timeout time.Duration, maxBytes int) (common.Protocol, io.ReadWriteCloser, error) {
	deadline := time.Now().Add(timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := conn.SetReadDeadline(deadline); err != nil {
		return common.ProtocolUnknown, conn, err
	}
	done := make(chan struct{})
	interruptDone := make(chan struct{})
	go func() {
		defer close(interruptDone)
		select {
		case <-ctx.Done():
			_ = conn.SetReadDeadline(time.Now())
		case <-done:
		}
	}()
	defer func() {
		close(done)
		<-interruptDone
		_ = conn.SetReadDeadline(time.Time{})
	}()

	prefix := make([]byte, 0, min(maxBytes, 4096))
	for len(prefix) < maxBytes {
		protocol, complete := classifyProtocol(prefix)
		if complete {
			return protocol, &replayConn{prefix: bytes.NewReader(prefix), ReadWriteCloser: conn}, nil
		}

		buf := make([]byte, min(4096, maxBytes-len(prefix)))
		n, err := conn.Read(buf)
		prefix = append(prefix, buf[:n]...)
		if err != nil {
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() && ctx.Err() == nil {
				return common.ProtocolUnknown, &replayConn{prefix: bytes.NewReader(prefix), ReadWriteCloser: conn}, nil
			}
			if ctx.Err() != nil {
				return common.ProtocolUnknown, conn, ctx.Err()
			}
			if errors.Is(err, io.EOF) && len(prefix) > 0 {
				return common.ProtocolUnknown, &replayConn{prefix: bytes.NewReader(prefix), ReadWriteCloser: conn}, nil
			}
			return common.ProtocolUnknown, conn, err
		}
	}

	protocol, complete := classifyProtocol(prefix)
	if !complete {
		protocol = common.ProtocolUnknown
	}
	return protocol, &replayConn{prefix: bytes.NewReader(prefix), ReadWriteCloser: conn}, nil
}

// classifyProtocol returns complete=false only while the prefix can still
// become a supported protocol with additional bytes.
func classifyProtocol(prefix []byte) (common.Protocol, bool) {
	if len(prefix) == 0 {
		return common.ProtocolUnknown, false
	}

	if len(prefix) >= len(http2ClientPreface) && bytes.HasPrefix(prefix, http2ClientPreface) {
		return common.ProtocolHTTP, true
	}
	if len(prefix) < len(http2ClientPreface) && bytes.Equal(prefix, http2ClientPreface[:len(prefix)]) {
		return common.ProtocolUnknown, false
	}

	if prefix[0] == 0x16 {
		if len(prefix) < 3 {
			return common.ProtocolUnknown, false
		}
		if prefix[1] != 0x03 || prefix[2] > 0x04 {
			return common.ProtocolUnknown, true
		}
		if len(prefix) < 6 {
			return common.ProtocolUnknown, false
		}
		if prefix[5] == 0x01 {
			return common.ProtocolTLS, true
		}
		return common.ProtocolUnknown, true
	}

	lineEnd := bytes.Index(prefix, []byte("\r\n"))
	line := prefix
	if lineEnd >= 0 {
		line = prefix[:lineEnd]
	}
	firstSpace := bytes.IndexByte(line, ' ')
	if firstSpace < 0 {
		for _, b := range line {
			if !isHTTPTokenByte(b) {
				return common.ProtocolUnknown, true
			}
		}
		return common.ProtocolUnknown, false
	}
	if firstSpace == 0 {
		return common.ProtocolUnknown, true
	}
	for _, b := range line[:firstSpace] {
		if !isHTTPTokenByte(b) {
			return common.ProtocolUnknown, true
		}
	}
	rest := line[firstSpace+1:]
	secondSpace := bytes.IndexByte(rest, ' ')
	if secondSpace < 0 {
		if lineEnd >= 0 {
			return common.ProtocolUnknown, true
		}
		return common.ProtocolUnknown, false
	}
	if secondSpace == 0 {
		return common.ProtocolUnknown, true
	}
	version := rest[secondSpace+1:]
	validVersion := []byte("HTTP/1.0")
	validVersion11 := []byte("HTTP/1.1")
	if len(version) > len(validVersion) ||
		(!bytes.Equal(version, validVersion[:min(len(version), len(validVersion))]) &&
			!bytes.Equal(version, validVersion11[:min(len(version), len(validVersion11))])) {
		return common.ProtocolUnknown, true
	}
	if lineEnd < 0 {
		return common.ProtocolUnknown, false
	}
	if bytes.Equal(version, validVersion) || bytes.Equal(version, validVersion11) {
		return common.ProtocolHTTP, true
	}
	return common.ProtocolUnknown, true
}

func isHTTPTokenByte(b byte) bool {
	if b >= '0' && b <= '9' || b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' {
		return true
	}
	return bytes.ContainsRune([]byte("!#$%&'*+-.^_`|~"), rune(b))
}
