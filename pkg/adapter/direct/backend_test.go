package direct

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/puppy/pkg/common"
)

func TestDirectDial_UsesProvidedDialer(t *testing.T) {
	wantErr := errors.New("dial stopped")
	var gotNetwork, gotAddress string
	dialer := common.DialFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
		gotNetwork, gotAddress = network, address
		return nil, wantErr
	})

	_, err := NewBackend().Dial(context.Background(), common.Target{
		Network: "udp", Host: "192.0.2.1", Port: 53,
	}, dialer)
	if !errors.Is(err, wantErr) {
		t.Fatalf("error = %v, want %v", err, wantErr)
	}
	if gotNetwork != "udp" || gotAddress != "192.0.2.1:53" {
		t.Fatalf("dial = (%q, %q), want (udp, 192.0.2.1:53)", gotNetwork, gotAddress)
	}
}

// echoServer starts a local TCP listener that mirrors bytes back to the writer.
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

func TestDirectDial_TCP(t *testing.T) {
	addr := echoServer(t)
	host, portStr, _ := net.SplitHostPort(addr)
	port := uint16(0)
	for _, r := range portStr {
		port = port*10 + uint16(r-'0')
	}

	b := NewBackend()
	conn, err := b.Dial(context.Background(), common.Target{Network: "tcp", Host: host, Port: port}, nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	msg := []byte("direct-echo")
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

func TestDirectDial_NetworkDefaultsTCP(t *testing.T) {
	addr := echoServer(t)
	host, portStr, _ := net.SplitHostPort(addr)
	port := uint16(0)
	for _, r := range portStr {
		port = port*10 + uint16(r-'0')
	}

	b := NewBackend()
	// Network intentionally left empty; Net() should default to "tcp".
	conn, err := b.Dial(context.Background(), common.Target{Host: host, Port: port}, nil)
	if err != nil {
		t.Fatalf("Dial with empty network: %v", err)
	}
	defer conn.Close()

	msg := []byte("default-tcp")
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
