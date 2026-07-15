package tunproxy

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/puppy/pkg/common"
)

func TestClassifyProtocol(t *testing.T) {
	tests := []struct {
		name     string
		prefix   []byte
		protocol common.Protocol
		complete bool
	}{
		{"partial HTTP method", []byte("GE"), common.ProtocolUnknown, false},
		{"partial HTTP request line", []byte("GET / HTTP/1."), common.ProtocolUnknown, false},
		{"HTTP 1.1", []byte("GET / HTTP/1.1\r\n"), common.ProtocolHTTP, true},
		{"HTTP 1.0", []byte("POST /submit HTTP/1.0\r\n"), common.ProtocolHTTP, true},
		{"partial HTTP2", http2ClientPreface[:8], common.ProtocolUnknown, false},
		{"HTTP2", http2ClientPreface, common.ProtocolHTTP, true},
		{"HTTP2 with first frame", append(append([]byte(nil), http2ClientPreface...), 0x00, 0x00, 0x00), common.ProtocolHTTP, true},
		{"partial TLS", []byte{0x16, 0x03, 0x03, 0x00, 0x10}, common.ProtocolUnknown, false},
		{"TLS client hello", []byte{0x16, 0x03, 0x03, 0x00, 0x10, 0x01}, common.ProtocolTLS, true},
		{"TLS non-client handshake", []byte{0x16, 0x03, 0x03, 0x00, 0x10, 0x02}, common.ProtocolUnknown, true},
		{"unknown", []byte{0x01, 0x02}, common.ProtocolUnknown, true},
		{"invalid HTTP version", []byte("GET / FTP/1.0\r\n"), common.ProtocolUnknown, true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			protocol, complete := classifyProtocol(test.prefix)
			if protocol != test.protocol || complete != test.complete {
				t.Fatalf("classifyProtocol() = (%q, %t), want (%q, %t)", protocol, complete, test.protocol, test.complete)
			}
		})
	}
}

func TestDetectProtocol_PreservesFragmentedPrefix(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	payload := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\nbody")
	go func() {
		_, _ = client.Write(payload[:2])
		time.Sleep(10 * time.Millisecond)
		_, _ = client.Write(payload[2:])
	}()

	protocol, replay, err := detectProtocol(context.Background(), server, time.Second, 16*1024)
	if err != nil {
		t.Fatalf("detectProtocol: %v", err)
	}
	if protocol != common.ProtocolHTTP {
		t.Fatalf("protocol = %q, want %q", protocol, common.ProtocolHTTP)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(replay, got); err != nil {
		t.Fatalf("read replay: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("replayed bytes = %q, want %q", got, payload)
	}
}

func TestDetectProtocol_TimeoutReturnsUnknownAndPrefix(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() { _, _ = client.Write([]byte("GE")) }()
	protocol, replay, err := detectProtocol(context.Background(), server, 20*time.Millisecond, 16*1024)
	if err != nil {
		t.Fatalf("detectProtocol: %v", err)
	}
	if protocol != common.ProtocolUnknown {
		t.Fatalf("protocol = %q, want unknown", protocol)
	}
	got := make([]byte, 2)
	if _, err := io.ReadFull(replay, got); err != nil {
		t.Fatalf("read replay: %v", err)
	}
	if string(got) != "GE" {
		t.Fatalf("replayed bytes = %q, want GE", got)
	}
}

func TestDetectProtocol_MaxBytesReturnsUnknown(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() { _, _ = client.Write([]byte("GET / HTTP/1.1\r\n")) }()
	protocol, replay, err := detectProtocol(context.Background(), server, time.Second, 8)
	if err != nil {
		t.Fatalf("detectProtocol: %v", err)
	}
	if protocol != common.ProtocolUnknown {
		t.Fatalf("protocol = %q, want unknown", protocol)
	}
	got := make([]byte, 8)
	if _, err := io.ReadFull(replay, got); err != nil {
		t.Fatalf("read replay: %v", err)
	}
	if string(got) != "GET / HT" {
		t.Fatalf("replayed bytes = %q, want %q", got, "GET / HT")
	}
}
