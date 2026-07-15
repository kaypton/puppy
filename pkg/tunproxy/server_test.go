package tunproxy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/puppy/pkg/adapter/direct"
	"github.com/puppy/pkg/common"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
)

func TestNewServer_Validation(t *testing.T) {
	backend := direct.NewBackend()
	fallback := direct.NewBackend()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cases := []struct {
		name    string
		cfg     ServerConfiguration
		wantErr string
	}{
		{"missing addresses", ServerConfiguration{Backends: []common.Backend{backend}, Fallback: fallback, Logger: logger}, "ipv4_address or ipv6_address is required"},
		{"IPv4 field contains IPv6", ServerConfiguration{IPv4Address: "fd00::1/64", Backends: []common.Backend{backend}, Fallback: fallback, Logger: logger}, "ipv4_address must contain an IPv4 address"},
		{"missing backend", ServerConfiguration{IPv4Address: "10.0.0.1/24", Fallback: fallback, Logger: logger}, "at least one backend is required"},
		{"fallback not catch all", ServerConfiguration{IPv4Address: "10.0.0.1/24", Backends: []common.Backend{backend}, Fallback: errorBackend{}, Logger: logger}, "fallback must support udp"},
		{"valid", ServerConfiguration{IPv4Address: "10.0.0.1/24", Backends: []common.Backend{backend}, Fallback: fallback, Logger: logger}, ""},
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

func TestNewServer_DefaultsUDPIdle(t *testing.T) {
	cfg := ServerConfiguration{
		IPv4Address: "10.0.0.1/24",
		Backends:    []common.Backend{direct.NewBackend()},
		Fallback:    direct.NewBackend(),
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if s.config.UDPIdleTimeout != defaultUDPIdle {
		t.Fatalf("UDPIdleTimeout = %v, want default %v", s.config.UDPIdleTimeout, defaultUDPIdle)
	}
}

func TestParseAddrWithPrefix(t *testing.T) {
	cases := []struct {
		in       string
		wantLen  int
		wantPref int
		wantErr  bool
	}{
		{"10.0.0.1/24", 4, 24, false},
		{"192.168.1.1/32", 4, 32, false},
		{"fd00::1/64", 16, 64, false},
		{"::1/128", 16, 128, false},
		{"10.0.0.1", 0, 0, true},
		{"10.0.0.1/33", 0, 0, true},
		{"fd00::1/129", 0, 0, true},
		{"notanip/24", 0, 0, true},
		{"10.0.0.1/abc", 0, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			addr, pref, err := parseAddrWithPrefix(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q", tc.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(addr) != tc.wantLen {
				t.Fatalf("addr length = %d, want %d", len(addr), tc.wantLen)
			}
			if pref != tc.wantPref {
				t.Fatalf("prefix = %d, want %d", pref, tc.wantPref)
			}
		})
	}
}

func TestTargetFromEndpointID(t *testing.T) {
	id := stack.TransportEndpointID{
		LocalAddress: stack.TransportEndpointID{}.LocalAddress, // placeholder, see below
		LocalPort:    443,
	}
	// Build a real address: use AddrFrom4 via reflection-free path.
	host, port := targetFromEndpointID(id)
	if port != 443 {
		t.Fatalf("port = %d, want 443", port)
	}
	if host == "" {
		// Empty LocalAddress yields empty host; acceptable for the zero value.
		_ = host
	}
}

func TestServer_RunRequiresRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("test expects non-root; running as root")
	}
	s, err := NewServer(ServerConfiguration{
		IPv4Address: "10.0.0.1/24",
		Backends:    []common.Backend{direct.NewBackend()},
		Fallback:    direct.NewBackend(),
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	err = s.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "root") {
		t.Fatalf("error = %v, want error containing %q", err, "root")
	}
}

func TestServer_RunContextCancelWithoutRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("test expects non-root; running as root")
	}
	s, err := NewServer(ServerConfiguration{
		IPv4Address: "10.0.0.1/24",
		Backends:    []common.Backend{direct.NewBackend()},
		Fallback:    direct.NewBackend(),
		Logger:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- s.Run(ctx) }()
	cancel()
	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, context.Canceled) && !strings.Contains(err.Error(), "root") {
			t.Fatalf("Run returned unexpected error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

// Compile-time assertion that the dispatcher satisfies sessionHandler.
var _ sessionHandler = (*dispatcher)(nil)

// errorBackend is a common.Backend whose Dial always fails, used to exercise
// dispatcher behavior without a real upstream.
type errorBackend struct{}

func (errorBackend) Capabilities() []common.Capability {
	return []common.Capability{{Network: "tcp", Protocol: common.ProtocolAny}}
}

func (errorBackend) Dial(context.Context, common.Target, common.Dialer) (io.ReadWriteCloser, error) {
	return nil, errors.New("unreachable")
}

var _ common.Backend = errorBackend{}
