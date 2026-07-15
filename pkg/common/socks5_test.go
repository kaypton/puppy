package common

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestSOCKS5ReplyText(t *testing.T) {
	cases := []struct {
		rep  byte
		want string
	}{
		{SOCKS5RepSuccess, "succeeded"},
		{SOCKS5RepGeneralFailure, "general SOCKS server failure"},
		{SOCKS5RepConnectionNotAllowed, "connection not allowed by ruleset"},
		{SOCKS5RepNetworkUnreachable, "network unreachable"},
		{SOCKS5RepHostUnreachable, "host unreachable"},
		{SOCKS5RepConnectionRefused, "connection refused"},
		{SOCKS5RepTTLExpired, "TTL expired"},
		{SOCKS5RepCmdNotSupported, "command not supported"},
		{SOCKS5RepAddrTypeNotSupported, "address type not supported"},
		{0xFF, "unknown error"},
	}
	for _, tc := range cases {
		got := SOCKS5ReplyText(tc.rep)
		if !strings.Contains(got, tc.want) {
			t.Fatalf("SOCKS5ReplyText(0x%02x) = %q, want substring %q", tc.rep, got, tc.want)
		}
	}
}

func TestReadSOCKS5Address(t *testing.T) {
	cases := []struct {
		name     string
		atyp     byte
		input    []byte
		wantHost string
		wantPort uint16
		wantErr  string
	}{
		{
			name:     "ipv4",
			atyp:     SOCKS5AtypIPv4,
			input:    []byte{127, 0, 0, 1, 0x1F, 0x90},
			wantHost: "127.0.0.1",
			wantPort: 8080,
		},
		{
			name:     "ipv6",
			atyp:     SOCKS5AtypIPv6,
			input:    []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x01, 0xBB},
			wantHost: "::1",
			wantPort: 443,
		},
		{
			name:     "domain",
			atyp:     SOCKS5AtypDomain,
			input:    []byte{11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 0x00, 0x50},
			wantHost: "example.com",
			wantPort: 80,
		},
		{
			name:    "unknown atyp",
			atyp:    0x09,
			input:   []byte{1, 2},
			wantErr: "unknown address type 0x09",
		},
		{
			name:    "ipv4 short",
			atyp:    SOCKS5AtypIPv4,
			input:   []byte{127, 0, 0},
			wantErr: "read IPv4 address",
		},
		{
			name:    "domain length short",
			atyp:    SOCKS5AtypDomain,
			input:   []byte{},
			wantErr: "read domain length",
		},
		{
			name:    "domain body short",
			atyp:    SOCKS5AtypDomain,
			input:   []byte{5, 'a', 'b'},
			wantErr: "read domain",
		},
		{
			name:    "port short",
			atyp:    SOCKS5AtypIPv4,
			input:   []byte{127, 0, 0, 1, 0x1F},
			wantErr: "read port",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			host, port, err := ReadSOCKS5Address(bytes.NewReader(tc.input), tc.atyp)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %v, want substring %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if host != tc.wantHost {
				t.Fatalf("host = %q, want %q", host, tc.wantHost)
			}
			if port != tc.wantPort {
				t.Fatalf("port = %d, want %d", port, tc.wantPort)
			}
		})
	}
}

func TestReadSOCKS5AddressEOF(t *testing.T) {
	_, _, err := ReadSOCKS5Address(errReader{}, SOCKS5AtypIPv4)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("error = %v, want io.EOF", err)
	}
}

type errReader struct{}

func (errReader) Read(p []byte) (int, error) { return 0, io.EOF }
