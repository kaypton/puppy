package common

import (
	"net/netip"
	"testing"
)

func TestNormalizeListenAddress(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"empty", "", "", true},
		{"hostname", "localhost", "localhost", false},
		{"ipv4", "127.0.0.1", "127.0.0.1", false},
		{"ipv4 dotted quad", "0.0.0.0", "0.0.0.0", false},
		{"ipv4 leading zeros", "127.000.000.001", "", true},
		{"bare ipv6", "::1", "", true},
		{"bracketed ipv6", "[::1]", "[::1]", false},
		{"full ipv6", "2001:db8::1", "", true},
		{"bracketed full ipv6", "[2001:db8::1]", "[2001:db8::1]", false},
		{"unspecified ipv6", "[::]", "[::]", false},
		{"ipv6 with port", "[::1]:8080", "", true},
		{"unclosed bracket left", "[::1", "", true},
		{"unclosed bracket right", "::1]", "", true},
		{"ipv6 with zone", "fe80::1%eth0", "", true},
		{"bracketed ipv6 with zone", "[fe80::1%eth0]", "", true},
		{"ipv4-mapped", "::ffff:127.0.0.1", "", true},
		{"bracketed ipv4-mapped", "[::ffff:127.0.0.1]", "", true},
		{"bracketed ipv4", "[127.0.0.1]", "", true},
		{"invalid", "not-an-address", "not-an-address", false},
		{"invalid ip with colon", "1:2:3", "", true},
		{"hostname with colon", "proxy.example.com:8080", "", true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := NormalizeListenAddress(test.input)
			if (err != nil) != test.wantErr {
				t.Fatalf("NormalizeListenAddress(%q) error = %v, wantErr = %v", test.input, err, test.wantErr)
			}
			if got != test.want {
				t.Fatalf("NormalizeListenAddress(%q) = %q, want %q", test.input, got, test.want)
			}
		})
	}
}

func TestNormalizeProxyAddress(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{"empty", "", "", true},
		{"hostname", "proxy.example.com:3128", "proxy.example.com:3128", false},
		{"ipv4", "127.0.0.1:3128", "127.0.0.1:3128", false},
		{"ipv4 leading zeros", "127.000.000.001:3128", "", true},
		{"bracketed ipv6", "[2001:db8::1]:1080", "[2001:db8::1]:1080", false},
		{"bracketed ipv6 local", "[::1]:1080", "[::1]:1080", false},
		{"unspecified ipv6", "[::]:1080", "[::]:1080", false},
		{"bracketed ipv6 without port", "[::1]", "", true},
		{"bare ipv6 invalid", "2001:db8::1:1080", "", true},
		{"missing host port", ":3128", "", true},
		{"missing port", "proxy.example.com", "", true},
		{"zero port", "proxy.example.com:0", "", true},
		{"max port", "proxy.example.com:65535", "proxy.example.com:65535", false},
		{"out of range port", "proxy.example.com:65536", "", true},
		{"ipv6 with zone", "[fe80::1%eth0]:1080", "", true},
		{"ipv4-mapped", "[::ffff:127.0.0.1]:1080", "", true},
		{"uppercase ipv6", "[2001:DB8::1]:1080", "[2001:db8::1]:1080", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := NormalizeProxyAddress(test.input)
			if (err != nil) != test.wantErr {
				t.Fatalf("NormalizeProxyAddress(%q) error = %v, wantErr = %v", test.input, err, test.wantErr)
			}
			if got != test.want {
				t.Fatalf("NormalizeProxyAddress(%q) = %q, want %q", test.input, got, test.want)
			}
		})
	}
}

func TestNormalizeListenAddressCanonicalizesIPv6(t *testing.T) {
	addr, err := NormalizeListenAddress("[2001:0DB8:0000:0000:0000:0000:0000:0001]")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if addr != "[2001:db8::1]" {
		t.Fatalf("got %q, want [2001:db8::1]", addr)
	}
	ip, err := netip.ParseAddr(addr[1 : len(addr)-1])
	if err != nil {
		t.Fatalf("result %q is not a valid IP: %v", addr, err)
	}
	if ip.Zone() != "" {
		t.Fatalf("result must not contain a zone")
	}
}

func TestNormalizeProxyAddressCanonicalizesIPv6(t *testing.T) {
	addr, err := NormalizeProxyAddress("[2001:0DB8:0000:0000:0000:0000:0000:0001]:8080")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if addr != "[2001:db8::1]:8080" {
		t.Fatalf("got %q, want [2001:db8::1]:8080", addr)
	}
}
