package tunproxy

import (
	"strings"
	"testing"
	"time"
)

func TestConfiguration_Validate(t *testing.T) {
	autoRoute := true
	cases := []struct {
		name    string
		cfg     Configuration
		wantErr string
	}{
		{
			name:    "missing both addresses",
			cfg:     Configuration{Backend: "b", Shim: "s"},
			wantErr: "ipv4_address or ipv6_address is required",
		},
		{
			name: "invalid ipv4 cidr",
			cfg: Configuration{
				IPv4Address: "10.0.0.1",
				Backend:     "b",
				Shim:        "s",
			},
			wantErr: "ipv4_address must be in CIDR form",
		},
		{
			name: "invalid ipv6 cidr",
			cfg: Configuration{
				IPv6Address: "fd00::1",
				Backend:     "b",
				Shim:        "s",
			},
			wantErr: "ipv6_address must be in CIDR form",
		},
		{
			name: "ipv4 field contains ipv6",
			cfg: Configuration{
				IPv4Address: "fd00::1/64",
				Backend:     "b",
				Shim:        "s",
			},
			wantErr: "ipv4_address must contain an IPv4 address",
		},
		{
			name: "ipv6 field contains ipv4",
			cfg: Configuration{
				IPv6Address: "10.0.0.1/24",
				Backend:     "b",
				Shim:        "s",
			},
			wantErr: "ipv6_address must contain an IPv6 address",
		},
		{
			name: "negative mtu",
			cfg: Configuration{
				IPv4Address: "10.0.0.1/24",
				MTU:         -1,
				Backend:     "b",
				Shim:        "s",
			},
			wantErr: "mtu must not be negative",
		},
		{
			name: "missing backend",
			cfg: Configuration{
				IPv4Address: "10.0.0.1/24",
				Shim:        "s",
			},
			wantErr: "backend or backends reference is required",
		},
		{
			name: "backend and backends conflict",
			cfg: Configuration{
				IPv4Address: "10.0.0.1/24",
				Backend:     "b",
				Backends:    []string{"b2"},
				Shim:        "s",
			},
			wantErr: "backend and backends are mutually exclusive",
		},
		{
			name: "duplicate backends",
			cfg: Configuration{
				IPv4Address: "10.0.0.1/24",
				Backends:    []string{"b", "b"},
				Shim:        "s",
			},
			wantErr: "duplicate reference",
		},
		{
			name: "negative protocol timeout",
			cfg: Configuration{
				IPv4Address:           "10.0.0.1/24",
				Backends:              []string{"b"},
				ProtocolDetectTimeout: -1,
				Shim:                  "s",
			},
			wantErr: "protocol_detect_timeout must not be negative",
		},
		{
			name: "missing shim",
			cfg: Configuration{
				IPv4Address: "10.0.0.1/24",
				Backend:     "b",
			},
			wantErr: "shim reference is required",
		},
		{
			name: "valid ipv4 only",
			cfg: Configuration{
				IPv4Address: "10.0.0.1/24",
				MTU:         1500,
				AutoRoute:   &autoRoute,
				Backend:     "b",
				Shim:        "s",
			},
		},
		{
			name: "valid ipv6 only",
			cfg: Configuration{
				IPv6Address: "fd00::1/64",
				Backend:     "b",
				Shim:        "s",
			},
		},
		{
			name: "valid dual stack",
			cfg: Configuration{
				IPv4Address: "10.0.0.1/24",
				IPv6Address: "fd00::1/64",
				Backend:     "b",
				Shim:        "s",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
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

func TestConfiguration_ServerConfigDefaults(t *testing.T) {
	autoRoute := false
	t.Run("default udp idle and auto_route", func(t *testing.T) {
		cfg := Configuration{IPv4Address: "10.0.0.1/24", Backend: "b", Shim: "s"}
		sc := cfg.ServerConfig(nil, nil, 0, nil)
		if sc.UDPIdleTimeout != defaultUDPIdle {
			t.Fatalf("UDPIdleTimeout = %v, want %v", sc.UDPIdleTimeout, defaultUDPIdle)
		}
		if !sc.AutoRoute {
			t.Fatal("AutoRoute should default to true")
		}
		if sc.ProtocolDetectTimeout != defaultProtocolDetectTimeout || sc.ProtocolDetectMaxBytes != defaultProtocolDetectMaxBytes {
			t.Fatalf("protocol detection defaults = (%v, %d)", sc.ProtocolDetectTimeout, sc.ProtocolDetectMaxBytes)
		}
	})
	t.Run("ordered backends and explicit detection limits", func(t *testing.T) {
		cfg := Configuration{
			IPv4Address:            "10.0.0.1/24",
			Backends:               []string{"first", "second"},
			ProtocolDetectTimeout:  3,
			ProtocolDetectMaxBytes: 4096,
			Shim:                   "s",
		}
		if got := cfg.BackendReferences(); len(got) != 2 || got[0] != "first" || got[1] != "second" {
			t.Fatalf("BackendReferences = %v", got)
		}
		sc := cfg.ServerConfig(nil, nil, 0, nil)
		if sc.ProtocolDetectTimeout != 3*time.Second || sc.ProtocolDetectMaxBytes != 4096 {
			t.Fatalf("protocol detection = (%v, %d)", sc.ProtocolDetectTimeout, sc.ProtocolDetectMaxBytes)
		}
	})
	t.Run("explicit auto_route false", func(t *testing.T) {
		cfg := Configuration{IPv4Address: "10.0.0.1/24", AutoRoute: &autoRoute, Backend: "b", Shim: "s"}
		sc := cfg.ServerConfig(nil, nil, 0, nil)
		if sc.AutoRoute {
			t.Fatal("AutoRoute should be false when explicitly set")
		}
	})
	t.Run("explicit udp idle", func(t *testing.T) {
		cfg := Configuration{IPv4Address: "10.0.0.1/24", UDPIdleTimeout: 10, Backend: "b", Shim: "s"}
		sc := cfg.ServerConfig(nil, nil, 0, nil)
		if sc.UDPIdleTimeout != 10*time.Second {
			t.Fatalf("UDPIdleTimeout = %v, want 10s", sc.UDPIdleTimeout)
		}
	})
}
