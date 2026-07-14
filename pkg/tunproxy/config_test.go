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
			wantErr: "backend reference is required",
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
		sc := cfg.ServerConfig(nil, 0, nil)
		if sc.UDPIdleTimeout != defaultUDPIdle {
			t.Fatalf("UDPIdleTimeout = %v, want %v", sc.UDPIdleTimeout, defaultUDPIdle)
		}
		if !sc.AutoRoute {
			t.Fatal("AutoRoute should default to true")
		}
	})
	t.Run("explicit auto_route false", func(t *testing.T) {
		cfg := Configuration{IPv4Address: "10.0.0.1/24", AutoRoute: &autoRoute, Backend: "b", Shim: "s"}
		sc := cfg.ServerConfig(nil, 0, nil)
		if sc.AutoRoute {
			t.Fatal("AutoRoute should be false when explicitly set")
		}
	})
	t.Run("explicit udp idle", func(t *testing.T) {
		cfg := Configuration{IPv4Address: "10.0.0.1/24", UDPIdleTimeout: 10, Backend: "b", Shim: "s"}
		sc := cfg.ServerConfig(nil, 0, nil)
		if sc.UDPIdleTimeout != 10*time.Second {
			t.Fatalf("UDPIdleTimeout = %v, want 10s", sc.UDPIdleTimeout)
		}
	})
}
