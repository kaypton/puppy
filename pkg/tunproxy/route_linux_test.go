//go:build linux

package tunproxy

import (
	"strings"
	"testing"
)

func TestParseDefaultRoute(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		wantGW  string
		wantIF  string
		wantErr string
	}{
		{
			name:   "standard",
			input:  "default via 192.168.1.1 dev eth0",
			wantGW: "192.168.1.1",
			wantIF: "eth0",
		},
		{
			name:   "with metric",
			input:  "default via 10.0.0.1 dev tun0 metric 100",
			wantGW: "10.0.0.1",
			wantIF: "tun0",
		},
		{
			name:    "missing gateway",
			input:   "default dev eth0",
			wantErr: "no default gateway",
		},
		{
			name:    "empty",
			input:   "",
			wantErr: "no default gateway",
		},
		{
			name:   "multiline with extra routes",
			input:  "default via 172.16.0.1 dev eth1\n10.0.0.0/8 via 172.16.0.2 dev eth1",
			wantGW: "172.16.0.1",
			wantIF: "eth1",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gw, iface, err := parseDefaultRoute(tc.input)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %q, want %q", err.Error(), tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gw != tc.wantGW {
				t.Fatalf("gateway = %q, want %q", gw, tc.wantGW)
			}
			if iface != tc.wantIF {
				t.Fatalf("interface = %q, want %q", iface, tc.wantIF)
			}
		})
	}
}
