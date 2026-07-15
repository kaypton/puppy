//go:build linux

package tunproxy

import (
	"errors"
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
			name:   "on-link default",
			input:  "default dev eth0",
			wantIF: "eth0",
		},
		{
			name:    "empty",
			input:   "",
			wantErr: "no default route interface",
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

func TestLinuxHostNetworkManager_ApplyAndRestore(t *testing.T) {
	var commands []string
	m := &linuxHostNetworkManager{
		device:    "tun9",
		ipv4Addr:  "10.0.0.1/24",
		ipv6Addr:  "fd00::1/64",
		autoRoute: true,
		run: func(args ...string) error {
			commands = append(commands, strings.Join(args, " "))
			return nil
		},
		defaultRoute: func(family string) (string, string, error) {
			return "192.0.2.1", "lo", nil
		},
		routeIface: func(family, destination string) (string, error) { return "lo", nil },
	}

	if _, err := m.Apply(); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if err := m.Restore(); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	want := []string{
		"link set dev tun9 up",
		"-4 addr add 10.0.0.1/24 dev tun9",
		"-6 addr add fd00::1/64 dev tun9",
		"-4 route add 0.0.0.0/1 dev tun9",
		"-4 route add 128.0.0.0/1 dev tun9",
		"-6 route add ::/1 dev tun9",
		"-6 route add 8000::/1 dev tun9",
		"-6 route del 8000::/1 dev tun9",
		"-6 route del ::/1 dev tun9",
		"-4 route del 128.0.0.0/1 dev tun9",
		"-4 route del 0.0.0.0/1 dev tun9",
		"-6 addr del fd00::1/64 dev tun9",
		"-4 addr del 10.0.0.1/24 dev tun9",
	}
	if strings.Join(commands, "\n") != strings.Join(want, "\n") {
		t.Fatalf("commands:\n%s\nwant:\n%s", strings.Join(commands, "\n"), strings.Join(want, "\n"))
	}
}

func TestLinuxHostNetworkManager_RollsBackPartialApply(t *testing.T) {
	var commands []string
	m := &linuxHostNetworkManager{
		device:    "tun9",
		ipv4Addr:  "10.0.0.1/24",
		autoRoute: true,
		run: func(args ...string) error {
			command := strings.Join(args, " ")
			commands = append(commands, command)
			if command == "-4 route add 128.0.0.0/1 dev tun9" {
				return errors.New("injected failure")
			}
			return nil
		},
		defaultRoute: func(family string) (string, string, error) {
			return "192.0.2.1", "lo", nil
		},
		routeIface: func(family, destination string) (string, error) { return "lo", nil },
	}

	if _, err := m.Apply(); err == nil || !strings.Contains(err.Error(), "injected failure") {
		t.Fatalf("Apply error = %v, want injected failure", err)
	}
	if m.applied {
		t.Fatal("manager remains applied after rollback")
	}
	wantTail := []string{
		"-4 route del 0.0.0.0/1 dev tun9",
		"-4 addr del 10.0.0.1/24 dev tun9",
	}
	gotTail := commands[len(commands)-len(wantTail):]
	if strings.Join(gotTail, "\n") != strings.Join(wantTail, "\n") {
		t.Fatalf("rollback = %v, want %v", gotTail, wantTail)
	}
}

func TestLinuxHostNetworkManager_RejectsExistingVPNBeforeMutation(t *testing.T) {
	mutated := false
	m := &linuxHostNetworkManager{
		device: "tun9", ipv4Addr: "10.0.0.1/24", autoRoute: true,
		run: func(args ...string) error { mutated = true; return nil },
		defaultRoute: func(string) (string, string, error) {
			return "192.0.2.1", "eth0", nil
		},
		routeIface: func(string, string) (string, error) { return "tun8", nil },
	}
	_, err := m.Apply()
	if err == nil || !strings.Contains(err.Error(), "existing VPN") {
		t.Fatalf("Apply error = %v, want existing VPN conflict", err)
	}
	if mutated {
		t.Fatal("host network was mutated before VPN conflict was rejected")
	}
}
