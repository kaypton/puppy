//go:build linux

package tunproxy

import (
	"errors"
	"fmt"
	"io"
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

func TestSystemdResolvedInterceptionEnabled(t *testing.T) {
	cases := []struct {
		name                       string
		autoRoute, dns, ipv4, want bool
	}{
		{name: "all enabled", autoRoute: true, dns: true, ipv4: true, want: true},
		{name: "manual routes", dns: true, ipv4: true},
		{name: "no DNS redirect", autoRoute: true, ipv4: true},
		{name: "IPv6 only", autoRoute: true, dns: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := systemdResolvedInterceptionEnabled(tc.autoRoute, tc.dns, tc.ipv4); got != tc.want {
				t.Fatalf("enabled = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestLinuxHostNetworkManager_InterceptsSystemdResolvedTransactionally(t *testing.T) {
	var events []string
	var appliedScript string
	m := &linuxHostNetworkManager{
		device: "tun9", ipv4Addr: "10.0.0.1/24", autoRoute: true,
		interceptSystemdResolved: true,
		nftTable:                 linuxNFTTableName("tun9"),
		run: func(args ...string) error {
			events = append(events, "ip "+strings.Join(args, " "))
			return nil
		},
		checkNFT: func(script string) error {
			events = append(events, "nft check")
			return nil
		},
		runNFT: func(script string) error {
			if strings.HasPrefix(script, "add table") {
				events = append(events, "nft add")
				appliedScript = script
			} else {
				events = append(events, "nft delete")
				want := "delete table ip " + linuxNFTTableName("tun9") + "\n"
				if script != want {
					t.Fatalf("delete script = %q, want %q", script, want)
				}
			}
			return nil
		},
		defaultRoute: func(string) (string, string, error) { return "192.0.2.1", "lo", nil },
		routeIface:   func(string, string) (string, error) { return "lo", nil },
	}

	if _, err := m.Apply(); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if err := m.EnableDNSInterception(noopDNSInterceptHandler{}); err != nil {
		t.Fatalf("EnableDNSInterception: %v", err)
	}
	assertSystemdResolvedNFTScript(t, appliedScript, linuxNFTTableName("tun9"), m.dnsProxy.udpPort(), m.dnsProxy.tcpPort())
	if err := m.Restore(); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	checkIndex := indexOf(events, "nft check")
	linkIndex := indexOf(events, "ip link set dev tun9 up")
	addIndex := indexOf(events, "nft add")
	lastRouteIndex := indexOf(events, "ip -4 route add 128.0.0.0/1 dev tun9")
	deleteIndex := indexOf(events, "nft delete")
	firstRouteDeleteIndex := indexOf(events, "ip -4 route del 128.0.0.0/1 dev tun9")
	if checkIndex < 0 || linkIndex < 0 || lastRouteIndex < 0 || addIndex < 0 || deleteIndex < 0 || firstRouteDeleteIndex < 0 ||
		!(checkIndex < linkIndex && lastRouteIndex < addIndex && addIndex < deleteIndex && deleteIndex < firstRouteDeleteIndex) {
		t.Fatalf("transaction order = %v", events)
	}
}

func TestLinuxHostNetworkManager_NFTPreflightFailsBeforeMutation(t *testing.T) {
	mutated := false
	m := &linuxHostNetworkManager{
		device: "tun9", ipv4Addr: "10.0.0.1/24", autoRoute: true,
		interceptSystemdResolved: true,
		nftTable:                 linuxNFTTableName("tun9"),
		run:                      func(...string) error { mutated = true; return nil },
		checkNFT:                 func(string) error { return errors.New("nft unavailable") },
		runNFT:                   func(string) error { mutated = true; return nil },
	}

	_, err := m.Apply()
	if err == nil || !strings.Contains(err.Error(), "validate nft DNS interception") {
		t.Fatalf("Apply error = %v, want nft preflight context", err)
	}
	if mutated {
		t.Fatal("host network was mutated after nft preflight failure")
	}
}

func TestLinuxHostNetworkManager_NFTApplyFailureLeavesNoListener(t *testing.T) {
	var commands []string
	m := &linuxHostNetworkManager{
		device: "tun9", ipv4Addr: "10.0.0.1/24", autoRoute: true,
		interceptSystemdResolved: true,
		nftTable:                 linuxNFTTableName("tun9"),
		run: func(args ...string) error {
			commands = append(commands, strings.Join(args, " "))
			return nil
		},
		checkNFT:     func(string) error { return nil },
		runNFT:       func(string) error { return errors.New("injected nft failure") },
		defaultRoute: func(string) (string, string, error) { return "192.0.2.1", "lo", nil },
		routeIface:   func(string, string) (string, error) { return "lo", nil },
	}

	if _, err := m.Apply(); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	err := m.EnableDNSInterception(noopDNSInterceptHandler{})
	if err == nil || !strings.Contains(err.Error(), "install nft DNS interception") {
		t.Fatalf("EnableDNSInterception error = %v", err)
	}
	if m.nftApplied || m.dnsProxy != nil {
		t.Fatalf("failed interception remains active: nft=%t proxy=%v", m.nftApplied, m.dnsProxy)
	}
	if err := m.Restore(); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if indexOf(commands, "-4 route del 128.0.0.0/1 dev tun9") < 0 {
		t.Fatalf("routes were not restored: %v", commands)
	}
}

func TestLinuxNFTTableName(t *testing.T) {
	first := linuxNFTTableName("tun-with.dots")
	if first != linuxNFTTableName("tun-with.dots") {
		t.Fatal("table name is not deterministic")
	}
	if first == linuxNFTTableName("tun-other") {
		t.Fatal("different device names produced the same test table name")
	}
	if !strings.HasPrefix(first, "puppy_tunproxy_") {
		t.Fatalf("table name = %q, want puppy prefix", first)
	}
}

func assertSystemdResolvedNFTScript(t *testing.T, script, table string, udpPort, tcpPort uint16) {
	t.Helper()
	for _, want := range []string{
		"add table ip " + table,
		"type nat hook output priority -100",
		"type nat hook postrouting priority 100",
		"meta mark != 0x50555059",
		fmt.Sprintf("ip daddr 127.0.0.53 udp dport 53 dnat to 127.0.0.1:%d", udpPort),
		fmt.Sprintf("ip daddr 127.0.0.53 tcp dport 53 dnat to 127.0.0.1:%d", tcpPort),
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("nft script missing %q:\n%s", want, script)
		}
	}
}

type noopDNSInterceptHandler struct{}

func (noopDNSInterceptHandler) serveInterceptedDNSStream(io.ReadWriteCloser) {}

func (noopDNSInterceptHandler) resolveInterceptedDNSDatagram([]byte) ([]byte, error) {
	return nil, errors.New("not implemented")
}

func indexOf(values []string, target string) int {
	for i, value := range values {
		if value == target {
			return i
		}
	}
	return -1
}
