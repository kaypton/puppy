//go:build darwin

package tunproxy

import (
	"strings"
	"testing"
)

func TestParseDarwinDefaultRoute(t *testing.T) {
	gateway, iface, err := parseDarwinDefaultRoute(`
   route to: default
destination: default
       mask: default
    gateway: 192.0.2.1
  interface: en0
`)
	if err != nil {
		t.Fatalf("parseDarwinDefaultRoute: %v", err)
	}
	if gateway != "192.0.2.1" || iface != "en0" {
		t.Fatalf("route = (%q, %q), want (192.0.2.1, en0)", gateway, iface)
	}
}

func TestDarwinHostNetworkManager_ApplyAndRestore(t *testing.T) {
	var commands []string
	m := &darwinHostNetworkManager{
		device:    "utun9",
		ipv4Addr:  "10.0.0.1/24",
		ipv6Addr:  "fd00::1/64",
		autoRoute: true,
		run: func(name string, args ...string) error {
			commands = append(commands, name+" "+strings.Join(args, " "))
			return nil
		},
		defaultRoute: func(family string) (string, string, error) {
			return "192.0.2.1", "lo0", nil
		},
		routeIface: func(family, destination string) (string, error) { return "lo0", nil },
	}

	if _, err := m.Apply(); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if err := m.Restore(); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	want := []string{
		"ifconfig utun9 inet 10.0.0.1 10.0.0.1 netmask 255.255.255.0 up",
		"ifconfig utun9 inet6 fd00::1 prefixlen 64 alias",
		"route -n add -inet -net 0.0.0.0/1 -interface utun9",
		"route -n add -inet -net 128.0.0.0/1 -interface utun9",
		"route -n add -inet6 -net ::/1 -interface utun9",
		"route -n add -inet6 -net 8000::/1 -interface utun9",
		"route -n delete -inet6 -net 8000::/1 -interface utun9",
		"route -n delete -inet6 -net ::/1 -interface utun9",
		"route -n delete -inet -net 128.0.0.0/1 -interface utun9",
		"route -n delete -inet -net 0.0.0.0/1 -interface utun9",
		"ifconfig utun9 inet6 fd00::1 -alias",
		"ifconfig utun9 inet 10.0.0.1 -alias",
	}
	if strings.Join(commands, "\n") != strings.Join(want, "\n") {
		t.Fatalf("commands:\n%s\nwant:\n%s", strings.Join(commands, "\n"), strings.Join(want, "\n"))
	}
}

func TestDarwinHostNetworkManager_RejectsExistingVPNBeforeMutation(t *testing.T) {
	mutated := false
	m := &darwinHostNetworkManager{
		device: "utun9", ipv4Addr: "10.0.0.1/24", autoRoute: true,
		run: func(name string, args ...string) error { mutated = true; return nil },
		defaultRoute: func(string) (string, string, error) {
			return "192.0.2.1", "en0", nil
		},
		routeIface: func(string, string) (string, error) { return "utun8", nil },
	}
	_, err := m.Apply()
	if err == nil || !strings.Contains(err.Error(), "existing VPN") {
		t.Fatalf("Apply error = %v, want existing VPN conflict", err)
	}
	if mutated {
		t.Fatal("host network was mutated before VPN conflict was rejected")
	}
}
