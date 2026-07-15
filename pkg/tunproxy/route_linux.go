//go:build linux

package tunproxy

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/puppy/pkg/common"
)

type linuxHostNetworkManager struct {
	device    string
	ipv4Addr  string
	ipv6Addr  string
	autoRoute bool
	egress4   string
	egress6   string

	configured4  bool
	configured6  bool
	routes       []linuxRoute
	applied      bool
	run          func(...string) error
	defaultRoute func(string) (string, string, error)
	routeIface   func(string, string) (string, error)
}

type linuxRoute struct {
	family string
	prefix string
}

func newHostNetworkManager(device, ipv4Addr, ipv6Addr string, autoRoute bool) hostNetworkManager {
	return &linuxHostNetworkManager{
		device: device, ipv4Addr: ipv4Addr, ipv6Addr: ipv6Addr, autoRoute: autoRoute,
		run: runLinuxIP, defaultRoute: linuxDefaultRoute, routeIface: linuxRouteInterface,
	}
}

func (m *linuxHostNetworkManager) Apply() (dialer common.Dialer, err error) {
	if m.applied {
		return nil, errors.New("tunproxy: host network already configured")
	}
	m.applied = true
	defer func() {
		if err != nil {
			err = errors.Join(err, m.Restore())
		}
	}()

	var iface4, iface6 string
	if m.autoRoute {
		if m.ipv4Addr != "" {
			_, iface4, err = m.defaultRoute("-4")
			if err != nil {
				return nil, fmt.Errorf("tunproxy: discover IPv4 default route: %w", err)
			}
			if err = m.validateEgress("-4", iface4, []string{"1.1.1.1", "8.8.8.8"}); err != nil {
				return nil, err
			}
		}
		if m.ipv6Addr != "" {
			_, iface6, err = m.defaultRoute("-6")
			if err != nil {
				return nil, fmt.Errorf("tunproxy: discover IPv6 default route: %w", err)
			}
			if err = m.validateEgress("-6", iface6, []string{"2606:4700:4700::1111", "2001:4860:4860::8888"}); err != nil {
				return nil, err
			}
		}
		m.egress4, m.egress6 = iface4, iface6
	}

	if err = m.run("link", "set", "dev", m.device, "up"); err != nil {
		return nil, fmt.Errorf("tunproxy: bring up %s: %w", m.device, err)
	}
	if m.ipv4Addr != "" {
		if err = m.run("-4", "addr", "add", m.ipv4Addr, "dev", m.device); err != nil {
			return nil, fmt.Errorf("tunproxy: add IPv4 address %s: %w", m.ipv4Addr, err)
		}
		m.configured4 = true
	}
	if m.ipv6Addr != "" {
		if err = m.run("-6", "addr", "add", m.ipv6Addr, "dev", m.device); err != nil {
			return nil, fmt.Errorf("tunproxy: add IPv6 address %s: %w", m.ipv6Addr, err)
		}
		m.configured6 = true
	}
	if !m.autoRoute {
		return common.SystemDialer(), nil
	}

	for _, route := range splitRoutes(m.ipv4Addr != "", m.ipv6Addr != "") {
		if err = m.run(route.family, "route", "add", route.prefix, "dev", m.device); err != nil {
			return nil, fmt.Errorf("tunproxy: add route %s: %w", route.prefix, err)
		}
		m.routes = append(m.routes, linuxRoute{family: route.family, prefix: route.prefix})
	}
	return newBoundDialer(iface4, iface6)
}

func (m *linuxHostNetworkManager) validateEgress(family, defaultIface string, probes []string) error {
	if isTunnelInterface(defaultIface) {
		return fmt.Errorf("tunproxy: default egress interface %s is already a tunnel; disable the existing VPN or set auto_route = false", defaultIface)
	}
	for _, destination := range probes {
		iface, err := m.routeIface(family, destination)
		if err != nil {
			return fmt.Errorf("tunproxy: inspect route to %s: %w", destination, err)
		}
		if iface != defaultIface {
			return fmt.Errorf("tunproxy: route to %s uses %s instead of default egress %s; disable the existing VPN or set auto_route = false", destination, iface, defaultIface)
		}
	}
	return nil
}

func (m *linuxHostNetworkManager) EgressInterfaces() (string, string) {
	return m.egress4, m.egress6
}

func (m *linuxHostNetworkManager) Restore() error {
	if !m.applied {
		return nil
	}
	m.applied = false
	m.egress4, m.egress6 = "", ""
	var errs []error
	for i := len(m.routes) - 1; i >= 0; i-- {
		route := m.routes[i]
		if err := m.run(route.family, "route", "del", route.prefix, "dev", m.device); err != nil {
			errs = append(errs, fmt.Errorf("delete route %s: %w", route.prefix, err))
		}
	}
	m.routes = nil
	if m.configured6 {
		if err := m.run("-6", "addr", "del", m.ipv6Addr, "dev", m.device); err != nil {
			errs = append(errs, fmt.Errorf("delete IPv6 address %s: %w", m.ipv6Addr, err))
		}
		m.configured6 = false
	}
	if m.configured4 {
		if err := m.run("-4", "addr", "del", m.ipv4Addr, "dev", m.device); err != nil {
			errs = append(errs, fmt.Errorf("delete IPv4 address %s: %w", m.ipv4Addr, err))
		}
		m.configured4 = false
	}
	return errors.Join(errs...)
}

func runLinuxIP(args ...string) error {
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func linuxDefaultRoute(family string) (gateway, iface string, err error) {
	out, err := exec.Command("ip", family, "route", "show", "default").CombinedOutput()
	if err != nil {
		return "", "", fmt.Errorf("ip %s route show default: %w: %s", family, err, strings.TrimSpace(string(out)))
	}
	return parseDefaultRoute(string(out))
}

func linuxRouteInterface(family, destination string) (string, error) {
	out, err := exec.Command("ip", family, "route", "get", destination).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("ip %s route get %s: %w: %s", family, destination, err, strings.TrimSpace(string(out)))
	}
	fields := strings.Fields(string(out))
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "dev" {
			return fields[i+1], nil
		}
	}
	return "", errors.New("route has no output interface")
}

// parseDefaultRoute selects the first default route and accepts both gateway
// and on-link defaults. Only the output interface is required for bypass.
func parseDefaultRoute(output string) (gateway, iface string, err error) {
	line := output
	if idx := strings.IndexByte(output, '\n'); idx != -1 {
		line = output[:idx]
	}
	fields := strings.Fields(strings.TrimSpace(line))
	for i := 0; i+1 < len(fields); i++ {
		switch fields[i] {
		case "via":
			gateway = fields[i+1]
		case "dev":
			iface = fields[i+1]
		}
	}
	if iface == "" {
		return "", "", errors.New("no default route interface")
	}
	return gateway, iface, nil
}
