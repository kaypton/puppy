//go:build darwin

package tunproxy

import (
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"

	"github.com/puppy/pkg/common"
)

type darwinHostNetworkManager struct {
	device    string
	ipv4Addr  string
	ipv6Addr  string
	autoRoute bool
	egress4   string
	egress6   string

	configured4  bool
	configured6  bool
	routes       []darwinRoute
	applied      bool
	run          func(string, ...string) error
	defaultRoute func(string) (string, string, error)
	routeIface   func(string, string) (string, error)
}

type darwinRoute struct {
	family string
	prefix string
}

func newHostNetworkManager(device, ipv4Addr, ipv6Addr string, autoRoute bool) hostNetworkManager {
	return &darwinHostNetworkManager{
		device: device, ipv4Addr: ipv4Addr, ipv6Addr: ipv6Addr, autoRoute: autoRoute,
		run: runDarwin, defaultRoute: darwinDefaultRoute, routeIface: darwinRouteInterface,
	}
}

func (m *darwinHostNetworkManager) Apply() (dialer common.Dialer, err error) {
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
			_, iface4, err = m.defaultRoute("-inet")
			if err != nil {
				return nil, fmt.Errorf("tunproxy: discover IPv4 default route: %w", err)
			}
			if err = m.validateEgress("-inet", iface4, []string{"1.1.1.1", "8.8.8.8"}); err != nil {
				return nil, err
			}
		}
		if m.ipv6Addr != "" {
			_, iface6, err = m.defaultRoute("-inet6")
			if err != nil {
				return nil, fmt.Errorf("tunproxy: discover IPv6 default route: %w", err)
			}
			if err = m.validateEgress("-inet6", iface6, []string{"2606:4700:4700::1111", "2001:4860:4860::8888"}); err != nil {
				return nil, err
			}
		}
		m.egress4, m.egress6 = iface4, iface6
	}

	if m.ipv4Addr != "" {
		ip, mask, parseErr := darwinIPv4Parts(m.ipv4Addr)
		if parseErr != nil {
			return nil, parseErr
		}
		if err = m.run("ifconfig", m.device, "inet", ip, ip, "netmask", mask, "up"); err != nil {
			return nil, fmt.Errorf("tunproxy: add IPv4 address %s: %w", m.ipv4Addr, err)
		}
		m.configured4 = true
	}
	if m.ipv6Addr != "" {
		ip, network, parseErr := net.ParseCIDR(m.ipv6Addr)
		if parseErr != nil {
			return nil, fmt.Errorf("tunproxy: parse IPv6 address %s: %w", m.ipv6Addr, parseErr)
		}
		prefix, _ := network.Mask.Size()
		if err = m.run("ifconfig", m.device, "inet6", ip.String(), "prefixlen", strconv.Itoa(prefix), "alias"); err != nil {
			return nil, fmt.Errorf("tunproxy: add IPv6 address %s: %w", m.ipv6Addr, err)
		}
		m.configured6 = true
	}
	if !m.autoRoute {
		return common.SystemDialer(), nil
	}

	for _, route := range splitRoutes(m.ipv4Addr != "", m.ipv6Addr != "") {
		family := "-inet"
		if route.family == "-6" {
			family = "-inet6"
		}
		if err = m.run("route", "-n", "add", family, "-net", route.prefix, "-interface", m.device); err != nil {
			return nil, fmt.Errorf("tunproxy: add route %s: %w", route.prefix, err)
		}
		m.routes = append(m.routes, darwinRoute{family: family, prefix: route.prefix})
	}
	return newBoundDialer(iface4, iface6)
}

func (m *darwinHostNetworkManager) validateEgress(family, defaultIface string, probes []string) error {
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

func (m *darwinHostNetworkManager) EgressInterfaces() (string, string) {
	return m.egress4, m.egress6
}

func (m *darwinHostNetworkManager) Restore() error {
	if !m.applied {
		return nil
	}
	m.applied = false
	m.egress4, m.egress6 = "", ""
	var errs []error
	for i := len(m.routes) - 1; i >= 0; i-- {
		route := m.routes[i]
		if err := m.run("route", "-n", "delete", route.family, "-net", route.prefix, "-interface", m.device); err != nil {
			errs = append(errs, fmt.Errorf("delete route %s: %w", route.prefix, err))
		}
	}
	m.routes = nil
	if m.configured6 {
		ip, _, _ := net.ParseCIDR(m.ipv6Addr)
		if err := m.run("ifconfig", m.device, "inet6", ip.String(), "-alias"); err != nil {
			errs = append(errs, fmt.Errorf("delete IPv6 address %s: %w", m.ipv6Addr, err))
		}
		m.configured6 = false
	}
	if m.configured4 {
		ip, _, _ := net.ParseCIDR(m.ipv4Addr)
		if err := m.run("ifconfig", m.device, "inet", ip.String(), "-alias"); err != nil {
			errs = append(errs, fmt.Errorf("delete IPv4 address %s: %w", m.ipv4Addr, err))
		}
		m.configured4 = false
	}
	return errors.Join(errs...)
}

func darwinIPv4Parts(cidr string) (string, string, error) {
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil || ip.To4() == nil {
		return "", "", fmt.Errorf("tunproxy: parse IPv4 address %s", cidr)
	}
	mask := net.IP(network.Mask).String()
	return ip.String(), mask, nil
}

func runDarwin(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func darwinDefaultRoute(family string) (gateway, iface string, err error) {
	out, err := exec.Command("route", "-n", "get", family, "default").CombinedOutput()
	if err != nil {
		return "", "", fmt.Errorf("route get %s default: %w: %s", family, err, strings.TrimSpace(string(out)))
	}
	return parseDarwinDefaultRoute(string(out))
}

func darwinRouteInterface(family, destination string) (string, error) {
	out, err := exec.Command("route", "-n", "get", family, destination).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("route get %s %s: %w: %s", family, destination, err, strings.TrimSpace(string(out)))
	}
	_, iface, err := parseDarwinDefaultRoute(string(out))
	return iface, err
}

func parseDarwinDefaultRoute(output string) (gateway, iface string, err error) {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "gateway:") {
			gateway = strings.TrimSpace(strings.TrimPrefix(line, "gateway:"))
		}
		if strings.HasPrefix(line, "interface:") {
			iface = strings.TrimSpace(strings.TrimPrefix(line, "interface:"))
		}
	}
	if iface == "" {
		return "", "", errors.New("no default route interface")
	}
	return gateway, iface, nil
}
