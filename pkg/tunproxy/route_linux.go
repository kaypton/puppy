//go:build linux

package tunproxy

import (
	"errors"
	"fmt"
	"hash/fnv"
	"os/exec"
	"strings"

	"github.com/puppy/pkg/common"
)

type linuxHostNetworkManager struct {
	device                   string
	ipv4Addr                 string
	ipv6Addr                 string
	autoRoute                bool
	interceptSystemdResolved bool
	egress4                  string
	egress6                  string

	configured4  bool
	configured6  bool
	routes       []linuxRoute
	nftTable     string
	nftApplied   bool
	dnsProxy     *linuxDNSProxy
	applied      bool
	run          func(...string) error
	checkNFT     func(string) error
	runNFT       func(string) error
	defaultRoute func(string) (string, string, error)
	routeIface   func(string, string) (string, error)
}

type linuxRoute struct {
	family string
	prefix string
}

func newHostNetworkManager(device, ipv4Addr, ipv6Addr string, autoRoute, interceptSystemdResolved bool) hostNetworkManager {
	return &linuxHostNetworkManager{
		device: device, ipv4Addr: ipv4Addr, ipv6Addr: ipv6Addr, autoRoute: autoRoute,
		interceptSystemdResolved: interceptSystemdResolved,
		nftTable:                 linuxNFTTableName(device),
		run:                      runLinuxIP, checkNFT: checkLinuxNFT, runNFT: runLinuxNFT,
		defaultRoute: linuxDefaultRoute, routeIface: linuxRouteInterface,
	}
}

func systemdResolvedInterceptionEnabled(autoRoute, dnsConfigured, ipv4Configured bool) bool {
	return autoRoute && dnsConfigured && ipv4Configured
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
	if m.autoRoute && m.interceptSystemdResolved {
		if err = m.checkNFT(m.nftApplyScript(1, 1)); err != nil {
			return nil, fmt.Errorf("tunproxy: validate nft DNS interception table %s (ensure nft is installed and remove any stale Puppy table): %w", m.nftTable, err)
		}
	}

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

func (m *linuxHostNetworkManager) EnableDNSInterception(handler dnsInterceptHandler) error {
	if !m.autoRoute || !m.interceptSystemdResolved {
		return nil
	}
	if !m.applied {
		return errors.New("host network must be configured before DNS interception")
	}
	if handler == nil {
		return errors.New("DNS interception handler is required")
	}
	if m.dnsProxy != nil || m.nftApplied {
		return errors.New("DNS interception is already enabled")
	}
	proxy, err := newLinuxDNSProxy(handler)
	if err != nil {
		return err
	}
	script := m.nftApplyScript(proxy.udpPort(), proxy.tcpPort())
	if err := m.checkNFT(script); err != nil {
		_ = proxy.Close()
		return fmt.Errorf("validate nft DNS interception: %w", err)
	}
	if err := m.runNFT(script); err != nil {
		_ = proxy.Close()
		return fmt.Errorf("install nft DNS interception: %w", err)
	}
	m.nftApplied = true
	m.dnsProxy = proxy
	proxy.Start()
	return nil
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
	if m.nftApplied {
		if err := m.runNFT(fmt.Sprintf("delete table ip %s\n", m.nftTable)); err != nil {
			errs = append(errs, fmt.Errorf("delete nft DNS interception table %s: %w", m.nftTable, err))
		} else {
			m.nftApplied = false
		}
	}
	if m.dnsProxy != nil {
		if err := m.dnsProxy.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close systemd-resolved DNS interceptor: %w", err))
		}
		m.dnsProxy = nil
	}
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

func (m *linuxHostNetworkManager) nftApplyScript(udpPort, tcpPort uint16) string {
	return fmt.Sprintf(`add table ip %[1]s
add chain ip %[1]s output { type nat hook output priority -100; policy accept; }
add chain ip %[1]s postrouting { type nat hook postrouting priority 100; policy accept; }
add rule ip %[1]s output meta mark != 0x%[2]x ip daddr 127.0.0.53 udp dport 53 dnat to 127.0.0.1:%[3]d
add rule ip %[1]s output meta mark != 0x%[2]x ip daddr 127.0.0.53 tcp dport 53 dnat to 127.0.0.1:%[4]d
`, m.nftTable, linuxBypassMark, udpPort, tcpPort)
}

func linuxNFTTableName(device string) string {
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(device))
	return fmt.Sprintf("puppy_tunproxy_%08x", hash.Sum32())
}

func checkLinuxNFT(script string) error {
	return runLinuxNFTCommand([]string{"--check", "--file", "-"}, script)
}

func runLinuxNFT(script string) error {
	return runLinuxNFTCommand([]string{"--file", "-"}, script)
}

func runLinuxNFTCommand(args []string, script string) error {
	path, err := exec.LookPath("nft")
	if err != nil {
		return fmt.Errorf("find nft command: %w", err)
	}
	command := exec.Command(path, args...)
	command.Stdin = strings.NewReader(script)
	out, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
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
