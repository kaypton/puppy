//go:build linux

package tunproxy

import (
	"fmt"
	"os/exec"
	"strings"
)

// linuxRouteManager installs the TUN device as the default route on Linux and
// restores the original default gateway on cleanup.
type linuxRouteManager struct {
	device   string
	gateway  string
	oldIface string
	applied  bool
}

func newRouteManager(device, ipv4Addr string) routeManager {
	return &linuxRouteManager{device: device}
}

// Apply captures the current default route, then replaces it with one through
// the TUN device.
func (r *linuxRouteManager) Apply() error {
	gw, iface, err := r.currentDefault()
	if err != nil {
		r.gateway = ""
		r.oldIface = ""
	} else {
		r.gateway = gw
		r.oldIface = iface
	}

	if out, err := exec.Command("ip", "route", "add", "default", "dev", r.device).CombinedOutput(); err != nil {
		// If a default route already exists via the tun, replace it.
		if replaceErr := exec.Command("ip", "route", "replace", "default", "dev", r.device).Run(); replaceErr != nil {
			return fmt.Errorf("tunproxy: ip route add default dev %s: %w: %s", r.device, err, strings.TrimSpace(string(out)))
		}
	}
	r.applied = true
	return nil
}

// Restore removes the TUN default route and reinstates the original gateway.
func (r *linuxRouteManager) Restore() error {
	if !r.applied {
		return nil
	}
	r.applied = false
	_, _ = exec.Command("ip", "route", "del", "default", "dev", r.device).CombinedOutput()
	if r.gateway != "" {
		args := []string{"route", "replace", "default", "via", r.gateway}
		if r.oldIface != "" {
			args = append(args, "dev", r.oldIface)
		}
		_, _ = exec.Command("ip", args...).CombinedOutput()
	}
	return nil
}

// currentDefault parses `ip route show default` for the gateway and interface.
func (r *linuxRouteManager) currentDefault() (gateway, iface string, err error) {
	out, err := exec.Command("ip", "-4", "route", "show", "default").CombinedOutput()
	if err != nil {
		return "", "", err
	}
	return parseDefaultRoute(string(out))
}

// parseDefaultRoute parses the output of `ip route show default` and returns
// the gateway and interface. It expects a line containing "via <gateway>" and
// "dev <interface>".
func parseDefaultRoute(output string) (gateway, iface string, err error) {
	// Use only the first line; multiple default routes are rare and the first
	// is sufficient for the common case.
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
	if gateway == "" {
		return "", "", fmt.Errorf("no default gateway")
	}
	return gateway, iface, nil
}
