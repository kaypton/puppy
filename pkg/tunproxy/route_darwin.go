//go:build darwin

package tunproxy

import (
	"fmt"
	"os/exec"
	"strings"
)

// darwinRouteManager installs the TUN device as the default route on macOS and
// restores the original default gateway on cleanup.
type darwinRouteManager struct {
	device   string
	gateway  string
	oldIface string
	applied  bool
}

func newRouteManager(device, ipv4Addr string) routeManager {
	return &darwinRouteManager{device: device}
}

// Apply captures the current default route, then points the default route at
// the TUN device.
func (r *darwinRouteManager) Apply() error {
	gw, iface, err := r.currentDefault()
	if err != nil {
		// No existing default route; nothing to restore but we can still add.
		r.gateway = ""
		r.oldIface = ""
	} else {
		r.gateway = gw
		r.oldIface = iface
	}

	// Add a default route through the TUN interface. Using a high-priority
	// (low metric) entry so it wins over the previous default.
	if out, err := exec.Command("route", "-n", "add", "-net", "default", "-interface", r.device).CombinedOutput(); err != nil {
		return fmt.Errorf("tunproxy: route add default -interface %s: %w: %s", r.device, err, strings.TrimSpace(string(out)))
	}
	r.applied = true
	return nil
}

// Restore removes the TUN default route and reinstates the original gateway if
// one was captured.
func (r *darwinRouteManager) Restore() error {
	if !r.applied {
		return nil
	}
	r.applied = false
	_, _ = exec.Command("route", "-n", "delete", "-net", "default", "-interface", r.device).CombinedOutput()
	if r.gateway != "" {
		args := []string{"-n", "add", "-net", "default", r.gateway}
		if r.oldIface != "" {
			args = append(args, "-interface", r.oldIface)
		}
		_, _ = exec.Command("route", args...).CombinedOutput()
	}
	return nil
}

// currentDefault parses `route -n get default` for the gateway and interface.
func (r *darwinRouteManager) currentDefault() (gateway, iface string, err error) {
	out, err := exec.Command("route", "-n", "get", "default").CombinedOutput()
	if err != nil {
		return "", "", err
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "gateway:") {
			gateway = strings.TrimSpace(strings.TrimPrefix(line, "gateway:"))
		}
		if strings.HasPrefix(line, "interface:") {
			iface = strings.TrimSpace(strings.TrimPrefix(line, "interface:"))
		}
	}
	if gateway == "" {
		return "", "", fmt.Errorf("no default gateway")
	}
	return gateway, iface, nil
}
