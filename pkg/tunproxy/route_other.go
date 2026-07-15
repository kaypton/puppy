//go:build !linux && !darwin

package tunproxy

import (
	"fmt"

	"github.com/puppy/pkg/common"
)

type unsupportedHostNetworkManager struct{}

func newHostNetworkManager(device, ipv4Addr, ipv6Addr string, autoRoute, interceptSystemdResolved bool) hostNetworkManager {
	return unsupportedHostNetworkManager{}
}

func systemdResolvedInterceptionEnabled(autoRoute, dnsConfigured, ipv4Configured bool) bool {
	return false
}

func (unsupportedHostNetworkManager) Apply() (common.Dialer, error) {
	return nil, fmt.Errorf("tunproxy: host network configuration not supported on this platform")
}

func (unsupportedHostNetworkManager) EnableDNSInterception(dnsInterceptHandler) error { return nil }

func (unsupportedHostNetworkManager) Restore() error { return nil }

func (unsupportedHostNetworkManager) EgressInterfaces() (string, string) { return "", "" }
