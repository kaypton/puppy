//go:build !linux && !darwin

package tunproxy

import (
	"fmt"

	"github.com/puppy/pkg/common"
)

type unsupportedHostNetworkManager struct{}

func newHostNetworkManager(device, ipv4Addr, ipv6Addr string, autoRoute bool) hostNetworkManager {
	return unsupportedHostNetworkManager{}
}

func (unsupportedHostNetworkManager) Apply() (common.Dialer, error) {
	return nil, fmt.Errorf("tunproxy: host network configuration not supported on this platform")
}

func (unsupportedHostNetworkManager) Restore() error { return nil }

func (unsupportedHostNetworkManager) EgressInterfaces() (string, string) { return "", "" }
