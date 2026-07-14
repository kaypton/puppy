//go:build !darwin && !linux

package tunproxy

import "fmt"

func newRouteManager(device, ipv4Addr string) routeManager {
	return &unsupportedRouteManager{}
}

type unsupportedRouteManager struct{}

func (unsupportedRouteManager) Apply() error {
	return fmt.Errorf("tunproxy: route configuration not supported on this platform")
}

func (unsupportedRouteManager) Restore() error { return nil }
