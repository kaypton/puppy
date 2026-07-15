//go:build !linux && !darwin

package tunproxy

import "fmt"

func newSocketControl(iface4, iface6 string) (socketControl, error) {
	return nil, fmt.Errorf("tunproxy: bound egress not supported on this platform")
}
