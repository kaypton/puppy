package tunproxy

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/puppy/pkg/common"
)

// Type identifies the TUN proxy frontend in a named configuration group.
const Type = "tun"

// defaultUDPIdle is used when udp_idle_timeout is unset or non-positive.
const defaultUDPIdle = 30 * time.Second

// Configuration is the TOML configuration owned by the TUN proxy frontend.
// Backend and Shim name other configuration groups assembled by the caller.
type Configuration struct {
	// DeviceName requests a specific TUN interface. Empty lets the OS assign
	// one ("utun" on macOS, "tunN" on Linux). On macOS use "utunN" to request
	// unit N; on Linux any kernel-accepted name is honored.
	DeviceName string `toml:"device_name"`
	// IPv4Address is the TUN interface address in CIDR form, e.g. "10.0.0.1/24".
	// Required.
	IPv4Address string `toml:"ipv4_address"`
	// IPv6Address optionally configures an IPv6 interface address in CIDR form.
	IPv6Address string `toml:"ipv6_address"`
	// MTU is the device maximum transmission unit. Zero defaults to 1500.
	MTU int `toml:"mtu"`
	// AutoRoute, when true (default), installs a default route through the TUN
	// device on startup and restores the previous default route on shutdown.
	AutoRoute *bool `toml:"auto_route"`
	// UDPIdleTimeout closes idle UDP sessions after this duration. Zero or
	// negative uses the 30s default.
	UDPIdleTimeout int `toml:"udp_idle_timeout"`
	// Backend references a [backends.<name>] group. Required.
	Backend string `toml:"backend"`
	// Shim references a [shims.<name>] group. Required.
	Shim string `toml:"shim"`
}

// Validate checks the TUN proxy frontend's own configuration fields.
func (c Configuration) Validate() error {
	if c.IPv4Address == "" && c.IPv6Address == "" {
		return errors.New("ipv4_address or ipv6_address is required")
	}
	if c.IPv4Address != "" {
		if _, _, err := net.ParseCIDR(c.IPv4Address); err != nil {
			return fmt.Errorf("ipv4_address must be in CIDR form: %w", err)
		}
	}
	if c.IPv6Address != "" {
		if _, _, err := net.ParseCIDR(c.IPv6Address); err != nil {
			return fmt.Errorf("ipv6_address must be in CIDR form: %w", err)
		}
	}
	if c.MTU < 0 {
		return errors.New("mtu must not be negative")
	}
	if c.Backend == "" {
		return errors.New("backend reference is required")
	}
	if c.Shim == "" {
		return errors.New("shim reference is required")
	}
	return nil
}

// ServerConfig adds runtime dependencies to the frontend's file configuration.
func (c Configuration) ServerConfig(backend common.Backend, shimBufferSize int, logger *slog.Logger) ServerConfiguration {
	mtu := uint32(c.MTU)
	udpIdle := time.Duration(c.UDPIdleTimeout) * time.Second
	if c.UDPIdleTimeout <= 0 {
		udpIdle = defaultUDPIdle
	}
	autoRoute := true
	if c.AutoRoute != nil {
		autoRoute = *c.AutoRoute
	}
	return ServerConfiguration{
		DeviceName:     c.DeviceName,
		IPv4Address:    c.IPv4Address,
		IPv6Address:    c.IPv6Address,
		MTU:            mtu,
		AutoRoute:      autoRoute,
		UDPIdleTimeout: udpIdle,
		Backend:        backend,
		ShimBufferSize: shimBufferSize,
		Logger:         logger,
	}
}

// String aids log output; trims to key fields.
func (c Configuration) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "tun{device=%q ipv4=%q ipv6=%q mtu=%d backend=%q shim=%q}",
		c.DeviceName, c.IPv4Address, c.IPv6Address, c.MTU, c.Backend, c.Shim)
	return b.String()
}
