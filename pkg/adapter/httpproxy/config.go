package httpproxy

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
)

// Type identifies the HTTP proxy backend in a named configuration group.
const Type = "httpproxy"

// Configuration is the TOML configuration owned by the HTTP proxy backend.
type Configuration struct {
	ProxyAddress string `toml:"proxy_address"`
	Username     string `toml:"username"`
	Password     string `toml:"password"`
}

// Validate checks the HTTP proxy backend's own configuration fields.
func (c Configuration) Validate() error {
	if c.ProxyAddress == "" {
		return errors.New("proxy_address is required")
	}
	host, portText, err := net.SplitHostPort(c.ProxyAddress)
	if err != nil {
		return fmt.Errorf("proxy_address must be in host:port form: %w", err)
	}
	if host == "" {
		return errors.New("proxy_address host is required")
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return errors.New("proxy_address port must be between 1 and 65535")
	}
	if (c.Username == "") != (c.Password == "") {
		return errors.New("username and password must both be set or both be empty")
	}
	return nil
}

// BackendConfig adds runtime dependencies to the backend's file configuration.
func (c Configuration) BackendConfig(logger *slog.Logger) BackendConfiguration {
	return BackendConfiguration{
		ProxyAddress: c.ProxyAddress,
		Username:     c.Username,
		Password:     c.Password,
		Logger:       logger,
	}
}
