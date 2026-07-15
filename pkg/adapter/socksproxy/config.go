package socksproxy

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
)

// Type identifies the SOCKS5 proxy backend in a named configuration group.
const Type = "socksproxy"

// Configuration is the TOML configuration owned by the SOCKS5 proxy backend.
type Configuration struct {
	ProxyAddress string `toml:"proxy_address"`
	Username     string `toml:"username"`
	Password     string `toml:"password"`
	// TLS enables TLS to the upstream SOCKS5 proxy when true. When false
	// (default), the backend connects over plaintext TCP.
	TLS bool `toml:"tls"`
	// TLSCAFile is a PEM file of additional CA certificates used to verify the
	// upstream proxy's server certificate. Only meaningful when TLS is true.
	// When empty, the system root certificates are used.
	TLSCAFile string `toml:"tls_ca_file"`
	// TLSServerName overrides the TLS SNI and certificate verification name.
	// When empty, the host portion of ProxyAddress is used. Only meaningful
	// when TLS is true.
	TLSServerName string `toml:"tls_server_name"`
	// TLSInsecureSkipVerify disables certificate verification. Only meaningful
	// when TLS is true, and mutually exclusive with TLSCAFile.
	TLSInsecureSkipVerify bool `toml:"tls_insecure_skip_verify"`
}

// Validate checks the SOCKS5 proxy backend's own configuration fields.
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
	if !c.TLS {
		if c.TLSCAFile != "" || c.TLSServerName != "" || c.TLSInsecureSkipVerify {
			return errors.New("tls_ca_file, tls_server_name, and tls_insecure_skip_verify require tls = true")
		}
	}
	if c.TLSInsecureSkipVerify && c.TLSCAFile != "" {
		return errors.New("tls_insecure_skip_verify and tls_ca_file are mutually exclusive")
	}
	return nil
}

// BackendConfig adds runtime dependencies to the backend's file configuration.
func (c Configuration) BackendConfig(logger *slog.Logger) BackendConfiguration {
	return BackendConfiguration{
		ProxyAddress:          c.ProxyAddress,
		Username:              c.Username,
		Password:              c.Password,
		TLS:                   c.TLS,
		TLSCAFile:             c.TLSCAFile,
		TLSServerName:         c.TLSServerName,
		TLSInsecureSkipVerify: c.TLSInsecureSkipVerify,
		Logger:                logger,
	}
}
