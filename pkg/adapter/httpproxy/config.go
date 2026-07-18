package httpproxy

import (
	"errors"
	"log/slog"

	"github.com/puppy/pkg/common"
)

// Type identifies the HTTP proxy backend in a named configuration group.
const Type = "httpproxy"

// Configuration is the TOML configuration owned by the HTTP proxy backend.
type Configuration struct {
	ProxyAddress string `toml:"proxy_address"`
	Username     string `toml:"username"`
	Password     string `toml:"password"`
	// TLS enables TLS to the upstream proxy (https_proxy=https://...) when true.
	// When false (default), the backend connects over plaintext TCP.
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

// Validate checks the HTTP proxy backend's own configuration fields.
func (c Configuration) Validate() error {
	if c.ProxyAddress == "" {
		return errors.New("proxy_address is required")
	}
	if _, err := common.NormalizeProxyAddress(c.ProxyAddress); err != nil {
		return err
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

// Normalize canonicalizes the configuration values in place.
func (c *Configuration) Normalize() error {
	if c.ProxyAddress == "" {
		return nil
	}
	normalized, err := common.NormalizeProxyAddress(c.ProxyAddress)
	if err != nil {
		return err
	}
	c.ProxyAddress = normalized
	return nil
}

// BackendConfig adds runtime dependencies to the backend's file configuration
// and validates the resulting runtime configuration.
func (c Configuration) BackendConfig(logger *slog.Logger) (BackendConfiguration, error) {
	bc := BackendConfiguration{
		ProxyAddress:          c.ProxyAddress,
		Username:              c.Username,
		Password:              c.Password,
		TLS:                   c.TLS,
		TLSCAFile:             c.TLSCAFile,
		TLSServerName:         c.TLSServerName,
		TLSInsecureSkipVerify: c.TLSInsecureSkipVerify,
		Logger:                logger,
	}
	if err := bc.Validate(); err != nil {
		return BackendConfiguration{}, err
	}
	return bc, nil
}
