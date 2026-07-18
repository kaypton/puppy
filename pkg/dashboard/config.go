package dashboard

import (
	"errors"
	"log/slog"

	"github.com/puppy/pkg/common"
	"github.com/puppy/pkg/common/stats"
)

// Configuration is the TOML configuration owned by the dashboard HTTP API
// server.
type Configuration struct {
	Enabled       bool   `toml:"enabled"`
	ListenAddress string `toml:"listen_address"`
	ListenPort    uint16 `toml:"listen_port"`
	TLSCertFile   string `toml:"tls_cert_file"`
	TLSKeyFile    string `toml:"tls_key_file"`
	Token         string `toml:"token"`
}

// Validate checks the dashboard configuration fields. Validation is skipped
// when the dashboard is disabled.
func (c Configuration) Validate() error {
	if !c.Enabled {
		return nil
	}
	if c.ListenAddress == "" {
		return errors.New("dashboard: listen_address is required when enabled")
	}
	if _, err := common.NormalizeListenAddress(c.ListenAddress); err != nil {
		return err
	}
	if c.ListenPort == 0 {
		return errors.New("dashboard: listen_port is required when enabled")
	}
	if (c.TLSCertFile == "") != (c.TLSKeyFile == "") {
		return errors.New("dashboard: tls_cert_file and tls_key_file must both be set or both be empty")
	}
	return nil
}

// Normalize canonicalizes the configuration values in place.
func (c *Configuration) Normalize() error {
	if !c.Enabled || c.ListenAddress == "" {
		return nil
	}
	normalized, err := common.NormalizeListenAddress(c.ListenAddress)
	if err != nil {
		return err
	}
	c.ListenAddress = normalized
	return nil
}

// ServerConfig adds runtime dependencies to the dashboard's file configuration
// and validates the resulting runtime configuration.
func (c *Configuration) ServerConfig(
	statsReg *stats.StatsRegistry, connReg *stats.ConnectionRegistry, bus *stats.EventBus,
	cfgProvider ConfigProvider, feProvider FrontendProvider, beProvider BackendProvider,
	controlCh chan<- ControlRequest, logger *slog.Logger,
) (ServerConfiguration, error) {
	sc := ServerConfiguration{
		ListenAddress:    c.ListenAddress,
		ListenPort:       c.ListenPort,
		TLSCertFile:      c.TLSCertFile,
		TLSKeyFile:       c.TLSKeyFile,
		Token:            c.Token,
		Stats:            statsReg,
		ConnReg:          connReg,
		Bus:              bus,
		ConfigProvider:   cfgProvider,
		FrontendProvider: feProvider,
		BackendProvider:  beProvider,
		ControlCh:        controlCh,
		Logger:           logger,
	}
	if err := sc.Validate(); err != nil {
		return ServerConfiguration{}, err
	}
	return sc, nil
}
