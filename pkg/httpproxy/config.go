package httpproxy

import (
	"errors"
	"log/slog"

	"github.com/puppy/pkg/common"
)

// Type identifies the HTTP proxy frontend in a named configuration group.
const Type = "httpproxy"

// Configuration is the TOML configuration owned by the HTTP proxy frontend.
// Backend and Shim name other configuration groups assembled by the caller.
type Configuration struct {
	ListenAddress    string           `toml:"listen_address"`
	ListenPort       uint16           `toml:"listen_port"`
	Username         string           `toml:"username"`
	Password         string           `toml:"password"`
	Camouflage       bool             `toml:"camouflage"`
	CamouflageMethod CamouflageMethod `toml:"camouflage_method"`
	Backend          string           `toml:"backend"`
	Shim             string           `toml:"shim"`
}

// Validate checks the HTTP proxy frontend's own configuration fields.
func (c Configuration) Validate() error {
	if c.ListenAddress == "" {
		return errors.New("listen_address is required")
	}
	if c.ListenPort == 0 {
		return errors.New("listen_port is required")
	}
	if (c.Username == "") != (c.Password == "") {
		return errors.New("username and password must both be set or both be empty")
	}
	if method := normalizeCamouflageMethod(c.CamouflageMethod); method != Return404 {
		return errors.New("camouflage_method must be return-404 or empty")
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
	return ServerConfiguration{
		ListenAddress:    c.ListenAddress,
		ListenPort:       c.ListenPort,
		Username:         c.Username,
		Password:         c.Password,
		Camouflage:       c.Camouflage,
		CamouflageMethod: normalizeCamouflageMethod(c.CamouflageMethod),
		Backend:          backend,
		ShimBufferSize:   shimBufferSize,
		Logger:           logger,
	}
}
