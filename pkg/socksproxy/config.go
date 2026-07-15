package socksproxy

import (
	"errors"
	"log/slog"

	"github.com/puppy/pkg/common"
	"github.com/puppy/pkg/common/stats"
)

// Type identifies the SOCKS5 proxy frontend in a named configuration group.
const Type = "socksproxy"

// Configuration is the TOML configuration owned by the SOCKS5 proxy frontend.
// Backend and Shim name other configuration groups assembled by the caller.
type Configuration struct {
	ListenAddress string `toml:"listen_address"`
	ListenPort    uint16 `toml:"listen_port"`
	// TLSCertFile and TLSKeyFile enable TLS for the proxy listener when both
	// are non-empty. The files must contain a matching PEM certificate and
	// key. This wraps SOCKS5 in TLS (SOCKS5-over-TLS), a non-standard but
	// useful arrangement for hiding or securing the SOCKS5 traffic.
	TLSCertFile string `toml:"tls_cert_file"`
	TLSKeyFile  string `toml:"tls_key_file"`
	// Username and Password enable RFC 1929 username/password authentication
	// when both are non-empty. When both are empty the proxy runs open (no
	// auth, method 0x00).
	Username string `toml:"username"`
	Password string `toml:"password"`
	Backend  string `toml:"backend"`
	Shim     string `toml:"shim"`
}

// Validate checks the SOCKS5 proxy frontend's own configuration fields.
func (c Configuration) Validate() error {
	if c.ListenAddress == "" {
		return errors.New("listen_address is required")
	}
	if c.ListenPort == 0 {
		return errors.New("listen_port is required")
	}
	if (c.TLSCertFile == "") != (c.TLSKeyFile == "") {
		return errors.New("tls_cert_file and tls_key_file must both be set or both be empty")
	}
	if (c.Username == "") != (c.Password == "") {
		return errors.New("username and password must both be set or both be empty")
	}
	if c.Backend == "" {
		return errors.New("backend reference is required")
	}
	if c.Shim == "" {
		return errors.New("shim reference is required")
	}
	return nil
}

// ServerConfig adds runtime dependencies to the frontend's file configuration
// and validates the resulting runtime configuration.
func (c Configuration) ServerConfig(backend common.Backend, shimBufferSize int, logger *slog.Logger, statsDeps stats.Deps) (ServerConfiguration, error) {
	sc := ServerConfiguration{
		ListenAddress:  c.ListenAddress,
		ListenPort:     c.ListenPort,
		TLSCertFile:    c.TLSCertFile,
		TLSKeyFile:     c.TLSKeyFile,
		Username:       c.Username,
		Password:       c.Password,
		Backend:        backend,
		ShimBufferSize: shimBufferSize,
		Logger:         logger,
		Name:           statsDeps.Name,
		Stats:          statsDeps.Stats,
		ConnReg:        statsDeps.ConnReg,
		Bus:            statsDeps.Bus,
	}
	if err := sc.Validate(); err != nil {
		return ServerConfiguration{}, err
	}
	return sc, nil
}
