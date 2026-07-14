package shim

import "errors"

// Configuration is the TOML configuration owned by the shim server.
type Configuration struct {
	BufferSize int `toml:"buffer_size"`
}

// Validate checks the shim server's own configuration fields.
func (c Configuration) Validate() error {
	if c.BufferSize < 0 {
		return errors.New("buffer_size must not be negative")
	}
	return nil
}
