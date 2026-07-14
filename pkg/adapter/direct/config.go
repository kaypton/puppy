package direct

// Type identifies the direct backend in a named configuration group.
const Type = "direct"

// Configuration is the TOML configuration owned by the direct backend.
// Direct connections currently have no implementation-specific settings.
type Configuration struct{}

// Validate checks the direct backend configuration.
func (Configuration) Validate() error { return nil }
