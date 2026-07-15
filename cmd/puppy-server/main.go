package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"

	"github.com/BurntSushi/toml"
	"github.com/puppy/pkg/adapter/direct"
	adapterhttpproxy "github.com/puppy/pkg/adapter/httpproxy"
	adaptersocksproxy "github.com/puppy/pkg/adapter/socksproxy"
	"github.com/puppy/pkg/common"
	frontendhttpproxy "github.com/puppy/pkg/httpproxy"
	"github.com/puppy/pkg/shim"
	frontendsocksproxy "github.com/puppy/pkg/socksproxy"
	frontendtunproxy "github.com/puppy/pkg/tunproxy"
	"github.com/spf13/cobra"
)

type rawConfiguration struct {
	Frontend  string                    `toml:"frontend"`
	Frontends map[string]toml.Primitive `toml:"frontends"`
	Backends  map[string]toml.Primitive `toml:"backends"`
	Shims     map[string]toml.Primitive `toml:"shims"`
}

type configuration struct {
	Frontend  string
	Frontends map[string]frontendGroup
	Backends  map[string]backendGroup
	Shims     map[string]shim.Configuration
}

type componentType struct {
	Type string `toml:"type"`
}

type componentConfiguration interface {
	Validate() error
}

type frontendGroup struct {
	Type          string
	Configuration componentConfiguration
}

type backendGroup struct {
	Type          string
	Configuration componentConfiguration
}

type frontendRunner interface {
	Run(context.Context) error
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := newRootCommand(runServer).ExecuteContext(ctx); err != nil {
		os.Exit(1)
	}
}

func newRootCommand(run func(context.Context, string) error) *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "puppy-server",
		Short: "Run the puppy proxy server",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Flag and argument errors should show usage, but configuration and
			// runtime errors should not.
			cmd.SilenceUsage = true
			return run(cmd.Context(), configPath)
		},
	}
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "path to the TOML configuration file")
	if err := cmd.MarkFlagRequired("config"); err != nil {
		panic(err)
	}
	return cmd
}

func runServer(ctx context.Context, configPath string) error {
	config, err := loadConfiguration(configPath)
	if err != nil {
		return err
	}
	frontend, err := buildFrontend(config, slog.Default())
	if err != nil {
		return err
	}
	return frontend.Run(ctx)
}

func loadConfiguration(path string) (*configuration, error) {
	var raw rawConfiguration
	metadata, err := toml.DecodeFile(path, &raw)
	if err != nil {
		return nil, fmt.Errorf("load configuration %q: %w", path, err)
	}

	config := &configuration{
		Frontend:  raw.Frontend,
		Frontends: make(map[string]frontendGroup, len(raw.Frontends)),
		Backends:  make(map[string]backendGroup, len(raw.Backends)),
		Shims:     make(map[string]shim.Configuration, len(raw.Shims)),
	}

	for _, name := range sortedNames(raw.Frontends) {
		primitive := raw.Frontends[name]
		var kind componentType
		if err := metadata.PrimitiveDecode(primitive, &kind); err != nil {
			return nil, fmt.Errorf("decode frontend %q type: %w", name, err)
		}
		switch kind.Type {
		case frontendhttpproxy.Type:
			var frontendConfig frontendhttpproxy.Configuration
			if err := metadata.PrimitiveDecode(primitive, &frontendConfig); err != nil {
				return nil, fmt.Errorf("decode frontend %q: %w", name, err)
			}
			config.Frontends[name] = frontendGroup{Type: kind.Type, Configuration: frontendConfig}
		case frontendsocksproxy.Type:
			var frontendConfig frontendsocksproxy.Configuration
			if err := metadata.PrimitiveDecode(primitive, &frontendConfig); err != nil {
				return nil, fmt.Errorf("decode frontend %q: %w", name, err)
			}
			config.Frontends[name] = frontendGroup{Type: kind.Type, Configuration: frontendConfig}
		case frontendtunproxy.Type:
			var frontendConfig frontendtunproxy.Configuration
			if err := metadata.PrimitiveDecode(primitive, &frontendConfig); err != nil {
				return nil, fmt.Errorf("decode frontend %q: %w", name, err)
			}
			config.Frontends[name] = frontendGroup{Type: kind.Type, Configuration: frontendConfig}
		default:
			return nil, fmt.Errorf("frontend %q: unknown type %q", name, kind.Type)
		}
	}

	for _, name := range sortedNames(raw.Backends) {
		primitive := raw.Backends[name]
		var kind componentType
		if err := metadata.PrimitiveDecode(primitive, &kind); err != nil {
			return nil, fmt.Errorf("decode backend %q type: %w", name, err)
		}
		switch kind.Type {
		case direct.Type:
			var directConfig direct.Configuration
			if err := metadata.PrimitiveDecode(primitive, &directConfig); err != nil {
				return nil, fmt.Errorf("decode backend %q: %w", name, err)
			}
			config.Backends[name] = backendGroup{Type: kind.Type, Configuration: directConfig}
		case adapterhttpproxy.Type:
			var backendConfig adapterhttpproxy.Configuration
			if err := metadata.PrimitiveDecode(primitive, &backendConfig); err != nil {
				return nil, fmt.Errorf("decode backend %q: %w", name, err)
			}
			config.Backends[name] = backendGroup{Type: kind.Type, Configuration: backendConfig}
		case adaptersocksproxy.Type:
			var backendConfig adaptersocksproxy.Configuration
			if err := metadata.PrimitiveDecode(primitive, &backendConfig); err != nil {
				return nil, fmt.Errorf("decode backend %q: %w", name, err)
			}
			config.Backends[name] = backendGroup{Type: kind.Type, Configuration: backendConfig}
		default:
			return nil, fmt.Errorf("backend %q: unknown type %q", name, kind.Type)
		}
	}

	for _, name := range sortedNames(raw.Shims) {
		primitive := raw.Shims[name]
		var shimConfig shim.Configuration
		if err := metadata.PrimitiveDecode(primitive, &shimConfig); err != nil {
			return nil, fmt.Errorf("decode shim %q: %w", name, err)
		}
		config.Shims[name] = shimConfig
	}

	if undecoded := metadata.Undecoded(); len(undecoded) > 0 {
		keys := make([]string, len(undecoded))
		for i, key := range undecoded {
			keys[i] = key.String()
		}
		return nil, fmt.Errorf("configuration contains unknown field(s): %s", strings.Join(keys, ", "))
	}
	if err := config.validate(); err != nil {
		return nil, fmt.Errorf("validate configuration %q: %w", path, err)
	}
	return config, nil
}

func sortedNames[T any](values map[string]T) []string {
	names := make([]string, 0, len(values))
	for name := range values {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (c *configuration) validate() error {
	if c.Frontend == "" {
		return errors.New("frontend selection is required")
	}
	if _, ok := c.Frontends[c.Frontend]; !ok {
		return fmt.Errorf("selected frontend %q does not exist", c.Frontend)
	}

	for _, name := range sortedNames(c.Frontends) {
		if name == "" {
			return errors.New("frontend name must not be empty")
		}
		group := c.Frontends[name]
		switch group.Type {
		case frontendhttpproxy.Type:
			frontendConfig, ok := group.Configuration.(frontendhttpproxy.Configuration)
			if !ok {
				return fmt.Errorf("frontend %q: configuration does not match type %q", name, group.Type)
			}
			if err := frontendConfig.Validate(); err != nil {
				return fmt.Errorf("frontend %q: %w", name, err)
			}
			if _, ok := c.Backends[frontendConfig.Backend]; !ok {
				return fmt.Errorf("frontend %q: backend %q does not exist", name, frontendConfig.Backend)
			}
			if _, ok := c.Shims[frontendConfig.Shim]; !ok {
				return fmt.Errorf("frontend %q: shim %q does not exist", name, frontendConfig.Shim)
			}
		case frontendsocksproxy.Type:
			frontendConfig, ok := group.Configuration.(frontendsocksproxy.Configuration)
			if !ok {
				return fmt.Errorf("frontend %q: configuration does not match type %q", name, group.Type)
			}
			if err := frontendConfig.Validate(); err != nil {
				return fmt.Errorf("frontend %q: %w", name, err)
			}
			if _, ok := c.Backends[frontendConfig.Backend]; !ok {
				return fmt.Errorf("frontend %q: backend %q does not exist", name, frontendConfig.Backend)
			}
			if _, ok := c.Shims[frontendConfig.Shim]; !ok {
				return fmt.Errorf("frontend %q: shim %q does not exist", name, frontendConfig.Shim)
			}
		case frontendtunproxy.Type:
			frontendConfig, ok := group.Configuration.(frontendtunproxy.Configuration)
			if !ok {
				return fmt.Errorf("frontend %q: configuration does not match type %q", name, group.Type)
			}
			if err := frontendConfig.Validate(); err != nil {
				return fmt.Errorf("frontend %q: %w", name, err)
			}
			for _, backendName := range frontendConfig.BackendReferences() {
				if _, ok := c.Backends[backendName]; !ok {
					return fmt.Errorf("frontend %q: backend %q does not exist", name, backendName)
				}
			}
			if frontendConfig.Fallback != "" {
				if _, ok := c.Backends[frontendConfig.Fallback]; !ok {
					return fmt.Errorf("frontend %q: fallback backend %q does not exist", name, frontendConfig.Fallback)
				}
			}
			if _, ok := c.Shims[frontendConfig.Shim]; !ok {
				return fmt.Errorf("frontend %q: shim %q does not exist", name, frontendConfig.Shim)
			}
		default:
			return fmt.Errorf("frontend %q: unknown type %q", name, group.Type)
		}
	}

	for _, name := range sortedNames(c.Backends) {
		if name == "" {
			return errors.New("backend name must not be empty")
		}
		group := c.Backends[name]
		switch group.Type {
		case direct.Type:
			backendConfig, ok := group.Configuration.(direct.Configuration)
			if !ok {
				return fmt.Errorf("backend %q: configuration does not match type %q", name, group.Type)
			}
			if err := backendConfig.Validate(); err != nil {
				return fmt.Errorf("backend %q: %w", name, err)
			}
		case adapterhttpproxy.Type:
			backendConfig, ok := group.Configuration.(adapterhttpproxy.Configuration)
			if !ok {
				return fmt.Errorf("backend %q: configuration does not match type %q", name, group.Type)
			}
			if err := backendConfig.Validate(); err != nil {
				return fmt.Errorf("backend %q: %w", name, err)
			}
		case adaptersocksproxy.Type:
			backendConfig, ok := group.Configuration.(adaptersocksproxy.Configuration)
			if !ok {
				return fmt.Errorf("backend %q: configuration does not match type %q", name, group.Type)
			}
			if err := backendConfig.Validate(); err != nil {
				return fmt.Errorf("backend %q: %w", name, err)
			}
		default:
			return fmt.Errorf("backend %q: unknown type %q", name, group.Type)
		}
	}

	for _, name := range sortedNames(c.Shims) {
		if name == "" {
			return errors.New("shim name must not be empty")
		}
		if err := c.Shims[name].Validate(); err != nil {
			return fmt.Errorf("shim %q: %w", name, err)
		}
	}
	return nil
}

func buildFrontend(config *configuration, logger *slog.Logger) (frontendRunner, error) {
	group := config.Frontends[config.Frontend]
	switch group.Type {
	case frontendhttpproxy.Type:
		frontendConfig, ok := group.Configuration.(frontendhttpproxy.Configuration)
		if !ok {
			return nil, fmt.Errorf("build frontend %q: configuration does not match type %q", config.Frontend, group.Type)
		}
		backend, err := buildBackend(config.Backends[frontendConfig.Backend], logger)
		if err != nil {
			return nil, fmt.Errorf("build backend %q: %w", frontendConfig.Backend, err)
		}
		shimConfig := config.Shims[frontendConfig.Shim]
		frontend, err := frontendhttpproxy.NewServer(frontendConfig.ServerConfig(backend, shimConfig.BufferSize, logger))
		if err != nil {
			return nil, fmt.Errorf("build frontend %q: %w", config.Frontend, err)
		}
		return frontend, nil
	case frontendsocksproxy.Type:
		frontendConfig, ok := group.Configuration.(frontendsocksproxy.Configuration)
		if !ok {
			return nil, fmt.Errorf("build frontend %q: configuration does not match type %q", config.Frontend, group.Type)
		}
		backend, err := buildBackend(config.Backends[frontendConfig.Backend], logger)
		if err != nil {
			return nil, fmt.Errorf("build backend %q: %w", frontendConfig.Backend, err)
		}
		shimConfig := config.Shims[frontendConfig.Shim]
		frontend, err := frontendsocksproxy.NewServer(frontendConfig.ServerConfig(backend, shimConfig.BufferSize, logger))
		if err != nil {
			return nil, fmt.Errorf("build frontend %q: %w", config.Frontend, err)
		}
		return frontend, nil
	case frontendtunproxy.Type:
		frontendConfig, ok := group.Configuration.(frontendtunproxy.Configuration)
		if !ok {
			return nil, fmt.Errorf("build frontend %q: configuration does not match type %q", config.Frontend, group.Type)
		}
		backendNames := frontendConfig.BackendReferences()
		backends := make([]common.Backend, 0, len(backendNames))
		for _, backendName := range backendNames {
			backend, err := buildBackend(config.Backends[backendName], logger)
			if err != nil {
				return nil, fmt.Errorf("build backend %q: %w", backendName, err)
			}
			backends = append(backends, backend)
		}
		fallback := common.Backend(direct.NewBackend())
		if frontendConfig.Fallback != "" {
			var err error
			fallback, err = buildBackend(config.Backends[frontendConfig.Fallback], logger)
			if err != nil {
				return nil, fmt.Errorf("build fallback backend %q: %w", frontendConfig.Fallback, err)
			}
		}
		shimConfig := config.Shims[frontendConfig.Shim]
		frontend, err := frontendtunproxy.NewServer(frontendConfig.ServerConfig(backends, fallback, shimConfig.BufferSize, logger))
		if err != nil {
			return nil, fmt.Errorf("build frontend %q: %w", config.Frontend, err)
		}
		return frontend, nil
	default:
		return nil, fmt.Errorf("build frontend %q: unsupported type %q", config.Frontend, group.Type)
	}
}

func buildBackend(group backendGroup, logger *slog.Logger) (common.Backend, error) {
	switch group.Type {
	case direct.Type:
		if _, ok := group.Configuration.(direct.Configuration); !ok {
			return nil, fmt.Errorf("configuration does not match type %q", group.Type)
		}
		return direct.NewBackend(), nil
	case adapterhttpproxy.Type:
		backendConfig, ok := group.Configuration.(adapterhttpproxy.Configuration)
		if !ok {
			return nil, fmt.Errorf("configuration does not match type %q", group.Type)
		}
		return adapterhttpproxy.NewBackend(backendConfig.BackendConfig(logger))
	case adaptersocksproxy.Type:
		backendConfig, ok := group.Configuration.(adaptersocksproxy.Configuration)
		if !ok {
			return nil, fmt.Errorf("configuration does not match type %q", group.Type)
		}
		return adaptersocksproxy.NewBackend(backendConfig.BackendConfig(logger))
	default:
		return nil, fmt.Errorf("unsupported type %q", group.Type)
	}
}
