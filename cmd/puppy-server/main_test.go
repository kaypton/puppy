package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/puppy/pkg/adapter/direct"
	adapterhttpproxy "github.com/puppy/pkg/adapter/httpproxy"
	frontendhttpproxy "github.com/puppy/pkg/httpproxy"
)

const validConfiguration = `
frontend = "office_proxy"

[frontends.office_proxy]
type = "httpproxy"
listen_address = "127.0.0.1"
listen_port = 8080
username = "alice"
password = "secret"
camouflage = true
camouflage_method = "return-404"
backend = "direct_out"
shim = "default_tunnel"

[frontends.unused_proxy]
type = "httpproxy"
listen_address = "127.0.0.1"
listen_port = 8081
backend = "corporate_proxy"
shim = "large_tunnel"

[backends.direct_out]
type = "direct"

[backends.corporate_proxy]
type = "httpproxy"
proxy_address = "proxy.example.com:3128"
username = "bob"
password = "password"

[shims.default_tunnel]
buffer_size = 32768

[shims.large_tunnel]
buffer_size = 65536
`

func writeConfig(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "puppy.toml")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestLoadConfiguration(t *testing.T) {
	config, err := loadConfiguration(writeConfig(t, validConfiguration))
	if err != nil {
		t.Fatalf("loadConfiguration: %v", err)
	}
	if config.Frontend != "office_proxy" {
		t.Fatalf("Frontend = %q, want office_proxy", config.Frontend)
	}
	if len(config.Frontends) != 2 || len(config.Backends) != 2 || len(config.Shims) != 2 {
		t.Fatalf("group counts = (%d, %d, %d), want (2, 2, 2)", len(config.Frontends), len(config.Backends), len(config.Shims))
	}
	frontendGroup := config.Frontends["office_proxy"]
	frontend, ok := frontendGroup.Configuration.(frontendhttpproxy.Configuration)
	if !ok {
		t.Fatalf("frontend configuration type = %T", frontendGroup.Configuration)
	}
	if frontend.Backend != "direct_out" || frontend.Shim != "default_tunnel" {
		t.Fatalf("frontend references = (%q, %q), want (direct_out, default_tunnel)", frontend.Backend, frontend.Shim)
	}
	if !frontend.Camouflage || frontend.CamouflageMethod != frontendhttpproxy.Return404 {
		t.Fatalf("frontend camouflage = (%t, %q), want (true, return-404)", frontend.Camouflage, frontend.CamouflageMethod)
	}
	backendGroup := config.Backends["corporate_proxy"]
	backend, ok := backendGroup.Configuration.(adapterhttpproxy.Configuration)
	if !ok {
		t.Fatalf("backend configuration type = %T", backendGroup.Configuration)
	}
	if backend.ProxyAddress != "proxy.example.com:3128" || backend.Username != "bob" {
		t.Fatalf("HTTP backend = %#v", backend)
	}
	if got := config.Shims["large_tunnel"].BufferSize; got != 65536 {
		t.Fatalf("large_tunnel buffer size = %d, want 65536", got)
	}
}

func TestLoadConfiguration_TLSFrontend(t *testing.T) {
	contents := strings.Replace(
		validConfiguration,
		"listen_port = 8081",
		"listen_port = 8081\ntls_cert_file = \"proxy-cert.pem\"\ntls_key_file = \"proxy-key.pem\"",
		1,
	)
	config, err := loadConfiguration(writeConfig(t, contents))
	if err != nil {
		t.Fatalf("loadConfiguration: %v", err)
	}
	frontend, ok := config.Frontends["unused_proxy"].Configuration.(frontendhttpproxy.Configuration)
	if !ok {
		t.Fatalf("frontend configuration type = %T", config.Frontends["unused_proxy"].Configuration)
	}
	if frontend.TLSCertFile != "proxy-cert.pem" || frontend.TLSKeyFile != "proxy-key.pem" {
		t.Fatalf("TLS files = (%q, %q)", frontend.TLSCertFile, frontend.TLSKeyFile)
	}
}

func TestLoadConfiguration_TLSBackend(t *testing.T) {
	contents := strings.Replace(
		validConfiguration,
		`proxy_address = "proxy.example.com:3128"`,
		`proxy_address = "proxy.example.com:3128"`+"\ntls = true\ntls_ca_file = \"./certs/ca-cert.pem\"\ntls_server_name = \"proxy.internal\"",
		1,
	)
	config, err := loadConfiguration(writeConfig(t, contents))
	if err != nil {
		t.Fatalf("loadConfiguration: %v", err)
	}
	backend, ok := config.Backends["corporate_proxy"].Configuration.(adapterhttpproxy.Configuration)
	if !ok {
		t.Fatalf("backend configuration type = %T", config.Backends["corporate_proxy"].Configuration)
	}
	if !backend.TLS || backend.TLSCAFile != "./certs/ca-cert.pem" || backend.TLSServerName != "proxy.internal" {
		t.Fatalf("TLS backend = %#v", backend)
	}
}

func TestLoadConfigurationErrors(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		wantErr string
	}{
		{
			name:    "invalid TOML",
			config:  `frontend = [`,
			wantErr: "load configuration",
		},
		{
			name: "missing selection",
			config: `
[frontends.proxy]
type = "httpproxy"
listen_address = "127.0.0.1"
listen_port = 8080
backend = "out"
shim = "tunnel"
[backends.out]
type = "direct"
[shims.tunnel]
`,
			wantErr: "frontend selection is required",
		},
		{
			name:    "selected frontend missing",
			config:  `frontend = "missing"`,
			wantErr: `selected frontend "missing" does not exist`,
		},
		{
			name:    "unknown top-level field",
			config:  strings.Replace(validConfiguration, `frontend = "office_proxy"`, "frontend = \"office_proxy\"\ndebug = true", 1),
			wantErr: "configuration contains unknown field(s): debug",
		},
		{
			name:    "unknown frontend field",
			config:  strings.Replace(validConfiguration, `listen_port = 8081`, "listen_port = 8081\nextra = true", 1),
			wantErr: "frontends.unused_proxy.extra",
		},
		{
			name: "unknown direct backend field",
			config: strings.Replace(validConfiguration, `[backends.direct_out]
type = "direct"`, `[backends.direct_out]
type = "direct"
proxy_address = "should-not-be-accepted:1"`, 1),
			wantErr: "backends.direct_out.proxy_address",
		},
		{
			name: "unknown unused frontend type",
			config: strings.Replace(validConfiguration, `type = "httpproxy"
listen_address = "127.0.0.1"
listen_port = 8081`, `type = "socks5"
listen_address = "127.0.0.1"
listen_port = 8081`, 1),
			wantErr: `frontend "unused_proxy": unknown type "socks5"`,
		},
		{
			name: "unknown unused backend type",
			config: strings.Replace(validConfiguration, `type = "httpproxy"
proxy_address = "proxy.example.com:3128"`, `type = "socks5"
proxy_address = "proxy.example.com:3128"`, 1),
			wantErr: `backend "corporate_proxy": unknown type "socks5"`,
		},
		{
			name:    "missing backend reference",
			config:  strings.Replace(validConfiguration, `backend = "corporate_proxy"`, `backend = "missing"`, 1),
			wantErr: `frontend "unused_proxy": backend "missing" does not exist`,
		},
		{
			name:    "missing shim reference",
			config:  strings.Replace(validConfiguration, `shim = "large_tunnel"`, `shim = "missing"`, 1),
			wantErr: `frontend "unused_proxy": shim "missing" does not exist`,
		},
		{
			name:    "unpaired frontend credentials",
			config:  strings.Replace(validConfiguration, `password = "secret"`, `password = ""`, 1),
			wantErr: `frontend "office_proxy": username and password`,
		},
		{
			name:    "unknown camouflage method",
			config:  strings.Replace(validConfiguration, `camouflage_method = "return-404"`, `camouflage_method = "unknown"`, 1),
			wantErr: `frontend "office_proxy": camouflage_method`,
		},
		{
			name:    "invalid unused proxy address",
			config:  strings.Replace(validConfiguration, `proxy_address = "proxy.example.com:3128"`, `proxy_address = "proxy.example.com"`, 1),
			wantErr: `backend "corporate_proxy": proxy_address must be in host:port form`,
		},
		{
			name:    "negative unused shim buffer",
			config:  strings.Replace(validConfiguration, `buffer_size = 65536`, `buffer_size = -1`, 1),
			wantErr: `shim "large_tunnel": buffer_size must not be negative`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := loadConfiguration(writeConfig(t, test.config))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", test.wantErr)
			}
			if !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("error = %q, want substring %q", err, test.wantErr)
			}
		})
	}
}

func TestLoadConfigurationMissingFile(t *testing.T) {
	_, err := loadConfiguration(filepath.Join(t.TempDir(), "missing.toml"))
	if err == nil || !strings.Contains(err.Error(), "load configuration") {
		t.Fatalf("error = %v, want load configuration error", err)
	}
}

func TestExampleConfiguration(t *testing.T) {
	path := filepath.Join("..", "..", "config.toml")
	config, err := loadConfiguration(path)
	if err != nil {
		t.Fatalf("load example configuration: %v", err)
	}
	if config.Frontend != "local_http_proxy" {
		t.Fatalf("selected frontend = %q, want local_http_proxy", config.Frontend)
	}
}

func TestBuildBackend(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	directBackend, err := buildBackend(backendGroup{
		Type:          direct.Type,
		Configuration: direct.Configuration{},
	}, logger)
	if err != nil {
		t.Fatalf("build direct backend: %v", err)
	}
	if _, ok := directBackend.(*direct.Backend); !ok {
		t.Fatalf("direct backend type = %T", directBackend)
	}

	httpBackend, err := buildBackend(backendGroup{
		Type: adapterhttpproxy.Type,
		Configuration: adapterhttpproxy.Configuration{
			ProxyAddress: "proxy.example.com:3128",
		},
	}, logger)
	if err != nil {
		t.Fatalf("build HTTP backend: %v", err)
	}
	if _, ok := httpBackend.(*adapterhttpproxy.Backend); !ok {
		t.Fatalf("HTTP backend type = %T", httpBackend)
	}
}

func TestBuildSelectedFrontend(t *testing.T) {
	config, err := loadConfiguration(writeConfig(t, validConfiguration))
	if err != nil {
		t.Fatalf("loadConfiguration: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	frontend, err := buildFrontend(config, logger)
	if err != nil {
		t.Fatalf("buildFrontend: %v", err)
	}
	if frontend == nil {
		t.Fatal("buildFrontend returned nil")
	}
}

func TestRootCommand(t *testing.T) {
	var gotPath string
	var gotContext context.Context
	cmd := newRootCommand(func(ctx context.Context, path string) error {
		gotContext = ctx
		gotPath = path
		return nil
	})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"--config", "custom.toml"})
	ctx := context.WithValue(context.Background(), struct{}{}, "marker")
	if err := cmd.ExecuteContext(ctx); err != nil {
		t.Fatalf("ExecuteContext: %v", err)
	}
	if gotPath != "custom.toml" {
		t.Fatalf("config path = %q, want custom.toml", gotPath)
	}
	if gotContext != ctx {
		t.Fatal("runner did not receive command context")
	}
}

func TestRootCommandRequiresConfig(t *testing.T) {
	called := false
	cmd := newRootCommand(func(context.Context, string) error {
		called = true
		return nil
	})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs(nil)
	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), `required flag(s) "config" not set`) {
		t.Fatalf("error = %v, want required config error", err)
	}
	if called {
		t.Fatal("runner called without required config")
	}
}

func TestRootCommandHidesUsageForRuntimeErrors(t *testing.T) {
	cmd := newRootCommand(func(context.Context, string) error {
		return errors.New("runtime failure")
	})
	var output strings.Builder
	cmd.SetOut(&output)
	cmd.SetErr(&output)
	cmd.SetArgs([]string{"--config", "broken.toml"})

	err := cmd.Execute()
	if err == nil || err.Error() != "runtime failure" {
		t.Fatalf("error = %v, want runtime failure", err)
	}
	if strings.Contains(output.String(), "Usage:") {
		t.Fatalf("runtime error printed usage: %q", output.String())
	}
}
