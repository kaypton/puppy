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
	adaptersocksproxy "github.com/puppy/pkg/adapter/socksproxy"
	"github.com/puppy/pkg/common/stats"
	frontendhttpproxy "github.com/puppy/pkg/httpproxy"
	frontendsocksproxy "github.com/puppy/pkg/socksproxy"
	frontendtunproxy "github.com/puppy/pkg/tunproxy"
)

// testStatsDeps returns a stats.Deps suitable for buildFrontend in tests.
func testStatsDeps(name string) stats.Deps {
	return stats.Deps{
		Name:    name,
		Stats:   stats.NewStatsRegistry(),
		ConnReg: stats.NewConnectionRegistry(),
		Bus:     stats.NewEventBus(),
	}
}

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

[frontends.unused_socks]
type = "socksproxy"
listen_address = "127.0.0.1"
listen_port = 1080
backend = "direct_out"
shim = "default_tunnel"

[frontends.unused_tun]
type = "tun"
ipv4_address = "10.0.0.1/24"
mtu = 1500
auto_route = false
dns_server = "1.1.1.1:53"
backend = "direct_out"
shim = "default_tunnel"

[backends.direct_out]
type = "direct"

[backends.corporate_proxy]
type = "httpproxy"
proxy_address = "proxy.example.com:3128"
username = "bob"
password = "password"

[backends.corporate_socks]
type = "socksproxy"
proxy_address = "socks.example.com:1080"
username = "carol"
password = "swordfish"

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
	if len(config.Frontends) != 4 || len(config.Backends) != 3 || len(config.Shims) != 2 {
		t.Fatalf("group counts = (%d, %d, %d), want (4, 3, 2)", len(config.Frontends), len(config.Backends), len(config.Shims))
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
	socksBackendGroup := config.Backends["corporate_socks"]
	socksBackend, ok := socksBackendGroup.Configuration.(adaptersocksproxy.Configuration)
	if !ok {
		t.Fatalf("socks backend configuration type = %T", socksBackendGroup.Configuration)
	}
	if socksBackend.ProxyAddress != "socks.example.com:1080" || socksBackend.Username != "carol" || socksBackend.Password != "swordfish" {
		t.Fatalf("SOCKS backend = %#v", socksBackend)
	}
	socksFrontendGroup := config.Frontends["unused_socks"]
	socksFrontend, ok := socksFrontendGroup.Configuration.(frontendsocksproxy.Configuration)
	if !ok {
		t.Fatalf("socks frontend configuration type = %T", socksFrontendGroup.Configuration)
	}
	if socksFrontend.ListenAddress != "127.0.0.1" || socksFrontend.ListenPort != 1080 {
		t.Fatalf("socks frontend listen = %s:%d", socksFrontend.ListenAddress, socksFrontend.ListenPort)
	}
	if socksFrontend.Backend != "direct_out" || socksFrontend.Shim != "default_tunnel" {
		t.Fatalf("socks frontend references = (%q, %q), want (direct_out, default_tunnel)", socksFrontend.Backend, socksFrontend.Shim)
	}
	if got := config.Shims["large_tunnel"].BufferSize; got != 65536 {
		t.Fatalf("large_tunnel buffer size = %d, want 65536", got)
	}
	tunGroup := config.Frontends["unused_tun"]
	tun, ok := tunGroup.Configuration.(frontendtunproxy.Configuration)
	if !ok {
		t.Fatalf("tun frontend configuration type = %T", tunGroup.Configuration)
	}
	if tun.IPv4Address != "10.0.0.1/24" || tun.MTU != 1500 {
		t.Fatalf("tun frontend = %#v", tun)
	}
	if tun.Backend != "direct_out" || tun.Shim != "default_tunnel" {
		t.Fatalf("tun frontend references = (%q, %q), want (direct_out, default_tunnel)", tun.Backend, tun.Shim)
	}
	if tun.AutoRoute == nil || *tun.AutoRoute != false {
		t.Fatalf("tun auto_route = %v, want false", tun.AutoRoute)
	}
	if tun.DNSServer != "1.1.1.1:53" {
		t.Fatalf("tun dns_server = %q, want 1.1.1.1:53", tun.DNSServer)
	}
}

func TestLoadConfiguration_TunFrontendErrors(t *testing.T) {
	cases := []struct {
		name    string
		config  string
		wantErr string
	}{
		{
			name: "tun missing address",
			config: `
frontend = "t"
[frontends.t]
type = "tun"
backend = "out"
shim = "s"
[backends.out]
type = "direct"
[shims.s]
`,
			wantErr: `frontend "t": ipv4_address or ipv6_address is required`,
		},
		{
			name: "tun invalid cidr",
			config: `
frontend = "t"
[frontends.t]
type = "tun"
ipv4_address = "10.0.0.1"
backend = "out"
shim = "s"
[backends.out]
type = "direct"
[shims.s]
`,
			wantErr: `frontend "t": ipv4_address must be in CIDR form`,
		},
		{
			name: "tun missing backend reference",
			config: `
frontend = "t"
[frontends.t]
type = "tun"
ipv4_address = "10.0.0.1/24"
backend = "missing"
shim = "s"
[backends.out]
type = "direct"
[shims.s]
`,
			wantErr: `frontend "t": backend "missing" does not exist`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadConfiguration(writeConfig(t, tc.config))
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %q, want substring %q", err, tc.wantErr)
			}
		})
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

func TestLoadConfiguration_TUNOrderedBackends(t *testing.T) {
	contents := strings.Replace(
		validConfiguration,
		`backend = "direct_out"
shim = "default_tunnel"

[backends.direct_out]`,
		`backends = ["corporate_proxy", "direct_out"]
fallback = "direct_out"
protocol_detect_timeout = 2
protocol_detect_max_bytes = 8192
shim = "default_tunnel"

[backends.direct_out]`,
		1,
	)
	config, err := loadConfiguration(writeConfig(t, contents))
	if err != nil {
		t.Fatalf("loadConfiguration: %v", err)
	}
	tun := config.Frontends["unused_tun"].Configuration.(frontendtunproxy.Configuration)
	if got := tun.BackendReferences(); len(got) != 2 || got[0] != "corporate_proxy" || got[1] != "direct_out" {
		t.Fatalf("TUN backend order = %v", got)
	}
	if tun.Fallback != "direct_out" || tun.ProtocolDetectTimeout != 2 || tun.ProtocolDetectMaxBytes != 8192 {
		t.Fatalf("TUN routing configuration = %#v", tun)
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
			name: "socks frontend missing address",
			config: strings.Replace(
				validConfiguration,
				`[frontends.unused_socks]
type = "socksproxy"
listen_address = "127.0.0.1"
listen_port = 1080`,
				`[frontends.unused_socks]
type = "socksproxy"
listen_port = 1080`,
				1,
			),
			wantErr: `frontend "unused_socks": listen_address`,
		},
		{
			name: "socks frontend unpaired credentials",
			config: strings.Replace(
				validConfiguration,
				`[frontends.unused_socks]
type = "socksproxy"
listen_address = "127.0.0.1"
listen_port = 1080
backend = "direct_out"`,
				`[frontends.unused_socks]
type = "socksproxy"
listen_address = "127.0.0.1"
listen_port = 1080
username = "alice"
backend = "direct_out"`,
				1,
			),
			wantErr: `frontend "unused_socks": username and password`,
		},
		{
			name: "socks frontend missing backend reference",
			config: strings.Replace(
				validConfiguration,
				`[frontends.unused_socks]
type = "socksproxy"
listen_address = "127.0.0.1"
listen_port = 1080
backend = "direct_out"`,
				`[frontends.unused_socks]
type = "socksproxy"
listen_address = "127.0.0.1"
listen_port = 1080
backend = "missing_socks"`,
				1,
			),
			wantErr: `frontend "unused_socks": backend "missing_socks" does not exist`,
		},
		{
			name: "socks frontend unpaired tls cert",
			config: strings.Replace(
				validConfiguration,
				`[frontends.unused_socks]
type = "socksproxy"
listen_address = "127.0.0.1"
listen_port = 1080
backend = "direct_out"`,
				`[frontends.unused_socks]
type = "socksproxy"
listen_address = "127.0.0.1"
listen_port = 1080
tls_cert_file = "proxy-cert.pem"
backend = "direct_out"`,
				1,
			),
			wantErr: `frontend "unused_socks": tls_cert_file and tls_key_file`,
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

	socksBackend, err := buildBackend(backendGroup{
		Type: adaptersocksproxy.Type,
		Configuration: adaptersocksproxy.Configuration{
			ProxyAddress: "socks.example.com:1080",
		},
	}, logger)
	if err != nil {
		t.Fatalf("build SOCKS backend: %v", err)
	}
	if _, ok := socksBackend.(*adaptersocksproxy.Backend); !ok {
		t.Fatalf("SOCKS backend type = %T", socksBackend)
	}
}

func TestBuildSelectedFrontend(t *testing.T) {
	config, err := loadConfiguration(writeConfig(t, validConfiguration))
	if err != nil {
		t.Fatalf("loadConfiguration: %v", err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	frontend, err := buildFrontend(config, logger, testStatsDeps(config.Frontend))
	if err != nil {
		t.Fatalf("buildFrontend: %v", err)
	}
	if frontend == nil {
		t.Fatal("buildFrontend returned nil")
	}
}

func TestBuildSelectedSocksFrontend(t *testing.T) {
	contents := strings.Replace(validConfiguration, `frontend = "office_proxy"`, `frontend = "unused_socks"`, 1)
	config, err := loadConfiguration(writeConfig(t, contents))
	if err != nil {
		t.Fatalf("loadConfiguration: %v", err)
	}
	frontend, err := buildFrontend(config, slog.New(slog.NewTextHandler(io.Discard, nil)), testStatsDeps(config.Frontend))
	if err != nil {
		t.Fatalf("buildFrontend: %v", err)
	}
	if frontend == nil {
		t.Fatal("buildFrontend returned nil")
	}
}

func TestBuildSelectedTUNFrontend(t *testing.T) {
	contents := strings.Replace(validConfiguration, `frontend = "office_proxy"`, `frontend = "unused_tun"`, 1)
	contents = strings.Replace(
		contents,
		`backend = "direct_out"
shim = "default_tunnel"

[backends.direct_out]`,
		`backends = ["corporate_proxy"]
fallback = "direct_out"
shim = "default_tunnel"

[backends.direct_out]`,
		1,
	)
	config, err := loadConfiguration(writeConfig(t, contents))
	if err != nil {
		t.Fatalf("loadConfiguration: %v", err)
	}
	frontend, err := buildFrontend(config, slog.New(slog.NewTextHandler(io.Discard, nil)), testStatsDeps(config.Frontend))
	if err != nil {
		t.Fatalf("buildFrontend: %v", err)
	}
	if frontend == nil {
		t.Fatal("buildFrontend returned nil")
	}
}

func TestBuildSelectedTUNFrontendRejectsNarrowFallback(t *testing.T) {
	contents := strings.Replace(validConfiguration, `frontend = "office_proxy"`, `frontend = "unused_tun"`, 1)
	contents = strings.Replace(
		contents,
		`backend = "direct_out"
shim = "default_tunnel"

[backends.direct_out]`,
		`backend = "direct_out"
fallback = "corporate_proxy"
shim = "default_tunnel"

[backends.direct_out]`,
		1,
	)
	config, err := loadConfiguration(writeConfig(t, contents))
	if err != nil {
		t.Fatalf("loadConfiguration: %v", err)
	}
	_, err = buildFrontend(config, slog.New(slog.NewTextHandler(io.Discard, nil)), testStatsDeps(config.Frontend))
	if err == nil || !strings.Contains(err.Error(), "fallback must support udp") {
		t.Fatalf("buildFrontend error = %v, want fallback UDP capability error", err)
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

func TestLoadConfigurationWithDashboard(t *testing.T) {
	contents := validConfiguration + `
[dashboard]
enabled = true
listen_address = "127.0.0.1"
listen_port = 8443
token = "test-token"
`
	config, err := loadConfiguration(writeConfig(t, contents))
	if err != nil {
		t.Fatalf("loadConfiguration: %v", err)
	}
	if config.Dashboard == nil {
		t.Fatal("Dashboard config should not be nil")
	}
	if !config.Dashboard.Enabled {
		t.Error("Dashboard should be enabled")
	}
	if config.Dashboard.ListenPort != 8443 {
		t.Errorf("ListenPort = %d, want 8443", config.Dashboard.ListenPort)
	}
	if config.Dashboard.Token != "test-token" {
		t.Errorf("Token = %q, want test-token", config.Dashboard.Token)
	}
}

func TestLoadConfigurationRejectsUnknownDashboardField(t *testing.T) {
	contents := validConfiguration + `
[dashboard]
enabled = true
listen_address = "127.0.0.1"
listen_port = 8443
unknown_field = "bad"
`
	_, err := loadConfiguration(writeConfig(t, contents))
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("expected unknown field error, got: %v", err)
	}
}

func TestProviders(t *testing.T) {
	config, err := loadConfiguration(writeConfig(t, validConfiguration))
	if err != nil {
		t.Fatalf("loadConfiguration: %v", err)
	}

	t.Run("config provider", func(t *testing.T) {
		cp := &configProvider{}
		cp.Update(config)
		result := cp.SanitizedConfig().(map[string]any)
		if result["frontend"] != "office_proxy" {
			t.Errorf("frontend = %v, want office_proxy", result["frontend"])
		}
		frontends := result["frontends"].(map[string]any)
		if len(frontends) != 4 {
			t.Errorf("frontends count = %d, want 4", len(frontends))
		}
	})

	t.Run("frontend provider", func(t *testing.T) {
		fp := &frontendProvider{}
		fp.Update(config)
		frontends := fp.Frontends()
		if len(frontends) != 4 {
			t.Fatalf("frontends count = %d, want 4", len(frontends))
		}
		for _, fe := range frontends {
			if fe.Name == "" || fe.Type == "" {
				t.Errorf("frontend has empty name or type: %+v", fe)
			}
		}
	})

	t.Run("backend provider", func(t *testing.T) {
		bp := &backendProvider{}
		bp.Update(config)
		backends := bp.Backends()
		if len(backends) != 3 {
			t.Fatalf("backends count = %d, want 3", len(backends))
		}
		for _, be := range backends {
			if be.Name == "direct_out" {
				if len(be.Capabilities) != 2 {
					t.Errorf("direct_out capabilities = %d, want 2", len(be.Capabilities))
				}
			}
		}
	})

	t.Run("provider update", func(t *testing.T) {
		cp := &configProvider{}
		cp.Update(config)
		original := cp.SanitizedConfig().(map[string]any)

		// Create a modified config with a different frontend selection.
		modified := *config
		modified.Frontend = "unused_socks"
		cp.Update(&modified)

		updated := cp.SanitizedConfig().(map[string]any)
		if updated["frontend"] != "unused_socks" {
			t.Errorf("after update: frontend = %v, want unused_socks", updated["frontend"])
		}
		if original["frontend"] != "office_proxy" {
			t.Errorf("original config was mutated: frontend = %v", original["frontend"])
		}
	})
}
