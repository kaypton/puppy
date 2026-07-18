package httpproxy

import (
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/puppy/pkg/adapter/direct"
	"github.com/puppy/pkg/common/stats"
)

func TestConfigurationValidate(t *testing.T) {
	valid := Configuration{
		ListenAddress: "127.0.0.1",
		ListenPort:    8080,
		Backend:       "out",
		Shim:          "tunnel",
	}
	if err := valid.Validate(); err != nil {
		t.Fatalf("Validate valid configuration: %v", err)
	}

	tests := []struct {
		name    string
		change  func(*Configuration)
		wantErr string
	}{
		{"missing address", func(c *Configuration) { c.ListenAddress = "" }, "listen_address"},
		{"missing port", func(c *Configuration) { c.ListenPort = 0 }, "listen_port"},
		{"certificate only", func(c *Configuration) { c.TLSCertFile = "proxy-cert.pem" }, "tls_cert_file and tls_key_file"},
		{"key only", func(c *Configuration) { c.TLSKeyFile = "proxy-key.pem" }, "tls_cert_file and tls_key_file"},
		{"unpaired credentials", func(c *Configuration) { c.Username = "alice" }, "username and password"},
		{"unknown camouflage method", func(c *Configuration) { c.CamouflageMethod = "unknown" }, "camouflage_method"},
		{"missing backend", func(c *Configuration) { c.Backend = "" }, "backend reference"},
		{"missing shim", func(c *Configuration) { c.Shim = "" }, "shim reference"},
		{"bare ipv6", func(c *Configuration) { c.ListenAddress = "2001:db8::1" }, ""},
		{"bracketed ipv6", func(c *Configuration) { c.ListenAddress = "[::1]" }, "must not contain brackets"},
		{"ipv4 with port", func(c *Configuration) { c.ListenAddress = "127.0.0.1:8080" }, "is not a valid IPv6 address"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := valid
			test.change(&config)
			err := config.Validate()
			if test.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("error = %v, want substring %q", err, test.wantErr)
			}
		})
	}
}

func TestConfigurationNormalize(t *testing.T) {
	config := Configuration{
		ListenAddress: "2001:0DB8:0000:0000:0000:0000:0000:0001",
		ListenPort:    8080,
		Backend:       "out",
		Shim:          "tunnel",
	}
	if err := config.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if config.ListenAddress != "2001:db8::1" {
		t.Fatalf("ListenAddress = %q, want 2001:db8::1", config.ListenAddress)
	}
}

func TestConfigurationNormalize_IPv4WithPort(t *testing.T) {
	config := Configuration{ListenAddress: "127.0.0.1:8080"}
	if err := config.Normalize(); err == nil || !strings.Contains(err.Error(), "not a valid IPv6 address") {
		t.Fatalf("expected IPv4 with port to be rejected, got error = %v", err)
	}
}

func TestConfigurationServerConfig(t *testing.T) {
	backend := direct.NewBackend()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	config := Configuration{
		ListenAddress:    "127.0.0.1",
		ListenPort:       8080,
		TLSCertFile:      "proxy-cert.pem",
		TLSKeyFile:       "proxy-key.pem",
		Username:         "alice",
		Password:         "secret",
		Camouflage:       true,
		CamouflageMethod: Return404,
		Backend:          "out",
		Shim:             "tunnel",
	}

	serverConfig, err := config.ServerConfig(backend, 65536, logger, stats.Deps{Name: "test", Stats: stats.NewStatsRegistry(), ConnReg: stats.NewConnectionRegistry(), Bus: stats.NewEventBus()})
	if err != nil {
		t.Fatalf("ServerConfig: %v", err)
	}
	if serverConfig.ListenAddress != config.ListenAddress || serverConfig.ListenPort != config.ListenPort {
		t.Fatalf("listen configuration = %s:%d", serverConfig.ListenAddress, serverConfig.ListenPort)
	}
	if serverConfig.TLSCertFile != config.TLSCertFile || serverConfig.TLSKeyFile != config.TLSKeyFile {
		t.Fatal("TLS certificate configuration was not copied")
	}
	if serverConfig.Username != config.Username || serverConfig.Password != config.Password {
		t.Fatal("credentials were not copied")
	}
	if !serverConfig.Camouflage || serverConfig.CamouflageMethod != Return404 {
		t.Fatal("camouflage configuration was not copied")
	}
	if serverConfig.Backend != backend || serverConfig.ShimBufferSize != 65536 || serverConfig.Logger != logger {
		t.Fatal("runtime dependencies were not attached")
	}
	if serverConfig.Name != "test" || serverConfig.Stats == nil || serverConfig.ConnReg == nil || serverConfig.Bus == nil {
		t.Fatal("stats dependencies were not attached")
	}
}

func TestConfigurationServerConfig_DefaultsCamouflageMethod(t *testing.T) {
	config := Configuration{
		ListenAddress: "127.0.0.1",
		ListenPort:    8080,
		Backend:       "out",
		Shim:          "tunnel",
	}
	serverConfig, err := config.ServerConfig(direct.NewBackend(), 0, nil, stats.Deps{})
	if err != nil {
		t.Fatalf("ServerConfig: %v", err)
	}
	if serverConfig.CamouflageMethod != Return404 {
		t.Fatalf("CamouflageMethod = %q, want %q", serverConfig.CamouflageMethod, Return404)
	}
}
