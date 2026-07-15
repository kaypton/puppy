package socksproxy

import (
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/puppy/pkg/adapter/direct"
)

func TestConfigurationValidate(t *testing.T) {
	valid := Configuration{
		ListenAddress: "127.0.0.1",
		ListenPort:    1080,
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
		{"missing backend", func(c *Configuration) { c.Backend = "" }, "backend reference"},
		{"missing shim", func(c *Configuration) { c.Shim = "" }, "shim reference"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := valid
			test.change(&config)
			err := config.Validate()
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("error = %v, want substring %q", err, test.wantErr)
			}
		})
	}
}

func TestConfigurationServerConfig(t *testing.T) {
	backend := direct.NewBackend()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	config := Configuration{
		ListenAddress: "127.0.0.1",
		ListenPort:    1080,
		TLSCertFile:   "proxy-cert.pem",
		TLSKeyFile:    "proxy-key.pem",
		Username:      "alice",
		Password:      "secret",
		Backend:       "out",
		Shim:          "tunnel",
	}

	serverConfig := config.ServerConfig(backend, 65536, logger)
	if serverConfig.ListenAddress != config.ListenAddress || serverConfig.ListenPort != config.ListenPort {
		t.Fatalf("listen configuration = %s:%d", serverConfig.ListenAddress, serverConfig.ListenPort)
	}
	if serverConfig.TLSCertFile != config.TLSCertFile || serverConfig.TLSKeyFile != config.TLSKeyFile {
		t.Fatal("TLS certificate configuration was not copied")
	}
	if serverConfig.Username != config.Username || serverConfig.Password != config.Password {
		t.Fatal("credentials were not copied")
	}
	if serverConfig.Backend != backend || serverConfig.ShimBufferSize != 65536 || serverConfig.Logger != logger {
		t.Fatal("runtime dependencies were not attached")
	}
}
