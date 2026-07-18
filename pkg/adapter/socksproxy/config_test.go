package socksproxy

import (
	"io"
	"log/slog"
	"strings"
	"testing"
)

func TestConfigurationValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  Configuration
		wantErr string
	}{
		{"valid", Configuration{ProxyAddress: "proxy.example.com:1080"}, ""},
		{"valid auth", Configuration{ProxyAddress: "proxy.example.com:1080", Username: "alice", Password: "secret"}, ""},
		{"valid tls", Configuration{ProxyAddress: "proxy.example.com:1080", TLS: true}, ""},
		{"valid tls with ca", Configuration{ProxyAddress: "proxy.example.com:1080", TLS: true, TLSCAFile: "./certs/ca-cert.pem"}, ""},
		{"valid tls with server name", Configuration{ProxyAddress: "proxy.example.com:1080", TLS: true, TLSServerName: "proxy.internal"}, ""},
		{"valid tls insecure", Configuration{ProxyAddress: "proxy.example.com:1080", TLS: true, TLSInsecureSkipVerify: true}, ""},
		{"missing address", Configuration{}, "proxy_address is required"},
		{"missing port", Configuration{ProxyAddress: "proxy.example.com"}, "host:port"},
		{"zero port", Configuration{ProxyAddress: "proxy.example.com:0"}, "between 1 and 65535"},
		{"bracketed ipv6", Configuration{ProxyAddress: "[2001:db8::1]:1080"}, ""},
		{"bare ipv6", Configuration{ProxyAddress: "2001:db8::1:1080"}, "host:port"},
		{"uppercase ipv6", Configuration{ProxyAddress: "[2001:DB8::1]:1080"}, ""},
		{"unpaired credentials", Configuration{ProxyAddress: "proxy.example.com:1080", Username: "alice"}, "username and password"},
		{"ca file without tls", Configuration{ProxyAddress: "proxy.example.com:1080", TLSCAFile: "./certs/ca-cert.pem"}, "require tls = true"},
		{"server name without tls", Configuration{ProxyAddress: "proxy.example.com:1080", TLSServerName: "proxy.internal"}, "require tls = true"},
		{"insecure without tls", Configuration{ProxyAddress: "proxy.example.com:1080", TLSInsecureSkipVerify: true}, "require tls = true"},
		{"insecure with ca file", Configuration{ProxyAddress: "proxy.example.com:1080", TLS: true, TLSCAFile: "./certs/ca-cert.pem", TLSInsecureSkipVerify: true}, "mutually exclusive"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.config.Validate()
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
	config := Configuration{ProxyAddress: "[2001:0DB8:0000:0000:0000:0000:0000:0001]:1080"}
	if err := config.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if config.ProxyAddress != "[2001:db8::1]:1080" {
		t.Fatalf("ProxyAddress = %q, want [2001:db8::1]:1080", config.ProxyAddress)
	}
}

func TestConfigurationBackendConfig(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	config := Configuration{
		ProxyAddress:          "proxy.example.com:1080",
		Username:              "alice",
		Password:              "secret",
		TLS:                   true,
		TLSCAFile:             "./certs/ca-cert.pem",
		TLSServerName:         "proxy.internal",
		TLSInsecureSkipVerify: false,
	}
	backendConfig, err := config.BackendConfig(logger)
	if err != nil {
		t.Fatalf("BackendConfig: %v", err)
	}
	if backendConfig.ProxyAddress != config.ProxyAddress || backendConfig.Username != config.Username || backendConfig.Password != config.Password {
		t.Fatal("file configuration was not copied")
	}
	if backendConfig.TLS != config.TLS || backendConfig.TLSCAFile != config.TLSCAFile || backendConfig.TLSServerName != config.TLSServerName || backendConfig.TLSInsecureSkipVerify != config.TLSInsecureSkipVerify {
		t.Fatalf("TLS configuration was not copied: %#v", backendConfig)
	}
	if backendConfig.Logger != logger {
		t.Fatal("logger was not attached")
	}
}
