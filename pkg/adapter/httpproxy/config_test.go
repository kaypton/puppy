package httpproxy

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
		{"valid", Configuration{ProxyAddress: "proxy.example.com:3128"}, ""},
		{"valid auth", Configuration{ProxyAddress: "proxy.example.com:3128", Username: "alice", Password: "secret"}, ""},
		{"missing address", Configuration{}, "proxy_address is required"},
		{"missing port", Configuration{ProxyAddress: "proxy.example.com"}, "host:port"},
		{"zero port", Configuration{ProxyAddress: "proxy.example.com:0"}, "between 1 and 65535"},
		{"unpaired credentials", Configuration{ProxyAddress: "proxy.example.com:3128", Username: "alice"}, "username and password"},
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

func TestConfigurationBackendConfig(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	config := Configuration{
		ProxyAddress: "proxy.example.com:3128",
		Username:     "alice",
		Password:     "secret",
	}
	backendConfig := config.BackendConfig(logger)
	if backendConfig.ProxyAddress != config.ProxyAddress || backendConfig.Username != config.Username || backendConfig.Password != config.Password {
		t.Fatal("file configuration was not copied")
	}
	if backendConfig.Logger != logger {
		t.Fatal("logger was not attached")
	}
}
