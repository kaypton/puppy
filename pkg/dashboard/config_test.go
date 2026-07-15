package dashboard

import (
	"strings"
	"testing"
)

func TestConfigurationValidate(t *testing.T) {
	valid := Configuration{Enabled: true, ListenAddress: "127.0.0.1", ListenPort: 8443}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid config: unexpected error: %v", err)
	}

	disabled := Configuration{Enabled: false}
	if err := disabled.Validate(); err != nil {
		t.Fatalf("disabled config should skip validation: %v", err)
	}

	cases := []struct {
		name    string
		cfg     Configuration
		wantErr string
	}{
		{"missing address", Configuration{Enabled: true, ListenPort: 8443}, "listen_address"},
		{"missing port", Configuration{Enabled: true, ListenAddress: "127.0.0.1"}, "listen_port"},
		{"cert only", Configuration{Enabled: true, ListenAddress: "127.0.0.1", ListenPort: 8443, TLSCertFile: "cert.pem"}, "tls_cert_file and tls_key_file"},
		{"key only", Configuration{Enabled: true, ListenAddress: "127.0.0.1", ListenPort: 8443, TLSKeyFile: "key.pem"}, "tls_cert_file and tls_key_file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want substring %q", err, tc.wantErr)
			}
		})
	}
}
