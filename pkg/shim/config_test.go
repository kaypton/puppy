package shim

import (
	"io"
	"testing"
)

func TestConfigurationValidate(t *testing.T) {
	for _, bufferSize := range []int{0, 1, 32 * 1024} {
		if err := (Configuration{BufferSize: bufferSize}).Validate(); err != nil {
			t.Fatalf("BufferSize %d: unexpected error: %v", bufferSize, err)
		}
	}
	if err := (Configuration{BufferSize: -1}).Validate(); err == nil {
		t.Fatal("negative BufferSize: expected error")
	}
}

func TestShimServerConfiguration_Validate(t *testing.T) {
	var rwc io.ReadWriteCloser = nopReadWriteCloser{}

	cases := []struct {
		name    string
		cfg     ShimServerConfiguration
		wantErr string
	}{
		{name: "nil frontend", cfg: ShimServerConfiguration{Backend: rwc}, wantErr: "shim: frontend is nil"},
		{name: "nil backend", cfg: ShimServerConfiguration{Frontend: rwc}, wantErr: "shim: backend is nil"},
		{name: "valid", cfg: ShimServerConfiguration{Frontend: rwc, Backend: rwc}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error %q, got nil", tc.wantErr)
			}
			if err.Error() != tc.wantErr {
				t.Fatalf("expected error %q, got %q", tc.wantErr, err.Error())
			}
		})
	}
}

type nopReadWriteCloser struct{}

func (nopReadWriteCloser) Read([]byte) (int, error)    { return 0, io.EOF }
func (nopReadWriteCloser) Write(p []byte) (int, error) { return len(p), nil }
func (nopReadWriteCloser) Close() error                { return nil }
