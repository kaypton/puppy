package shim

import "testing"

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
