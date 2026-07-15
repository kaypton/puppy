//go:build darwin

package tunproxy

import "testing"

func TestParseUtunUnit(t *testing.T) {
	cases := []struct {
		in      string
		want    int
		wantErr bool
	}{
		{"", 0, false},
		{"utun", 0, false},
		{"utun0", 0, false},
		{"utun9", 9, false},
		{"utun100", 100, false},
		{"tun0", 0, true},
		{"utunx", 0, true},
		{"utun-1", 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := parseUtunUnit(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %q", tc.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("unit = %d, want %d", got, tc.want)
			}
		})
	}
}
