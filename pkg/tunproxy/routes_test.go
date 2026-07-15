package tunproxy

import "testing"

func TestSplitRoutes(t *testing.T) {
	routes := splitRoutes(true, true)
	want := []splitRoute{
		{family: "-4", prefix: "0.0.0.0/1"},
		{family: "-4", prefix: "128.0.0.0/1"},
		{family: "-6", prefix: "::/1"},
		{family: "-6", prefix: "8000::/1"},
	}
	if len(routes) != len(want) {
		t.Fatalf("route count = %d, want %d", len(routes), len(want))
	}
	for i := range want {
		if routes[i] != want[i] {
			t.Fatalf("route[%d] = %#v, want %#v", i, routes[i], want[i])
		}
	}
}

func TestSelectInterface(t *testing.T) {
	cases := []struct {
		name, network, address string
		iface4, iface6         string
		wantIface              string
		wantFamily             int
		wantErr                bool
	}{
		{"tcp4 network", "tcp4", "example.com:443", "en0", "en1", "en0", 4, false},
		{"IPv4 literal", "tcp", "192.0.2.1:443", "en0", "en1", "en0", 4, false},
		{"IPv6 literal", "udp", "[2001:db8::1]:53", "en0", "en1", "en1", 6, false},
		{"IPv6 only hostname", "tcp", "example.com:443", "", "en1", "en1", 6, false},
		{"missing IPv6", "tcp6", "[2001:db8::1]:443", "en0", "", "", 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			iface, family, err := selectInterface(tc.network, tc.address, tc.iface4, tc.iface6)
			if (err != nil) != tc.wantErr {
				t.Fatalf("error = %v, wantErr %t", err, tc.wantErr)
			}
			if iface != tc.wantIface || family != tc.wantFamily {
				t.Fatalf("result = (%q, %d), want (%q, %d)", iface, family, tc.wantIface, tc.wantFamily)
			}
		})
	}
}
