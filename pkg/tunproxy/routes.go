package tunproxy

import "strings"

type splitRoute struct {
	family string
	prefix string
}

func isTunnelInterface(name string) bool {
	return strings.HasPrefix(name, "tun") ||
		strings.HasPrefix(name, "utun") ||
		strings.HasPrefix(name, "wg")
}

func splitRoutes(ipv4, ipv6 bool) []splitRoute {
	routes := make([]splitRoute, 0, 4)
	if ipv4 {
		routes = append(routes,
			splitRoute{family: "-4", prefix: "0.0.0.0/1"},
			splitRoute{family: "-4", prefix: "128.0.0.0/1"},
		)
	}
	if ipv6 {
		routes = append(routes,
			splitRoute{family: "-6", prefix: "::/1"},
			splitRoute{family: "-6", prefix: "8000::/1"},
		)
	}
	return routes
}
