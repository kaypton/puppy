package tunproxy

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// parseAddrWithPrefix parses an "IP/prefix" string (e.g. "10.0.0.1/24" or
// "fd00::1/64") and returns the address as a 4- or 16-byte slice plus the
// prefix length. IPv4-mapped IPv6 addresses are normalized to IPv4.
func parseAddrWithPrefix(s string) ([]byte, int, error) {
	ipStr, prefixStr, found := strings.Cut(s, "/")
	if !found {
		return nil, 0, fmt.Errorf("missing prefix length")
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, 0, fmt.Errorf("invalid IP %q", ipStr)
	}
	prefixLen, err := strconv.Atoi(prefixStr)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid prefix %q: %w", prefixStr, err)
	}
	if v4 := ip.To4(); v4 != nil {
		if prefixLen < 0 || prefixLen > 32 {
			return nil, 0, fmt.Errorf("ipv4 prefix %d out of range [0,32]", prefixLen)
		}
		return v4, prefixLen, nil
	}
	if prefixLen < 0 || prefixLen > 128 {
		return nil, 0, fmt.Errorf("ipv6 prefix %d out of range [0,128]", prefixLen)
	}
	return ip.To16(), prefixLen, nil
}
