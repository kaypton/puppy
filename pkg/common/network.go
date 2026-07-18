package common

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// NormalizeListenAddress validates and canonicalizes an address intended for
// net.Listen("tcp", net.JoinHostPort(addr, port)). It accepts hostnames and
// IPv4 literals as-is, and requires bracketed IPv6 literals (e.g. "[::1]").
// The returned address is a canonical form suitable for storage and
// comparison: hostnames and IPv4 are returned as-is, IPv6 is returned as the
// standard compressed form without brackets. An error is returned for empty
// strings, bare IPv6 literals, invalid addresses, bracketed IPv4, bracketed
// addresses with ports, unclosed brackets, IPv4 leading zeros, IPv4-mapped
// IPv6, or IPv6 zone identifiers.
func NormalizeListenAddress(addr string) (string, error) {
	if addr == "" {
		return "", fmt.Errorf("listen address is required")
	}
	if strings.Contains(addr, "]") || strings.Contains(addr, "[") {
		if len(addr) < 2 || addr[0] != '[' || addr[len(addr)-1] != ']' {
			return "", fmt.Errorf("listen address %q has unclosed brackets", addr)
		}
		ipStr := addr[1 : len(addr)-1]
		ip, err := netip.ParseAddr(ipStr)
		if err != nil {
			return "", fmt.Errorf("listen address %q is not a valid IPv6 address: %w", addr, err)
		}
		if ip.Zone() != "" {
			return "", fmt.Errorf("listen address must not contain an IPv6 zone")
		}
		if ip.Is4In6() {
			return "", fmt.Errorf("listen address must not be an IPv4-mapped IPv6 address")
		}
		if ip.Is4() {
			return "", fmt.Errorf("listen address must not wrap IPv4 in brackets")
		}
		return ip.String(), nil
	}

	if strings.Contains(addr, ":") {
		return "", fmt.Errorf("listen address IPv6 must be wrapped in brackets, e.g. [%s]", addr)
	}

	if ip, err := netip.ParseAddr(addr); err == nil {
		if ip.Zone() != "" {
			return "", fmt.Errorf("listen address must not contain an IPv6 zone")
		}
		if ip.Is4In6() {
			return "", fmt.Errorf("listen address must not be an IPv4-mapped IPv6 address")
		}
		if ip.Is4() {
			strict, err := parseStrictIPv4(addr)
			if err != nil {
				return "", err
			}
			return strict.String(), nil
		}
		return "", fmt.Errorf("listen address IPv6 must be wrapped in brackets, e.g. [%s]", addr)
	}

	// If it looks like an IPv4 attempt but netip.ParseAddr rejected it, fail
	// rather than silently treating it as a hostname.
	if looksLikeIPv4(addr) {
		if _, err := parseStrictIPv4(addr); err != nil {
			return "", err
		}
	}

	return addr, nil
}

// NormalizeProxyAddress validates and canonicalizes an upstream proxy address
// in host:port form. It accepts hostnames, IPv4 literals, and bracketed IPv6
// literals (e.g. [2001:db8::1]:1080). Bare IPv6 literals are rejected. The
// returned address is always in the host:port form expected by net.Dial; IPv6
// addresses are returned with brackets, IPv4 and hostnames without.
func NormalizeProxyAddress(addr string) (string, error) {
	if addr == "" {
		return "", fmt.Errorf("proxy address is required")
	}
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("proxy address must be in host:port form: %w", err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || port == 0 {
		return "", fmt.Errorf("proxy address port must be between 1 and 65535")
	}
	if host == "" {
		return "", fmt.Errorf("proxy address host is required")
	}

	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Zone() != "" {
			return "", fmt.Errorf("proxy address must not contain an IPv6 zone")
		}
		if ip.Is4In6() {
			return "", fmt.Errorf("proxy address must not be an IPv4-mapped IPv6 address")
		}
		if ip.Is4() {
			strict, err := parseStrictIPv4(host)
			if err != nil {
				return "", fmt.Errorf("proxy address host: %w", err)
			}
			return net.JoinHostPort(strict.String(), portStr), nil
		}
		return net.JoinHostPort(ip.String(), portStr), nil
	}

	if looksLikeIPv4(host) {
		if _, err := parseStrictIPv4(host); err != nil {
			return "", fmt.Errorf("proxy address host: %w", err)
		}
	}

	return net.JoinHostPort(host, portStr), nil
}

// looksLikeIPv4 reports whether s consists only of digits and dots and has
// the visual structure of an IPv4 address. It is used to distinguish invalid
// IPv4 literals from arbitrary hostnames.
func looksLikeIPv4(s string) bool {
	if strings.Contains(s, ":") {
		return false
	}
	if strings.Count(s, ".") < 3 {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && r != '.' {
			return false
		}
	}
	return true
}

// parseStrictIPv4 parses a strict IPv4 address, rejecting octets with leading
// zeros, and returns the canonical 4-byte form.
func parseStrictIPv4(s string) (net.IP, error) {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return nil, fmt.Errorf("address %q is not a valid IPv4 address", s)
	}
	for _, part := range parts {
		if part == "" || len(part) > 1 && part[0] == '0' {
			return nil, fmt.Errorf("address %q has invalid IPv4 octet", s)
		}
		if _, err := strconv.ParseUint(part, 10, 8); err != nil {
			return nil, fmt.Errorf("address %q is not a valid IPv4 address", s)
		}
	}
	ip := net.ParseIP(s)
	if ip == nil || ip.To4() == nil {
		return nil, fmt.Errorf("address %q is not a valid IPv4 address", s)
	}
	return ip.To4(), nil
}
