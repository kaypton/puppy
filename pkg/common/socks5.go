package common

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
)

// SOCKS5 protocol constants defined by RFC 1928 and RFC 1929. They are shared
// between the inbound frontend (pkg/socksproxy) and the outbound chaining
// backend (pkg/adapter/socksproxy).
const (
	// SOCKS5Version is the SOCKS protocol version byte.
	SOCKS5Version byte = 0x05

	// Method selection codes used during the initial negotiation.
	SOCKS5MethodNoAuth           byte = 0x00
	SOCKS5MethodUsernamePassword byte = 0x02
	SOCKS5MethodNoAcceptable     byte = 0xFF

	// SOCKS5AuthVersion is the version byte of the RFC 1929 username/password
	// sub-negotiation.
	SOCKS5AuthVersion byte = 0x01

	// SOCKS5CmdConnect identifies the CONNECT command. BIND and UDP ASSOCIATE
	// are not supported by puppy.
	SOCKS5CmdConnect byte = 0x01

	// Address-type codes for DST.ADDR / BND.ADDR.
	SOCKS5AtypIPv4   byte = 0x01
	SOCKS5AtypDomain byte = 0x03
	SOCKS5AtypIPv6   byte = 0x04

	// Reply (REP) codes returned in SOCKS5 replies.
	SOCKS5RepSuccess              byte = 0x00
	SOCKS5RepGeneralFailure       byte = 0x01
	SOCKS5RepConnectionNotAllowed byte = 0x02
	SOCKS5RepNetworkUnreachable   byte = 0x03
	SOCKS5RepHostUnreachable      byte = 0x04
	SOCKS5RepConnectionRefused    byte = 0x05
	SOCKS5RepTTLExpired           byte = 0x06
	SOCKS5RepCmdNotSupported      byte = 0x07
	SOCKS5RepAddrTypeNotSupported byte = 0x08
)

// SOCKS5ReplyText maps a SOCKS5 reply code to a human-readable description.
func SOCKS5ReplyText(rep byte) string {
	switch rep {
	case SOCKS5RepSuccess:
		return "succeeded"
	case SOCKS5RepGeneralFailure:
		return "general SOCKS server failure"
	case SOCKS5RepConnectionNotAllowed:
		return "connection not allowed by ruleset"
	case SOCKS5RepNetworkUnreachable:
		return "network unreachable"
	case SOCKS5RepHostUnreachable:
		return "host unreachable"
	case SOCKS5RepConnectionRefused:
		return "connection refused"
	case SOCKS5RepTTLExpired:
		return "TTL expired"
	case SOCKS5RepCmdNotSupported:
		return "command not supported"
	case SOCKS5RepAddrTypeNotSupported:
		return "address type not supported"
	default:
		return "unknown error (0x" + strconv.FormatUint(uint64(rep), 16) + ")"
	}
}

// ReadSOCKS5Address reads a SOCKS5 DST.ADDR (or BND.ADDR) followed by the
// 2-byte big-endian DST.PORT from r, decoding IPv4, IPv6, and domain address
// types. The returned host is the literal IP (stringified) or domain name; the
// returned port is the decoded port number. An error is returned for unknown
// address types or short reads.
func ReadSOCKS5Address(r io.Reader, atyp byte) (host string, port uint16, err error) {
	switch atyp {
	case SOCKS5AtypIPv4:
		var addr [4]byte
		if _, err := io.ReadFull(r, addr[:]); err != nil {
			return "", 0, fmt.Errorf("read IPv4 address: %w", err)
		}
		host = net.IP(addr[:]).String()
	case SOCKS5AtypIPv6:
		var addr [16]byte
		if _, err := io.ReadFull(r, addr[:]); err != nil {
			return "", 0, fmt.Errorf("read IPv6 address: %w", err)
		}
		host = net.IP(addr[:]).String()
	case SOCKS5AtypDomain:
		var lenByte [1]byte
		if _, err := io.ReadFull(r, lenByte[:]); err != nil {
			return "", 0, fmt.Errorf("read domain length: %w", err)
		}
		domain := make([]byte, lenByte[0])
		if _, err := io.ReadFull(r, domain); err != nil {
			return "", 0, fmt.Errorf("read domain: %w", err)
		}
		host = string(domain)
	default:
		return "", 0, fmt.Errorf("unknown address type 0x%02x", atyp)
	}

	var portBytes [2]byte
	if _, err := io.ReadFull(r, portBytes[:]); err != nil {
		return "", 0, fmt.Errorf("read port: %w", err)
	}
	port = binary.BigEndian.Uint16(portBytes[:])
	return host, port, nil
}
