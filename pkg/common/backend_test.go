package common

import "testing"

func TestCapabilities(t *testing.T) {
	capabilities := []Capability{
		{Network: "tcp", Protocol: ProtocolHTTP},
		{Network: "udp", Protocol: ProtocolAny},
	}

	if !SupportsNetwork(capabilities, "tcp") || SupportsNetwork(capabilities, "icmp") {
		t.Fatal("unexpected network capability match")
	}
	if SupportsAnyProtocol(capabilities, "tcp") || !SupportsAnyProtocol(capabilities, "udp") {
		t.Fatal("unexpected wildcard capability match")
	}
	if !Supports(capabilities, Target{Network: "tcp", Protocol: ProtocolHTTP}) {
		t.Fatal("HTTP over TCP should be supported")
	}
	if Supports(capabilities, Target{Network: "tcp", Protocol: ProtocolTLS}) {
		t.Fatal("TLS over TCP should not be supported")
	}
	if !Supports(capabilities, Target{Network: "udp", Protocol: ProtocolTLS}) {
		t.Fatal("UDP wildcard should support TLS marker")
	}
	if Supports(capabilities, Target{Network: "tcp"}) {
		t.Fatal("empty protocol should normalize to unknown, not HTTP")
	}
}
