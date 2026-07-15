//go:build linux

package tunproxy

import (
	"bytes"
	"io"
	"net"
	"strconv"
	"testing"
	"time"
)

type echoDNSInterceptHandler struct{}

func (echoDNSInterceptHandler) serveInterceptedDNSStream(conn io.ReadWriteCloser) {
	_, _ = io.Copy(conn, conn)
}

func (echoDNSInterceptHandler) resolveInterceptedDNSDatagram(query []byte) ([]byte, error) {
	return append([]byte("response:"), query...), nil
}

func TestLinuxDNSProxy_ForwardsTCPAndUDP(t *testing.T) {
	proxy, err := newLinuxDNSProxy(echoDNSInterceptHandler{})
	if err != nil {
		t.Fatalf("newLinuxDNSProxy: %v", err)
	}
	proxy.Start()

	udp, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(proxy.udpPort())})
	if err != nil {
		t.Fatalf("dial UDP proxy: %v", err)
	}
	if err := udp.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set UDP deadline: %v", err)
	}
	query := []byte("query")
	if _, err := udp.Write(query); err != nil {
		t.Fatalf("write UDP query: %v", err)
	}
	buf := make([]byte, 64)
	n, err := udp.Read(buf)
	if err != nil {
		t.Fatalf("read UDP response: %v", err)
	}
	if want := []byte("response:query"); !bytes.Equal(buf[:n], want) {
		t.Fatalf("UDP response = %q, want %q", buf[:n], want)
	}
	_ = udp.Close()

	tcp, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", portString(proxy.tcpPort())), time.Second)
	if err != nil {
		t.Fatalf("dial TCP proxy: %v", err)
	}
	if err := tcp.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set TCP deadline: %v", err)
	}
	if _, err := tcp.Write(query); err != nil {
		t.Fatalf("write TCP query: %v", err)
	}
	got := make([]byte, len(query))
	if _, err := io.ReadFull(tcp, got); err != nil {
		t.Fatalf("read TCP response: %v", err)
	}
	if !bytes.Equal(got, query) {
		t.Fatalf("TCP response = %q, want %q", got, query)
	}
	_ = tcp.Close()

	if err := proxy.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := proxy.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func portString(port uint16) string {
	return strconv.Itoa(int(port))
}
