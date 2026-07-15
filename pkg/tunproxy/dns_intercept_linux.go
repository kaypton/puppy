//go:build linux

package tunproxy

import (
	"errors"
	"fmt"
	"net"
	"sync"
)

// linuxDNSProxy receives nft DNAT traffic on ephemeral loopback ports and
// hands it to the regular TUN dispatcher. Keeping the redirected traffic on
// loopback avoids changing Linux's route_localnet and reverse-path settings.
type linuxDNSProxy struct {
	handler dnsInterceptHandler
	udp     *net.UDPConn
	tcp     *net.TCPListener

	startOnce sync.Once
	closeOnce sync.Once
	loopWG    sync.WaitGroup
	handlerWG sync.WaitGroup
	closeErr  error
}

func newLinuxDNSProxy(handler dnsInterceptHandler) (*linuxDNSProxy, error) {
	udpAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}
	udp, err := net.ListenUDP("udp4", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("listen for redirected UDP DNS: %w", err)
	}
	tcpAddr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)}
	tcp, err := net.ListenTCP("tcp4", tcpAddr)
	if err != nil {
		_ = udp.Close()
		return nil, fmt.Errorf("listen for redirected TCP DNS: %w", err)
	}
	return &linuxDNSProxy{handler: handler, udp: udp, tcp: tcp}, nil
}

func (p *linuxDNSProxy) udpPort() uint16 {
	return uint16(p.udp.LocalAddr().(*net.UDPAddr).Port)
}

func (p *linuxDNSProxy) tcpPort() uint16 {
	return uint16(p.tcp.Addr().(*net.TCPAddr).Port)
}

func (p *linuxDNSProxy) Start() {
	p.startOnce.Do(func() {
		p.loopWG.Add(2)
		go p.serveUDP()
		go p.serveTCP()
	})
}

func (p *linuxDNSProxy) serveUDP() {
	defer p.loopWG.Done()
	buf := make([]byte, maxDNSMessageSize)
	for {
		n, client, err := p.udp.ReadFromUDP(buf)
		if err != nil {
			return
		}
		query := append([]byte(nil), buf[:n]...)
		p.handlerWG.Add(1)
		go func() {
			defer p.handlerWG.Done()
			response, err := p.handler.resolveInterceptedDNSDatagram(query)
			if err == nil {
				_, _ = p.udp.WriteToUDP(response, client)
			}
		}()
	}
}

func (p *linuxDNSProxy) serveTCP() {
	defer p.loopWG.Done()
	for {
		conn, err := p.tcp.AcceptTCP()
		if err != nil {
			return
		}
		p.handlerWG.Add(1)
		go func() {
			defer p.handlerWG.Done()
			defer conn.Close()
			p.handler.serveInterceptedDNSStream(conn)
		}()
	}
}

func (p *linuxDNSProxy) Close() error {
	p.closeOnce.Do(func() {
		p.closeErr = errors.Join(p.udp.Close(), p.tcp.Close())
		p.loopWG.Wait()
		p.handlerWG.Wait()
	})
	return p.closeErr
}
