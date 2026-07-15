package tunproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"syscall"
	"time"

	"github.com/sagernet/gvisor/pkg/buffer"
	"github.com/sagernet/gvisor/pkg/tcpip"
	"github.com/sagernet/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/sagernet/gvisor/pkg/tcpip/header"
	"github.com/sagernet/gvisor/pkg/tcpip/link/channel"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv4"
	"github.com/sagernet/gvisor/pkg/tcpip/network/ipv6"
	"github.com/sagernet/gvisor/pkg/tcpip/stack"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/tcp"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/udp"
	"github.com/sagernet/gvisor/pkg/waiter"
)

// nicID is the single virtual NIC used by tunproxy's netstack.
const nicID tcpip.NICID = 1

// networkStack owns the gVisor netstack, the channel link endpoint bridging it
// to the TUN device, and the inbound/outbound pump goroutines.
type networkStack struct {
	stack  *stack.Stack
	linkEP *channel.Endpoint

	device Device

	// inboundCtx cancels the inbound pump goroutine on shutdown.
	inboundCtx    context.Context
	inboundCancel context.CancelFunc
	inboundWG     sync.WaitGroup

	// outboundWG tracks the outbound pump goroutine.
	outboundWG sync.WaitGroup

	// handler dispatches accepted TCP/UDP sessions to the backend.
	handler sessionHandler
}

// sessionHandler is implemented by the dispatch layer; netstack calls it when
// a TCP or UDP session is accepted.
type sessionHandler interface {
	HandleTCP(req *tcp.ForwarderRequest)
	HandleUDP(req *udp.ForwarderRequest)
}

// newNetworkStack builds the gVisor stack with IPv4/IPv6 and TCP/UDP enabled,
// creates a channel link endpoint, and wires the TCP/UDP forwarders. The
// handler must be set on the returned networkStack before startPumps is called.
func newNetworkStack(device Device, mtu uint32) (*networkStack, error) {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})

	if m := mtu; m == 0 {
		mtu = defaultMTU
	}
	linkEP := channel.New(512, mtu, "")

	// Promiscuous mode + a catch-all route so the stack accepts packets whose
	// destination is not the NIC's own address (the proxy intercepts traffic
	// addressed to arbitrary hosts).
	if err := s.CreateNIC(nicID, linkEP); err != nil {
		return nil, fmt.Errorf("tunproxy: create NIC: %s", err)
	}
	if err := s.SetPromiscuousMode(nicID, true); err != nil {
		return nil, fmt.Errorf("tunproxy: set promiscuous mode: %s", err)
	}
	// Forwarded endpoints must reply with the intercepted destination as their
	// source address. Those addresses are intentionally not assigned to the
	// NIC, so outgoing address selection requires spoofing in addition to
	// promiscuous receive mode.
	if err := s.SetSpoofing(nicID, true); err != nil {
		return nil, fmt.Errorf("tunproxy: set spoofing: %s", err)
	}
	s.SetRouteTable([]tcpip.Route{
		{
			Destination: header.IPv4EmptySubnet,
			NIC:         nicID,
		},
		{
			Destination: header.IPv6EmptySubnet,
			NIC:         nicID,
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	ns := &networkStack{
		stack:         s,
		linkEP:        linkEP,
		device:        device,
		inboundCtx:    ctx,
		inboundCancel: cancel,
	}

	tcpFwd := tcp.NewForwarder(s, 0, 1<<16, func(req *tcp.ForwarderRequest) {
		if ns.handler != nil {
			ns.handler.HandleTCP(req)
		} else {
			req.Complete(true)
		}
	})
	s.SetTransportProtocolHandler(header.TCPProtocolNumber, tcpFwd.HandlePacket)
	udpFwd := udp.NewForwarder(s, func(req *udp.ForwarderRequest) bool {
		if ns.handler != nil {
			ns.handler.HandleUDP(req)
		}
		return true
	})
	s.SetTransportProtocolHandler(header.UDPProtocolNumber, udpFwd.HandlePacket)

	return ns, nil
}

// startPumps launches the inbound (device -> netstack) and outbound
// (netstack -> device) goroutines. It must be called once after
// newNetworkStack.
func (ns *networkStack) startPumps() <-chan error {
	errs := make(chan error, 2)
	// Inbound: read raw IP packets from the TUN device and inject them into
	// the netstack via the channel endpoint.
	ns.inboundWG.Add(1)
	go func() {
		defer ns.inboundWG.Done()
		buf := make([]byte, ns.device.MTU()+header.IPv6MinimumSize)
		for {
			n, err := ns.device.Read(buf)
			if err != nil {
				if ctxErr := ns.inboundCtx.Err(); ctxErr != nil {
					return
				}
				if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) {
					select {
					case <-ns.inboundCtx.Done():
						return
					case <-time.After(time.Millisecond):
						continue
					}
				}
				errs <- fmt.Errorf("tunproxy: read TUN device: %w", err)
				return
			}
			if n == 0 {
				continue
			}
			data := make([]byte, n)
			copy(data, buf[:n])

			var proto tcpip.NetworkProtocolNumber
			switch data[0] >> 4 {
			case 4:
				proto = header.IPv4ProtocolNumber
			case 6:
				proto = header.IPv6ProtocolNumber
			default:
				continue
			}

			pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
				Payload: buffer.MakeWithData(data),
			})
			ns.linkEP.InjectInbound(proto, pkt)
			pkt.DecRef()
		}
	}()

	// Outbound: drain packets the netstack wants to send out and write them
	// to the TUN device.
	ns.outboundWG.Add(1)
	go func() {
		defer ns.outboundWG.Done()
		for {
			pkt := ns.linkEP.ReadContext(ns.inboundCtx)
			if pkt == nil {
				return
			}
			pktBuf := pkt.ToBuffer()
			data := pktBuf.Flatten()
			n, err := ns.device.Write(data)
			pktBuf.Release()
			pkt.DecRef()
			if err != nil {
				if ctxErr := ns.inboundCtx.Err(); ctxErr != nil {
					return
				}
				errs <- fmt.Errorf("tunproxy: write TUN device: %w", err)
				return
			}
			if n != len(data) {
				errs <- fmt.Errorf("tunproxy: write TUN device: %w", io.ErrShortWrite)
				return
			}
		}
	}()
	return errs
}

// stop halts the pumps and releases the netstack resources. It is safe to
// call multiple times.
func (ns *networkStack) stop() {
	ns.inboundCancel()
	ns.linkEP.Close()
	// Close the device to unblock any pending Read.
	_ = ns.device.Close()
	ns.inboundWG.Wait()
	ns.outboundWG.Wait()
	ns.stack.Close()
}

// addAddress assigns a network-layer address with prefix to the virtual NIC.
// addr must be in "IP/prefix" form, e.g. "10.0.0.1/24".
func (ns *networkStack) addAddress(addrWithPrefix string) error {
	addr, prefixLen, err := parseAddrWithPrefix(addrWithPrefix)
	if err != nil {
		return fmt.Errorf("tunproxy: parse address %q: %w", addrWithPrefix, err)
	}
	var proto tcpip.NetworkProtocolNumber
	switch len(addr) {
	case header.IPv4AddressSize:
		proto = header.IPv4ProtocolNumber
	case header.IPv6AddressSize:
		proto = header.IPv6ProtocolNumber
	default:
		return fmt.Errorf("tunproxy: unsupported address length for %q", addrWithPrefix)
	}
	if err := ns.stack.AddProtocolAddress(nicID, tcpip.ProtocolAddress{
		Protocol: proto,
		AddressWithPrefix: tcpip.AddressWithPrefix{
			Address:   tcpip.AddrFromSlice(addr),
			PrefixLen: prefixLen,
		},
	}, stack.AddressProperties{}); err != nil {
		return fmt.Errorf("tunproxy: add address %q: %s", addrWithPrefix, err)
	}
	return nil
}

// endpointFromRequest creates a connected gVisor endpoint for a TCP
// ForwarderRequest and returns it wrapped as a gonet TCP connection.
func (ns *networkStack) endpointFromTCPRequest(req *tcp.ForwarderRequest) (*gonet.TCPConn, error) {
	wq := &waiter.Queue{}
	ep, err := req.CreateEndpoint(wq)
	if err != nil {
		return nil, fmt.Errorf("create tcp endpoint: %s", err)
	}
	return gonet.NewTCPConn(wq, ep), nil
}

// endpointFromUDPRequest creates a connected gVisor endpoint for a UDP
// ForwarderRequest and returns it wrapped as a gonet UDP connection.
func (ns *networkStack) endpointFromUDPRequest(req *udp.ForwarderRequest) (*gonet.UDPConn, error) {
	wq := &waiter.Queue{}
	ep, err := req.CreateEndpoint(wq)
	if err != nil {
		return nil, fmt.Errorf("create udp endpoint: %s", err)
	}
	return gonet.NewUDPConn(wq, ep), nil
}

// targetFromEndpointID converts a gVisor TransportEndpointID (whose
// LocalAddress/LocalPort is the original destination from the client's
// perspective) into a host/port pair.
func targetFromEndpointID(id stack.TransportEndpointID) (host string, port uint16) {
	return id.LocalAddress.String(), id.LocalPort
}
