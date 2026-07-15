package tunproxy

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/puppy/pkg/common"
	"github.com/puppy/pkg/shim"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/tcp"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/udp"
)

const (
	dnsPort           uint16 = 53
	maxDNSMessageSize        = 1<<16 - 1
)

// dispatcher implements sessionHandler. It accepts TCP/UDP sessions from the
// netstack and forwards them to a common.Backend.
type dispatcher struct {
	ns             *networkStack
	backends       []common.Backend
	fallback       common.Backend
	dialer         common.Dialer
	dns            *common.Target
	shimBuf        int
	udpIdle        time.Duration
	detectTimeout  time.Duration
	detectMaxBytes int
	logger         *slog.Logger
	ctx            context.Context
	wg             sync.WaitGroup
}

// newDispatcher creates a dispatcher bound to the given context. Run must be
// cancelled to release in-flight sessions.
func newDispatcher(ctx context.Context, ns *networkStack, backends []common.Backend, fallback common.Backend, dialer common.Dialer, dns *common.Target, shimBuf int, udpIdle, detectTimeout time.Duration, detectMaxBytes int, logger *slog.Logger) *dispatcher {
	return &dispatcher{
		ns:             ns,
		backends:       backends,
		fallback:       fallback,
		dialer:         dialer,
		dns:            dns,
		shimBuf:        shimBuf,
		udpIdle:        udpIdle,
		detectTimeout:  detectTimeout,
		detectMaxBytes: detectMaxBytes,
		logger:         logger,
		ctx:            ctx,
	}
}

// HandleTCP is invoked by the netstack TCP forwarder for each new connection
// attempt. It dials the backend, then pipes bytes both ways via a ShimServer.
func (d *dispatcher) HandleTCP(req *tcp.ForwarderRequest) {
	id := req.ID()
	host, port := targetFromEndpointID(id)
	target := common.Target{Network: "tcp", Host: host, Port: port}

	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		d.serveTCP(req, target)
	}()
}

func (d *dispatcher) serveTCP(req *tcp.ForwarderRequest, target common.Target) {
	originalTarget := target
	target, dnsRedirect := d.redirectDNS(target)
	frontend, err := d.ns.endpointFromTCPRequest(req)
	if err != nil {
		d.logger.Info("tunproxy: tcp endpoint creation failed", "target", target.Address(), "err", err)
		req.Complete(true)
		return
	}
	var frontendConn io.ReadWriteCloser = frontend
	var backend common.Backend
	var backendIndex int
	var fallback bool
	if dnsRedirect {
		backend, backendIndex, fallback = d.selectBackend(target)
	} else {
		backend, backendIndex, fallback = d.selectTCPBackend(target)
	}
	if !dnsRedirect && backendIndex >= 0 && !common.SupportsAnyProtocol(backend.Capabilities(), "tcp") {
		target.Protocol, frontendConn, err = detectProtocol(d.ctx, frontend, d.detectTimeout, d.detectMaxBytes)
		if err != nil {
			d.logger.Info("tunproxy: tcp protocol detection failed", "target", target.Address(), "err", err)
			_ = frontend.Close()
			return
		}
		backend, backendIndex, fallback = d.selectBackend(target)
	} else if !dnsRedirect {
		target.Protocol = common.ProtocolUnknown
	}
	d.logger.Info("tunproxy: tcp route selected", "original_target", originalTarget.Address(), "target", target.Address(), "protocol", target.Protocol, "backend_index", backendIndex, "fallback", fallback)

	upstream, err := backend.Dial(d.ctx, target, d.dialer)
	if err != nil {
		d.logger.Info("tunproxy: tcp backend dial failed", "target", target.Address(), "protocol", target.Protocol, "backend_index", backendIndex, "fallback", fallback, "err", err)
		_ = frontendConn.Close()
		return
	}
	defer func() {
		_ = frontendConn.Close()
		_ = upstream.Close()
	}()

	s, err := shim.NewShimServer(shim.ShimServerConfiguration{
		Frontend:   frontendConn,
		Backend:    upstream,
		BufferSize: d.shimBuf,
	})
	if err != nil {
		d.logger.Error("tunproxy: shim construction failed", "target", target.Address(), "err", err)
		return
	}
	d.logger.Info("tunproxy: tcp tunnel established", "target", target.Address())
	_, _, _ = s.Run(d.ctx)
}

// HandleUDP is invoked by the netstack UDP forwarder for each new datagram
// flow. It dials the backend and relays datagrams both ways until idle.
func (d *dispatcher) HandleUDP(req *udp.ForwarderRequest) {
	id := req.ID()
	host, port := targetFromEndpointID(id)
	target := common.Target{Network: "udp", Host: host, Port: port}
	// Register the endpoint before returning from the forwarder callback. If
	// backend dialing happens first, subsequent datagrams for the same flow can
	// trigger additional ForwarderRequests and race to bind the same port.
	frontend, err := d.ns.endpointFromUDPRequest(req)
	if err != nil {
		d.logger.Info("tunproxy: udp endpoint creation failed", "target", target.Address(), "err", err)
		return
	}

	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		d.serveUDP(frontend, target)
	}()
}

func (d *dispatcher) serveUDP(frontend io.ReadWriteCloser, target common.Target) {
	defer frontend.Close()
	if dnsTarget, ok := d.redirectDNS(target); ok {
		d.serveUDPDNS(frontend, target, dnsTarget)
		return
	}
	target.Protocol = common.ProtocolUnknown
	backend, backendIndex, fallback := d.selectBackend(target)
	d.logger.Info("tunproxy: udp route selected", "target", target.Address(), "backend_index", backendIndex, "fallback", fallback)
	upstream, err := backend.Dial(d.ctx, target, d.dialer)
	if err != nil {
		d.logger.Info("tunproxy: udp backend dial failed", "target", target.Address(), "backend_index", backendIndex, "fallback", fallback, "err", err)
		return
	}
	defer upstream.Close()

	d.logger.Info("tunproxy: udp tunnel established", "target", target.Address())

	idleReset := make(chan struct{}, 1)
	stop := make(chan struct{})
	defer close(stop)
	go d.watchUDPIdle(frontend, upstream, idleReset, stop)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		pipeUDP(frontend, upstream, idleReset)
		_ = upstream.Close()
	}()
	go func() {
		defer wg.Done()
		pipeUDP(upstream, frontend, idleReset)
		_ = frontend.Close()
	}()
	wg.Wait()
}

// serveUDPDNS converts each intercepted UDP DNS datagram to the two-byte
// length-prefixed DNS-over-TCP format expected by the backend connection. The
// TCP connection is reused for the lifetime of the UDP flow.
func (d *dispatcher) serveUDPDNS(frontend io.ReadWriteCloser, originalTarget, target common.Target) {
	backend, backendIndex, fallback := d.selectBackend(target)
	d.logger.Info("tunproxy: udp dns route selected", "original_target", originalTarget.Address(), "target", target.Address(), "protocol", target.Protocol, "backend_index", backendIndex, "fallback", fallback)
	upstream, err := backend.Dial(d.ctx, target, d.dialer)
	if err != nil {
		d.logger.Info("tunproxy: udp dns backend dial failed", "original_target", originalTarget.Address(), "target", target.Address(), "backend_index", backendIndex, "fallback", fallback, "err", err)
		return
	}
	defer upstream.Close()

	d.logger.Info("tunproxy: udp dns tunnel established", "original_target", originalTarget.Address(), "target", target.Address())
	idleReset := make(chan struct{}, 1)
	stop := make(chan struct{})
	defer close(stop)
	go d.watchUDPIdle(frontend, upstream, idleReset, stop)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_ = pipeUDPToDNSStream(upstream, frontend, idleReset)
		_ = upstream.Close()
	}()
	go func() {
		defer wg.Done()
		_ = pipeDNSStreamToUDP(frontend, upstream, idleReset)
		_ = frontend.Close()
	}()
	wg.Wait()
}

// serveInterceptedDNSStream forwards a TCP DNS connection redirected from the
// systemd-resolved stub to the configured DNS target.
func (d *dispatcher) serveInterceptedDNSStream(frontend io.ReadWriteCloser) {
	if d.dns == nil {
		d.logger.Error("tunproxy: systemd-resolved tcp dns interception has no configured target")
		return
	}
	target := *d.dns
	backend, backendIndex, fallback := d.selectBackend(target)
	d.logger.Info("tunproxy: systemd-resolved tcp dns route selected", "target", target.Address(), "backend_index", backendIndex, "fallback", fallback)
	upstream, err := backend.Dial(d.ctx, target, d.dialer)
	if err != nil {
		d.logger.Info("tunproxy: systemd-resolved tcp dns backend dial failed", "target", target.Address(), "backend_index", backendIndex, "fallback", fallback, "err", err)
		return
	}
	defer upstream.Close()

	s, err := shim.NewShimServer(shim.ShimServerConfiguration{
		Frontend:   frontend,
		Backend:    upstream,
		BufferSize: d.shimBuf,
	})
	if err != nil {
		d.logger.Error("tunproxy: systemd-resolved tcp dns shim construction failed", "target", target.Address(), "err", err)
		return
	}
	_, _, _ = s.Run(d.ctx)
}

// resolveInterceptedDNSDatagram carries one redirected UDP DNS query over a
// DNS-over-TCP backend connection and returns its single response datagram.
func (d *dispatcher) resolveInterceptedDNSDatagram(query []byte) ([]byte, error) {
	if d.dns == nil {
		return nil, errors.New("systemd-resolved DNS interception has no configured target")
	}
	if len(query) == 0 {
		return nil, errors.New("empty UDP DNS message")
	}
	if len(query) > maxDNSMessageSize {
		return nil, errors.New("UDP DNS message exceeds maximum size")
	}
	target := *d.dns
	backend, backendIndex, fallback := d.selectBackend(target)
	d.logger.Info("tunproxy: systemd-resolved udp dns route selected", "target", target.Address(), "backend_index", backendIndex, "fallback", fallback)
	upstream, err := backend.Dial(d.ctx, target, d.dialer)
	if err != nil {
		return nil, err
	}
	defer upstream.Close()
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-d.ctx.Done():
			_ = upstream.Close()
		case <-done:
		}
	}()

	frame := make([]byte, 2+len(query))
	binary.BigEndian.PutUint16(frame, uint16(len(query)))
	copy(frame[2:], query)
	if err := writeFull(upstream, frame); err != nil {
		return nil, err
	}
	var length [2]byte
	if _, err := io.ReadFull(upstream, length[:]); err != nil {
		return nil, err
	}
	size := int(binary.BigEndian.Uint16(length[:]))
	if size == 0 {
		return nil, errors.New("empty TCP DNS message")
	}
	response := make([]byte, size)
	if _, err := io.ReadFull(upstream, response); err != nil {
		return nil, err
	}
	return response, nil
}

// redirectDNS replaces a destination-port-53 target with the configured
// fixed DNS-over-TCP resolver.
func (d *dispatcher) redirectDNS(target common.Target) (common.Target, bool) {
	if d.dns == nil || target.Port != dnsPort {
		return target, false
	}
	return *d.dns, true
}

// watchUDPIdle closes both sides of a UDP relay after inactivity or context
// cancellation, interrupting any blocked reads.
func (d *dispatcher) watchUDPIdle(frontend, upstream io.Closer, idleReset <-chan struct{}, stop <-chan struct{}) {
	timer := time.NewTimer(d.udpIdle)
	defer timer.Stop()
	for {
		select {
		case <-d.ctx.Done():
			_ = frontend.Close()
			_ = upstream.Close()
			return
		case <-stop:
			return
		case <-idleReset:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(d.udpIdle)
		case <-timer.C:
			_ = frontend.Close()
			_ = upstream.Close()
			return
		}
	}
}

func (d *dispatcher) selectTCPBackend(target common.Target) (common.Backend, int, bool) {
	for index, backend := range d.backends {
		if common.SupportsNetwork(backend.Capabilities(), "tcp") {
			return backend, index, false
		}
	}
	return d.fallback, -1, true
}

func (d *dispatcher) selectBackend(target common.Target) (common.Backend, int, bool) {
	for index, backend := range d.backends {
		if common.Supports(backend.Capabilities(), target) {
			return backend, index, false
		}
	}
	return d.fallback, -1, true
}

// pipeUDP copies from src to dst, signaling idleReset on each successful
// transfer so the watchdog can extend the session lifetime.
func pipeUDP(dst io.Writer, src io.Reader, idleReset chan<- struct{}) {
	buf := make([]byte, 2048)
	for {
		n, err := src.Read(buf)
		if err != nil {
			return
		}
		if _, werr := dst.Write(buf[:n]); werr != nil {
			return
		}
		select {
		case idleReset <- struct{}{}:
		default:
		}
	}
}

// pipeUDPToDNSStream frames UDP datagrams for a DNS-over-TCP stream.
func pipeUDPToDNSStream(dst io.Writer, src io.Reader, idleReset chan<- struct{}) error {
	buf := make([]byte, maxDNSMessageSize)
	for {
		n, err := src.Read(buf)
		if err != nil {
			return err
		}
		if n == 0 {
			return errors.New("empty UDP DNS message")
		}
		frame := make([]byte, 2+n)
		binary.BigEndian.PutUint16(frame, uint16(n))
		copy(frame[2:], buf[:n])
		if err := writeFull(dst, frame); err != nil {
			return err
		}
		signalIdle(idleReset)
	}
}

// pipeDNSStreamToUDP removes DNS-over-TCP framing and writes each message as
// one UDP datagram.
func pipeDNSStreamToUDP(dst io.Writer, src io.Reader, idleReset chan<- struct{}) error {
	var length [2]byte
	for {
		if _, err := io.ReadFull(src, length[:]); err != nil {
			return err
		}
		n := int(binary.BigEndian.Uint16(length[:]))
		if n == 0 {
			return errors.New("empty TCP DNS message")
		}
		message := make([]byte, n)
		if _, err := io.ReadFull(src, message); err != nil {
			return err
		}
		written, err := dst.Write(message)
		if err != nil {
			return err
		}
		if written != len(message) {
			return io.ErrShortWrite
		}
		signalIdle(idleReset)
	}
}

func writeFull(dst io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := dst.Write(data)
		if n > 0 {
			data = data[n:]
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrNoProgress
		}
	}
	return nil
}

func signalIdle(idleReset chan<- struct{}) {
	select {
	case idleReset <- struct{}{}:
	default:
	}
}

// wait blocks until all in-flight TCP and UDP sessions have exited.
func (d *dispatcher) wait() {
	d.wg.Wait()
}
