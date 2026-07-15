package tunproxy

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/puppy/pkg/common"
	"github.com/puppy/pkg/shim"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/tcp"
	"github.com/sagernet/gvisor/pkg/tcpip/transport/udp"
)

// dispatcher implements sessionHandler. It accepts TCP/UDP sessions from the
// netstack and forwards them to a common.Backend.
type dispatcher struct {
	ns             *networkStack
	backends       []common.Backend
	fallback       common.Backend
	dialer         common.Dialer
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
func newDispatcher(ctx context.Context, ns *networkStack, backends []common.Backend, fallback common.Backend, dialer common.Dialer, shimBuf int, udpIdle, detectTimeout time.Duration, detectMaxBytes int, logger *slog.Logger) *dispatcher {
	return &dispatcher{
		ns:             ns,
		backends:       backends,
		fallback:       fallback,
		dialer:         dialer,
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
	frontend, err := d.ns.endpointFromTCPRequest(req)
	if err != nil {
		d.logger.Info("tunproxy: tcp endpoint creation failed", "target", target.Address(), "err", err)
		req.Complete(true)
		return
	}
	var frontendConn io.ReadWriteCloser = frontend
	backend, backendIndex, fallback := d.selectTCPBackend(target)
	if backendIndex >= 0 && !common.SupportsAnyProtocol(backend.Capabilities(), "tcp") {
		target.Protocol, frontendConn, err = detectProtocol(d.ctx, frontend, d.detectTimeout, d.detectMaxBytes)
		if err != nil {
			d.logger.Info("tunproxy: tcp protocol detection failed", "target", target.Address(), "err", err)
			_ = frontend.Close()
			return
		}
		backend, backendIndex, fallback = d.selectBackend(target)
	} else {
		target.Protocol = common.ProtocolUnknown
	}
	d.logger.Info("tunproxy: tcp route selected", "target", target.Address(), "protocol", target.Protocol, "backend_index", backendIndex, "fallback", fallback)

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
	_ = s.Run(d.ctx)
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

	// UDP has no close signal, so a watchdog closes both sides after udpIdle
	// of inactivity to interrupt the blocking reads below.
	idleReset := make(chan struct{}, 1)
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		timer := time.NewTimer(d.udpIdle)
		for {
			select {
			case <-d.ctx.Done():
				_ = frontend.Close()
				_ = upstream.Close()
				return
			case <-stop:
				timer.Stop()
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
	}()

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

// wait blocks until all in-flight TCP and UDP sessions have exited.
func (d *dispatcher) wait() {
	d.wg.Wait()
}
