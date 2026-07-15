package tunproxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/puppy/pkg/common"
)

// ServerConfiguration configures a TUN proxy server.
type ServerConfiguration struct {
	DeviceName             string
	IPv4Address            string
	IPv6Address            string
	MTU                    uint32
	AutoRoute              bool
	UDPIdleTimeout         time.Duration
	DNSServer              string
	Backends               []common.Backend
	Fallback               common.Backend
	ProtocolDetectTimeout  time.Duration
	ProtocolDetectMaxBytes int
	ShimBufferSize         int
	Logger                 *slog.Logger
}

// Server is a TUN-mode proxy frontend. It opens a virtual TUN device, runs a
// userspace network stack, and forwards accepted TCP/UDP sessions to a
// common.Backend.
type Server struct {
	config ServerConfiguration
	logger *slog.Logger
	dns    *common.Target
}

// NewServer validates the configuration and returns a ready-to-run server.
func NewServer(config ServerConfiguration) (*Server, error) {
	if err := validateAddresses(config.IPv4Address, config.IPv6Address); err != nil {
		return nil, fmt.Errorf("tunproxy: %w", err)
	}
	if len(config.Backends) == 0 {
		return nil, errors.New("tunproxy: at least one backend is required")
	}
	dns, err := parseDNSServer(config.DNSServer)
	if err != nil {
		return nil, fmt.Errorf("tunproxy: %w", err)
	}
	for _, backend := range config.Backends {
		if backend == nil {
			return nil, errors.New("tunproxy: backends must not contain nil")
		}
	}
	if config.Fallback == nil {
		return nil, errors.New("tunproxy: fallback is required")
	}
	for _, network := range []string{"tcp", "udp"} {
		if !common.SupportsAnyProtocol(config.Fallback.Capabilities(), network) {
			return nil, fmt.Errorf("tunproxy: fallback must support %s with any application protocol", network)
		}
	}
	if config.UDPIdleTimeout <= 0 {
		config.UDPIdleTimeout = defaultUDPIdle
	}
	if config.ProtocolDetectTimeout <= 0 {
		config.ProtocolDetectTimeout = defaultProtocolDetectTimeout
	}
	if config.ProtocolDetectMaxBytes <= 0 {
		config.ProtocolDetectMaxBytes = defaultProtocolDetectMaxBytes
	}
	logger := config.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{config: config, logger: logger, dns: dns}, nil
}

// Run opens the TUN device, configures routing, and serves until ctx is
// cancelled. It always restores routing state before returning.
func (s *Server) Run(ctx context.Context) (runErr error) {
	if os.Geteuid() != 0 {
		return errors.New("tunproxy: TUN mode requires root privileges")
	}

	device, err := openDevice(s.config.DeviceName, s.config.MTU)
	if err != nil {
		return err
	}
	s.logger.Info("tunproxy: device opened", "name", device.Name(), "mtu", device.MTU())
	defer func() { _ = device.Close() }()

	ns, err := newNetworkStack(device, device.MTU())
	if err != nil {
		return err
	}
	stackStopped := false
	defer func() {
		if !stackStopped {
			ns.stop()
		}
	}()
	if s.config.IPv4Address != "" {
		if err := ns.addAddress(s.config.IPv4Address); err != nil {
			return err
		}
	}
	if s.config.IPv6Address != "" {
		if err := ns.addAddress(s.config.IPv6Address); err != nil {
			return err
		}
	}

	networkMgr := newHostNetworkManager(
		device.Name(), s.config.IPv4Address, s.config.IPv6Address, s.config.AutoRoute,
	)
	dialer, err := networkMgr.Apply()
	if err != nil {
		return fmt.Errorf("tunproxy: configure host network: %w", err)
	}
	runCtx, cancel := context.WithCancel(ctx)
	dispatcher := newDispatcher(runCtx, ns, s.config.Backends, s.config.Fallback, dialer, s.dns, s.config.ShimBufferSize, s.config.UDPIdleTimeout, s.config.ProtocolDetectTimeout, s.config.ProtocolDetectMaxBytes, s.logger)
	ns.handler = dispatcher
	defer func() {
		// Restore host routing before waiting for sessions. In particular, UDP
		// relays may otherwise keep dispatcher.wait blocked while the split
		// routes continue to black-hole all host traffic.
		cancel()
		if err := networkMgr.Restore(); err != nil {
			s.logger.Error("tunproxy: restore host network failed", "err", err)
			runErr = errors.Join(runErr, fmt.Errorf("tunproxy: restore host network: %w", err))
		}
		ns.stop()
		stackStopped = true
		dispatcher.wait()
	}()
	pumpErr := ns.startPumps()
	egress4, egress6 := networkMgr.EgressInterfaces()

	s.logger.Info("tunproxy: serving",
		"device", device.Name(),
		"ipv4", s.config.IPv4Address,
		"ipv6", s.config.IPv6Address,
		"egress_ipv4_interface", egress4,
		"egress_ipv6_interface", egress6,
		"auto_route", s.config.AutoRoute)

	select {
	case <-ctx.Done():
		s.logger.Info("tunproxy: shutting down")
		return nil
	case err := <-pumpErr:
		cancel()
		return err
	}
}
