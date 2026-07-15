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

// Validate checks the runtime configuration fields.
func (c ServerConfiguration) Validate() error {
	if err := validateAddresses(c.IPv4Address, c.IPv6Address); err != nil {
		return fmt.Errorf("tunproxy: %w", err)
	}
	if len(c.Backends) == 0 {
		return errors.New("tunproxy: at least one backend is required")
	}
	if _, err := parseDNSServer(c.DNSServer); err != nil {
		return fmt.Errorf("tunproxy: %w", err)
	}
	for _, backend := range c.Backends {
		if backend == nil {
			return errors.New("tunproxy: backends must not contain nil")
		}
	}
	if c.Fallback == nil {
		return errors.New("tunproxy: fallback is required")
	}
	for _, network := range []string{"tcp", "udp"} {
		if !common.SupportsAnyProtocol(c.Fallback.Capabilities(), network) {
			return fmt.Errorf("tunproxy: fallback must support %s with any application protocol", network)
		}
	}
	return nil
}

// Server is a TUN-mode proxy frontend. It opens a virtual TUN device, runs a
// userspace network stack, and forwards accepted TCP/UDP sessions to a
// common.Backend.
type Server struct {
	config ServerConfiguration
	logger *slog.Logger
	dns    *common.Target
}

// NewServer applies defaults and returns a ready-to-run server. Configuration
// validation must be performed via Validate() (typically through ServerConfig())
// before calling NewServer.
func NewServer(config ServerConfiguration) (*Server, error) {
	dns, err := parseDNSServer(config.DNSServer)
	if err != nil {
		return nil, fmt.Errorf("tunproxy: %w", err)
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

	interceptSystemdResolved := systemdResolvedInterceptionEnabled(
		s.config.AutoRoute, s.dns != nil, s.config.IPv4Address != "",
	)
	networkMgr := newHostNetworkManager(
		device.Name(), s.config.IPv4Address, s.config.IPv6Address, s.config.AutoRoute,
		interceptSystemdResolved,
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
	if err := networkMgr.EnableDNSInterception(dispatcher); err != nil {
		return fmt.Errorf("tunproxy: enable systemd-resolved interception: %w", err)
	}
	pumpErr := ns.startPumps()
	egress4, egress6 := networkMgr.EgressInterfaces()

	s.logger.Info("tunproxy: serving",
		"device", device.Name(),
		"ipv4", s.config.IPv4Address,
		"ipv6", s.config.IPv6Address,
		"egress_ipv4_interface", egress4,
		"egress_ipv6_interface", egress6,
		"systemd_resolved_intercept", interceptSystemdResolved,
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
