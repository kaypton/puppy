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
	DeviceName     string
	IPv4Address    string
	IPv6Address    string
	MTU            uint32
	AutoRoute      bool
	UDPIdleTimeout time.Duration
	Backend        common.Backend
	ShimBufferSize int
	Logger         *slog.Logger
}

// Server is a TUN-mode proxy frontend. It opens a virtual TUN device, runs a
// userspace network stack, and forwards accepted TCP/UDP sessions to a
// common.Backend.
type Server struct {
	config ServerConfiguration
	logger *slog.Logger
}

// NewServer validates the configuration and returns a ready-to-run server.
func NewServer(config ServerConfiguration) (*Server, error) {
	if config.IPv4Address == "" && config.IPv6Address == "" {
		return nil, errors.New("tunproxy: ipv4_address or ipv6_address is required")
	}
	if config.Backend == nil {
		return nil, errors.New("tunproxy: backend is required")
	}
	if config.UDPIdleTimeout <= 0 {
		config.UDPIdleTimeout = defaultUDPIdle
	}
	logger := config.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{config: config, logger: logger}, nil
}

// Run opens the TUN device, configures routing, and serves until ctx is
// cancelled. It always restores routing state before returning.
func (s *Server) Run(ctx context.Context) error {
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

	dispatcher := newDispatcher(ctx, ns, s.config.Backend, s.config.ShimBufferSize, s.config.UDPIdleTimeout, s.logger)
	ns.handler = dispatcher
	ns.startPumps()
	defer func() {
		ns.stop()
		dispatcher.wait()
	}()

	var routeMgr routeManager
	if s.config.AutoRoute {
		routeMgr = newRouteManager(device.Name(), s.config.IPv4Address)
	} else {
		routeMgr = noOpRouteManager{}
	}
	if err := routeMgr.Apply(); err != nil {
		return fmt.Errorf("tunproxy: apply routes: %w", err)
	}
	defer func() {
		if err := routeMgr.Restore(); err != nil {
			s.logger.Error("tunproxy: restore routes failed", "err", err)
		}
	}()

	s.logger.Info("tunproxy: serving",
		"device", device.Name(),
		"ipv4", s.config.IPv4Address,
		"ipv6", s.config.IPv6Address,
		"auto_route", s.config.AutoRoute)

	<-ctx.Done()
	s.logger.Info("tunproxy: shutting down")
	return nil
}
