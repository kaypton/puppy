package socksproxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/puppy/pkg/common"
	"github.com/puppy/pkg/common/counting"
	"github.com/puppy/pkg/common/stats"
	"github.com/puppy/pkg/shim"
)

// ServerConfiguration configures a SOCKS5 proxy server.
type ServerConfiguration struct {
	ListenAddress string
	ListenPort    uint16
	// TLSCertFile and TLSKeyFile enable TLS for the proxy listener when both
	// are non-empty. The files must contain a matching PEM certificate and key.
	TLSCertFile string
	TLSKeyFile  string
	// Username and Password enable RFC 1929 username/password authentication
	// when both are non-empty. When both are empty the proxy runs open (no auth).
	Username string
	Password string
	// Backend dials the upstream connection for each CONNECT target. Required.
	// Implementations live in pkg/adapter/* (direct, httpproxy, socksproxy, ...).
	Backend common.Backend
	// EgressDialer establishes backend transport connections. When nil, the
	// host's normal network path is used.
	EgressDialer common.Dialer
	// ShimBufferSize controls the per-direction copy buffer used by each
	// tunnel. When non-positive, the shim package default is used.
	ShimBufferSize int
	// Logger receives structured log events. When nil, slog.Default() is used.
	Logger *slog.Logger
	// Name identifies this frontend in stats and dashboard views. When
	// non-empty, accepted connections are attributed to this name.
	Name string
	// Stats receives global counter updates. When nil, no global statistics
	// are collected.
	Stats *stats.StatsRegistry
	// ConnReg tracks active connections for this frontend. When nil, no
	// per-connection registry is maintained.
	ConnReg *stats.ConnectionRegistry
	// Bus broadcasts lifecycle events. When nil, no events are published.
	Bus *stats.EventBus
}

// Validate checks the runtime configuration fields.
func (c ServerConfiguration) Validate() error {
	if c.ListenAddress == "" {
		return errors.New("socksproxy: listen address is required")
	}
	if c.ListenPort == 0 {
		return errors.New("socksproxy: listen port is required")
	}
	if (c.TLSCertFile == "") != (c.TLSKeyFile == "") {
		return errors.New("socksproxy: TLS certificate and key files must both be set or both be empty")
	}
	if c.Backend == nil {
		return errors.New("socksproxy: backend is required")
	}
	if !common.Supports(c.Backend.Capabilities(), common.Target{Network: "tcp", Protocol: common.ProtocolUnknown}) {
		return errors.New("socksproxy: backend must support tcp with unknown application protocol")
	}
	if (c.Username == "") != (c.Password == "") {
		return errors.New("socksproxy: username and password must both be set or both be empty")
	}
	return nil
}

// Server is a SOCKS5 proxy that fronts a ShimServer per connection.
type Server struct {
	config    ServerConfiguration
	logger    *slog.Logger
	backend   common.Backend
	dialer    common.Dialer
	tlsConfig *tls.Config
}

// NewServer applies defaults and returns a ready-to-run proxy. Configuration
// validation must be performed via Validate() (typically through ServerConfig())
// before calling NewServer.
func NewServer(config ServerConfiguration) (*Server, error) {
	if config.EgressDialer == nil {
		config.EgressDialer = common.SystemDialer()
	}
	logger := config.Logger
	if logger == nil {
		logger = slog.Default()
	}

	var tlsConfig *tls.Config
	if config.TLSCertFile != "" {
		certificate, err := tls.LoadX509KeyPair(config.TLSCertFile, config.TLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("socksproxy: load TLS certificate and key: %w", err)
		}
		// No ALPN: SOCKS5 has no negotiated application protocol, and advertising
		// http/1.1 would mislead clients into speaking HTTP after the TLS handshake.
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{certificate},
			MinVersion:   tls.VersionTLS12,
		}
	}
	return &Server{config: config, logger: logger, backend: config.Backend, dialer: config.EgressDialer, tlsConfig: tlsConfig}, nil
}

// Run listens and accepts connections until ctx is cancelled. It returns nil
// on graceful shutdown and a wrapped error on listener failures.
func (s *Server) Run(ctx context.Context) error {
	addr := net.JoinHostPort(s.config.ListenAddress, strconv.Itoa(int(s.config.ListenPort)))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("socksproxy: listen: %w", err)
	}
	transport := "socks5"
	if s.tlsConfig != nil {
		transport = "socks5+tls"
	}
	s.logger.Info("socksproxy listening", "addr", ln.Addr().String(), "transport", transport)

	// Close the listener when ctx is cancelled to unblock Accept.
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	var wg sync.WaitGroup
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				break // graceful shutdown
			}
			wg.Wait()
			return fmt.Errorf("socksproxy: accept: %w", err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.handleConn(ctx, conn)
		}()
	}
	wg.Wait()
	return nil
}

// handleConn processes a single accepted connection: handshake, dial upstream,
// then run a ShimServer to pipe bytes between client and upstream.
func (s *Server) handleConn(ctx context.Context, conn net.Conn) {
	defer func() { _ = conn.Close() }()

	// Bound both TLS and SOCKS5 handshakes so a stalled read or write cannot
	// hold a goroutine forever.
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	s.config.Stats.IncTotal()

	preparedConn, err := s.prepareFrontendConn(ctx, conn)
	if err != nil {
		s.logger.Debug("TLS handshake failed", "remote", conn.RemoteAddr(), "err", err)
		return
	}
	conn = preparedConn

	target, frontend, err := s.handshake(conn)
	if err != nil {
		s.logger.Error("handshake failed", "remote", conn.RemoteAddr(), "err", err)
		return
	}

	// Handshake done; clear the deadline for the tunneled phase.
	_ = conn.SetDeadline(time.Time{})

	upstream, err := s.backend.Dial(ctx, target, s.dialer)
	if err != nil {
		s.config.Stats.IncDialFailure()
		s.config.Bus.Publish(stats.Event{Type: stats.EventDialFailed, Frontend: s.config.Name, Target: target.Address(), RemoteAddr: conn.RemoteAddr().String(), Message: err.Error()})
		s.writeReply(conn, repForDialError(err))
		s.logger.Info("backend dial failed", "target", target.Address(), "err", err)
		return
	}
	defer func() { _ = upstream.Close() }()
	s.config.Stats.IncDialSuccess()

	// Tell the client the tunnel is up. BND.ADDR/BND.PORT are 0.0.0.0:0.
	if err := s.writeReply(conn, common.SOCKS5RepSuccess); err != nil {
		s.logger.Debug("write success reply failed", "target", target, "err", err)
		return
	}

	// Register the connection for stats tracking and wrap the frontend side
	// with a counting connection so per-connection and global byte counters
	// stay in sync.
	var connInfo *stats.ConnectionInfo
	if s.config.ConnReg != nil {
		connInfo = s.config.ConnReg.Register(&stats.ConnectionInfo{
			ID:         stats.GenerateConnectionID(),
			Frontend:   s.config.Name,
			RemoteAddr: conn.RemoteAddr().String(),
			Target:     target,
			Protocol:   target.Protocol,
			Network:    target.Net(),
		})
		s.config.Stats.IncActive()
		s.config.Bus.Publish(stats.Event{Type: stats.EventConnect, Frontend: s.config.Name, ConnectionID: connInfo.ID, Target: target.Address(), RemoteAddr: conn.RemoteAddr().String()})
	}
	wrappedFrontend := frontend
	if s.config.ConnReg != nil || s.config.Stats != nil {
		wrappedFrontend = counting.NewConn(frontend, connInfo, s.config.Stats)
	}

	shimCfg := shim.ShimServerConfiguration{
		Frontend:   wrappedFrontend,
		Backend:    upstream,
		BufferSize: s.config.ShimBufferSize,
	}
	if err := shimCfg.Validate(); err != nil {
		s.logger.Error("shim configuration invalid", "target", target, "err", err)
		if connInfo != nil {
			s.config.ConnReg.Remove(connInfo.ID)
			s.config.Stats.DecActive()
		}
		return
	}
	shimServer, err := shim.NewShimServer(shimCfg)
	if err != nil {
		s.logger.Error("shim construction failed", "target", target, "err", err)
		if connInfo != nil {
			s.config.ConnReg.Remove(connInfo.ID)
			s.config.Stats.DecActive()
		}
		return
	}

	s.logger.Info("tunnel established", "target", target.Address(), "remote", conn.RemoteAddr())
	_, _, _ = shimServer.Run(ctx)
	s.logger.Info("tunnel closed", "target", target.Address())

	if connInfo != nil {
		s.config.ConnReg.Remove(connInfo.ID)
		s.config.Stats.DecActive()
		s.config.Bus.Publish(stats.Event{Type: stats.EventDisconnect, Frontend: s.config.Name, ConnectionID: connInfo.ID, Target: target.Address()})
	}
}

// prepareFrontendConn completes the optional TLS transport handshake before
// the SOCKS5 handshake starts.
func (s *Server) prepareFrontendConn(ctx context.Context, conn net.Conn) (net.Conn, error) {
	if s.tlsConfig == nil {
		return conn, nil
	}
	tlsConn := tls.Server(conn, s.tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("TLS handshake: %w", err)
	}
	return tlsConn, nil
}

// writeReply writes a SOCKS5 reply with the given REP code and a zeroed
// BND.ADDR (0.0.0.0) / BND.PORT (0).
func (s *Server) writeReply(conn net.Conn, rep byte) error {
	// VER REP RSV ATYP IPv4(4) PORT(2)
	_, err := conn.Write([]byte{common.SOCKS5Version, rep, 0x00, common.SOCKS5AtypIPv4, 0, 0, 0, 0, 0, 0})
	return err
}

// repForDialError maps a backend dial error to a SOCKS5 REP code so clients
// receive a meaningful failure reason.
func repForDialError(err error) byte {
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return common.SOCKS5RepConnectionRefused
	case errors.Is(err, syscall.EHOSTUNREACH):
		return common.SOCKS5RepHostUnreachable
	case errors.Is(err, syscall.ENETUNREACH):
		return common.SOCKS5RepNetworkUnreachable
	case errors.Is(err, context.DeadlineExceeded):
		return common.SOCKS5RepTTLExpired
	default:
		return common.SOCKS5RepGeneralFailure
	}
}
