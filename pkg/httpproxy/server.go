package httpproxy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/puppy/pkg/common"
	"github.com/puppy/pkg/shim"
)

// ServerConfiguration configures an HTTP CONNECT proxy server.
type ServerConfiguration struct {
	ListenAddress string
	ListenPort    uint16
	// Username and Password enable HTTP Basic proxy authentication when both
	// are non-empty. When both are empty the proxy runs open (no auth).
	Username string
	Password string
	// Backend dials the upstream connection for each CONNECT target. Required.
	// Implementations live in pkg/adapter/* (direct, httpproxy, ...).
	Backend common.Backend
	// ShimBufferSize controls the per-direction copy buffer used by each
	// tunnel. When non-positive, the shim package default is used.
	ShimBufferSize int
	// Logger receives structured log events. When nil, slog.Default() is used.
	Logger *slog.Logger
}

// Server is an HTTP CONNECT proxy that fronts a ShimServer per connection.
type Server struct {
	config  ServerConfiguration
	logger  *slog.Logger
	backend common.Backend
}

// NewServer validates the configuration and returns a ready-to-run proxy.
func NewServer(config ServerConfiguration) (*Server, error) {
	if config.ListenAddress == "" {
		return nil, errors.New("httpproxy: listen address is required")
	}
	if config.ListenPort == 0 {
		return nil, errors.New("httpproxy: listen port is required")
	}
	if config.Backend == nil {
		return nil, errors.New("httpproxy: backend is required")
	}
	if (config.Username == "") != (config.Password == "") {
		return nil, errors.New("httpproxy: username and password must both be set or both be empty")
	}
	logger := config.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{config: config, logger: logger, backend: config.Backend}, nil
}

// Run listens and accepts connections until ctx is cancelled. It returns nil
// on graceful shutdown and a wrapped error on listener failures.
func (s *Server) Run(ctx context.Context) error {
	addr := net.JoinHostPort(s.config.ListenAddress, strconv.Itoa(int(s.config.ListenPort)))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("httpproxy: listen: %w", err)
	}
	s.logger.Info("httpproxy listening", "addr", ln.Addr().String())

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
			return fmt.Errorf("httpproxy: accept: %w", err)
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

	// Bound the handshake phase so a silent client cannot hold a goroutine forever.
	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	target, frontend, err := s.handshake(conn)
	if err != nil {
		s.logger.Error("handshake failed", "remote", conn.RemoteAddr(), "err", err)
		return
	}

	// Handshake done; clear the deadline for the tunneled phase.
	_ = conn.SetReadDeadline(time.Time{})

	upstream, err := s.backend.Dial(ctx, target)
	if err != nil {
		s.writeError(conn, httpStatusBadGateway, nil)
		s.logger.Info("backend dial failed", "target", target.Address(), "err", err)
		return
	}
	defer func() { _ = upstream.Close() }()

	// Tell the client the tunnel is up. Per RFC 7231 the 2xx response has no
	// body and the connection becomes a raw tunnel.
	if _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		s.logger.Debug("write 200 failed", "target", target, "err", err)
		return
	}

	shimServer, err := shim.NewShimServer(shim.ShimServerConfiguration{
		Frontend:   frontend,
		Backend:    upstream,
		BufferSize: s.config.ShimBufferSize,
	})
	if err != nil {
		s.logger.Error("shim construction failed", "target", target, "err", err)
		return
	}

	s.logger.Info("tunnel established", "target", target.Address(), "remote", conn.RemoteAddr())
	_ = shimServer.Run(ctx)
	s.logger.Info("tunnel closed", "target", target.Address())
}
