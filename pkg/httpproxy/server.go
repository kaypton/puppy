package httpproxy

import (
	"context"
	"crypto/tls"
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

// CamouflageMethod identifies how the server disguises rejected requests.
type CamouflageMethod string

const (
	// Return404 makes the frontend resemble an HTTP service whose resources do
	// not exist and which does not support CONNECT without valid credentials.
	Return404 CamouflageMethod = "return-404"
)

// ServerConfiguration configures an HTTP CONNECT proxy server.
type ServerConfiguration struct {
	ListenAddress string
	ListenPort    uint16
	// TLSCertFile and TLSKeyFile enable TLS for the proxy listener when both
	// are non-empty. The files must contain a matching PEM certificate and key.
	TLSCertFile string
	TLSKeyFile  string
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
	// Camouflage hides proxy-specific responses from unauthenticated clients.
	Camouflage bool
	// CamouflageMethod selects the disguise. Empty defaults to Return404.
	CamouflageMethod CamouflageMethod
}

// Server is an HTTP CONNECT proxy that fronts a ShimServer per connection.
type Server struct {
	config    ServerConfiguration
	logger    *slog.Logger
	backend   common.Backend
	tlsConfig *tls.Config
}

// NewServer validates the configuration and returns a ready-to-run proxy.
func NewServer(config ServerConfiguration) (*Server, error) {
	if config.ListenAddress == "" {
		return nil, errors.New("httpproxy: listen address is required")
	}
	if config.ListenPort == 0 {
		return nil, errors.New("httpproxy: listen port is required")
	}
	if (config.TLSCertFile == "") != (config.TLSKeyFile == "") {
		return nil, errors.New("httpproxy: TLS certificate and key files must both be set or both be empty")
	}
	if config.Backend == nil {
		return nil, errors.New("httpproxy: backend is required")
	}
	if (config.Username == "") != (config.Password == "") {
		return nil, errors.New("httpproxy: username and password must both be set or both be empty")
	}
	config.CamouflageMethod = normalizeCamouflageMethod(config.CamouflageMethod)
	if config.CamouflageMethod != Return404 {
		return nil, fmt.Errorf("httpproxy: unsupported camouflage method %q", config.CamouflageMethod)
	}
	logger := config.Logger
	if logger == nil {
		logger = slog.Default()
	}

	var tlsConfig *tls.Config
	if config.TLSCertFile != "" {
		certificate, err := tls.LoadX509KeyPair(config.TLSCertFile, config.TLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("httpproxy: load TLS certificate and key: %w", err)
		}
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{certificate},
			MinVersion:   tls.VersionTLS12,
			NextProtos:   []string{"http/1.1"},
		}
	}
	return &Server{config: config, logger: logger, backend: config.Backend, tlsConfig: tlsConfig}, nil
}

func normalizeCamouflageMethod(method CamouflageMethod) CamouflageMethod {
	if method == "" {
		return Return404
	}
	return method
}

// Run listens and accepts connections until ctx is cancelled. It returns nil
// on graceful shutdown and a wrapped error on listener failures.
func (s *Server) Run(ctx context.Context) error {
	addr := net.JoinHostPort(s.config.ListenAddress, strconv.Itoa(int(s.config.ListenPort)))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("httpproxy: listen: %w", err)
	}
	transport := "http"
	if s.tlsConfig != nil {
		transport = "https"
	}
	s.logger.Info("httpproxy listening", "addr", ln.Addr().String(), "transport", transport)

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

	// Bound both TLS and HTTP handshakes so a stalled read or write cannot hold
	// a goroutine forever.
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

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

// prepareFrontendConn completes the optional TLS transport handshake before
// the HTTP CONNECT handshake starts.
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
