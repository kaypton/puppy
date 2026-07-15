// Package dashboard implements a RESTful HTTP management API for puppy. It
// exposes runtime statistics, active connections, configuration, and control
// endpoints via stdlib net/http with http.ServeMux pattern routing. The API
// follows RESTful conventions under /api/v1/ and uses JSON for all request
// and response bodies.
//
// Authentication is via Bearer token (configurable, disabled when empty).
// The server defaults to HTTPS when TLS certificate and key files are
// provided. Real-time updates are available through SSE at
// /api/v1/events.
package dashboard

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/puppy/pkg/common/stats"
)

// ServerConfiguration configures the dashboard HTTP API server.
type ServerConfiguration struct {
	// ListenAddress is the bind address for the dashboard listener.
	ListenAddress string
	// ListenPort is the bind port for the dashboard listener.
	ListenPort uint16
	// TLSCertFile and TLSKeyFile enable HTTPS when both are non-empty. The
	// files must contain a matching PEM certificate and key.
	TLSCertFile string
	// TLSKeyFile is the PEM private key file for HTTPS.
	TLSKeyFile string
	// Token enables Bearer token authentication when non-empty. When empty,
	// authentication is disabled (suitable for localhost-only listeners).
	Token string
	// Stats provides global counter snapshots.
	Stats *stats.StatsRegistry
	// ConnReg provides the active connection registry.
	ConnReg *stats.ConnectionRegistry
	// Bus provides lifecycle events for SSE streaming.
	Bus *stats.EventBus
	// ConfigProvider returns the current effective configuration in a
	// sanitized, JSON-serializable form. May be nil to disable the config
	// endpoint.
	ConfigProvider ConfigProvider
	// FrontendProvider returns the list of configured frontends and their
	// runtime status. May be nil to disable the frontends endpoint.
	FrontendProvider FrontendProvider
	// BackendProvider returns the list of configured backends. May be nil to
	// disable the backends endpoint.
	BackendProvider BackendProvider
	// ControlCh sends control requests to the main goroutine. May be nil to
	// disable control endpoints.
	ControlCh chan<- ControlRequest
	// Logger receives structured log events. When nil, slog.Default() is used.
	Logger *slog.Logger
}

// ConfigProvider returns a sanitized view of the current configuration.
type ConfigProvider interface {
	SanitizedConfig() any
}

// FrontendProvider returns the list of configured frontends and their status.
type FrontendProvider interface {
	Frontends() []FrontendInfo
}

// BackendProvider returns the list of configured backends.
type BackendProvider interface {
	Backends() []BackendInfo
}

// FrontendInfo describes a configured frontend for API responses.
type FrontendInfo struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Status string `json:"status"`
}

// BackendInfo describes a configured backend for API responses.
type BackendInfo struct {
	Name         string           `json:"name"`
	Type         string           `json:"type"`
	Capabilities []CapabilityInfo `json:"capabilities"`
}

// CapabilityInfo describes a backend capability for API responses.
type CapabilityInfo struct {
	Network  string `json:"network"`
	Protocol string `json:"protocol"`
}

// Server is the dashboard HTTP API server.
type Server struct {
	config ServerConfiguration
	logger *slog.Logger
	mux    *http.ServeMux
}

// NewServer validates the configuration and returns a ready-to-run dashboard
// server.
func NewServer(config ServerConfiguration) (*Server, error) {
	if config.ListenAddress == "" {
		return nil, errors.New("dashboard: listen address is required")
	}
	if (config.TLSCertFile == "") != (config.TLSKeyFile == "") {
		return nil, errors.New("dashboard: TLS certificate and key files must both be set or both be empty")
	}
	if config.Stats == nil {
		return nil, errors.New("dashboard: stats registry is required")
	}
	if config.ConnReg == nil {
		return nil, errors.New("dashboard: connection registry is required")
	}
	if config.Bus == nil {
		return nil, errors.New("dashboard: event bus is required")
	}
	logger := config.Logger
	if logger == nil {
		logger = slog.Default()
	}
	s := &Server{config: config, logger: logger, mux: http.NewServeMux()}
	s.registerRoutes()
	return s, nil
}

// Run starts the dashboard HTTP server and blocks until ctx is cancelled or
// the server encounters a fatal error. It returns nil on graceful shutdown.
func (s *Server) Run(ctx context.Context) error {
	addr := net.JoinHostPort(s.config.ListenAddress, strconv.Itoa(int(s.config.ListenPort)))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("dashboard: listen: %w", err)
	}

	scheme := "http"
	if s.config.TLSCertFile != "" {
		scheme = "https"
		certificate, err := tls.LoadX509KeyPair(s.config.TLSCertFile, s.config.TLSKeyFile)
		if err != nil {
			_ = ln.Close()
			return fmt.Errorf("dashboard: load TLS certificate and key: %w", err)
		}
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{certificate},
			MinVersion:   tls.VersionTLS12,
		}
		ln = tls.NewListener(ln, tlsConfig)
	}
	s.logger.Info("dashboard listening", "addr", ln.Addr().String(), "scheme", scheme)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Intercept CORS preflight requests before the mux's method-based
		// 405 handling kicks in.
		if r.Method == http.MethodOptions {
			s.corsHandler(w, r)
			return
		}
		s.mux.ServeHTTP(w, r)
	})

	httpServer := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		if err := httpServer.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("dashboard: serve: %w", err)
			return
		}
		errCh <- nil
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
		return nil
	case err := <-errCh:
		return err
	}
}

// corsHandler responds to CORS preflight requests with appropriate headers.
func (s *Server) corsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
	w.WriteHeader(http.StatusNoContent)
}
