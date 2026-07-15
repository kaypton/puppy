package dashboard

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/puppy/pkg/common"
	"github.com/puppy/pkg/common/stats"
)

// testServer creates a dashboard server with all dependencies wired for
// testing. It returns the server and a cleanup function.
func testServer(t *testing.T, token string) (*Server, *stats.StatsRegistry, *stats.ConnectionRegistry, *stats.EventBus) {
	t.Helper()
	registry := stats.NewStatsRegistry()
	connReg := stats.NewConnectionRegistry()
	bus := stats.NewEventBus()

	cfg := ServerConfiguration{
		ListenAddress:  "127.0.0.1",
		ListenPort:     0,
		Token:          token,
		Stats:          registry,
		ConnReg:        connReg,
		Bus:            bus,
		ConfigProvider: &testConfigProvider{},
		FrontendProvider: &testFrontendProvider{
			frontends: []FrontendInfo{
				{Name: "fe1", Type: "httpproxy", Status: "running"},
				{Name: "fe2", Type: "socksproxy", Status: "stopped"},
			},
		},
		BackendProvider: &testBackendProvider{
			backends: []BackendInfo{
				{Name: "be1", Type: "direct", Capabilities: []CapabilityInfo{{Network: "tcp", Protocol: "*"}}},
			},
		},
	}
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return s, registry, connReg, bus
}

type testConfigProvider struct{}

func (t *testConfigProvider) SanitizedConfig() any {
	return map[string]any{
		"frontend": "fe1",
		"frontends": map[string]any{
			"fe1": map[string]any{"type": "httpproxy", "listen_address": "127.0.0.1"},
		},
	}
}

type testFrontendProvider struct {
	frontends []FrontendInfo
}

func (t *testFrontendProvider) Frontends() []FrontendInfo { return t.frontends }

type testBackendProvider struct {
	backends []BackendInfo
}

func (t *testBackendProvider) Backends() []BackendInfo { return t.backends }

// doRequest performs a request against the server's mux and returns the
// response. OPTIONS requests are intercepted by the CORS handler.
func doRequest(s *Server, method, path, token string, body io.Reader) (*http.Response, error) {
	req := httptest.NewRequest(method, path, body)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	if method == http.MethodOptions {
		s.corsHandler(rec, req)
	} else {
		s.mux.ServeHTTP(rec, req)
	}
	return rec.Result(), nil
}

func decodeJSON(t *testing.T, r io.Reader) map[string]any {
	t.Helper()
	var v map[string]any
	if err := json.NewDecoder(r).Decode(&v); err != nil {
		t.Fatalf("decode JSON: %v", err)
	}
	return v
}

func TestGetSystem(t *testing.T) {
	s, _, _, _ := testServer(t, "")
	resp, err := doRequest(s, "GET", "/api/v1/system", "", nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body := decodeJSON(t, resp.Body)
	if body["version"] != "v1" {
		t.Errorf("version = %v, want v1", body["version"])
	}
	if body["go_version"] == nil {
		t.Error("go_version should not be nil")
	}
	if body["pid"] == nil {
		t.Error("pid should not be nil")
	}
}

func TestGetStats(t *testing.T) {
	s, registry, _, _ := testServer(t, "")
	registry.IncTotal()
	registry.IncActive()
	registry.AddBytesIn(1024)
	registry.AddBytesOut(2048)

	resp, err := doRequest(s, "GET", "/api/v1/stats", "", nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body := decodeJSON(t, resp.Body)
	if body["total_connections"] != float64(1) {
		t.Errorf("total_connections = %v, want 1", body["total_connections"])
	}
	if body["active_connections"] != float64(1) {
		t.Errorf("active_connections = %v, want 1", body["active_connections"])
	}
	if body["bytes_in"] != float64(1024) {
		t.Errorf("bytes_in = %v, want 1024", body["bytes_in"])
	}
	if body["bytes_out"] != float64(2048) {
		t.Errorf("bytes_out = %v, want 2048", body["bytes_out"])
	}
	if body["started_at"] == nil {
		t.Error("started_at should not be nil")
	}
}

func TestGetFrontendStats(t *testing.T) {
	s, _, connReg, _ := testServer(t, "")
	connReg.Register(&stats.ConnectionInfo{
		ID:         "c1",
		Frontend:   "fe1",
		RemoteAddr: "1.2.3.4:1234",
		Target:     common.Target{Host: "example.com", Port: 443},
		Protocol:   common.ProtocolTLS,
		Network:    "tcp",
		StartedAt:  time.Now(),
	})
	connReg.Register(&stats.ConnectionInfo{
		ID:       "c2",
		Frontend: "fe2",
		Target:   common.Target{Host: "other.com", Port: 80},
		Network:  "tcp",
	})

	resp, err := doRequest(s, "GET", "/api/v1/stats/frontends/fe1", "", nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body := decodeJSON(t, resp.Body)
	if body["frontend"] != "fe1" {
		t.Errorf("frontend = %v, want fe1", body["frontend"])
	}
	if body["active_connections"] != float64(1) {
		t.Errorf("active_connections = %v, want 1", body["active_connections"])
	}
}

func TestListConnections(t *testing.T) {
	s, _, connReg, _ := testServer(t, "")
	connReg.Register(&stats.ConnectionInfo{ID: "c1", Frontend: "fe1", Target: common.Target{Host: "a.com", Port: 443}, Network: "tcp", StartedAt: time.Now()})
	connReg.Register(&stats.ConnectionInfo{ID: "c2", Frontend: "fe2", Target: common.Target{Host: "b.com", Port: 80}, Network: "tcp", StartedAt: time.Now()})

	resp, err := doRequest(s, "GET", "/api/v1/connections", "", nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body := decodeJSON(t, resp.Body)
	if body["count"] != float64(2) {
		t.Errorf("count = %v, want 2", body["count"])
	}
}

func TestListConnections_FrontendFilter(t *testing.T) {
	s, _, connReg, _ := testServer(t, "")
	connReg.Register(&stats.ConnectionInfo{ID: "c1", Frontend: "fe1", Target: common.Target{Host: "a.com", Port: 443}, Network: "tcp", StartedAt: time.Now()})
	connReg.Register(&stats.ConnectionInfo{ID: "c2", Frontend: "fe2", Target: common.Target{Host: "b.com", Port: 80}, Network: "tcp", StartedAt: time.Now()})

	resp, err := doRequest(s, "GET", "/api/v1/connections?frontend=fe1", "", nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	body := decodeJSON(t, resp.Body)
	if body["count"] != float64(1) {
		t.Errorf("count = %v, want 1", body["count"])
	}
}

func TestGetConnection(t *testing.T) {
	s, _, connReg, _ := testServer(t, "")
	connReg.Register(&stats.ConnectionInfo{ID: "c1", Frontend: "fe1", RemoteAddr: "1.2.3.4:5", Target: common.Target{Host: "example.com", Port: 443}, Protocol: common.ProtocolTLS, Network: "tcp", StartedAt: time.Now()})

	resp, err := doRequest(s, "GET", "/api/v1/connections/c1", "", nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body := decodeJSON(t, resp.Body)
	if body["id"] != "c1" {
		t.Errorf("id = %v, want c1", body["id"])
	}
}

func TestGetConnection_NotFound(t *testing.T) {
	s, _, _, _ := testServer(t, "")
	resp, err := doRequest(s, "GET", "/api/v1/connections/nonexistent", "", nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

func TestGetConfig(t *testing.T) {
	s, _, _, _ := testServer(t, "")
	resp, err := doRequest(s, "GET", "/api/v1/config", "", nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body := decodeJSON(t, resp.Body)
	if body["frontend"] != "fe1" {
		t.Errorf("frontend = %v, want fe1", body["frontend"])
	}
}

func TestListFrontends(t *testing.T) {
	s, _, _, _ := testServer(t, "")
	resp, err := doRequest(s, "GET", "/api/v1/frontends", "", nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body := decodeJSON(t, resp.Body)
	if body["count"] != float64(2) {
		t.Errorf("count = %v, want 2", body["count"])
	}
}

func TestListBackends(t *testing.T) {
	s, _, _, _ := testServer(t, "")
	resp, err := doRequest(s, "GET", "/api/v1/backends", "", nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body := decodeJSON(t, resp.Body)
	if body["count"] != float64(1) {
		t.Errorf("count = %v, want 1", body["count"])
	}
}

func TestAuth_WithToken(t *testing.T) {
	s, _, _, _ := testServer(t, "secret-token")

	// No auth header
	resp, _ := doRequest(s, "GET", "/api/v1/system", "", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no auth: status = %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()

	// Wrong token
	resp, _ = doRequest(s, "GET", "/api/v1/system", "wrong", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong token: status = %d, want 401", resp.StatusCode)
	}
	resp.Body.Close()

	// Correct token
	resp, _ = doRequest(s, "GET", "/api/v1/system", "secret-token", nil)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("correct token: status = %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestAuth_NoToken(t *testing.T) {
	s, _, _, _ := testServer(t, "")
	resp, _ := doRequest(s, "GET", "/api/v1/system", "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("no token configured: status = %d, want 200", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestCORS_Preflight(t *testing.T) {
	s, _, _, _ := testServer(t, "")
	resp, _ := doRequest(s, "OPTIONS", "/api/v1/system", "", nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", resp.StatusCode)
	}
	if resp.Header.Get("Access-Control-Allow-Origin") != "*" {
		t.Error("CORS origin header missing")
	}
	resp.Body.Close()
}

func TestServerConfiguration_Validate(t *testing.T) {
	cases := []struct {
		name    string
		cfg     ServerConfiguration
		wantErr string
	}{
		{"missing address", ServerConfiguration{ListenPort: 1, Stats: stats.NewStatsRegistry(), ConnReg: stats.NewConnectionRegistry(), Bus: stats.NewEventBus()}, "listen address"},
		{"cert only", ServerConfiguration{ListenAddress: "127.0.0.1", ListenPort: 1, TLSCertFile: "cert.pem", Stats: stats.NewStatsRegistry(), ConnReg: stats.NewConnectionRegistry(), Bus: stats.NewEventBus()}, "certificate and key files"},
		{"key only", ServerConfiguration{ListenAddress: "127.0.0.1", ListenPort: 1, TLSKeyFile: "key.pem", Stats: stats.NewStatsRegistry(), ConnReg: stats.NewConnectionRegistry(), Bus: stats.NewEventBus()}, "certificate and key files"},
		{"missing stats", ServerConfiguration{ListenAddress: "127.0.0.1", ListenPort: 1, ConnReg: stats.NewConnectionRegistry(), Bus: stats.NewEventBus()}, "stats registry is required"},
		{"missing connreg", ServerConfiguration{ListenAddress: "127.0.0.1", ListenPort: 1, Stats: stats.NewStatsRegistry(), Bus: stats.NewEventBus()}, "connection registry is required"},
		{"missing bus", ServerConfiguration{ListenAddress: "127.0.0.1", ListenPort: 1, Stats: stats.NewStatsRegistry(), ConnReg: stats.NewConnectionRegistry()}, "event bus is required"},
		{"valid", ServerConfiguration{ListenAddress: "127.0.0.1", ListenPort: 1, Stats: stats.NewStatsRegistry(), ConnReg: stats.NewConnectionRegistry(), Bus: stats.NewEventBus()}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %q, want substring %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func TestSSE_Events(t *testing.T) {
	s, _, _, bus := testServer(t, "")

	// Use a real httptest.Server since SSE writes to the connection
	// asynchronously; httptest.ResponseRecorder is not safe for concurrent
	// reads/writes.
	ts := httptest.NewServer(s.mux)
	defer ts.Close()

	// Connect to the SSE endpoint.
	resp, err := http.Get(ts.URL + "/api/v1/events")
	if err != nil {
		t.Fatalf("SSE connect: %v", err)
	}
	defer resp.Body.Close()

	// Give the subscription a moment to register.
	time.Sleep(100 * time.Millisecond)

	// Publish an event.
	bus.Publish(stats.Event{Type: stats.EventConnect, Frontend: "fe1", ConnectionID: "c1", Target: "example.com:443"})

	// Read from the SSE stream until we see the event or timeout.
	done := make(chan string, 1)
	go func() {
		buf := make([]byte, 4096)
		n, _ := resp.Body.Read(buf)
		done <- string(buf[:n])
	}()

	select {
	case body := <-done:
		if !strings.Contains(body, "connect") {
			t.Errorf("SSE body should contain 'connect', got: %s", body)
		}
		if !strings.Contains(body, "example.com:443") {
			t.Errorf("SSE body should contain target, got: %s", body)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for SSE event")
	}
}

func TestControl_NoControlChannel(t *testing.T) {
	s, _, _, _ := testServer(t, "")
	// ControlCh is nil in testServer, so control endpoints should return 501
	resp, _ := doRequest(s, "POST", "/api/v1/system/shutdown", "", nil)
	if resp.StatusCode != http.StatusNotImplemented {
		t.Errorf("shutdown: status = %d, want 501", resp.StatusCode)
	}
	resp.Body.Close()

	resp, _ = doRequest(s, "POST", "/api/v1/config/reload", "", nil)
	if resp.StatusCode != http.StatusNotImplemented {
		t.Errorf("reload: status = %d, want 501", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestControl_WithChannel(t *testing.T) {
	controlCh := make(chan ControlRequest, 1)
	registry := stats.NewStatsRegistry()
	connReg := stats.NewConnectionRegistry()
	bus := stats.NewEventBus()

	cfg := ServerConfiguration{
		ListenAddress: "127.0.0.1",
		ListenPort:    0,
		Stats:         registry,
		ConnReg:       connReg,
		Bus:           bus,
		ControlCh:     controlCh,
	}
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	// Start a fake control consumer.
	go func() {
		for req := range controlCh {
			req.Reply <- ControlResponse{Success: true, Message: "ok"}
		}
	}()

	resp, _ := doRequest(s, "POST", "/api/v1/system/shutdown", "", nil)
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("shutdown: status = %d, want 202", resp.StatusCode)
	}
	resp.Body.Close()
}

func TestServer_RunAndShutdown(t *testing.T) {
	registry := stats.NewStatsRegistry()
	connReg := stats.NewConnectionRegistry()
	bus := stats.NewEventBus()

	// Grab a free port from the OS, then release it.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	cfg := ServerConfiguration{
		ListenAddress: "127.0.0.1",
		ListenPort:    uint16(mustPort(t, addr)),
		Stats:         registry,
		ConnReg:       connReg,
		Bus:           bus,
	}
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- s.Run(ctx) }()

	// Wait for the server to start listening.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		c, derr := net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if derr == nil {
			_ = c.Close()
			break
		}
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("Run returned error after cancel: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

// mustPort extracts the port from a "host:port" address.
func mustPort(t *testing.T, addr string) int {
	t.Helper()
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	return port
}
