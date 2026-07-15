package dashboard

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"runtime/debug"

	"github.com/puppy/pkg/common/stats"
)

// registerRoutes wires all API endpoints to the server's ServeMux using Go
// 1.22+ method+path patterns.
func (s *Server) registerRoutes() {
	s.mux.HandleFunc("GET /api/v1/system", s.middleware(s.handleGetSystem))
	s.mux.HandleFunc("POST /api/v1/system/shutdown", s.middleware(s.handleShutdown))
	s.mux.HandleFunc("GET /api/v1/stats", s.middleware(s.handleGetStats))
	s.mux.HandleFunc("GET /api/v1/stats/frontends/{name}", s.middleware(s.handleGetFrontendStats))
	s.mux.HandleFunc("GET /api/v1/connections", s.middleware(s.handleListConnections))
	s.mux.HandleFunc("GET /api/v1/connections/{id}", s.middleware(s.handleGetConnection))
	s.mux.HandleFunc("DELETE /api/v1/connections/{id}", s.middleware(s.handleCloseConnection))
	s.mux.HandleFunc("GET /api/v1/config", s.middleware(s.handleGetConfig))
	s.mux.HandleFunc("POST /api/v1/config/reload", s.middleware(s.handleReloadConfig))
	s.mux.HandleFunc("GET /api/v1/frontends", s.middleware(s.handleListFrontends))
	s.mux.HandleFunc("GET /api/v1/backends", s.middleware(s.handleListBackends))
	s.mux.HandleFunc("GET /api/v1/events", s.middleware(s.handleEvents))
}

// middleware wraps a handler with token authentication, CORS headers, panic
// recovery, JSON content-type, and request logging.
func (s *Server) middleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		if !s.checkAuth(r) {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}

		defer func() {
			if rec := recover(); rec != nil {
				s.logger.Error("dashboard panic", "method", r.Method, "path", r.URL.Path, "panic", rec, "stack", string(debug.Stack()))
				writeError(w, http.StatusInternalServerError, "internal server error")
			}
		}()

		next(w, r)
	}
}

// checkAuth validates the Bearer token. When no token is configured, all
// requests are allowed.
func (s *Server) checkAuth(r *http.Request) bool {
	if s.config.Token == "" {
		return true
	}
	auth := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(auth) <= len(prefix) || auth[:len(prefix)] != prefix {
		return false
	}
	provided := auth[len(prefix):]
	return subtle.ConstantTimeCompare([]byte(provided), []byte(s.config.Token)) == 1
}

// writeJSON encodes v as JSON and writes it to w with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		// Best-effort; the status code and headers are already sent.
		_ = err
	}
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, ErrorResponse{Error: msg})
}

// ErrorResponse is the standard error response body.
type ErrorResponse struct {
	Error string `json:"error"`
}

// systemInfo holds system-level information for the /system endpoint.
type systemInfo struct {
	Version         string  `json:"version"`
	GoVersion       string  `json:"go_version"`
	StartedAt       string  `json:"started_at"`
	UptimeSeconds   float64 `json:"uptime_seconds"`
	PID             int     `json:"pid"`
	ActiveConns     int     `json:"active_connections"`
	SubscriberCount int     `json:"sse_subscribers"`
}

// statsResponse holds the global statistics snapshot.
type statsResponse struct {
	TotalConnections  uint64  `json:"total_connections"`
	ActiveConnections uint64  `json:"active_connections"`
	DialSuccesses     uint64  `json:"dial_successes"`
	DialFailures      uint64  `json:"dial_failures"`
	BytesIn           uint64  `json:"bytes_in"`
	BytesOut          uint64  `json:"bytes_out"`
	StartedAt         string  `json:"started_at"`
	UptimeSeconds     float64 `json:"uptime_seconds"`
}

// connectionResponse holds active connection details.
type connectionResponse struct {
	ID         string `json:"id"`
	Frontend   string `json:"frontend"`
	RemoteAddr string `json:"remote_addr"`
	Target     string `json:"target"`
	Protocol   string `json:"protocol"`
	Network    string `json:"network"`
	StartedAt  string `json:"started_at"`
	BytesIn    uint64 `json:"bytes_in"`
	BytesOut   uint64 `json:"bytes_out"`
}

// statsSnapshotToResponse converts a stats.StatsSnapshot to a statsResponse.
func statsSnapshotToResponse(snap stats.StatsSnapshot) statsResponse {
	return statsResponse{
		TotalConnections:  snap.TotalConnections,
		ActiveConnections: snap.ActiveConnections,
		DialSuccesses:     snap.DialSuccesses,
		DialFailures:      snap.DialFailures,
		BytesIn:           snap.BytesIn,
		BytesOut:          snap.BytesOut,
		StartedAt:         snap.StartedAt.Format(timeRFC3339),
		UptimeSeconds:     timeSinceSeconds(snap.StartedAt),
	}
}

// connInfoToResponse converts a stats.ConnectionInfo to a connectionResponse.
func connInfoToResponse(info *stats.ConnectionInfo) connectionResponse {
	return connectionResponse{
		ID:         info.ID,
		Frontend:   info.Frontend,
		RemoteAddr: info.RemoteAddr,
		Target:     info.Target.Address(),
		Protocol:   string(info.Protocol),
		Network:    info.Network,
		StartedAt:  info.StartedAt.Format(timeRFC3339),
		BytesIn:    info.BytesIn(),
		BytesOut:   info.BytesOut(),
	}
}
