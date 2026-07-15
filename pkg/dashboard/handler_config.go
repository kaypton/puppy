package dashboard

import (
	"net/http"
)

// handleGetConfig returns the current effective configuration in a sanitized
// form (passwords and secrets are redacted).
func (s *Server) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	if s.config.ConfigProvider == nil {
		writeError(w, http.StatusNotImplemented, "config endpoint is not configured")
		return
	}
	writeJSON(w, http.StatusOK, s.config.ConfigProvider.SanitizedConfig())
}

// handleReloadConfig triggers a hot reload of the configuration. It sends a
// control request to the main goroutine and returns 202 Accepted.
func (s *Server) handleReloadConfig(w http.ResponseWriter, r *http.Request) {
	if s.config.ControlCh == nil {
		writeError(w, http.StatusNotImplemented, "control endpoint is not configured")
		return
	}
	reply := make(chan ControlResponse, 1)
	select {
	case s.config.ControlCh <- ControlRequest{Type: ControlReloadConfig, Reply: reply}:
	default:
		writeError(w, http.StatusServiceUnavailable, "control channel is busy")
		return
	}
	writeJSON(w, http.StatusAccepted, asyncResponse{JobID: "reload", Message: "reload request submitted"})
}
