package dashboard

import (
	"net/http"
)

// handleListFrontends returns all configured frontends and their runtime
// status.
func (s *Server) handleListFrontends(w http.ResponseWriter, r *http.Request) {
	if s.config.FrontendProvider == nil {
		writeError(w, http.StatusNotImplemented, "frontends endpoint is not configured")
		return
	}
	frontends := s.config.FrontendProvider.Frontends()
	writeJSON(w, http.StatusOK, listFrontendsResponse{
		Count:     len(frontends),
		Frontends: frontends,
	})
}

// handleStopFrontend stops a specific frontend by name.
func (s *Server) handleStopFrontend(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "frontend name is required")
		return
	}
	if s.config.ControlCh == nil {
		writeError(w, http.StatusNotImplemented, "control endpoint is not configured")
		return
	}
	reply := make(chan ControlResponse, 1)
	select {
	case s.config.ControlCh <- ControlRequest{Type: ControlStopFrontend, Frontend: name, Reply: reply}:
	default:
		writeError(w, http.StatusServiceUnavailable, "control channel is busy")
		return
	}
	writeJSON(w, http.StatusAccepted, asyncResponse{JobID: "stop-" + name, Message: "stop request submitted for frontend " + name})
}

// handleStartFrontend starts a specific frontend by name.
func (s *Server) handleStartFrontend(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "frontend name is required")
		return
	}
	if s.config.ControlCh == nil {
		writeError(w, http.StatusNotImplemented, "control endpoint is not configured")
		return
	}
	reply := make(chan ControlResponse, 1)
	select {
	case s.config.ControlCh <- ControlRequest{Type: ControlStartFrontend, Frontend: name, Reply: reply}:
	default:
		writeError(w, http.StatusServiceUnavailable, "control channel is busy")
		return
	}
	writeJSON(w, http.StatusAccepted, asyncResponse{JobID: "start-" + name, Message: "start request submitted for frontend " + name})
}

// listFrontendsResponse holds the list of configured frontends.
type listFrontendsResponse struct {
	Count     int            `json:"count"`
	Frontends []FrontendInfo `json:"frontends"`
}
