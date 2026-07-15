package dashboard

import (
	"net/http"
)

// handleListBackends returns all configured backends and their capabilities.
func (s *Server) handleListBackends(w http.ResponseWriter, r *http.Request) {
	if s.config.BackendProvider == nil {
		writeError(w, http.StatusNotImplemented, "backends endpoint is not configured")
		return
	}
	backends := s.config.BackendProvider.Backends()
	writeJSON(w, http.StatusOK, listBackendsResponse{
		Count:    len(backends),
		Backends: backends,
	})
}

// listBackendsResponse holds the list of configured backends.
type listBackendsResponse struct {
	Count    int           `json:"count"`
	Backends []BackendInfo `json:"backends"`
}
