package dashboard

import (
	"net/http"
)

// handleListFrontends returns all configured frontends.
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

// listFrontendsResponse holds the list of configured frontends.
type listFrontendsResponse struct {
	Count     int            `json:"count"`
	Frontends []FrontendInfo `json:"frontends"`
}
