package dashboard

import (
	"net/http"
)

// handleListConnections returns all active connections, optionally filtered by
// the "frontend" query parameter.
func (s *Server) handleListConnections(w http.ResponseWriter, r *http.Request) {
	frontend := r.URL.Query().Get("frontend")

	var responses []connectionResponse
	if frontend != "" {
		conns := s.config.ConnReg.ActiveByFrontend(frontend)
		responses = make([]connectionResponse, 0, len(conns))
		for _, info := range conns {
			responses = append(responses, connInfoToResponse(info))
		}
	} else {
		conns := s.config.ConnReg.Active()
		responses = make([]connectionResponse, 0, len(conns))
		for _, info := range conns {
			responses = append(responses, connInfoToResponse(info))
		}
	}

	writeJSON(w, http.StatusOK, listConnectionsResponse{
		Count:       len(responses),
		Connections: responses,
	})
}

// handleGetConnection returns details of a single active connection by ID.
func (s *Server) handleGetConnection(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "connection id is required")
		return
	}
	info := s.config.ConnReg.Get(id)
	if info == nil {
		writeError(w, http.StatusNotFound, "connection not found")
		return
	}
	writeJSON(w, http.StatusOK, connInfoToResponse(info))
}

// handleCloseConnection closes a single active connection by ID. This is a
// stub that will be wired to an active connection closer in a later phase.
func (s *Server) handleCloseConnection(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "connection id is required")
		return
	}
	info := s.config.ConnReg.Get(id)
	if info == nil {
		writeError(w, http.StatusNotFound, "connection not found")
		return
	}
	_ = info
	writeError(w, http.StatusNotImplemented, "connection closing is not yet implemented")
}

// listConnectionsResponse holds the list of active connections.
type listConnectionsResponse struct {
	Count       int                  `json:"count"`
	Connections []connectionResponse `json:"connections"`
}
