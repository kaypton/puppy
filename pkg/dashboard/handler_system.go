package dashboard

import (
	"net/http"
)

// handleGetSystem returns system-level information.
func (s *Server) handleGetSystem(w http.ResponseWriter, r *http.Request) {
	snap := s.config.Stats.Snapshot()
	info := systemInfo{
		Version:         Version,
		GoVersion:       goVersion(),
		StartedAt:       snap.StartedAt.Format(timeRFC3339),
		UptimeSeconds:   timeSinceSeconds(snap.StartedAt),
		PID:             pid(),
		ActiveConns:     s.config.ConnReg.Count(),
		SubscriberCount: s.config.Bus.SubscriberCount(),
	}
	writeJSON(w, http.StatusOK, info)
}

// handleGetStats returns the global statistics snapshot.
func (s *Server) handleGetStats(w http.ResponseWriter, r *http.Request) {
	snap := s.config.Stats.Snapshot()
	writeJSON(w, http.StatusOK, statsSnapshotToResponse(snap))
}

// handleGetFrontendStats returns statistics filtered by frontend name.
func (s *Server) handleGetFrontendStats(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "frontend name is required")
		return
	}

	conns := s.config.ConnReg.ActiveByFrontend(name)
	resp := frontendStatsResponse{
		Frontend:          name,
		ActiveConnections: len(conns),
		BytesIn:           0,
		BytesOut:          0,
		Connections:       make([]connectionResponse, 0, len(conns)),
	}
	for _, info := range conns {
		resp.BytesIn += info.BytesIn()
		resp.BytesOut += info.BytesOut()
		resp.Connections = append(resp.Connections, connInfoToResponse(info))
	}
	writeJSON(w, http.StatusOK, resp)
}

// frontendStatsResponse holds per-frontend statistics.
type frontendStatsResponse struct {
	Frontend          string               `json:"frontend"`
	ActiveConnections int                  `json:"active_connections"`
	BytesIn           uint64               `json:"bytes_in"`
	BytesOut          uint64               `json:"bytes_out"`
	Connections       []connectionResponse `json:"connections"`
}
