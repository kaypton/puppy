package dashboard

import (
	"net/http"
)

// handleShutdown triggers a graceful shutdown of the puppy server. It sends a
// control request to the main goroutine and returns 202 Accepted.
func (s *Server) handleShutdown(w http.ResponseWriter, r *http.Request) {
	if s.config.ControlCh == nil {
		writeError(w, http.StatusNotImplemented, "control endpoint is not configured")
		return
	}
	reply := make(chan ControlResponse, 1)
	select {
	case s.config.ControlCh <- ControlRequest{Type: ControlShutdown, Reply: reply}:
	default:
		writeError(w, http.StatusServiceUnavailable, "control channel is busy")
		return
	}
	writeJSON(w, http.StatusAccepted, asyncResponse{JobID: "shutdown", Message: "shutdown request submitted"})
}

// asyncResponse is returned for control operations that are processed
// asynchronously. The result is delivered via the SSE event stream.
type asyncResponse struct {
	JobID   string `json:"job_id"`
	Message string `json:"message"`
}
