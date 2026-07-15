package dashboard

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// handleEvents streams lifecycle events to the client via Server-Sent Events
// (SSE). The connection stays open until the client disconnects or the server
// shuts down.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, "streaming not supported")
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	// Override the JSON content-type set by middleware.
	w.Header().Set("Content-Type", "text/event-stream")

	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	// Subscribe to the event bus with the request context so the subscription
	// is automatically cleaned up when the client disconnects.
	ch := s.config.Bus.Subscribe(r.Context())

	// Send a heartbeat ping every 15 seconds to keep proxies from closing
	// idle connections.
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			data, err := json.Marshal(sseEvent{
				Type:         string(ev.Type),
				Time:         ev.Time.Format(time.RFC3339),
				Frontend:     ev.Frontend,
				ConnectionID: ev.ConnectionID,
				Target:       ev.Target,
				RemoteAddr:   ev.RemoteAddr,
				Message:      ev.Message,
			})
			if err != nil {
				s.logger.Error("dashboard sse marshal", "err", err)
				continue
			}
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		case <-ticker.C:
			fmt.Fprintf(w, ": ping\n\n")
			flusher.Flush()
		}
	}
}

// sseEvent is the JSON payload of a single SSE message.
type sseEvent struct {
	Type         string `json:"type"`
	Time         string `json:"time"`
	Frontend     string `json:"frontend,omitempty"`
	ConnectionID string `json:"connection_id,omitempty"`
	Target       string `json:"target,omitempty"`
	RemoteAddr   string `json:"remote_addr,omitempty"`
	Message      string `json:"message,omitempty"`
}
