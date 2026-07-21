package dashboard

import (
	"fmt"

	"net/http"

	"time"
)

// events streams server-sent events: one "topology" event whenever the
// reconciler publishes a topology with a new revision. htmx (with its SSE
// extension) uses it to refresh the current page, and the graph script to
// redraw.
func (h *handler) events(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	// The connecting client just rendered the current revision: only
	// notify on subsequent changes.
	last := h.topo.Load().Revision

	fmt.Fprint(w, ": connected\n\n")
	flusher.Flush()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case <-r.Context().Done():
			return

		case <-heartbeat.C:
			fmt.Fprint(w, ": ping\n\n")
			flusher.Flush()

		case <-ticker.C:
			revision := h.topo.Load().Revision
			if revision == last {
				continue
			}

			last = revision

			fmt.Fprintf(w, "event: topology\ndata: %s\n\n", revision)
			flusher.Flush()
		}
	}
}
