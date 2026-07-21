package dashboard

import (
	"net/http"
)

// yamlGateway serves the manifest of one owned Gateway.
func (h *handler) yamlGateway(w http.ResponseWriter, r *http.Request) {
	uid := r.PathValue("uid")

	for _, gw := range h.topo.Load().Gateways {
		if gw.UID == uid && gw.YAML != "" {
			writeYAML(w, gw.YAML)
			return
		}
	}

	http.NotFound(w, r)
}

// yamlRoute serves the manifest of one attached HTTPRoute.
func (h *handler) yamlRoute(w http.ResponseWriter, r *http.Request) {
	uid := r.PathValue("uid")

	for _, route := range h.topo.Load().Routes {
		if route.UID == uid && route.YAML != "" {
			writeYAML(w, route.YAML)
			return
		}
	}

	http.NotFound(w, r)
}

// yamlBackend serves the manifest of one referenced backend Service.
func (h *handler) yamlBackend(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("namespace") + "/" + r.PathValue("name")

	if manifest, ok := h.topo.Load().Backends[key]; ok && manifest != "" {
		writeYAML(w, manifest)
		return
	}

	http.NotFound(w, r)
}

func writeYAML(w http.ResponseWriter, manifest string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(manifest))
}
