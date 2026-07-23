// Package dashboard renders the control-plane dashboard: a web UI listing
// gateways, routes and backends, plus a topology graph. Every asset is
// embedded in the binary; no CDN is used. It is deliberately not an actor —
// it is the HTTP engine driven by the dashboard server actor.
package dashboard

import (
	"fmt"
	"log/slog"

	"strings"

	"bytes"
	"embed"
	"html/template"

	"net/http"

	"github.com/link-society/krouter/internal/lib/k8s/gatewayapi"
	"github.com/link-society/krouter/internal/lib/snapshot"
)

//go:embed templates
var templatesFS embed.FS

//go:embed static
var staticFS embed.FS

var templateFuncs = template.FuncMap{
	"short": func(s string) string {
		if len(s) > 8 {
			return s[:8]
		}

		return s
	},
	"join": strings.Join,
}

// handler serves the dashboard from the latest topology snapshot.
type handler struct {
	topo  *snapshot.Store[*gatewayapi.Topology]
	pages map[string]*template.Template
}

// NewHandler builds the dashboard HTTP engine reading the topology
// snapshots published by the reconciler actor.
func NewHandler(topo *snapshot.Store[*gatewayapi.Topology]) http.Handler {
	h := &handler{
		topo:  topo,
		pages: map[string]*template.Template{},
	}

	for _, page := range []string{"overview", "gateways", "routes", "backends"} {
		h.pages[page] = template.Must(
			template.New(page).
				Funcs(templateFuncs).
				ParseFS(templatesFS,
					"templates/layouts/base.html",
					fmt.Sprintf("templates/pages/%s.html", page),
				),
		)
	}

	mux := http.NewServeMux()

	mux.Handle("GET /static/", http.FileServerFS(staticFS))

	mux.HandleFunc("GET /{$}", h.overview)
	mux.HandleFunc("GET /gateways", h.gateways)
	mux.HandleFunc("GET /routes", h.routes)
	mux.HandleFunc("GET /backends", h.backends)
	mux.HandleFunc("GET /api/graph", h.graph)
	mux.HandleFunc("GET /api/yaml/gateway/{uid}", h.yamlGateway)
	mux.HandleFunc("GET /api/yaml/route/{uid}", h.yamlRoute)
	mux.HandleFunc("GET /api/yaml/backend/{namespace}/{name}", h.yamlBackend)
	mux.HandleFunc("GET /events", h.events)

	return mux
}

func (h *handler) overview(w http.ResponseWriter, r *http.Request) {
	topo := h.topo.Load()

	h.render(w, r, "overview", overviewData{
		Page:  pageChrome("Overview", "overview", "/", topo),
		Tiles: buildTiles(topo),
	})
}

func (h *handler) gateways(w http.ResponseWriter, r *http.Request) {
	topo := h.topo.Load()

	h.render(w, r, "gateways", gatewaysData{
		Page:     pageChrome("Gateways", "gateways", "/gateways", topo),
		Gateways: topo.Gateways,
	})
}

func (h *handler) routes(w http.ResponseWriter, r *http.Request) {
	topo := h.topo.Load()

	h.render(w, r, "routes", routesData{
		Page:   pageChrome("Routes", "routes", "/routes", topo),
		Routes: buildRouteRows(topo),
	})
}

func (h *handler) backends(w http.ResponseWriter, r *http.Request) {
	topo := h.topo.Load()

	h.render(w, r, "backends", backendsData{
		Page:     pageChrome("Backends", "backends", "/backends", topo),
		Backends: buildBackendRows(topo),
	})
}

// render writes the full document, or only the page content for htmx
// refresh requests. The page is rendered to a buffer first, so template
// errors yield a clean 500 instead of a truncated body.
func (h *handler) render(w http.ResponseWriter, r *http.Request, page string, data any) {
	tmpl := h.pages[page]

	root := "base"
	if r.Header.Get("HX-Request") == "true" {
		root = "content"
	}

	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, root, data); err != nil {
		slog.Error("dashboard render failed", "page", page, "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(buf.Bytes())
}
