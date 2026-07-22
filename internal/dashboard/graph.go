package dashboard

import (
	"fmt"

	"strings"

	"encoding/json"

	"net/http"

	"github.com/link-society/krouter/internal/lib/k8s/gatewayapi"
)

// graphNode is one box of the topology flowchart rendered by d3+dagre.
// Lines are preformatted so the frontend stays purely presentational.
type graphNode struct {
	ID        string   `json:"id"`
	Kind      string   `json:"kind"` // gateway | route | backend
	Namespace string   `json:"namespace"`
	Title     string   `json:"title"`
	Lines     []string `json:"lines"`
	OK        bool     `json:"ok"`

	// YAMLPath is the endpoint serving the object's manifest; empty when
	// the object does not exist (e.g. a missing backend Service).
	YAMLPath string `json:"yamlPath,omitempty"`
}

// graphLink is one edge; OK mirrors the attachment/reference validity.
type graphLink struct {
	Source string `json:"source"`
	Target string `json:"target"`
	OK     bool   `json:"ok"`
}

type graphData struct {
	Revision string      `json:"revision"`
	Nodes    []graphNode `json:"nodes"`
	Links    []graphLink `json:"links"`
}

func buildGraph(topo *gatewayapi.Topology) graphData {
	graph := graphData{
		Revision: topo.Revision,
		Nodes:    []graphNode{},
		Links:    []graphLink{},
	}

	seenNodes := map[string]bool{}
	seenLinks := map[string]bool{}

	addNode := func(node graphNode) {
		if !seenNodes[node.ID] {
			seenNodes[node.ID] = true
			graph.Nodes = append(graph.Nodes, node)
		}
	}

	addLink := func(link graphLink) {
		key := link.Source + "→" + link.Target
		if !seenLinks[key] {
			seenLinks[key] = true
			graph.Links = append(graph.Links, link)
		}
	}

	for _, gw := range topo.Gateways {
		lines := []string{"class " + gw.Class}

		if gw.Address != "" {
			lines = append(lines, gw.Address)
		}

		for _, lst := range gw.Listeners {
			line := fmt.Sprintf("%s :%d", lst.Protocol, lst.Port)
			if lst.Hostname != "" {
				line += " " + lst.Hostname
			}

			if !lst.Valid {
				line += " (" + lst.Reason + ")"
			}

			lines = append(lines, line)
		}

		if !gw.Programmed {
			lines = append(lines, "not programmed: "+gw.ProgrammedReason)
		}

		addNode(graphNode{
			ID:        "gw:" + gw.UID,
			Kind:      "gateway",
			Namespace: gw.Namespace,
			Title:     gw.Namespace + "/" + gw.Name,
			Lines:     lines,
			OK:        gw.Programmed,
			YAMLPath:  "/api/yaml/gateway/" + gw.UID,
		})
	}

	for _, route := range topo.Routes {
		routeID := "rt:" + route.UID

		routeOK := len(route.Parents) > 0
		rules := 0

		var reasons []string

		for _, parent := range route.Parents {
			if !parent.Accepted || !parent.RefsResolved {
				routeOK = false
			}

			if !parent.Accepted && parent.Reason != "" {
				reasons = append(reasons, parent.Reason)
			}

			if !parent.RefsResolved && parent.RefsReason != "" {
				reasons = append(reasons, parent.RefsReason)
			}

			if len(parent.Rules) > rules {
				rules = len(parent.Rules)
			}
		}

		var lines []string

		// The route kind distinguishes HTTP, TCP and TLS routing on the
		// topology (docs/spec/overview.md route types).
		lines = append(lines, route.Kind)

		if len(route.Hostnames) > 0 {
			lines = append(lines, strings.Join(route.Hostnames, ", "))
		}

		lines = append(lines, fmt.Sprintf("%d rule(s)", rules))
		lines = append(lines, reasons...)

		addNode(graphNode{
			ID:        routeID,
			Kind:      "route",
			Namespace: route.Namespace,
			Title:     route.Namespace + "/" + route.Name,
			Lines:     lines,
			OK:        routeOK,
			YAMLPath:  "/api/yaml/route/" + route.UID,
		})

		for _, parent := range route.Parents {
			addLink(graphLink{
				Source: "gw:" + parent.GatewayUID,
				Target: routeID,
				OK:     parent.Accepted && parent.RefsResolved,
			})

			for _, rule := range parent.Rules {
				for _, backend := range rule.Backends {
					backendID := fmt.Sprintf("be:%s/%s:%d",
						backend.Namespace, backend.Name, backend.Port)

					lines := []string{fmt.Sprintf("port %d", backend.Port)}
					if !backend.Valid && backend.InvalidReason != "" {
						lines = append(lines, backend.InvalidReason)
					}

					yamlPath := ""
					key := backend.Namespace + "/" + backend.Name
					if manifest, ok := topo.Backends[key]; ok && manifest != "" {
						yamlPath = fmt.Sprintf("/api/yaml/backend/%s/%s",
							backend.Namespace, backend.Name)
					}

					addNode(graphNode{
						ID:        backendID,
						Kind:      "backend",
						Namespace: backend.Namespace,
						Title:     backend.Namespace + "/" + backend.Name,
						Lines:     lines,
						OK:        backend.Valid,
						YAMLPath:  yamlPath,
					})

					addLink(graphLink{
						Source: routeID,
						Target: backendID,
						OK:     backend.Valid,
					})
				}
			}
		}
	}

	return graph
}

func (h *handler) graph(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(buildGraph(h.topo.Load())); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
