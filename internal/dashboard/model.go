package dashboard

import (
	"fmt"

	"sort"
	"strings"

	"github.com/link-society/krouter/internal/lib/k8s/gatewayapi"
)

// Page is the chrome shared by every rendered page.
type Page struct {
	Title    string
	Active   string
	Path     string
	Revision string
}

func pageChrome(title, active, path string, topo *gatewayapi.Topology) Page {
	return Page{
		Title:    title,
		Active:   active,
		Path:     path,
		Revision: topo.Revision,
	}
}

type overviewData struct {
	Page
	Tiles []statTile
}

// statTile is one "weather map" tile of the overview page: a colored box
// whose state reflects the health of the counted objects.
type statTile struct {
	Label  string
	Value  string
	Detail string
	State  string // Bulma color modifier
}

func tileState(healthy, total int) string {
	switch {
	case total == 0:
		return ""

	case healthy == total:
		return "is-success"

	case healthy == 0:
		return "is-danger"

	default:
		return "is-warning"
	}
}

func buildTiles(topo *gatewayapi.Topology) []statTile {
	stats := buildStats(topo)

	return []statTile{
		{
			Label:  "Gateways",
			Value:  fmt.Sprintf("%d / %d", stats.GatewaysProgrammed, stats.Gateways),
			Detail: "programmed",
			State:  tileState(stats.GatewaysProgrammed, stats.Gateways),
		},
		{
			Label:  "Routes",
			Value:  fmt.Sprintf("%d / %d", stats.RoutesAccepted, stats.Routes),
			Detail: "attachments healthy",
			State:  tileState(stats.RoutesAccepted, stats.Routes),
		},
		{
			Label:  "Backends",
			Value:  fmt.Sprintf("%d / %d", stats.BackendsValid, stats.Backends),
			Detail: "resolved",
			State:  tileState(stats.BackendsValid, stats.Backends),
		},
	}
}

type statsData struct {
	Gateways           int
	GatewaysProgrammed int
	Routes             int
	RoutesAccepted     int
	Backends           int
	BackendsValid      int
}

type gatewaysData struct {
	Page
	Gateways []gatewayapi.GatewayInfo
}

type routesData struct {
	Page
	Routes []routeRow
}

// routeRow is one (route, gateway) attachment.
type routeRow struct {
	Kind         string
	Namespace    string
	Name         string
	UID          string
	Hostnames    string
	Gateway      string
	Accepted     bool
	Reason       string
	RefsResolved bool
	RefsReason   string
}

type backendsData struct {
	Page
	Backends []backendRow
}

// backendRow is one backend Service port aggregated over every rule that
// references it.
type backendRow struct {
	Namespace string
	Name      string
	Port      int32
	Routes    int
	Valid     bool
	Reason    string
	HasYAML   bool
}

func buildStats(topo *gatewayapi.Topology) statsData {
	stats := statsData{
		Gateways: len(topo.Gateways),
		Routes:   len(topo.Routes),
	}

	for _, gw := range topo.Gateways {
		if gw.Programmed {
			stats.GatewaysProgrammed++
		}
	}

	for _, route := range topo.Routes {
		accepted := len(route.Parents) > 0
		for _, parent := range route.Parents {
			if !parent.Accepted || !parent.RefsResolved {
				accepted = false
			}
		}

		if accepted {
			stats.RoutesAccepted++
		}
	}

	backends := buildBackendRows(topo)
	stats.Backends = len(backends)
	for _, backend := range backends {
		if backend.Valid {
			stats.BackendsValid++
		}
	}

	return stats
}

func buildRouteRows(topo *gatewayapi.Topology) []routeRow {
	var rows []routeRow

	for _, route := range topo.Routes {
		for _, parent := range route.Parents {
			row := routeRow{
				Kind:         route.Kind,
				Namespace:    route.Namespace,
				Name:         route.Name,
				UID:          route.UID,
				Hostnames:    strings.Join(route.Hostnames, ", "),
				Gateway:      parent.GatewayNamespace + "/" + parent.GatewayName,
				Accepted:     parent.Accepted,
				Reason:       parent.Reason,
				RefsResolved: parent.RefsResolved,
				RefsReason:   parent.RefsReason,
			}

			rows = append(rows, row)
		}
	}

	return rows
}

func buildBackendRows(topo *gatewayapi.Topology) []backendRow {
	type aggregate struct {
		row    backendRow
		routes map[string]bool
	}

	byKey := map[string]*aggregate{}

	for _, route := range topo.Routes {
		routeKey := route.Namespace + "/" + route.Name

		for _, parent := range route.Parents {
			for _, rule := range parent.Rules {
				for _, backend := range rule.Backends {
					key := fmt.Sprintf("%s/%s:%d",
						backend.Namespace, backend.Name, backend.Port)

					agg, ok := byKey[key]
					if !ok {
						manifest := topo.Backends[backend.Namespace+"/"+backend.Name]

						agg = &aggregate{
							row: backendRow{
								Namespace: backend.Namespace,
								Name:      backend.Name,
								Port:      backend.Port,
								HasYAML:   manifest != "",
							},
							routes: map[string]bool{},
						}
						byKey[key] = agg
					}

					agg.routes[routeKey] = true

					if backend.Valid {
						agg.row.Valid = true
					} else if agg.row.Reason == "" {
						agg.row.Reason = backend.InvalidReason
					}
				}
			}
		}
	}

	keys := make([]string, 0, len(byKey))
	for key := range byKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	rows := make([]backendRow, 0, len(keys))
	for _, key := range keys {
		agg := byKey[key]
		agg.row.Routes = len(agg.routes)
		rows = append(rows, agg.row)
	}

	return rows
}
