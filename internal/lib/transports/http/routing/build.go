package routing

import (
	"fmt"

	"sort"

	"crypto/tls"

	"time"

	corev1 "k8s.io/api/core/v1"

	"github.com/link-society/krouter/internal/lib/k8s/compiled"
)

// BuildGatewayTable turns verified compiled payloads into runtime tables.
func BuildGatewayTable(
	generation string,
	gateway *compiled.GatewayConfig,
	routes []*compiled.RouteConfig,
	secret *corev1.Secret,
) (*GatewayTable, error) {
	table := &GatewayTable{
		Generation: generation,
		byPort:     map[int32]*PortTable{},
		namespaces: map[string]bool{},
	}

	listeners := map[string]*ListenerTable{}

	for _, lst := range gateway.Listeners {
		entry := &ListenerTable{name: lst.Name, hostname: lst.Hostname}

		if lst.HasTLS {
			if secret == nil {
				return nil, fmt.Errorf("listener %s: missing generation TLS secret", lst.Name)
			}

			cert, err := tls.X509KeyPair(
				secret.Data[lst.Name+".tls.crt"],
				secret.Data[lst.Name+".tls.key"],
			)
			if err != nil {
				return nil, fmt.Errorf("listener %s: invalid certificate: %w", lst.Name, err)
			}

			entry.cert = &cert
		}

		port, ok := table.byPort[lst.InternalPort]
		if !ok {
			port = &PortTable{
				gatewayUID:     gateway.UID,
				gatewayName:    gateway.Namespace + "/" + gateway.Name,
				tls:            lst.HasTLS,
				tcp:            lst.Protocol == "TCP",
				tlsPassthrough: lst.Protocol == "TLS",
			}
			table.byPort[lst.InternalPort] = port
		}

		port.listeners = append(port.listeners, entry)
		listeners[lst.Name] = entry
	}

	for _, route := range routes {
		rt := &RouteTable{
			namespace: route.Namespace,
			name:      route.Name,
			hostnames: route.Hostnames,
			created:   route.Created,
		}

		for _, rule := range route.Rules {
			entry := &RuleTable{
				matches:        rule.Matches,
				filters:        rule.Filters,
				grpc:           route.GRPC,
				requestTimeout: time.Duration(rule.RequestTimeoutMillis) * time.Millisecond,
				backendTimeout: time.Duration(rule.BackendTimeoutMillis) * time.Millisecond,
			}

			for _, filter := range rule.Filters {
				if filter.Type != "RequestMirror" || filter.Mirror == nil {
					continue
				}

				percent := float64(100)
				if filter.MirrorPercent != nil {
					percent = *filter.MirrorPercent
				}

				entry.mirrors = append(entry.mirrors, &MirrorTable{
					backend: &BackendTable{
						namespace: filter.Mirror.Namespace,
						name:      filter.Mirror.Name,
						port:      filter.Mirror.Port,
						weight:    1,
						valid:     filter.Mirror.Valid,
					},
					percent: percent,
				})

				if filter.Mirror.Valid {
					table.namespaces[filter.Mirror.Namespace] = true
				}
			}

			for _, backend := range rule.Backends {
				weight := backend.Weight
				if weight <= 0 {
					continue
				}

				entry.backends = append(entry.backends, &BackendTable{
					namespace: backend.Namespace,
					name:      backend.Name,
					port:      backend.Port,
					weight:    weight,
					valid:     backend.Valid,
				})
				entry.total += int64(weight)

				if backend.Valid {
					table.namespaces[backend.Namespace] = true
				}
			}

			rt.rules = append(rt.rules, entry)
		}

		for _, name := range route.Listeners {
			if lst, ok := listeners[name]; ok {
				lst.routes = append(lst.routes, rt)
			}
		}
	}

	// Most specific listener first: exact hostname > wildcard > none.
	for _, port := range table.byPort {
		sort.SliceStable(port.listeners, func(i, j int) bool {
			return hostnameSpecificity(port.listeners[i].hostname) >
				hostnameSpecificity(port.listeners[j].hostname)
		})
	}

	return table, nil
}

// MergeTables combines every gateway's table into the swap-ready set.
// Internal ports are unique per gateway listener group (docs/spec/frontend.md), so the
// merge cannot conflict; errors in one gateway never invalidate another
// (docs/spec/architecture.md).
func MergeTables(gateways map[string]*GatewayTable) *Tables {
	merged := EmptyTables()

	for _, gw := range gateways {
		for port, table := range gw.byPort {
			merged.byPort[port] = table
		}

		for ns := range gw.namespaces {
			merged.backends[ns] = true
		}
	}

	return merged
}
