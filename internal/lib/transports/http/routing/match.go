package routing

import (
	"fmt"

	"sort"
	"strings"

	"net/http"

	discoveryv1 "k8s.io/api/discovery/v1"

	"github.com/link-society/krouter/internal/lib/k8s/compiled"
	"github.com/link-society/krouter/internal/lib/transports/grpc"
	"github.com/link-society/krouter/internal/lib/transports/tcp"
	"github.com/link-society/krouter/internal/lib/transports/tls"
)

// Match resolves the rule serving a request: most specific listener first,
// then route hostnames, then rule matches (docs/spec/traffic.md). gRPC
// requests prefer GRPCRoute rules and MAY fall back to HTTPRoute rules;
// plain requests never match GRPCRoute rules.
func (t *Tables) Match(port int32, host string, r *http.Request) (*RuleTable, *ListenerTable, *RouteTable) {
	if grpc.IsRequest(r) {
		if rule, listener, route := t.match(port, host, r, true); rule != nil {
			return rule, listener, route
		}
	}

	return t.match(port, host, r, false)
}

func (t *Tables) match(
	port int32,
	host string,
	r *http.Request,
	wantGRPC bool,
) (*RuleTable, *ListenerTable, *RouteTable) {
	table := t.byPort[port]
	if table == nil {
		return nil, nil, nil
	}

	for _, listener := range table.listeners {
		if !hostnameMatches(listener.hostname, host) {
			continue
		}

		for _, route := range listener.routes {
			if !routeHostnameMatches(route.hostnames, host) {
				continue
			}

			for _, rule := range route.rules {
				if rule.grpc != wantGRPC {
					continue
				}

				if ruleMatches(rule, r) {
					return rule, listener, route
				}
			}
		}
	}

	return nil, nil, nil
}

// CertificateFor selects the certificate for an SNI value on a port, so a
// rotated certificate serves new handshakes without terminating connections
// using the previous one (docs/spec/security.md).
func (t *Tables) CertificateFor(port int32, serverName string) *ListenerTable {
	table := t.byPort[port]
	if table == nil {
		return nil
	}

	var fallback *ListenerTable
	for _, lst := range table.listeners {
		if lst.cert == nil {
			continue
		}

		if fallback == nil {
			fallback = lst
		}

		if serverName != "" && hostnameMatches(lst.hostname, serverName) {
			return lst
		}
	}

	return fallback
}

func hostnameSpecificity(hostname string) int {
	switch {
	case hostname == "":
		return 0

	case strings.HasPrefix(hostname, "*."):
		return 1

	default:
		return 2
	}
}

func hostnameMatches(pattern, host string) bool {
	if pattern == "" {
		return true
	}

	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // ".example.com"

		// A wildcard label matches one or more labels (Gateway API
		// Hostname semantics, docs/spec/traffic.md).
		return len(host) > len(suffix) && strings.HasSuffix(host, suffix)
	}

	return strings.EqualFold(pattern, host)
}

func routeHostnameMatches(hostnames []string, host string) bool {
	if len(hostnames) == 0 {
		return true
	}

	for _, pattern := range hostnames {
		if hostnameMatches(pattern, host) {
			return true
		}
	}

	return false
}

func ruleMatches(rule *RuleTable, r *http.Request) bool {
	if len(rule.matches) == 0 {
		return true
	}

	for _, match := range rule.matches {
		if matchApplies(match, r) {
			return true
		}
	}

	return false
}

func matchApplies(match compiled.Match, r *http.Request) bool {
	switch match.PathType {
	case "", "PathPrefix":
		if match.PathValue != "" && !pathPrefixMatches(match.PathValue, r.URL.Path) {
			return false
		}

	case "Exact":
		if r.URL.Path != match.PathValue {
			return false
		}

	default:
		return false
	}

	for _, header := range match.Headers {
		if r.Header.Get(header.Name) != header.Value {
			return false
		}
	}

	return true
}

func pathPrefixMatches(prefix, path string) bool {
	if prefix == "/" {
		return true
	}

	if !strings.HasPrefix(path, prefix) {
		return false
	}

	return len(path) == len(prefix) || path[len(prefix)] == '/'
}

// PickBackend implements weighted round-robin over rule backends
// (docs/spec/traffic.md): invalid backends keep their share and answer 500, per the
// Gateway API required behavior for unresolvable refs.
func (r *RuleTable) PickBackend() *BackendTable {
	return pickBucket(r.counter.Add(1)-1, r.backends, r.total)
}

// PickTCP selects the backend endpoint for one new downstream connection
// on a TCP internal listener port (docs/spec/traffic.md): route weights,
// then round-robin over eligible endpoints. Invalid backends keep their
// weight share and refuse their connections, per the Gateway API.
func (t *Tables) PickTCP(port int32, index *EndpointsIndex) (tcp.Selection, bool) {
	table := t.byPort[port]
	if table == nil || !table.tcp {
		return tcp.Selection{}, false
	}

	for _, listener := range table.listeners {
		for _, route := range listener.routes {
			for _, rule := range route.rules {
				backend := rule.PickBackend()
				if backend == nil || !backend.valid {
					return tcp.Selection{}, false
				}

				endpoint, ok := backend.Pick(index)
				if !ok {
					return tcp.Selection{}, false
				}

				return tcp.Selection{
					Endpoint: fmt.Sprintf("%s:%d", endpoint.Address, endpoint.Port),
					Gateway:  table.gatewayName,
					Route:    route.Key(),
					Backend: fmt.Sprintf("%s/%s:%d",
						backend.namespace, backend.name, backend.port),
				}, true
			}
		}
	}

	return tcp.Selection{}, false
}

// PickTCP implements tcp.Picker over the live snapshots.
func (s *State) PickTCP(port int32) (tcp.Selection, bool) {
	return s.Tables.Load().PickTCP(port, s.Endpoints.Load())
}

var _ tcp.Picker = (*State)(nil)

// PickTLS selects the backend endpoint for one new downstream connection
// on a TLS passthrough port (docs/spec/traffic.md): the SNI value selects
// the listener (most specific hostname first) and the route, then route
// weights and endpoint round-robin apply as for every other route type.
func (t *Tables) PickTLS(port int32, sni string, index *EndpointsIndex) (tls.Selection, bool) {
	table := t.byPort[port]
	if table == nil || !table.tlsPassthrough {
		return tls.Selection{}, false
	}

	for _, listener := range table.listeners {
		if !hostnameMatches(listener.hostname, sni) {
			continue
		}

		for _, route := range listener.routes {
			if !routeHostnameMatches(route.hostnames, sni) {
				continue
			}

			for _, rule := range route.rules {
				backend := rule.PickBackend()
				if backend == nil || !backend.valid {
					return tls.Selection{}, false
				}

				endpoint, ok := backend.Pick(index)
				if !ok {
					return tls.Selection{}, false
				}

				return tls.Selection{
					Endpoint: fmt.Sprintf("%s:%d", endpoint.Address, endpoint.Port),
					Gateway:  table.gatewayName,
					Route:    route.Key(),
					Backend: fmt.Sprintf("%s/%s:%d",
						backend.namespace, backend.name, backend.port),
				}, true
			}
		}
	}

	return tls.Selection{}, false
}

// PickTLS implements tls.Picker over the live snapshots.
func (s *State) PickTLS(port int32, sni string) (tls.Selection, bool) {
	return s.Tables.Load().PickTLS(port, sni, s.Endpoints.Load())
}

var _ tls.Picker = (*State)(nil)

func pickBucket(counter int64, backends []*BackendTable, total int64) *BackendTable {
	if total <= 0 {
		return nil
	}

	slot := counter % total
	for _, backend := range backends {
		slot -= int64(backend.weight)
		if slot < 0 {
			return backend
		}
	}

	return nil
}

// Pick selects the next ready endpoint for the backend, round-robin over
// the sorted endpoint list (docs/spec/traffic.md).
func (b *BackendTable) Pick(index *EndpointsIndex) (Endpoint, bool) {
	endpoints := index.Endpoints(b.namespace, b.name, b.port)
	if len(endpoints) == 0 {
		return Endpoint{}, false
	}

	return endpoints[int(b.counter.Add(1)-1)%len(endpoints)], true
}

// Endpoints returns the ready, non-terminating endpoints of a Service port,
// sorted for stable round-robin. Kubernetes probes and EndpointSlice
// conditions are the source of backend health (docs/spec/traffic.md).
func (idx *EndpointsIndex) Endpoints(namespace, name string, servicePort int32) []Endpoint {
	key := namespace + "/" + name

	svc := idx.Services[key]
	if svc == nil {
		return nil
	}

	var portName string
	found := false
	for _, port := range svc.Spec.Ports {
		if port.Port == servicePort {
			portName = port.Name
			found = true
			break
		}
	}
	if !found {
		return nil
	}

	var endpoints []Endpoint
	for _, slice := range idx.Slices[key] {
		if slice.AddressType != discoveryv1.AddressTypeIPv4 {
			continue
		}

		var targetPort int32
		portFound := false
		for _, port := range slice.Ports {
			named := port.Name == nil && portName == "" ||
				port.Name != nil && *port.Name == portName

			if named && port.Port != nil {
				targetPort = *port.Port
				portFound = true
				break
			}
		}
		if !portFound {
			continue
		}

		for _, ep := range slice.Endpoints {
			if ep.Conditions.Ready != nil && !*ep.Conditions.Ready {
				continue
			}

			if ep.Conditions.Terminating != nil && *ep.Conditions.Terminating {
				continue
			}

			for _, address := range ep.Addresses {
				endpoints = append(endpoints, Endpoint{Address: address, Port: targetPort})
			}
		}
	}

	sort.Slice(endpoints, func(i, j int) bool {
		return endpoints[i].Address < endpoints[j].Address
	})

	return endpoints
}
