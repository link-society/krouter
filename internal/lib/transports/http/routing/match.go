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
	"github.com/link-society/krouter/internal/lib/transports/udp"
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

	// Gateway API matching precedence (docs/spec/traffic.md): most specific
	// listener hostname, then most specific route hostname, then Exact over
	// longest-prefix path, then method presence, then most header matches,
	// then most query-parameter matches, then the oldest route (name as
	// final tie-break), then rule/match order within the route.
	//
	// Listener isolation (docs/spec/traffic.md): only the most specific
	// listener whose hostname matches the request authority serves it;
	// routes attached to less specific listeners never apply.
	var (
		bestRule     *RuleTable
		bestListener *ListenerTable
		bestRoute    *RouteTable
		bestScore    matchScore
	)

	winning := -1
	for _, listener := range table.listeners {
		if !hostnameMatches(listener.hostname, host) {
			continue
		}

		if score := hostnameScore(listener.hostname); score > winning {
			winning = score
		}
	}

	for _, listener := range table.listeners {
		if !hostnameMatches(listener.hostname, host) ||
			hostnameScore(listener.hostname) != winning {
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

				matched, specificity := ruleBestMatch(rule, r)
				if !matched {
					continue
				}

				score := matchScore{
					listenerHostname: hostnameScore(listener.hostname),
					routeHostname:    routeHostnameScore(listener, route, host),
					specificity:      specificity,
					created:          route.created,
					name:             route.Key(),
				}

				if bestRule == nil || score.beats(bestScore) {
					bestRule, bestListener, bestRoute = rule, listener, route
					bestScore = score
				}
			}
		}
	}

	return bestRule, bestListener, bestRoute
}

// ruleSpecificity ranks one applying match by the in-rule precedence
// dimensions (docs/spec/traffic.md): path specificity, method presence,
// matched header count, matched query-parameter count.
type ruleSpecificity struct {
	path        int
	method      int
	headers     int
	queryParams int
}

func (s ruleSpecificity) beats(other ruleSpecificity) bool {
	if s.path != other.path {
		return s.path > other.path
	}

	if s.method != other.method {
		return s.method > other.method
	}

	if s.headers != other.headers {
		return s.headers > other.headers
	}

	return s.queryParams > other.queryParams
}

// matchScore orders candidate rules by the Gateway API matching precedence
// (docs/spec/traffic.md). Higher hostname/specificity scores win; ties fall
// to the oldest route, then the lexically smallest namespaced name, then
// the first candidate in table order.
type matchScore struct {
	listenerHostname int
	routeHostname    int
	specificity      ruleSpecificity
	created          int64
	name             string
}

func (s matchScore) beats(other matchScore) bool {
	if s.listenerHostname != other.listenerHostname {
		return s.listenerHostname > other.listenerHostname
	}

	if s.routeHostname != other.routeHostname {
		return s.routeHostname > other.routeHostname
	}

	if s.specificity != other.specificity {
		return s.specificity.beats(other.specificity)
	}

	if s.created != other.created {
		return s.created < other.created
	}

	return s.name < other.name
}

// hostnameScore ranks a hostname pattern: any exact hostname beats any
// wildcard, longer patterns beat shorter ones, absent hostnames rank last.
func hostnameScore(hostname string) int {
	switch {
	case hostname == "":
		return 0

	case strings.HasPrefix(hostname, "*."):
		return len(hostname)

	default:
		return 1<<16 + len(hostname)
	}
}

// routeHostnameScore ranks the hostname under which a route matched the
// request: the most specific matching route hostname, or the listener
// hostname when the route declares none.
func routeHostnameScore(listener *ListenerTable, route *RouteTable, host string) int {
	if len(route.hostnames) == 0 {
		return hostnameScore(listener.hostname)
	}

	best := 0
	for _, pattern := range route.hostnames {
		if !hostnameMatches(pattern, host) {
			continue
		}

		if score := hostnameScore(pattern); score > best {
			best = score
		}
	}

	return best
}

// ruleBestMatch reports whether the rule matches the request and the
// specificity of its best applying match (docs/spec/traffic.md).
func ruleBestMatch(rule *RuleTable, r *http.Request) (bool, ruleSpecificity) {
	if len(rule.matches) == 0 {
		return true, ruleSpecificity{}
	}

	matched := false
	best := ruleSpecificity{}

	for _, match := range rule.matches {
		if !matchApplies(match, r) {
			continue
		}

		specificity := ruleSpecificity{
			path:        pathScore(match),
			headers:     len(match.Headers),
			queryParams: len(match.QueryParams),
		}
		if match.Method != "" {
			specificity.method = 1
		}

		if !matched || specificity.beats(best) {
			best = specificity
		}
		matched = true
	}

	return matched, best
}

func pathScore(match compiled.Match) int {
	switch match.PathType {
	case "Exact":
		return 1<<16 + len(match.PathValue)

	case "", "PathPrefix":
		return len(strings.TrimSuffix(match.PathValue, "/"))

	default:
		return 0
	}
}

// Misdirected reports whether a request authority is owned by a different
// listener than the one the connection's SNI selected on this port
// (docs/spec/traffic.md): such requests are answered 421 Misdirected
// Request so the client retries on a fresh connection.
func (t *Tables) Misdirected(port int32, serverName, host string) bool {
	table := t.byPort[port]
	if table == nil {
		return false
	}

	selected := bestListenerFor(table, serverName)
	if selected == nil {
		return false
	}

	return bestListenerFor(table, host) != selected
}

// bestListenerFor is the listener owning a hostname on the port: the most
// specific listener whose hostname pattern matches it
// (docs/spec/traffic.md listener isolation).
func bestListenerFor(table *PortTable, host string) *ListenerTable {
	var best *ListenerTable
	bestScore := -1

	for _, listener := range table.listeners {
		if !hostnameMatches(listener.hostname, host) {
			continue
		}

		if score := hostnameScore(listener.hostname); score > bestScore {
			best, bestScore = listener, score
		}
	}

	return best
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

	if match.Method != "" && r.Method != match.Method {
		return false
	}

	for _, header := range match.Headers {
		if r.Header.Get(header.Name) != header.Value {
			return false
		}
	}

	if len(match.QueryParams) > 0 {
		query := r.URL.Query()

		for _, param := range match.QueryParams {
			// Only the first value of a repeated parameter is considered
			// (Gateway API HTTPQueryParamMatch semantics, docs/spec/traffic.md).
			values, ok := query[param.Name]
			if !ok || len(values) == 0 || values[0] != param.Value {
				return false
			}
		}
	}

	return true
}

func pathPrefixMatches(prefix, path string) bool {
	// Prefix matching is segment-wise (docs/spec/traffic.md): a trailing
	// slash on the prefix is not a segment of its own.
	prefix = strings.TrimSuffix(prefix, "/")
	if prefix == "" {
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

// PickUDP selects the backend endpoint for one new flow on a UDP internal
// listener port (docs/spec/traffic.md): route weights, then round-robin
// over eligible endpoints, exactly as for TCP connections.
func (t *Tables) PickUDP(port int32, index *EndpointsIndex) (udp.Selection, bool) {
	table := t.byPort[port]
	if table == nil || !table.udp {
		return udp.Selection{}, false
	}

	for _, listener := range table.listeners {
		for _, route := range listener.routes {
			for _, rule := range route.rules {
				backend := rule.PickBackend()
				if backend == nil || !backend.valid {
					return udp.Selection{}, false
				}

				endpoint, ok := backend.Pick(index)
				if !ok {
					return udp.Selection{}, false
				}

				return udp.Selection{
					Endpoint: fmt.Sprintf("%s:%d", endpoint.Address, endpoint.Port),
					Gateway:  table.gatewayName,
					Route:    route.Key(),
					Backend: fmt.Sprintf("%s/%s:%d",
						backend.namespace, backend.name, backend.port),
				}, true
			}
		}
	}

	return udp.Selection{}, false
}

// PickUDP implements udp.Picker over the live snapshots.
func (s *State) PickUDP(port int32) (udp.Selection, bool) {
	return s.Tables.Load().PickUDP(port, s.Endpoints.Load())
}

var _ udp.Picker = (*State)(nil)

// PickTLS selects the backend endpoint for one new downstream connection
// on a TLS passthrough port (docs/spec/traffic.md): the SNI value selects
// the listener and route by hostname precedence (most specific matching
// hostname, oldest route on ties), then route weights and endpoint
// round-robin apply as for every other route type.
func (t *Tables) PickTLS(port int32, sni string, index *EndpointsIndex) (tls.Selection, bool) {
	table := t.byPort[port]
	if table == nil || !table.tlsPassthrough {
		return tls.Selection{}, false
	}

	var (
		bestRule  *RuleTable
		bestRoute *RouteTable
		bestScore matchScore
	)

	for _, listener := range table.listeners {
		if !hostnameMatches(listener.hostname, sni) {
			continue
		}

		for _, route := range listener.routes {
			if !routeHostnameMatches(route.hostnames, sni) {
				continue
			}

			for _, rule := range route.rules {
				score := matchScore{
					listenerHostname: hostnameScore(listener.hostname),
					routeHostname:    routeHostnameScore(listener, route, sni),
					created:          route.created,
					name:             route.Key(),
				}

				if bestRule == nil || score.beats(bestScore) {
					bestRule, bestRoute = rule, route
					bestScore = score
				}
			}
		}
	}

	if bestRule == nil {
		return tls.Selection{}, false
	}

	backend := bestRule.PickBackend()
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
		Route:    bestRoute.Key(),
		Backend: fmt.Sprintf("%s/%s:%d",
			backend.namespace, backend.name, backend.port),
	}, true
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
