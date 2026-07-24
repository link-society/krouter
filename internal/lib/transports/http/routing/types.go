// Package routing is the data-plane domain model: the routing tables built
// from compiled configuration, the backend endpoints index, and the state
// published by the actors for the request path. It contains only datatypes
// and pure functions — all behavior lives in the actors that own them.
package routing

import (
	"encoding/json"

	"crypto/tls"
	"crypto/x509"

	"net/http"

	"sync/atomic"
	"time"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"

	"github.com/link-society/krouter/internal/extensions/ratelimiting"
	"github.com/link-society/krouter/internal/lib/k8s/compiled"
	"github.com/link-society/krouter/internal/lib/snapshot"
)

// ----------------------------------------------------------------- tables --

// Tables is the complete, swap-ready routing state. It is immutable once
// built and swapped atomically (docs/spec/configuration.md), so requests never observe a
// broken in-between state and reloads never disturb established
// connections (docs/spec/traffic.md).
type Tables struct {
	byPort   map[int32]*PortTable
	backends map[string]bool
}

func EmptyTables() *Tables {
	return &Tables{
		byPort:   map[int32]*PortTable{},
		backends: map[string]bool{},
	}
}

// Port returns the table serving one internal listener port.
func (t *Tables) Port(port int32) *PortTable {
	return t.byPort[port]
}

// PortSpec describes one internal listener port for the listener
// supervisor: which server kind to run and whether it terminates TLS.
type PortSpec struct {
	TLS            bool
	TCP            bool
	UDP            bool
	TLSPassthrough bool
}

// Ports returns every internal listener port and its spec, for the
// listener supervisor to reconcile its children.
func (t *Tables) Ports() map[int32]PortSpec {
	ports := make(map[int32]PortSpec, len(t.byPort))
	for port, table := range t.byPort {
		ports[port] = PortSpec{
			TLS:            table.tls,
			TCP:            table.tcp,
			UDP:            table.udp,
			TLSPassthrough: table.tlsPassthrough,
		}
	}

	return ports
}

// Backends returns the namespaces containing accepted backends, for the
// resolver actor.
func (t *Tables) Backends() map[string]bool {
	return t.backends
}

type PortTable struct {
	gatewayUID     string
	gatewayName    string // namespace/name, for access logs
	tls            bool
	tcp            bool
	udp            bool
	tlsPassthrough bool
	listeners      []*ListenerTable
}

type ListenerTable struct {
	name     string
	hostname string
	cert     *tls.Certificate
	// terminate marks a TLS-protocol listener in Terminate mode: the
	// session ends at the gateway and the decrypted stream is forwarded
	// (docs/spec/traffic.md TLS passthrough and termination).
	terminate bool
	// clientCAs + clientAuth implement frontend client-certificate
	// validation (docs/spec/security.md); NoClientCert means none.
	clientCAs  *x509.CertPool
	clientAuth tls.ClientAuthType
	routes     []*RouteTable
}

func (l *ListenerTable) Name() string { return l.name }

// ClientValidation returns the frontend client-certificate validation of
// the listener (docs/spec/security.md).
func (l *ListenerTable) ClientValidation() (*x509.CertPool, tls.ClientAuthType) {
	if l == nil {
		return nil, tls.NoClientCert
	}

	return l.clientCAs, l.clientAuth
}

// Certificate returns the listener's TLS certificate, if any.
func (l *ListenerTable) Certificate() *tls.Certificate {
	if l == nil {
		return nil
	}

	return l.cert
}

type RouteTable struct {
	namespace string
	name      string
	hostnames []string
	created   int64 // creation unix time, precedence tie-break (docs/spec/traffic.md)
	rules     []*RuleTable
}

func (r *RouteTable) Key() string { return r.namespace + "/" + r.name }

type RuleTable struct {
	matches        []compiled.Match
	filters        []compiled.Filter
	backends       []*BackendTable
	mirrors        []*MirrorTable
	cors           *compiled.CORS
	grpc           bool
	requestTimeout time.Duration // zero means no timeout (docs/spec/traffic.md)
	backendTimeout time.Duration
	total          int64
	counter        atomic.Int64

	// limiter enforces the rule's merged rate limiting configuration;
	// extensionsInvalid marks a broken ExtensionRef target: matching
	// requests are answered 500 (docs/spec/extensions.md).
	limiter           *ratelimiting.Limiter
	extensionsInvalid bool
}

// RateLimiter returns the rule's rate limiter, or nil
// (docs/spec/extensions.md Rate limiting).
func (r *RuleTable) RateLimiter() *ratelimiting.Limiter { return r.limiter }

// ExtensionsInvalid reports a broken ExtensionRef target: the rule fails
// closed (docs/spec/extensions.md Resolution and status).
func (r *RuleTable) ExtensionsInvalid() bool { return r.extensionsInvalid }

// Filters returns the compiled filters of the rule.
func (r *RuleTable) Filters() []compiled.Filter { return r.filters }

// CORS returns the rule's CORS configuration, or nil
// (docs/spec/traffic.md Routing and filters).
func (r *RuleTable) CORS() *compiled.CORS { return r.cors }

// Timeout returns the effective per-request deadline of the rule: the
// smallest non-zero of the request and backendRequest timeouts
// (docs/spec/traffic.md).
func (r *RuleTable) Timeout() time.Duration {
	switch {
	case r.requestTimeout == 0:
		return r.backendTimeout

	case r.backendTimeout == 0 || r.requestTimeout < r.backendTimeout:
		return r.requestTimeout

	default:
		return r.backendTimeout
	}
}

// Mirrors returns the rule's request mirror targets (docs/spec/traffic.md).
func (r *RuleTable) Mirrors() []*MirrorTable { return r.mirrors }

// MirrorTable is one RequestMirror target: a copy of matching requests is
// delivered to a single endpoint of the backend, sampled by percent
// (docs/spec/traffic.md).
type MirrorTable struct {
	backend *BackendTable
	percent float64 // 0-100
}

func (m *MirrorTable) Backend() *BackendTable { return m.backend }
func (m *MirrorTable) Percent() float64       { return m.percent }

// GRPC reports whether the rule belongs to a GRPCRoute: it only matches
// gRPC requests and its backends speak cleartext HTTP/2
// (docs/spec/traffic.md gRPC routing).
func (r *RuleTable) GRPC() bool { return r.grpc }

type BackendTable struct {
	namespace string
	name      string
	port      int32
	weight    int32
	valid     bool

	// h2c marks a backend Service port declaring appProtocol
	// kubernetes.io/h2c, dialed with cleartext HTTP/2
	// (docs/spec/traffic.md Protocol handling).
	h2c bool

	// filters apply only to traffic forwarded to this backend, after the
	// rule-level filters (docs/spec/traffic.md Routing and filters).
	filters []compiled.Filter

	// tlsKey fingerprints the TLS client configuration behind
	// tlsTransport, so equivalent transports are adopted across table
	// swaps and pooled connections survive (docs/spec/configuration.md).
	tlsKey string
	// tlsTransport carries requests to a backend covered by a
	// BackendTLSPolicy; tlsInvalid marks a rejected policy whose backend
	// MUST fail closed (docs/spec/traffic.md Backend TLS).
	tlsTransport *http.Transport
	tlsInvalid   bool

	counter atomic.Int64
}

// Valid reports whether the backend reference resolved (invalid refs answer
// 500 for their traffic share, per the Gateway API).
func (b *BackendTable) Valid() bool { return b.valid }

// H2C reports whether the backend is dialed with cleartext HTTP/2
// (docs/spec/traffic.md Protocol handling).
func (b *BackendTable) H2C() bool { return b.h2c }

// Filters returns the per-backendRef filters of the backend
// (docs/spec/traffic.md Routing and filters).
func (b *BackendTable) Filters() []compiled.Filter { return b.filters }

// TLSTransport returns the verified-TLS transport of the backend, or nil
// for cleartext backends (docs/spec/traffic.md Backend TLS).
func (b *BackendTable) TLSTransport() *http.Transport { return b.tlsTransport }

// TLSInvalid reports a rejected BackendTLSPolicy: requests MUST fail
// closed instead of falling back to cleartext (docs/spec/traffic.md).
func (b *BackendTable) TLSInvalid() bool { return b.tlsInvalid }

// GatewayTable is one gateway's slice of the routing tables.
type GatewayTable struct {
	Generation string

	byPort     map[int32]*PortTable
	namespaces map[string]bool
}

// -------------------------------------------------------------- endpoints --

// EndpointsIndex is the immutable backend discovery snapshot published by
// the resolver actor and read by the request path (docs/spec/traffic.md).
type EndpointsIndex struct {
	Services map[string]*corev1.Service              // ns/name
	Slices   map[string][]*discoveryv1.EndpointSlice // ns/svcname
}

func NewEndpointsIndex() *EndpointsIndex {
	return &EndpointsIndex{
		Services: map[string]*corev1.Service{},
		Slices:   map[string][]*discoveryv1.EndpointSlice{},
	}
}

// Endpoint is one ready backend address.
type Endpoint struct {
	Address string
	Port    int32
}

// ---------------------------------------------------------------- status --

// GatewayStatus is the per-Gateway acknowledgement exposed on /readyz
// (docs/spec/status.md).
type GatewayStatus struct {
	DesiredGeneration string `json:"desiredGeneration"`
	AppliedGeneration string `json:"appliedGeneration"`
	LastError         string `json:"lastError,omitempty"`
}

// ----------------------------------------------------------------- state --

// State holds the snapshots published by the data-plane actors. Each
// snapshot has exactly one writing actor; the request path and the
// management endpoints only read.
type State struct {
	Tables    *snapshot.Store[*Tables]                  // written by the loader actor
	Statuses  *snapshot.Store[map[string]GatewayStatus] // written by the loader actor
	Endpoints *snapshot.Store[*EndpointsIndex]          // written by the resolver actor
}

func NewState() *State {
	return &State{
		Tables:    snapshot.New(EmptyTables()),
		Statuses:  snapshot.New(map[string]GatewayStatus{}),
		Endpoints: snapshot.New(NewEndpointsIndex()),
	}
}

// Readyz renders the readiness acknowledgement body (docs/spec/status.md, docs/spec/observability.md).
// Liveness reports process health, not configuration validity: an invalid
// desired generation keeps readiness true while the last valid generation
// serves.
func (s *State) Readyz() ([]byte, int) {
	body, _ := json.Marshal(map[string]any{
		"ready":    true,
		"gateways": s.Statuses.Load(),
	})

	return body, 200
}
