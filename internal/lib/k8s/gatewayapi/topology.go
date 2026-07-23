package gatewayapi

import (
	"slices"
	"strings"

	"encoding/json"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	corev1 "k8s.io/api/core/v1"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"

	"sigs.k8s.io/yaml"

	"github.com/link-society/krouter/internal/lib/k8s/compiled"
)

func conditionTrue(cond metav1.Condition) bool {
	return cond.Status == metav1.ConditionTrue
}

// Topology is the dashboard-facing projection of one reconciliation pass:
// every owned Gateway, every Route attached to them, and the compiled
// rules linking routes to backend Services. It is published as an
// immutable snapshot by the reconciler actor.
//
// The embedded YAML documents are excluded from the revision so that
// change notifications only fire for projected state changes.
type Topology struct {
	Revision string        `json:"revision"`
	Gateways []GatewayInfo `json:"gateways"`
	Routes   []RouteInfo   `json:"routes"`

	// Backends maps "namespace/name" to the backend Service manifest;
	// the empty string marks a reference to a missing Service.
	Backends map[string]string `json:"-"`
}

func EmptyTopology() *Topology {
	return &Topology{Revision: "empty", Backends: map[string]string{}}
}

// GatewayInfo is the observed state of one owned Gateway.
type GatewayInfo struct {
	Namespace  string `json:"namespace"`
	Name       string `json:"name"`
	UID        string `json:"uid"`
	Class      string `json:"class"`
	Address    string `json:"address"`
	Generation string `json:"generation"`

	Accepted         bool   `json:"accepted"`
	AcceptedReason   string `json:"acceptedReason"`
	Programmed       bool   `json:"programmed"`
	ProgrammedReason string `json:"programmedReason"`

	YAML string `json:"-"`

	Listeners []ListenerInfo `json:"listeners"`
}

// ListenerInfo is the validated state of one Gateway listener.
type ListenerInfo struct {
	Name           string `json:"name"`
	Port           int32  `json:"port"`
	Protocol       string `json:"protocol"`
	Hostname       string `json:"hostname"`
	InternalPort   int32  `json:"internalPort"`
	Valid          bool   `json:"valid"`
	Reason         string `json:"reason"`
	AttachedRoutes int32  `json:"attachedRoutes"`
}

// RouteInfo is one route referencing at least one owned Gateway.
type RouteInfo struct {
	Kind      string   `json:"kind"` // HTTPRoute | TCPRoute
	Namespace string   `json:"namespace"`
	Name      string   `json:"name"`
	UID       string   `json:"uid"`
	Hostnames []string `json:"hostnames"`

	YAML string `json:"-"`

	Parents []RouteParentInfo `json:"parents"`
}

// RouteParentInfo is the outcome of one (route, gateway) attachment,
// including the compiled rules when the attachment was accepted.
type RouteParentInfo struct {
	GatewayNamespace string `json:"gatewayNamespace"`
	GatewayName      string `json:"gatewayName"`
	GatewayUID       string `json:"gatewayUID"`

	Accepted     bool   `json:"accepted"`
	Reason       string `json:"reason"`
	RefsResolved bool   `json:"refsResolved"`
	RefsReason   string `json:"refsReason"`

	Rules []compiled.Rule `json:"rules"`
}

// topologyBuilder accumulates the projection during one engine pass.
type topologyBuilder struct {
	gateways []GatewayInfo
	routes   map[string]*RouteInfo

	services map[string]*corev1.Service
	backends map[string]string
}

func newTopologyBuilder(services map[string]*corev1.Service) *topologyBuilder {
	return &topologyBuilder{
		routes:   map[string]*RouteInfo{},
		services: services,
		backends: map[string]string{},
	}
}

// objectYAML renders one Kubernetes object as a standalone manifest,
// without the server-side noise.
func objectYAML(obj any, apiVersion, kind string, meta *metav1.ObjectMeta) string {
	meta.ManagedFields = nil

	payload, err := json.Marshal(obj)
	if err != nil {
		return ""
	}

	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		return ""
	}

	decoded["apiVersion"] = apiVersion
	decoded["kind"] = kind

	rendered, err := yaml.Marshal(decoded)
	if err != nil {
		return ""
	}

	return string(rendered)
}

func (b *topologyBuilder) addGateway(
	gw *gatewayv1.Gateway,
	input gatewayStatusInput,
	generation string,
) {
	clone := gw.DeepCopy()

	info := GatewayInfo{
		Namespace:  gw.Namespace,
		Name:       gw.Name,
		UID:        string(gw.UID),
		Class:      string(gw.Spec.GatewayClassName),
		Address:    input.address,
		Generation: generation,

		Accepted:         conditionTrue(input.accepted),
		AcceptedReason:   input.accepted.Reason,
		Programmed:       conditionTrue(input.programmed),
		ProgrammedReason: input.programmed.Reason,

		YAML: objectYAML(clone,
			gatewayv1.GroupVersion.String(), "Gateway", &clone.ObjectMeta),
	}

	for _, lst := range input.listeners {
		hostname := ""
		if lst.spec.Hostname != nil {
			hostname = string(*lst.spec.Hostname)
		}

		reason := lst.acceptedReason
		if lst.accepted && !lst.refsResolved {
			reason = lst.refsReason
		}

		info.Listeners = append(info.Listeners, ListenerInfo{
			Name:           string(lst.spec.Name),
			Port:           int32(lst.spec.Port),
			Protocol:       string(lst.spec.Protocol),
			Hostname:       hostname,
			InternalPort:   lst.internalPort,
			Valid:          lst.valid(),
			Reason:         reason,
			AttachedRoutes: lst.attachedRoutes,
		})
	}

	b.gateways = append(b.gateways, info)
}

func (b *topologyBuilder) addRouteParent(gw *gatewayv1.Gateway, outcome *routeParentOutcome) {
	kind := outcome.routeKind()
	meta := outcome.routeMeta()

	key := outcomeKey(kind, meta.Namespace, meta.Name)

	info, ok := b.routes[key]
	if !ok {
		info = &RouteInfo{
			Kind:      kind,
			Namespace: meta.Namespace,
			Name:      meta.Name,
			UID:       string(meta.UID),
		}

		switch {
		case outcome.grpcRoute != nil:
			clone := outcome.grpcRoute.DeepCopy()
			info.YAML = objectYAML(clone,
				gatewayv1.GroupVersion.String(), "GRPCRoute", &clone.ObjectMeta)

			for _, hostname := range outcome.grpcRoute.Spec.Hostnames {
				info.Hostnames = append(info.Hostnames, string(hostname))
			}

		case outcome.tcpRoute != nil:
			clone := outcome.tcpRoute.DeepCopy()
			info.YAML = objectYAML(clone,
				gatewayv1alpha2.GroupVersion.String(), "TCPRoute", &clone.ObjectMeta)

		case outcome.tlsRoute != nil:
			clone := outcome.tlsRoute.DeepCopy()
			info.YAML = objectYAML(clone,
				gatewayv1alpha2.GroupVersion.String(), "TLSRoute", &clone.ObjectMeta)

			for _, hostname := range outcome.tlsRoute.Spec.Hostnames {
				info.Hostnames = append(info.Hostnames, string(hostname))
			}

		case outcome.udpRoute != nil:
			clone := outcome.udpRoute.DeepCopy()
			info.YAML = objectYAML(clone,
				gatewayv1alpha2.GroupVersion.String(), "UDPRoute", &clone.ObjectMeta)

		default:
			clone := outcome.route.DeepCopy()
			info.YAML = objectYAML(clone,
				gatewayv1.GroupVersion.String(), "HTTPRoute", &clone.ObjectMeta)

			for _, hostname := range outcome.route.Spec.Hostnames {
				info.Hostnames = append(info.Hostnames, string(hostname))
			}
		}

		b.routes[key] = info
	}

	parent := RouteParentInfo{
		GatewayNamespace: gw.Namespace,
		GatewayName:      gw.Name,
		GatewayUID:       string(gw.UID),

		Accepted:     outcome.accepted,
		Reason:       outcome.acceptedReason,
		RefsResolved: outcome.refsResolved,
		RefsReason:   outcome.refsReason,
	}

	if outcome.config != nil {
		parent.Rules = outcome.config.Rules
	}

	for _, rule := range parent.Rules {
		for _, backend := range rule.Backends {
			key := nsName(backend.Namespace, backend.Name)

			if _, ok := b.backends[key]; ok {
				continue
			}

			if svc, ok := b.services[key]; ok {
				clone := svc.DeepCopy()
				b.backends[key] = objectYAML(clone,
					"v1", "Service", &clone.ObjectMeta)
			} else {
				b.backends[key] = ""
			}
		}
	}

	info.Parents = append(info.Parents, parent)
}

// finish sorts the projection deterministically and stamps a content
// revision so consumers can detect changes cheaply.
func (b *topologyBuilder) finish() *Topology {
	topo := &Topology{Gateways: b.gateways, Backends: b.backends}

	for _, route := range b.routes {
		topo.Routes = append(topo.Routes, *route)
	}

	slices.SortFunc(topo.Gateways, func(a, z GatewayInfo) int {
		return strings.Compare(nsName(a.Namespace, a.Name), nsName(z.Namespace, z.Name))
	})

	slices.SortFunc(topo.Routes, func(a, z RouteInfo) int {
		return strings.Compare(nsName(a.Namespace, a.Name), nsName(z.Namespace, z.Name))
	})

	payload, err := json.Marshal(topo)
	if err != nil {
		topo.Revision = "unknown"

		return topo
	}

	topo.Revision = compiled.ChecksumBytes(payload)

	return topo
}
