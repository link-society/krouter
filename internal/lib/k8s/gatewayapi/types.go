package gatewayapi

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	"github.com/link-society/krouter/internal/lib/k8s/compiled"
)

// world is the cluster snapshot one reconciliation pass operates on.
type world struct {
	classes    []gatewayv1.GatewayClass
	gateways   []gatewayv1.Gateway
	routes     []gatewayv1.HTTPRoute
	grpcRoutes []gatewayv1.GRPCRoute
	tcpRoutes  []gatewayv1alpha2.TCPRoute
	tlsRoutes  []gatewayv1alpha2.TLSRoute
	udpRoutes  []gatewayv1alpha2.UDPRoute
	grants     []gatewayv1beta1.ReferenceGrant
	namespaces map[string]map[string]string

	listenerSets []gatewayv1.ListenerSet

	backendTLSPolicies []gatewayv1.BackendTLSPolicy
	backendTLSStates   []*backendTLSPolicyState
	backendTLS         map[string][]*backendTLSBinding // "ns/service" -> bindings

	services         map[string]*corev1.Service
	krouterServices  []*corev1.Service
	generatedCMs     []corev1.ConfigMap
	generatedSecrets []corev1.Secret

	acks          AckState
	bundleVersion string
}

// listenerState is the validated view of one effective Gateway listener:
// the Gateway's own, or one merged from an attached ListenerSet
// (docs/spec/frontend.md Listener sets).
type listenerState struct {
	spec         gatewayv1.Listener
	internalPort int32

	// set is the owning ListenerSet, nil for the Gateway's own listeners.
	// Routes bind per owner: a parentRef to the Gateway only reaches its
	// own listeners, a parentRef to a set only reaches that set's
	// (docs/spec/frontend.md).
	set *gatewayv1.ListenerSet

	accepted       bool
	acceptedReason string

	// conflicted marks a listener rejected by the cross-owner merge
	// (ProtocolConflict or HostnameConflict, docs/spec/frontend.md).
	conflicted bool

	refsResolved bool
	refsReason   string
	refsMessage  string

	// supportedKinds is published on the listener status: the route kinds
	// requested by allowedRoutes.kinds (or all protocol-compatible kinds
	// when unspecified) that this listener can actually serve
	// (docs/spec/frontend.md).
	supportedKinds []gatewayv1.RouteGroupKind

	// allowedKinds gates route attachment: a route kind absent from this
	// set is rejected with NotAllowedByListeners (docs/spec/status.md).
	allowedKinds map[string]bool

	certData map[string][]byte // keys "<effective name>.tls.crt" / ".tls.key"

	attachedRoutes int32
}

func (l *listenerState) valid() bool {
	return l.accepted && l.refsResolved
}

// ownerKey identifies the listener's owner for route binding: empty for
// the Gateway, "namespace/name" for a ListenerSet.
func (l *listenerState) ownerKey() string {
	if l.set == nil {
		return ""
	}

	return l.set.Namespace + "/" + l.set.Name
}

// effectiveName uniquely identifies the listener across the Gateway and
// its ListenerSets in compiled configuration and generated Secrets
// (listener names are only unique within their owner).
func (l *listenerState) effectiveName() string {
	if l.set == nil {
		return string(l.spec.Name)
	}

	return l.set.Namespace + "--" + l.set.Name + "--" + string(l.spec.Name)
}

// routeParentOutcome is the computed status of one (route, gateway)
// attachment, plus its compiled form. Exactly one of route/grpcRoute/
// tcpRoute/tlsRoute/udpRoute is set, depending on the attachment kind.
type routeParentOutcome struct {
	route     *gatewayv1.HTTPRoute
	grpcRoute *gatewayv1.GRPCRoute
	tcpRoute  *gatewayv1alpha2.TCPRoute
	tlsRoute  *gatewayv1alpha2.TLSRoute
	udpRoute  *gatewayv1alpha2.UDPRoute
	parentRef gatewayv1.ParentReference

	accepted       bool
	acceptedReason string

	refsResolved bool
	refsReason   string
	refsMessage  string

	config *compiled.RouteConfig // nil when not accepted
}

func (o *routeParentOutcome) routeKind() string {
	switch {
	case o.grpcRoute != nil:
		return "GRPCRoute"

	case o.tcpRoute != nil:
		return "TCPRoute"

	case o.tlsRoute != nil:
		return "TLSRoute"

	case o.udpRoute != nil:
		return "UDPRoute"

	default:
		return "HTTPRoute"
	}
}

func (o *routeParentOutcome) routeMeta() metav1.ObjectMeta {
	switch {
	case o.grpcRoute != nil:
		return o.grpcRoute.ObjectMeta

	case o.tcpRoute != nil:
		return o.tcpRoute.ObjectMeta

	case o.tlsRoute != nil:
		return o.tlsRoute.ObjectMeta

	case o.udpRoute != nil:
		return o.udpRoute.ObjectMeta

	default:
		return o.route.ObjectMeta
	}
}

// outcomeKey disambiguates routes of different kinds sharing a name.
func outcomeKey(kind, namespace, name string) string {
	return kind + ":" + namespace + "/" + name
}

// gatewayStatusInput carries the computed conditions for one status write.
type gatewayStatusInput struct {
	accepted     metav1.Condition
	programmed   metav1.Condition
	resolvedRefs metav1.Condition
	address      string
	listeners    []*listenerState
	gatewayAcked bool

	// staticAddresses, when set, replace the generated Service address in
	// status (docs/spec/frontend.md Gateway addresses).
	staticAddresses []string

	// attachedListenerSets is published when the Gateway allows listener
	// sets (docs/spec/frontend.md Listener sets).
	attachedListenerSets *int32
}

// servicePort is one listener group exposed by the generated Service.
type servicePort struct {
	name         string
	externalPort int32
	internalPort int32
	nodePort     int32
	protocol     corev1.Protocol
}

// paramsError marks invalid Gateway parameters (docs/spec/parameters.md).
type paramsError struct{ message string }

var _ error = (*paramsError)(nil)

func (e *paramsError) Error() string { return e.message }

// ----------------------------------------------------- acknowledgements --

// GatewayAck mirrors one entry of the data-plane readiness body (docs/spec/status.md).
type GatewayAck struct {
	DesiredGeneration string `json:"desiredGeneration"`
	AppliedGeneration string `json:"appliedGeneration"`
	LastError         string `json:"lastError"`
}

// AckState is the view of every data-plane pod published by the ack-polling
// actor: which pods are healthy and which configuration generations they
// acknowledge.
type AckState struct {
	Pods map[string]PodAck // by pod name
}

func EmptyAckState() AckState {
	return AckState{Pods: map[string]PodAck{}}
}

type PodAck struct {
	Healthy  bool
	IP       string
	HostIP   string
	NodeName string
	Gateways map[string]GatewayAck
}

// AllAcked reports whether Programmed=True is permitted for a generation
// (docs/spec/status.md): at least one healthy pod, and every healthy pod reporting
// the desired generation as applied.
func (s AckState) AllAcked(gatewayUID, generation string) bool {
	healthy := 0

	for _, pod := range s.Pods {
		if !pod.Healthy {
			continue
		}

		healthy++

		ack, ok := pod.Gateways[gatewayUID]
		if !ok || ack.AppliedGeneration != generation {
			return false
		}
	}

	return healthy > 0
}

// AckedGenerations returns every generation applied by any pod, gating
// garbage collection (docs/spec/configuration.md retention).
func (s AckState) AckedGenerations(gatewayUID string) map[string]bool {
	acked := map[string]bool{}

	for _, pod := range s.Pods {
		if ack, ok := pod.Gateways[gatewayUID]; ok && ack.AppliedGeneration != "" {
			acked[ack.AppliedGeneration] = true
		}
	}

	return acked
}
