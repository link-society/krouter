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
	grants     []gatewayv1beta1.ReferenceGrant
	namespaces map[string]map[string]string

	services         map[string]*corev1.Service
	krouterServices  []*corev1.Service
	generatedCMs     []corev1.ConfigMap
	generatedSecrets []corev1.Secret

	acks          AckState
	bundleVersion string
}

// listenerState is the validated view of one Gateway listener.
type listenerState struct {
	spec         gatewayv1.Listener
	internalPort int32

	accepted       bool
	acceptedReason string

	refsResolved bool
	refsReason   string
	refsMessage  string

	certData map[string][]byte // keys "<name>.tls.crt" / "<name>.tls.key"

	attachedRoutes int32
}

func (l *listenerState) valid() bool {
	return l.accepted && l.refsResolved
}

// routeParentOutcome is the computed status of one (route, gateway)
// attachment, plus its compiled form. Exactly one of route/grpcRoute/
// tcpRoute/tlsRoute is set, depending on the attachment kind.
type routeParentOutcome struct {
	route     *gatewayv1.HTTPRoute
	grpcRoute *gatewayv1.GRPCRoute
	tcpRoute  *gatewayv1alpha2.TCPRoute
	tlsRoute  *gatewayv1alpha2.TLSRoute
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
	address      string
	listeners    []*listenerState
	gatewayAcked bool
}

// servicePort is one listener group exposed by the generated Service.
type servicePort struct {
	name         string
	externalPort int32
	internalPort int32
	nodePort     int32
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
