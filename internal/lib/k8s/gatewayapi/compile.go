package gatewayapi

import (
	"context"
	"fmt"

	"strings"

	"time"

	stdtls "crypto/tls"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	"github.com/link-society/krouter/internal/lib/k8s/compiled"
)

// ------------------------------------------------------------ listeners --

// validateListeners builds the effective listener set of one Gateway: its
// own listeners first, then the entries of every accepted ListenerSet in
// precedence order (docs/spec/frontend.md Listener sets).
func (r *Engine) validateListeners(
	ctx context.Context,
	w *world,
	gw *gatewayv1.Gateway,
	sets []*listenerSetState,
	allocator *portAllocator,
) []*listenerState {
	listeners := make([]*listenerState, 0, len(gw.Spec.Listeners))

	for _, spec := range gw.Spec.Listeners {
		listeners = append(listeners, r.validateListener(ctx, w, gw, spec, nil, allocator))
	}

	for _, set := range sets {
		if !set.accepted {
			continue
		}

		for _, entry := range set.set.Spec.Listeners {
			spec := gatewayv1.Listener{
				Name:          entry.Name,
				Hostname:      entry.Hostname,
				Port:          entry.Port,
				Protocol:      entry.Protocol,
				TLS:           entry.TLS,
				AllowedRoutes: entry.AllowedRoutes,
			}

			listeners = append(listeners,
				r.validateListener(ctx, w, gw, spec, set.set, allocator))
		}
	}

	rejectConflictingListeners(listeners)

	return listeners
}

// validateListener validates one effective listener owned by the Gateway
// (set == nil) or by an attached ListenerSet.
func (r *Engine) validateListener(
	ctx context.Context,
	w *world,
	gw *gatewayv1.Gateway,
	spec gatewayv1.Listener,
	set *gatewayv1.ListenerSet,
	allocator *portAllocator,
) *listenerState {
	state := &listenerState{
		spec:           spec,
		set:            set,
		accepted:       true,
		acceptedReason: string(gatewayv1.ListenerReasonAccepted),
		refsResolved:   true,
		refsReason:     string(gatewayv1.ListenerReasonResolvedRefs),
		certData:       map[string][]byte{},
	}

	switch spec.Protocol {
	case gatewayv1.HTTPProtocolType, gatewayv1.HTTPSProtocolType,
		gatewayv1.TCPProtocolType, gatewayv1.UDPProtocolType:

	case gatewayv1.TLSProtocolType:
		// Passthrough only (docs/spec/overview.md): krouter routes on the
		// SNI value and never holds the certificate. Terminate is a
		// valid protocol with an unsupported mode value.
		if spec.TLS == nil || spec.TLS.Mode == nil ||
			*spec.TLS.Mode != gatewayv1.TLSModePassthrough {
			state.accepted = false
			state.acceptedReason = string(gatewayv1.ListenerReasonUnsupportedValue)
		}

	default:
		state.accepted = false
		state.acceptedReason = string(gatewayv1.ListenerReasonUnsupportedProtocol)
	}

	resolveRouteKinds(state)

	if spec.Protocol == gatewayv1.HTTPSProtocolType && state.refsResolved {
		r.resolveCertificates(ctx, w, gw, state)
	}

	port, err := allocator.Allocate(string(gw.UID), int32(spec.Port), string(spec.Protocol))
	if err != nil {
		// Exhausted range: reject programming without disturbing
		// existing allocations (docs/spec/frontend.md, docs/spec/failure-modes.md).
		state.accepted = false
		state.acceptedReason = string(gatewayv1.ListenerReasonPortUnavailable)
	}
	state.internalPort = port

	return state
}

// rejectConflictingListeners applies the cross-owner merge rules
// (docs/spec/frontend.md Listener sets): on one port, differing protocols
// conflict (ProtocolConflict) and equal protocol+hostname pairs conflict
// (HostnameConflict). Listeners are already ordered by precedence, so the
// later entry loses.
func rejectConflictingListeners(listeners []*listenerState) {
	type key struct {
		protocol gatewayv1.ProtocolType
		hostname string
	}

	byPort := map[gatewayv1.PortNumber][]key{}

	for _, lst := range listeners {
		if !lst.accepted {
			continue
		}

		hostname := ""
		if lst.spec.Hostname != nil {
			hostname = string(*lst.spec.Hostname)
		}

		conflictReason := ""
		for _, existing := range byPort[lst.spec.Port] {
			if existing.protocol != lst.spec.Protocol {
				conflictReason = string(gatewayv1.ListenerReasonProtocolConflict)
				break
			}

			if existing.hostname == hostname {
				conflictReason = string(gatewayv1.ListenerReasonHostnameConflict)
				break
			}
		}

		if conflictReason != "" {
			lst.accepted = false
			lst.acceptedReason = conflictReason
			lst.conflicted = true
			resolveRouteKinds(lst) // a rejected listener serves nothing

			continue
		}

		byPort[lst.spec.Port] = append(byPort[lst.spec.Port],
			key{protocol: lst.spec.Protocol, hostname: hostname})
	}
}

// protocolRouteKinds returns the route kinds a listener protocol can serve
// (docs/spec/frontend.md).
func protocolRouteKinds(protocol gatewayv1.ProtocolType) []string {
	switch protocol {
	case gatewayv1.HTTPProtocolType, gatewayv1.HTTPSProtocolType:
		return []string{"HTTPRoute", "GRPCRoute"}

	case gatewayv1.TCPProtocolType:
		return []string{"TCPRoute"}

	case gatewayv1.UDPProtocolType:
		return []string{"UDPRoute"}

	case gatewayv1.TLSProtocolType:
		return []string{"TLSRoute"}

	default:
		return nil
	}
}

// resolveRouteKinds computes the listener's supported and allowed route
// kinds from allowedRoutes.kinds. Requested kinds the listener cannot serve
// surface as ResolvedRefs=False with reason InvalidRouteKinds, and
// supportedKinds only advertises the kinds that remain (docs/spec/status.md).
func resolveRouteKinds(state *listenerState) {
	state.allowedKinds = map[string]bool{}
	state.supportedKinds = []gatewayv1.RouteGroupKind{}

	// A rejected listener serves nothing: it advertises no supported kinds
	// and admits no routes (docs/spec/status.md).
	if !state.accepted {
		return
	}

	compatible := protocolRouteKinds(state.spec.Protocol)

	requested := []gatewayv1.RouteGroupKind{}
	if state.spec.AllowedRoutes != nil {
		requested = state.spec.AllowedRoutes.Kinds
	}

	if len(requested) == 0 {
		for _, kind := range compatible {
			state.allowedKinds[kind] = true
			state.supportedKinds = append(state.supportedKinds, gatewayv1.RouteGroupKind{
				Group: ptr.To(gatewayv1.Group(gatewayv1.GroupName)),
				Kind:  gatewayv1.Kind(kind),
			})
		}

		return
	}

	invalid := false
	for _, kind := range requested {
		groupOK := kind.Group == nil || *kind.Group == gatewayv1.GroupName

		kindOK := false
		for _, candidate := range compatible {
			if string(kind.Kind) == candidate {
				kindOK = true
				break
			}
		}

		if !groupOK || !kindOK {
			invalid = true
			continue
		}

		if state.allowedKinds[string(kind.Kind)] {
			continue
		}

		state.allowedKinds[string(kind.Kind)] = true
		state.supportedKinds = append(state.supportedKinds, gatewayv1.RouteGroupKind{
			Group: ptr.To(gatewayv1.Group(gatewayv1.GroupName)),
			Kind:  kind.Kind,
		})
	}

	if invalid && state.refsResolved {
		state.refsResolved = false
		state.refsReason = string(gatewayv1.ListenerReasonInvalidRouteKinds)
		state.refsMessage = "allowedRoutes.kinds contains kinds this listener cannot serve"
	}
}

// resolveCertificates validates listener certificate references and
// applicable ReferenceGrants (docs/spec/security.md). References resolve in
// the listener owner's namespace — the Gateway's, or the ListenerSet's for
// merged listeners — and cross-namespace grants must name the owner's kind
// (docs/spec/frontend.md Listener sets).
func (r *Engine) resolveCertificates(
	ctx context.Context,
	w *world,
	gw *gatewayv1.Gateway,
	state *listenerState,
) {
	ownerNamespace := gw.Namespace
	ownerKind := "Gateway"
	if state.set != nil {
		ownerNamespace = state.set.Namespace
		ownerKind = "ListenerSet"
	}

	tls := state.spec.TLS
	if tls == nil || len(tls.CertificateRefs) == 0 {
		state.refsResolved = false
		state.refsReason = string(gatewayv1.ListenerReasonInvalidCertificateRef)
		state.refsMessage = "HTTPS listener requires a certificateRef"
		return
	}

	for _, ref := range tls.CertificateRefs {
		if (ref.Kind != nil && *ref.Kind != "Secret") ||
			(ref.Group != nil && *ref.Group != "") {
			state.refsResolved = false
			state.refsReason = string(gatewayv1.ListenerReasonInvalidCertificateRef)
			state.refsMessage = "certificateRefs must reference core Secrets"
			return
		}

		namespace := ownerNamespace
		if ref.Namespace != nil {
			namespace = string(*ref.Namespace)
		}

		if namespace != ownerNamespace {
			allowed := referenceGrantAllows(
				w.grants,
				gatewayv1.GroupName, ownerKind, ownerNamespace,
				"Secret", namespace, string(ref.Name),
			)
			if !allowed {
				state.refsResolved = false
				state.refsReason = string(gatewayv1.ListenerReasonRefNotPermitted)
				state.refsMessage = fmt.Sprintf(
					"reference to Secret %s/%s not permitted by any ReferenceGrant",
					namespace, ref.Name,
				)
				return
			}
		}

		secret, err := r.client.CoreV1().Secrets(namespace).
			Get(ctx, string(ref.Name), metav1.GetOptions{})
		if err != nil {
			state.refsResolved = false
			state.refsReason = string(gatewayv1.ListenerReasonInvalidCertificateRef)
			state.refsMessage = fmt.Sprintf("Secret %s/%s not found", namespace, ref.Name)
			return
		}

		cert, key := secret.Data[corev1.TLSCertKey], secret.Data[corev1.TLSPrivateKeyKey]
		if len(cert) == 0 || len(key) == 0 {
			state.refsResolved = false
			state.refsReason = string(gatewayv1.ListenerReasonInvalidCertificateRef)
			state.refsMessage = fmt.Sprintf("Secret %s/%s has no TLS material", namespace, ref.Name)
			return
		}

		if _, err := stdtls.X509KeyPair(cert, key); err != nil {
			state.refsResolved = false
			state.refsReason = string(gatewayv1.ListenerReasonInvalidCertificateRef)
			state.refsMessage = fmt.Sprintf(
				"Secret %s/%s has malformed TLS material: %v", namespace, ref.Name, err)
			return
		}

		// Only referenced material is copied into the generated Secret
		// (docs/spec/security.md); the data plane never reads source Secrets.
		state.certData[state.effectiveName()+".tls.crt"] = cert
		state.certData[state.effectiveName()+".tls.key"] = key
	}
}

// ---------------------------------------------------------------- routes --

// attachRoutes computes every (route, gateway) attachment outcome and
// increments per-listener attachedRoutes counts (docs/spec/status.md).
func (r *Engine) attachRoutes(
	w *world,
	gw *gatewayv1.Gateway,
	sets []*listenerSetState,
	listeners []*listenerState,
) []*routeParentOutcome {
	var outcomes []*routeParentOutcome

	for i := range w.routes {
		route := &w.routes[i]

		for _, parentRef := range route.Spec.ParentRefs {
			ownerKey, ok := resolveRouteParent(parentRef, route.Namespace, gw, sets)
			if !ok {
				continue
			}

			outcome := r.attachRoute(w, gw, listenersOwnedBy(listeners, ownerKey), route, parentRef)
			outcomes = append(outcomes, outcome)
		}
	}

	return outcomes
}

// resolveRouteParent maps one parentRef onto this Gateway's listener
// owners: the Gateway itself (owner key "") or one of the ListenerSets
// targeting it (docs/spec/frontend.md Listener sets). Routes bind only to
// the listeners of the referenced owner.
func resolveRouteParent(
	ref gatewayv1.ParentReference,
	routeNamespace string,
	gw *gatewayv1.Gateway,
	sets []*listenerSetState,
) (string, bool) {
	if ref.Group != nil && *ref.Group != gatewayv1.GroupName && *ref.Group != "" {
		return "", false
	}

	namespace := routeNamespace
	if ref.Namespace != nil {
		namespace = string(*ref.Namespace)
	}

	kind := "Gateway"
	if ref.Kind != nil {
		kind = string(*ref.Kind)
	}

	switch kind {
	case "Gateway":
		if namespace == gw.Namespace && string(ref.Name) == gw.Name {
			return "", true
		}

	case "ListenerSet":
		for _, set := range sets {
			if set.set.Namespace == namespace && set.set.Name == string(ref.Name) {
				return namespace + "/" + string(ref.Name), true
			}
		}
	}

	return "", false
}

// listenersOwnedBy narrows the effective listeners to one owner's.
func listenersOwnedBy(listeners []*listenerState, ownerKey string) []*listenerState {
	var owned []*listenerState
	for _, lst := range listeners {
		if lst.ownerKey() == ownerKey {
			owned = append(owned, lst)
		}
	}

	return owned
}

// admitListeners applies the attachment admission ladder shared by every
// route kind (docs/spec/status.md): sectionName and parentRef port
// narrowing first (docs/spec/traffic.md Routing and filters), then
// listener kind admission, then namespace policy. It returns the admitted
// listeners, or the Accepted-condition reason for the rejection.
func admitListeners(
	listeners []*listenerState,
	parentRef gatewayv1.ParentReference,
	routeKind string,
	routeNamespace, gatewayNamespace string,
	namespaces map[string]map[string]string,
) ([]*listenerState, string) {
	var candidates []*listenerState
	for _, lst := range listeners {
		if parentRef.SectionName != nil && *parentRef.SectionName != lst.spec.Name {
			continue
		}

		if parentRef.Port != nil && *parentRef.Port != lst.spec.Port {
			continue
		}

		candidates = append(candidates, lst)
	}

	if len(candidates) == 0 {
		return nil, string(gatewayv1.RouteReasonNoMatchingParent)
	}

	var kindAdmitted []*listenerState
	for _, lst := range candidates {
		if lst.allowedKinds[routeKind] {
			kindAdmitted = append(kindAdmitted, lst)
		}
	}

	if len(kindAdmitted) == 0 {
		return nil, string(gatewayv1.RouteReasonNotAllowedByListeners)
	}

	var admitted []*listenerState
	for _, lst := range kindAdmitted {
		if namespaceAllowed(lst.spec.AllowedRoutes, routeNamespace, gatewayNamespace, namespaces) {
			admitted = append(admitted, lst)
		}
	}

	if len(admitted) == 0 {
		return nil, string(gatewayv1.RouteReasonNotAllowedByListeners)
	}

	return admitted, ""
}

func (r *Engine) attachRoute(
	w *world,
	gw *gatewayv1.Gateway,
	listeners []*listenerState,
	route *gatewayv1.HTTPRoute,
	parentRef gatewayv1.ParentReference,
) *routeParentOutcome {
	outcome := &routeParentOutcome{
		route:        route,
		parentRef:    parentRef,
		refsResolved: true,
		refsReason:   string(gatewayv1.RouteReasonResolvedRefs),
	}

	namespaceAdmitted, reason := admitListeners(
		listeners, parentRef, "HTTPRoute", route.Namespace, gw.Namespace, w.namespaces)
	if reason != "" {
		outcome.acceptedReason = reason
		return outcome
	}

	var admitted []*listenerState
	for _, lst := range namespaceAdmitted {
		if hostnamesIntersect(lst.spec.Hostname, route.Spec.Hostnames) {
			admitted = append(admitted, lst)
		}
	}

	if len(admitted) == 0 {
		outcome.acceptedReason = string(gatewayv1.RouteReasonNoMatchingListenerHostname)
		return outcome
	}

	outcome.config = r.compileRoute(w, gw, route, admitted, outcome)
	if outcome.config == nil {
		outcome.acceptedReason = string(gatewayv1.RouteReasonUnsupportedValue)
		return outcome
	}

	outcome.accepted = true
	outcome.acceptedReason = string(gatewayv1.RouteReasonAccepted)

	for _, lst := range admitted {
		lst.attachedRoutes++
	}

	return outcome
}

// attachTCPRoutes computes every (TCPRoute, gateway) attachment outcome
// (docs/spec/traffic.md): TCPRoutes attach to TCP listeners only and carry
// no hostname, path or filter semantics.
func (r *Engine) attachTCPRoutes(
	w *world,
	gw *gatewayv1.Gateway,
	sets []*listenerSetState,
	listeners []*listenerState,
) []*routeParentOutcome {
	var outcomes []*routeParentOutcome

	for i := range w.tcpRoutes {
		route := &w.tcpRoutes[i]

		for _, parentRef := range route.Spec.ParentRefs {
			ownerKey, ok := resolveRouteParent(parentRef, route.Namespace, gw, sets)
			if !ok {
				continue
			}

			outcome := r.attachTCPRoute(w, gw, listenersOwnedBy(listeners, ownerKey), route, parentRef)
			outcomes = append(outcomes, outcome)
		}
	}

	return outcomes
}

func (r *Engine) attachTCPRoute(
	w *world,
	gw *gatewayv1.Gateway,
	listeners []*listenerState,
	route *gatewayv1alpha2.TCPRoute,
	parentRef gatewayv1.ParentReference,
) *routeParentOutcome {
	outcome := &routeParentOutcome{
		tcpRoute:     route,
		parentRef:    parentRef,
		refsResolved: true,
		refsReason:   string(gatewayv1.RouteReasonResolvedRefs),
	}

	admitted, reason := admitListeners(
		listeners, parentRef, "TCPRoute", route.Namespace, gw.Namespace, w.namespaces)
	if reason != "" {
		outcome.acceptedReason = reason
		return outcome
	}

	if len(route.Spec.Rules) != 1 {
		outcome.acceptedReason = string(gatewayv1.RouteReasonUnsupportedValue)
		return outcome
	}

	outcome.accepted = true
	outcome.acceptedReason = string(gatewayv1.RouteReasonAccepted)

	for _, lst := range admitted {
		lst.attachedRoutes++
	}

	config := &compiled.RouteConfig{
		UID:       string(route.UID),
		Namespace: route.Namespace,
		Name:      route.Name,
		Created:   route.CreationTimestamp.Unix(),
	}

	for _, lst := range admitted {
		if lst.valid() {
			config.Listeners = append(config.Listeners, lst.effectiveName())
		}
	}

	rule := compiled.Rule{}
	for _, backendRef := range route.Spec.Rules[0].BackendRefs {
		rule.Backends = append(rule.Backends,
			r.compileBackend(w, route.Namespace, "TCPRoute", backendRef, outcome))
	}

	config.Rules = append(config.Rules, rule)
	outcome.config = config

	return outcome
}

// attachUDPRoutes computes every (UDPRoute, gateway) attachment outcome
// (docs/spec/traffic.md): UDPRoutes attach to UDP listeners only and carry
// no hostname, path or filter semantics.
func (r *Engine) attachUDPRoutes(
	w *world,
	gw *gatewayv1.Gateway,
	sets []*listenerSetState,
	listeners []*listenerState,
) []*routeParentOutcome {
	var outcomes []*routeParentOutcome

	for i := range w.udpRoutes {
		route := &w.udpRoutes[i]

		for _, parentRef := range route.Spec.ParentRefs {
			ownerKey, ok := resolveRouteParent(parentRef, route.Namespace, gw, sets)
			if !ok {
				continue
			}

			outcome := r.attachUDPRoute(w, gw, listenersOwnedBy(listeners, ownerKey), route, parentRef)
			outcomes = append(outcomes, outcome)
		}
	}

	return outcomes
}

func (r *Engine) attachUDPRoute(
	w *world,
	gw *gatewayv1.Gateway,
	listeners []*listenerState,
	route *gatewayv1alpha2.UDPRoute,
	parentRef gatewayv1.ParentReference,
) *routeParentOutcome {
	outcome := &routeParentOutcome{
		udpRoute:     route,
		parentRef:    parentRef,
		refsResolved: true,
		refsReason:   string(gatewayv1.RouteReasonResolvedRefs),
	}

	admitted, reason := admitListeners(
		listeners, parentRef, "UDPRoute", route.Namespace, gw.Namespace, w.namespaces)
	if reason != "" {
		outcome.acceptedReason = reason
		return outcome
	}

	if len(route.Spec.Rules) != 1 {
		outcome.acceptedReason = string(gatewayv1.RouteReasonUnsupportedValue)
		return outcome
	}

	outcome.accepted = true
	outcome.acceptedReason = string(gatewayv1.RouteReasonAccepted)

	for _, lst := range admitted {
		lst.attachedRoutes++
	}

	config := &compiled.RouteConfig{
		UID:       string(route.UID),
		Namespace: route.Namespace,
		Name:      route.Name,
		Created:   route.CreationTimestamp.Unix(),
	}

	for _, lst := range admitted {
		if lst.valid() {
			config.Listeners = append(config.Listeners, lst.effectiveName())
		}
	}

	rule := compiled.Rule{}
	for _, backendRef := range route.Spec.Rules[0].BackendRefs {
		rule.Backends = append(rule.Backends,
			r.compileBackend(w, route.Namespace, "UDPRoute", backendRef, outcome))
	}

	config.Rules = append(config.Rules, rule)
	outcome.config = config

	return outcome
}

// attachTLSRoutes computes every (TLSRoute, gateway) attachment outcome
// (docs/spec/traffic.md): TLSRoutes attach to TLS passthrough listeners,
// matched by SNI hostname intersection.
func (r *Engine) attachTLSRoutes(
	w *world,
	gw *gatewayv1.Gateway,
	sets []*listenerSetState,
	listeners []*listenerState,
) []*routeParentOutcome {
	var outcomes []*routeParentOutcome

	for i := range w.tlsRoutes {
		route := &w.tlsRoutes[i]

		for _, parentRef := range route.Spec.ParentRefs {
			ownerKey, ok := resolveRouteParent(parentRef, route.Namespace, gw, sets)
			if !ok {
				continue
			}

			outcome := r.attachTLSRoute(w, gw, listenersOwnedBy(listeners, ownerKey), route, parentRef)
			outcomes = append(outcomes, outcome)
		}
	}

	return outcomes
}

func (r *Engine) attachTLSRoute(
	w *world,
	gw *gatewayv1.Gateway,
	listeners []*listenerState,
	route *gatewayv1alpha2.TLSRoute,
	parentRef gatewayv1.ParentReference,
) *routeParentOutcome {
	outcome := &routeParentOutcome{
		tlsRoute:     route,
		parentRef:    parentRef,
		refsResolved: true,
		refsReason:   string(gatewayv1.RouteReasonResolvedRefs),
	}

	namespaceAdmitted, reason := admitListeners(
		listeners, parentRef, "TLSRoute", route.Namespace, gw.Namespace, w.namespaces)
	if reason != "" {
		outcome.acceptedReason = reason
		return outcome
	}

	var admitted []*listenerState
	for _, lst := range namespaceAdmitted {
		if hostnamesIntersect(lst.spec.Hostname, route.Spec.Hostnames) {
			admitted = append(admitted, lst)
		}
	}

	if len(admitted) == 0 {
		outcome.acceptedReason = string(gatewayv1.RouteReasonNoMatchingListenerHostname)
		return outcome
	}

	if len(route.Spec.Rules) != 1 {
		outcome.acceptedReason = string(gatewayv1.RouteReasonUnsupportedValue)
		return outcome
	}

	outcome.accepted = true
	outcome.acceptedReason = string(gatewayv1.RouteReasonAccepted)

	for _, lst := range admitted {
		lst.attachedRoutes++
	}

	config := &compiled.RouteConfig{
		UID:       string(route.UID),
		Namespace: route.Namespace,
		Name:      route.Name,
		Created:   route.CreationTimestamp.Unix(),
	}

	for _, lst := range admitted {
		if lst.valid() {
			config.Listeners = append(config.Listeners, lst.effectiveName())
		}
	}

	for _, hostname := range route.Spec.Hostnames {
		config.Hostnames = append(config.Hostnames, string(hostname))
	}

	rule := compiled.Rule{}
	for _, backendRef := range route.Spec.Rules[0].BackendRefs {
		rule.Backends = append(rule.Backends,
			r.compileBackend(w, route.Namespace, "TLSRoute", backendRef, outcome))
	}

	config.Rules = append(config.Rules, rule)
	outcome.config = config

	return outcome
}

// attachGRPCRoutes computes every (GRPCRoute, gateway) attachment outcome
// (docs/spec/traffic.md gRPC routing): GRPCRoutes attach to HTTP and HTTPS
// listeners alongside HTTPRoutes, with the same hostname semantics.
func (r *Engine) attachGRPCRoutes(
	w *world,
	gw *gatewayv1.Gateway,
	sets []*listenerSetState,
	listeners []*listenerState,
) []*routeParentOutcome {
	var outcomes []*routeParentOutcome

	for i := range w.grpcRoutes {
		route := &w.grpcRoutes[i]

		for _, parentRef := range route.Spec.ParentRefs {
			ownerKey, ok := resolveRouteParent(parentRef, route.Namespace, gw, sets)
			if !ok {
				continue
			}

			outcome := r.attachGRPCRoute(w, gw, listenersOwnedBy(listeners, ownerKey), route, parentRef)
			outcomes = append(outcomes, outcome)
		}
	}

	return outcomes
}

func (r *Engine) attachGRPCRoute(
	w *world,
	gw *gatewayv1.Gateway,
	listeners []*listenerState,
	route *gatewayv1.GRPCRoute,
	parentRef gatewayv1.ParentReference,
) *routeParentOutcome {
	outcome := &routeParentOutcome{
		grpcRoute:    route,
		parentRef:    parentRef,
		refsResolved: true,
		refsReason:   string(gatewayv1.RouteReasonResolvedRefs),
	}

	namespaceAdmitted, reason := admitListeners(
		listeners, parentRef, "GRPCRoute", route.Namespace, gw.Namespace, w.namespaces)
	if reason != "" {
		outcome.acceptedReason = reason
		return outcome
	}

	var admitted []*listenerState
	for _, lst := range namespaceAdmitted {
		if hostnamesIntersect(lst.spec.Hostname, route.Spec.Hostnames) {
			admitted = append(admitted, lst)
		}
	}

	if len(admitted) == 0 {
		outcome.acceptedReason = string(gatewayv1.RouteReasonNoMatchingListenerHostname)
		return outcome
	}

	config := &compiled.RouteConfig{
		UID:       string(route.UID),
		Namespace: route.Namespace,
		Name:      route.Name,
		Created:   route.CreationTimestamp.Unix(),
		GRPC:      true,
	}

	for _, hostname := range route.Spec.Hostnames {
		config.Hostnames = append(config.Hostnames, string(hostname))
	}

	for _, rule := range route.Spec.Rules {
		compiledRule, err := r.compileGRPCRule(w, route, rule, outcome)
		if err != nil {
			outcome.acceptedReason = string(gatewayv1.RouteReasonUnsupportedValue)
			return outcome
		}

		config.Rules = append(config.Rules, compiledRule)
	}

	outcome.accepted = true
	outcome.acceptedReason = string(gatewayv1.RouteReasonAccepted)

	for _, lst := range admitted {
		lst.attachedRoutes++

		if lst.valid() {
			config.Listeners = append(config.Listeners, lst.effectiveName())
		}
	}

	outcome.config = config

	return outcome
}

// compileGRPCRule translates one GRPCRoute rule into its canonical HTTP/2
// form (docs/spec/traffic.md gRPC routing): exact method matches become
// exact path matches on "/service/method".
func (r *Engine) compileGRPCRule(
	w *world,
	route *gatewayv1.GRPCRoute,
	rule gatewayv1.GRPCRouteRule,
	outcome *routeParentOutcome,
) (compiled.Rule, error) {
	compiledRule := compiled.Rule{}

	for _, match := range rule.Matches {
		entry := compiled.Match{}

		if match.Method != nil {
			if match.Method.Type != nil &&
				*match.Method.Type != gatewayv1.GRPCMethodMatchExact {
				return compiled.Rule{}, fmt.Errorf("unsupported method match type")
			}

			service := ""
			if match.Method.Service != nil {
				service = *match.Method.Service
			}

			method := ""
			if match.Method.Method != nil {
				method = *match.Method.Method
			}

			switch {
			case service != "" && method != "":
				entry.PathType = "Exact"
				entry.PathValue = "/" + service + "/" + method

			case service != "":
				entry.PathType = "PathPrefix"
				entry.PathValue = "/" + service

			default:
				// Method without service requires suffix matching, which
				// is not part of the Core profile.
				return compiled.Rule{}, fmt.Errorf("method match requires a service")
			}
		}

		for _, header := range match.Headers {
			if header.Type != nil && *header.Type != gatewayv1.GRPCHeaderMatchExact {
				return compiled.Rule{}, fmt.Errorf("unsupported header match type")
			}

			entry.Headers = append(entry.Headers, compiled.HeaderMatch{
				Name:  string(header.Name),
				Value: header.Value,
			})
		}

		compiledRule.Matches = append(compiledRule.Matches, entry)
	}

	for _, filter := range rule.Filters {
		entry, keep, err := r.compileGRPCFilter(w, route.Namespace, filter, outcome)
		if err != nil {
			// Unsupported filters MUST reject the route, never be silently
			// dropped (docs/spec/traffic.md).
			return compiled.Rule{}, err
		}

		if keep {
			compiledRule.Filters = append(compiledRule.Filters, entry)
		}
	}

	for _, backendRef := range rule.BackendRefs {
		compiledRule.Backends = append(compiledRule.Backends,
			r.compileBackend(w, route.Namespace, "GRPCRoute", backendRef.BackendRef, outcome))
	}

	return compiledRule, nil
}

// compileGRPCFilter translates one GRPCRoute filter: header modifiers and
// request mirroring behave as for HTTPRoute rules (docs/spec/traffic.md).
func (r *Engine) compileGRPCFilter(
	w *world,
	routeNamespace string,
	filter gatewayv1.GRPCRouteFilter,
	outcome *routeParentOutcome,
) (compiled.Filter, bool, error) {
	switch filter.Type {
	case gatewayv1.GRPCRouteFilterRequestHeaderModifier:
		if filter.RequestHeaderModifier == nil {
			return compiled.Filter{}, false, fmt.Errorf("missing requestHeaderModifier")
		}

		return compileHeaderModifier("RequestHeaderModifier", filter.RequestHeaderModifier), true, nil

	case gatewayv1.GRPCRouteFilterResponseHeaderModifier:
		if filter.ResponseHeaderModifier == nil {
			return compiled.Filter{}, false, fmt.Errorf("missing responseHeaderModifier")
		}

		return compileHeaderModifier("ResponseHeaderModifier", filter.ResponseHeaderModifier), true, nil

	case gatewayv1.GRPCRouteFilterRequestMirror:
		if filter.RequestMirror == nil {
			return compiled.Filter{}, false, fmt.Errorf("missing requestMirror")
		}

		return r.compileMirror(w, routeNamespace, "GRPCRoute", filter.RequestMirror, outcome)

	default:
		return compiled.Filter{}, false, fmt.Errorf("unsupported filter type %q", filter.Type)
	}
}

// compileRoute builds the (Gateway, Route) attachment payload, validating
// backend references and ReferenceGrants (docs/spec/traffic.md). It returns
// nil when the route uses filters this implementation does not support:
// such routes MUST be rejected, never partially applied (docs/spec/traffic.md).
func (r *Engine) compileRoute(
	w *world,
	gw *gatewayv1.Gateway,
	route *gatewayv1.HTTPRoute,
	admitted []*listenerState,
	outcome *routeParentOutcome,
) *compiled.RouteConfig {
	config := &compiled.RouteConfig{
		UID:       string(route.UID),
		Namespace: route.Namespace,
		Name:      route.Name,
		Created:   route.CreationTimestamp.Unix(),
	}

	for _, lst := range admitted {
		if lst.valid() {
			config.Listeners = append(config.Listeners, lst.effectiveName())
		}
	}

	for _, hostname := range route.Spec.Hostnames {
		config.Hostnames = append(config.Hostnames, string(hostname))
	}

	for _, rule := range route.Spec.Rules {
		compiledRule := compiled.Rule{}

		for _, match := range rule.Matches {
			entry := compiled.Match{}

			if match.Path != nil {
				if match.Path.Type != nil {
					entry.PathType = string(*match.Path.Type)
				}

				if match.Path.Value != nil {
					entry.PathValue = *match.Path.Value
				}
			}

			for _, header := range match.Headers {
				entry.Headers = append(entry.Headers, compiled.HeaderMatch{
					Name:  string(header.Name),
					Value: header.Value,
				})
			}

			compiledRule.Matches = append(compiledRule.Matches, entry)
		}

		for _, filter := range rule.Filters {
			entry, keep, err := r.compileHTTPFilter(w, route.Namespace, "HTTPRoute", rule, filter, outcome)
			if err != nil {
				return nil
			}

			if keep {
				compiledRule.Filters = append(compiledRule.Filters, entry)
			}
		}

		if err := compileTimeouts(&compiledRule, rule.Timeouts); err != nil {
			return nil
		}

		for _, backendRef := range rule.BackendRefs {
			compiledRule.Backends = append(compiledRule.Backends,
				r.compileBackend(w, route.Namespace, "HTTPRoute", backendRef.BackendRef, outcome))
		}

		config.Rules = append(config.Rules, compiledRule)
	}

	return config
}

// compileHTTPFilter translates one HTTPRoute filter (docs/spec/traffic.md).
// Unsupported filter types or values yield an error so the whole route is
// rejected with UnsupportedValue instead of silently dropping the filter.
// A mirror whose backend does not resolve is dropped (keep=false) after
// degrading the ResolvedRefs condition, per the Gateway API.
func (r *Engine) compileHTTPFilter(
	w *world,
	routeNamespace, routeKind string,
	rule gatewayv1.HTTPRouteRule,
	filter gatewayv1.HTTPRouteFilter,
	outcome *routeParentOutcome,
) (compiled.Filter, bool, error) {
	switch filter.Type {
	case gatewayv1.HTTPRouteFilterRequestHeaderModifier:
		if filter.RequestHeaderModifier == nil {
			return compiled.Filter{}, false, fmt.Errorf("missing requestHeaderModifier")
		}

		return compileHeaderModifier("RequestHeaderModifier", filter.RequestHeaderModifier), true, nil

	case gatewayv1.HTTPRouteFilterResponseHeaderModifier:
		if filter.ResponseHeaderModifier == nil {
			return compiled.Filter{}, false, fmt.Errorf("missing responseHeaderModifier")
		}

		return compileHeaderModifier("ResponseHeaderModifier", filter.ResponseHeaderModifier), true, nil

	case gatewayv1.HTTPRouteFilterRequestRedirect:
		redirect := filter.RequestRedirect
		if redirect == nil {
			return compiled.Filter{}, false, fmt.Errorf("missing requestRedirect")
		}

		entry := compiled.Filter{Type: "RequestRedirect", StatusCode: 302}

		if redirect.Scheme != nil {
			entry.Scheme = *redirect.Scheme
		}

		if redirect.Hostname != nil {
			entry.Hostname = string(*redirect.Hostname)
		}

		if redirect.Port != nil {
			entry.Port = int32(*redirect.Port)
		}

		if redirect.StatusCode != nil {
			entry.StatusCode = *redirect.StatusCode
		}

		if redirect.Path != nil {
			if err := compilePathModifier(&entry, redirect.Path, rule.Matches); err != nil {
				return compiled.Filter{}, false, err
			}
		}

		return entry, true, nil

	case gatewayv1.HTTPRouteFilterURLRewrite:
		rewrite := filter.URLRewrite
		if rewrite == nil {
			return compiled.Filter{}, false, fmt.Errorf("missing urlRewrite")
		}

		entry := compiled.Filter{Type: "URLRewrite"}

		if rewrite.Hostname != nil {
			entry.Hostname = string(*rewrite.Hostname)
		}

		if rewrite.Path != nil {
			if err := compilePathModifier(&entry, rewrite.Path, rule.Matches); err != nil {
				return compiled.Filter{}, false, err
			}
		}

		return entry, true, nil

	case gatewayv1.HTTPRouteFilterRequestMirror:
		if filter.RequestMirror == nil {
			return compiled.Filter{}, false, fmt.Errorf("missing requestMirror")
		}

		return r.compileMirror(w, routeNamespace, routeKind, filter.RequestMirror, outcome)

	default:
		return compiled.Filter{}, false, fmt.Errorf("unsupported filter type %q", filter.Type)
	}
}

// compilePathModifier compiles the path replacement shared by
// RequestRedirect and URLRewrite (docs/spec/traffic.md). ReplacePrefixMatch
// captures the rule's single PathPrefix match, guaranteed by API
// validation, so the data plane needs no match context.
func compilePathModifier(
	entry *compiled.Filter,
	modifier *gatewayv1.HTTPPathModifier,
	matches []gatewayv1.HTTPRouteMatch,
) error {
	switch modifier.Type {
	case gatewayv1.FullPathHTTPPathModifier:
		if modifier.ReplaceFullPath == nil {
			return fmt.Errorf("missing replaceFullPath")
		}

		entry.PathRewriteType = "ReplaceFullPath"
		entry.PathRewriteValue = *modifier.ReplaceFullPath

	case gatewayv1.PrefixMatchHTTPPathModifier:
		if modifier.ReplacePrefixMatch == nil {
			return fmt.Errorf("missing replacePrefixMatch")
		}

		entry.PathRewriteType = "ReplacePrefixMatch"
		entry.PathRewriteValue = *modifier.ReplacePrefixMatch
		entry.PathPrefix = rulePathPrefix(matches)

	default:
		return fmt.Errorf("unsupported path modifier %q", modifier.Type)
	}

	return nil
}

// rulePathPrefix returns the rule's PathPrefix match value; the API
// guarantees exactly one PathPrefix match when ReplacePrefixMatch is used.
func rulePathPrefix(matches []gatewayv1.HTTPRouteMatch) string {
	for _, match := range matches {
		if match.Path == nil || match.Path.Value == nil {
			continue
		}

		if match.Path.Type == nil || *match.Path.Type == gatewayv1.PathMatchPathPrefix {
			return *match.Path.Value
		}
	}

	return "/"
}

// compileTimeouts parses rules[].timeouts (docs/spec/traffic.md): a zero
// duration disables the timeout, and backendRequest may not exceed the
// effective request timeout.
func compileTimeouts(rule *compiled.Rule, timeouts *gatewayv1.HTTPRouteTimeouts) error {
	if timeouts == nil {
		return nil
	}

	if timeouts.Request != nil {
		request, err := time.ParseDuration(string(*timeouts.Request))
		if err != nil || request < 0 {
			return fmt.Errorf("invalid request timeout")
		}

		rule.RequestTimeoutMillis = request.Milliseconds()
	}

	if timeouts.BackendRequest != nil {
		backend, err := time.ParseDuration(string(*timeouts.BackendRequest))
		if err != nil || backend < 0 {
			return fmt.Errorf("invalid backendRequest timeout")
		}

		if rule.RequestTimeoutMillis > 0 &&
			backend.Milliseconds() > rule.RequestTimeoutMillis {
			return fmt.Errorf("backendRequest timeout exceeds request timeout")
		}

		rule.BackendTimeoutMillis = backend.Milliseconds()
	}

	return nil
}

// compileMirror resolves a RequestMirror target (docs/spec/traffic.md).
func (r *Engine) compileMirror(
	w *world,
	routeNamespace, routeKind string,
	mirror *gatewayv1.HTTPRequestMirrorFilter,
	outcome *routeParentOutcome,
) (compiled.Filter, bool, error) {
	backend := r.compileBackend(w, routeNamespace, routeKind,
		gatewayv1.BackendRef{BackendObjectReference: mirror.BackendRef}, outcome)
	if !backend.Valid {
		// Unresolvable mirrors degrade ResolvedRefs (done by
		// compileBackend) and are dropped, per the Gateway API.
		return compiled.Filter{}, false, nil
	}

	entry := compiled.Filter{Type: "RequestMirror", Mirror: &backend}

	if mirror.Percent != nil {
		percent := float64(*mirror.Percent)
		entry.MirrorPercent = &percent
	}

	if mirror.Fraction != nil {
		denominator := int32(100)
		if mirror.Fraction.Denominator != nil {
			denominator = *mirror.Fraction.Denominator
		}

		if denominator <= 0 {
			return compiled.Filter{}, false, fmt.Errorf("invalid mirror fraction denominator")
		}

		percent := float64(mirror.Fraction.Numerator) / float64(denominator) * 100
		entry.MirrorPercent = &percent
	}

	return entry, true, nil
}

func compileHeaderModifier(filterType string, modifier *gatewayv1.HTTPHeaderFilter) compiled.Filter {
	entry := compiled.Filter{
		Type:       filterType,
		SetHeaders: map[string]string{},
		AddHeaders: map[string]string{},
	}

	for _, header := range modifier.Set {
		entry.SetHeaders[string(header.Name)] = header.Value
	}

	for _, header := range modifier.Add {
		entry.AddHeaders[string(header.Name)] = header.Value
	}

	entry.RemoveHeaders = modifier.Remove

	return entry
}

func (r *Engine) compileBackend(
	w *world,
	routeNamespace string,
	routeKind string,
	ref gatewayv1.BackendRef,
	outcome *routeParentOutcome,
) compiled.Backend {
	backend := compiled.Backend{
		Name:   string(ref.Name),
		Weight: 1,
		Valid:  true,
	}

	if ref.Weight != nil {
		backend.Weight = *ref.Weight
	}

	backend.Namespace = routeNamespace
	if ref.Namespace != nil {
		backend.Namespace = string(*ref.Namespace)
	}

	if ref.Port != nil {
		backend.Port = int32(*ref.Port)
	}

	invalidate := func(reason, message string) {
		backend.Valid = false
		backend.InvalidReason = reason

		// First failure wins for the parent's ResolvedRefs condition.
		if outcome.refsResolved {
			outcome.refsResolved = false
			outcome.refsReason = reason
			outcome.refsMessage = message
		}
	}

	if (ref.Kind != nil && *ref.Kind != "Service") ||
		(ref.Group != nil && *ref.Group != "") {
		invalidate(string(gatewayv1.RouteReasonInvalidKind),
			"backendRefs must reference core Services")

		return backend
	}

	if backend.Port == 0 {
		invalidate(string(gatewayv1.RouteReasonUnsupportedValue),
			"backendRefs to Services require a port")

		return backend
	}

	// Cross-namespace backends require a ReferenceGrant (docs/spec/traffic.md).
	if backend.Namespace != routeNamespace {
		allowed := referenceGrantAllows(
			w.grants,
			gatewayv1.GroupName, routeKind, routeNamespace,
			"Service", backend.Namespace, backend.Name,
		)
		if !allowed {
			invalidate(string(gatewayv1.RouteReasonRefNotPermitted), fmt.Sprintf(
				"reference to Service %s/%s not permitted by any ReferenceGrant",
				backend.Namespace, backend.Name,
			))

			return backend
		}
	}

	if _, ok := w.services[backend.Namespace+"/"+backend.Name]; !ok {
		invalidate(string(gatewayv1.RouteReasonBackendNotFound), fmt.Sprintf(
			"Service %s/%s not found", backend.Namespace, backend.Name,
		))

		return backend
	}

	// BackendTLSPolicy (docs/spec/traffic.md Backend TLS): connections to
	// this backend are upgraded to verified TLS; rejected policies fail
	// closed.
	backend.TLS = backendTLSFor(w, backend.Namespace, backend.Name,
		servicePortName(w, backend.Namespace, backend.Name, backend.Port))

	return backend
}

// servicePortName resolves the name of the Service port a backend
// references, for BackendTLSPolicy sectionName matching.
func servicePortName(w *world, namespace, name string, port int32) string {
	svc, ok := w.services[namespace+"/"+name]
	if !ok {
		return ""
	}

	for _, svcPort := range svc.Spec.Ports {
		if svcPort.Port == port {
			return svcPort.Name
		}
	}

	return ""
}

// --------------------------------------------------------------- helpers --

func referenceGrantAllows(
	grants []gatewayv1beta1.ReferenceGrant,
	fromGroup, fromKind, fromNamespace string,
	toKind, toNamespace, toName string,
) bool {
	for i := range grants {
		grant := &grants[i]
		if grant.Namespace != toNamespace {
			continue
		}

		fromOK := false
		for _, from := range grant.Spec.From {
			if string(from.Group) == fromGroup &&
				string(from.Kind) == fromKind &&
				string(from.Namespace) == fromNamespace {
				fromOK = true
				break
			}
		}
		if !fromOK {
			continue
		}

		for _, to := range grant.Spec.To {
			if string(to.Group) != "" || string(to.Kind) != toKind {
				continue
			}

			if to.Name != nil && string(*to.Name) != toName {
				continue
			}

			return true
		}
	}

	return false
}

func namespaceAllowed(
	allowed *gatewayv1.AllowedRoutes,
	routeNamespace, gatewayNamespace string,
	namespaces map[string]map[string]string,
) bool {
	from := gatewayv1.NamespacesFromSame
	var selector *metav1.LabelSelector

	if allowed != nil && allowed.Namespaces != nil {
		if allowed.Namespaces.From != nil {
			from = *allowed.Namespaces.From
		}

		selector = allowed.Namespaces.Selector
	}

	switch from {
	case gatewayv1.NamespacesFromAll:
		return true

	case gatewayv1.NamespacesFromSame:
		return routeNamespace == gatewayNamespace

	case gatewayv1.NamespacesFromSelector:
		if selector == nil {
			return false
		}

		parsed, err := metav1.LabelSelectorAsSelector(selector)
		if err != nil {
			return false
		}

		return parsed.Matches(labelsSet(namespaces[routeNamespace]))

	default:
		return false
	}
}

func hostnamesIntersect(listenerHostname *gatewayv1.Hostname, routeHostnames []gatewayv1.Hostname) bool {
	if listenerHostname == nil || *listenerHostname == "" || len(routeHostnames) == 0 {
		return true
	}

	pattern := string(*listenerHostname)

	for _, hostname := range routeHostnames {
		host := string(hostname)

		if wildcardMatches(pattern, host) || wildcardMatches(host, pattern) {
			return true
		}
	}

	return false
}

func wildcardMatches(pattern, host string) bool {
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:]

		return len(host) > len(suffix) && strings.HasSuffix(host, suffix)
	}

	return strings.EqualFold(pattern, host)
}
