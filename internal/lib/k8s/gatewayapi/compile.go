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
			// ListenerEntry and Listener are field-for-field identical in
			// v1.6.1; the conversion breaks loudly if they ever diverge.
			spec := gatewayv1.Listener(entry)

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
		// Passthrough or Terminate (docs/spec/traffic.md TLS passthrough
		// and termination); other mode values are unsupported.
		if spec.TLS == nil || spec.TLS.Mode == nil ||
			(*spec.TLS.Mode != gatewayv1.TLSModePassthrough &&
				*spec.TLS.Mode != gatewayv1.TLSModeTerminate) {
			state.accepted = false
			state.acceptedReason = string(gatewayv1.ListenerReasonUnsupportedValue)
		}

	default:
		state.accepted = false
		state.acceptedReason = string(gatewayv1.ListenerReasonUnsupportedProtocol)
	}

	resolveRouteKinds(state)

	if state.refsResolved &&
		(spec.Protocol == gatewayv1.HTTPSProtocolType || listenerTerminatesTLS(spec)) {
		r.resolveCertificates(ctx, w, gw, state)
	}

	if spec.Protocol == gatewayv1.HTTPSProtocolType && state.refsResolved {
		r.resolveFrontendValidation(ctx, w, gw, state)
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

// listenerTerminatesTLS reports a TLS-protocol listener in Terminate mode
// (docs/spec/traffic.md TLS passthrough and termination).
func listenerTerminatesTLS(spec gatewayv1.Listener) bool {
	return spec.Protocol == gatewayv1.TLSProtocolType &&
		spec.TLS != nil && spec.TLS.Mode != nil &&
		*spec.TLS.Mode == gatewayv1.TLSModeTerminate
}

// frontendValidationFor selects the client-certificate validation applying
// to a listener port: the per-port entry, or the gateway default
// (docs/spec/security.md Frontend client certificate validation).
func frontendValidationFor(gw *gatewayv1.Gateway, port gatewayv1.PortNumber) *gatewayv1.FrontendTLSValidation {
	if gw.Spec.TLS == nil || gw.Spec.TLS.Frontend == nil {
		return nil
	}

	for i := range gw.Spec.TLS.Frontend.PerPort {
		entry := &gw.Spec.TLS.Frontend.PerPort[i]
		if entry.Port == port && entry.TLS.Validation != nil {
			return entry.TLS.Validation
		}
	}

	return gw.Spec.TLS.Frontend.Default.Validation
}

// resolveFrontendValidation resolves the client-certificate CAs of one
// HTTPS listener (docs/spec/security.md Frontend client certificate
// validation). Invalid references reject the listener with
// NoValidCACertificate.
func (r *Engine) resolveFrontendValidation(
	ctx context.Context,
	w *world,
	gw *gatewayv1.Gateway,
	state *listenerState,
) {
	validation := frontendValidationFor(gw, state.spec.Port)
	if validation == nil {
		return
	}

	invalidate := func(refsReason string) {
		state.refsResolved = false
		state.refsReason = refsReason
		state.accepted = false
		state.acceptedReason = string(gatewayv1.ListenerReasonNoValidCACertificate)
	}

	var pemBundle []byte

	for _, ref := range validation.CACertificateRefs {
		if string(ref.Kind) != "ConfigMap" || string(ref.Group) != "" {
			invalidate(string(gatewayv1.ListenerReasonInvalidCACertificateKind))
			return
		}

		namespace := gw.Namespace
		if ref.Namespace != nil {
			namespace = string(*ref.Namespace)
		}

		if namespace != gw.Namespace {
			allowed := referenceGrantAllows(
				w.grants,
				gatewayv1.GroupName, "Gateway", gw.Namespace,
				"ConfigMap", namespace, string(ref.Name),
			)
			if !allowed {
				invalidate(string(gatewayv1.ListenerReasonRefNotPermitted))
				return
			}
		}

		cm, err := r.client.CoreV1().ConfigMaps(namespace).
			Get(ctx, string(ref.Name), metav1.GetOptions{})
		if err != nil {
			invalidate(string(gatewayv1.ListenerReasonInvalidCACertificateRef))
			return
		}

		pemBundle = append(pemBundle, []byte(cm.Data["ca.crt"])...)
		pemBundle = append(pemBundle, '\n')
	}

	if !validCAPem(pemBundle) {
		invalidate(string(gatewayv1.ListenerReasonInvalidCACertificateRef))
		return
	}

	mode := gatewayv1.AllowValidOnly
	if validation.Mode != "" {
		mode = validation.Mode
	}

	state.clientCAMode = string(mode)
	state.certData[state.effectiveName()+".client-ca.crt"] = pemBundle
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

// attachAll computes every (route, gateway) attachment outcome for one
// route kind (docs/spec/status.md): each parentRef resolving onto this
// Gateway or one of its ListenerSets yields one outcome, attached against
// the owner's listeners only (docs/spec/frontend.md Listener sets).
func attachAll[R any, PR interface {
	*R
	GetNamespace() string
}](
	w *world,
	gw *gatewayv1.Gateway,
	sets []*listenerSetState,
	listeners []*listenerState,
	routes []R,
	parentRefs func(PR) []gatewayv1.ParentReference,
	attach func(*world, *gatewayv1.Gateway, []*listenerState, PR, gatewayv1.ParentReference) *routeParentOutcome,
) []*routeParentOutcome {
	var outcomes []*routeParentOutcome

	for i := range routes {
		route := PR(&routes[i])

		for _, parentRef := range parentRefs(route) {
			ownerKey, ok := resolveRouteParent(parentRef, route.GetNamespace(), gw, sets)
			if !ok {
				continue
			}

			outcome := attach(w, gw, listenersOwnedBy(listeners, ownerKey), route, parentRef)
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
				return nsName(namespace, ref.Name), true
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

// admitByHostname narrows admitted listeners to those whose hostname
// intersects the route's (docs/spec/traffic.md).
func admitByHostname(listeners []*listenerState, hostnames []gatewayv1.Hostname) []*listenerState {
	var admitted []*listenerState
	for _, lst := range listeners {
		if hostnamesIntersect(lst.spec.Hostname, hostnames) {
			admitted = append(admitted, lst)
		}
	}

	return admitted
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

	admitted := admitByHostname(namespaceAdmitted, route.Spec.Hostnames)
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

// attachL4Route finishes a TCPRoute, UDPRoute or TLSRoute attachment
// after kind-specific admission (docs/spec/traffic.md): rules carry no
// matching semantics on L4 routes, so a route declaring more than one
// rule is ambiguous and rejected with UnsupportedValue, never partially
// applied.
func (r *Engine) attachL4Route(
	w *world,
	admitted []*listenerState,
	kind string,
	meta metav1.ObjectMeta,
	hostnames []gatewayv1.Hostname,
	rules [][]gatewayv1.BackendRef,
	outcome *routeParentOutcome,
) *routeParentOutcome {
	if len(rules) != 1 {
		outcome.acceptedReason = string(gatewayv1.RouteReasonUnsupportedValue)
		return outcome
	}

	outcome.accepted = true
	outcome.acceptedReason = string(gatewayv1.RouteReasonAccepted)

	for _, lst := range admitted {
		lst.attachedRoutes++
	}

	config := &compiled.RouteConfig{
		UID:       string(meta.UID),
		Namespace: meta.Namespace,
		Name:      meta.Name,
		Created:   meta.CreationTimestamp.Unix(),
	}

	for _, lst := range admitted {
		if lst.valid() {
			config.Listeners = append(config.Listeners, lst.effectiveName())
		}
	}

	for _, hostname := range hostnames {
		config.Hostnames = append(config.Hostnames, string(hostname))
	}

	rule := compiled.Rule{}
	for _, backendRef := range rules[0] {
		rule.Backends = append(rule.Backends,
			r.compileBackend(w, meta.Namespace, kind, backendRef, outcome))
	}

	config.Rules = append(config.Rules, rule)
	outcome.config = config

	return outcome
}

// attachTCPRoute computes one (TCPRoute, gateway) attachment outcome
// (docs/spec/traffic.md): TCPRoutes attach to TCP listeners only and
// carry no hostname, path or filter semantics.
func (r *Engine) attachTCPRoute(
	w *world,
	gw *gatewayv1.Gateway,
	listeners []*listenerState,
	route *gatewayv1.TCPRoute,
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

	rules := make([][]gatewayv1.BackendRef, 0, len(route.Spec.Rules))
	for _, rule := range route.Spec.Rules {
		rules = append(rules, rule.BackendRefs)
	}

	return r.attachL4Route(w, admitted, "TCPRoute", route.ObjectMeta, nil, rules, outcome)
}

// attachUDPRoutes computes every (UDPRoute, gateway) attachment outcome
// (docs/spec/traffic.md): UDPRoutes attach to UDP listeners only and carry
// no hostname, path or filter semantics.
// attachUDPRoute computes one (UDPRoute, gateway) attachment outcome
// (docs/spec/traffic.md): UDPRoutes attach to UDP listeners only and
// carry no hostname, path or filter semantics.
func (r *Engine) attachUDPRoute(
	w *world,
	gw *gatewayv1.Gateway,
	listeners []*listenerState,
	route *gatewayv1.UDPRoute,
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

	rules := make([][]gatewayv1.BackendRef, 0, len(route.Spec.Rules))
	for _, rule := range route.Spec.Rules {
		rules = append(rules, rule.BackendRefs)
	}

	return r.attachL4Route(w, admitted, "UDPRoute", route.ObjectMeta, nil, rules, outcome)
}

// attachTLSRoute computes one (TLSRoute, gateway) attachment outcome
// (docs/spec/traffic.md): TLSRoutes attach to TLS passthrough listeners,
// matched by SNI hostname intersection.
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

	admitted := admitByHostname(namespaceAdmitted, route.Spec.Hostnames)
	if len(admitted) == 0 {
		outcome.acceptedReason = string(gatewayv1.RouteReasonNoMatchingListenerHostname)
		return outcome
	}

	rules := make([][]gatewayv1.BackendRef, 0, len(route.Spec.Rules))
	for _, rule := range route.Spec.Rules {
		rules = append(rules, rule.BackendRefs)
	}

	return r.attachL4Route(
		w, admitted, "TLSRoute", route.ObjectMeta, route.Spec.Hostnames, rules, outcome)
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

	admitted := admitByHostname(namespaceAdmitted, route.Spec.Hostnames)
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

	var extensionRefs []gatewayv1.LocalObjectReference

	for _, filter := range rule.Filters {
		if filter.Type == gatewayv1.GRPCRouteFilterExtensionRef {
			if filter.ExtensionRef == nil {
				return compiled.Rule{}, fmt.Errorf("missing extensionRef")
			}

			extensionRefs = append(extensionRefs, *filter.ExtensionRef)
			continue
		}

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

	ext, err := r.compileExtensions(w, route.Namespace, extensionRefs, outcome)
	if err != nil {
		return compiled.Rule{}, err
	}

	compiledRule.RateLimit = ext.rateLimit
	compiledRule.WAF = ext.waf
	compiledRule.ExtensionsInvalid = ext.invalid

	for _, backendRef := range rule.BackendRefs {
		backend := r.compileBackend(w, route.Namespace, "GRPCRoute", backendRef.BackendRef, outcome)

		for _, filter := range backendRef.Filters {
			entry, err := compileBackendHeaderFilter(
				string(filter.Type),
				filter.RequestHeaderModifier,
				filter.ResponseHeaderModifier,
			)
			if err != nil {
				return compiled.Rule{}, err
			}

			backend.Filters = append(backend.Filters, entry)
		}

		compiledRule.Backends = append(compiledRule.Backends, backend)
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

		return compileHeaderModifier(compiled.FilterRequestHeaderModifier, filter.RequestHeaderModifier), true, nil

	case gatewayv1.GRPCRouteFilterResponseHeaderModifier:
		if filter.ResponseHeaderModifier == nil {
			return compiled.Filter{}, false, fmt.Errorf("missing responseHeaderModifier")
		}

		return compileHeaderModifier(compiled.FilterResponseHeaderModifier, filter.ResponseHeaderModifier), true, nil

	case gatewayv1.GRPCRouteFilterRequestMirror:
		if filter.RequestMirror == nil {
			return compiled.Filter{}, false, fmt.Errorf("missing requestMirror")
		}

		return r.compileMirror(w, routeNamespace, "GRPCRoute", filter.RequestMirror, outcome)

	default:
		return compiled.Filter{}, false, fmt.Errorf("unsupported filter type %q", filter.Type)
	}
}

// compileHTTPMatch validates one HTTPRoute match (docs/spec/traffic.md
// Routing and filters): Exact and PathPrefix paths, methods, Exact headers
// and Exact query parameters. Any other match type rejects the route with
// UnsupportedValue, never a silently widened match.
func compileHTTPMatch(match gatewayv1.HTTPRouteMatch) (compiled.Match, error) {
	entry := compiled.Match{}

	if match.Path != nil {
		if match.Path.Type != nil {
			entry.PathType = string(*match.Path.Type)
		}

		if match.Path.Value != nil {
			entry.PathValue = *match.Path.Value
		}

		if match.Path.Type != nil &&
			*match.Path.Type != gatewayv1.PathMatchExact &&
			*match.Path.Type != gatewayv1.PathMatchPathPrefix {
			return entry, fmt.Errorf("unsupported path match type %q", *match.Path.Type)
		}
	}

	if match.Method != nil {
		entry.Method = string(*match.Method)
	}

	for _, header := range match.Headers {
		if header.Type != nil && *header.Type != gatewayv1.HeaderMatchExact {
			return entry, fmt.Errorf("unsupported header match type %q", *header.Type)
		}

		entry.Headers = append(entry.Headers, compiled.HeaderMatch{
			Name:  string(header.Name),
			Value: header.Value,
		})
	}

	for _, param := range match.QueryParams {
		if param.Type != nil && *param.Type != gatewayv1.QueryParamMatchExact {
			return entry, fmt.Errorf("unsupported query parameter match type %q", *param.Type)
		}

		entry.QueryParams = append(entry.QueryParams, compiled.QueryParamMatch{
			Name:  string(param.Name),
			Value: param.Value,
		})
	}

	return entry, nil
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
			entry, err := compileHTTPMatch(match)
			if err != nil {
				return nil
			}

			compiledRule.Matches = append(compiledRule.Matches, entry)
		}

		var extensionRefs []gatewayv1.LocalObjectReference

		for _, filter := range rule.Filters {
			if filter.Type == gatewayv1.HTTPRouteFilterExtensionRef {
				if filter.ExtensionRef == nil {
					return nil
				}

				extensionRefs = append(extensionRefs, *filter.ExtensionRef)
				continue
			}

			entry, keep, err := r.compileHTTPFilter(w, route.Namespace, "HTTPRoute", rule, filter, outcome)
			if err != nil {
				return nil
			}

			if keep {
				compiledRule.Filters = append(compiledRule.Filters, entry)
			}
		}

		ext, err := r.compileExtensions(w, route.Namespace, extensionRefs, outcome)
		if err != nil {
			return nil
		}

		compiledRule.RateLimit = ext.rateLimit
		compiledRule.WAF = ext.waf
		compiledRule.ExtensionsInvalid = ext.invalid

		if err := compileTimeouts(&compiledRule, rule.Timeouts); err != nil {
			return nil
		}

		for _, backendRef := range rule.BackendRefs {
			backend := r.compileBackend(w, route.Namespace, "HTTPRoute", backendRef.BackendRef, outcome)

			for _, filter := range backendRef.Filters {
				entry, err := compileBackendHeaderFilter(
					string(filter.Type),
					filter.RequestHeaderModifier,
					filter.ResponseHeaderModifier,
				)
				if err != nil {
					return nil
				}

				backend.Filters = append(backend.Filters, entry)
			}

			compiledRule.Backends = append(compiledRule.Backends, backend)
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

		return compileHeaderModifier(compiled.FilterRequestHeaderModifier, filter.RequestHeaderModifier), true, nil

	case gatewayv1.HTTPRouteFilterResponseHeaderModifier:
		if filter.ResponseHeaderModifier == nil {
			return compiled.Filter{}, false, fmt.Errorf("missing responseHeaderModifier")
		}

		return compileHeaderModifier(compiled.FilterResponseHeaderModifier, filter.ResponseHeaderModifier), true, nil

	case gatewayv1.HTTPRouteFilterCORS:
		if filter.CORS == nil {
			return compiled.Filter{}, false, fmt.Errorf("missing cors")
		}

		return compileCORS(filter.CORS), true, nil

	case gatewayv1.HTTPRouteFilterRequestRedirect:
		redirect := filter.RequestRedirect
		if redirect == nil {
			return compiled.Filter{}, false, fmt.Errorf("missing requestRedirect")
		}

		entry := compiled.Filter{Type: compiled.FilterRequestRedirect, StatusCode: 302}

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

		entry := compiled.Filter{Type: compiled.FilterURLRewrite}

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

	entry := compiled.Filter{Type: compiled.FilterRequestMirror, Mirror: &backend}

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

// compileCORS translates the CORS filter configuration
// (docs/spec/traffic.md Routing and filters). maxAge defaults to 5 seconds
// per the Gateway API.
func compileCORS(cors *gatewayv1.HTTPCORSFilter) compiled.Filter {
	entry := compiled.CORS{MaxAgeSeconds: 5}

	if cors.MaxAge > 0 {
		entry.MaxAgeSeconds = cors.MaxAge
	}

	if cors.AllowCredentials != nil {
		entry.AllowCredentials = *cors.AllowCredentials
	}

	for _, origin := range cors.AllowOrigins {
		entry.AllowOrigins = append(entry.AllowOrigins, string(origin))
	}

	for _, method := range cors.AllowMethods {
		entry.AllowMethods = append(entry.AllowMethods, string(method))
	}

	for _, header := range cors.AllowHeaders {
		entry.AllowHeaders = append(entry.AllowHeaders, string(header))
	}

	for _, header := range cors.ExposeHeaders {
		entry.ExposeHeaders = append(entry.ExposeHeaders, string(header))
	}

	return compiled.Filter{Type: compiled.FilterCORS, CORS: &entry}
}

// compileBackendHeaderFilter translates one per-backendRef filter
// (docs/spec/traffic.md Routing and filters): header modifiers only; any
// other type rejects the route with UnsupportedValue.
func compileBackendHeaderFilter(
	filterType string,
	requestModifier, responseModifier *gatewayv1.HTTPHeaderFilter,
) (compiled.Filter, error) {
	switch filterType {
	case compiled.FilterRequestHeaderModifier:
		if requestModifier == nil {
			return compiled.Filter{}, fmt.Errorf("missing requestHeaderModifier")
		}

		return compileHeaderModifier(compiled.FilterRequestHeaderModifier, requestModifier), nil

	case compiled.FilterResponseHeaderModifier:
		if responseModifier == nil {
			return compiled.Filter{}, fmt.Errorf("missing responseHeaderModifier")
		}

		return compileHeaderModifier(compiled.FilterResponseHeaderModifier, responseModifier), nil

	default:
		return compiled.Filter{}, fmt.Errorf("unsupported backendRef filter type %q", filterType)
	}
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

	if _, ok := w.services[nsName(backend.Namespace, backend.Name)]; !ok {
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

	// Backend protocol selection (docs/spec/traffic.md Protocol handling).
	backend.AppProtocol = servicePortAppProtocol(
		w, backend.Namespace, backend.Name, backend.Port)

	return backend
}

// servicePortName resolves the name of the Service port a backend
// references, for BackendTLSPolicy sectionName matching.
func servicePortName(w *world, namespace, name string, port int32) string {
	svc, ok := w.services[nsName(namespace, name)]
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

// servicePortAppProtocol resolves the appProtocol of the Service port a
// backend references (docs/spec/traffic.md Protocol handling).
func servicePortAppProtocol(w *world, namespace, name string, port int32) string {
	svc, ok := w.services[nsName(namespace, name)]
	if !ok {
		return ""
	}

	for _, svcPort := range svc.Spec.Ports {
		if svcPort.Port == port && svcPort.AppProtocol != nil {
			return *svcPort.AppProtocol
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
