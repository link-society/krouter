package gatewayapi

import (
	"context"
	"fmt"

	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	"github.com/link-society/krouter/internal/lib/k8s/compiled"
)

// ------------------------------------------------------------ listeners --

func (r *Engine) validateListeners(
	ctx context.Context,
	w *world,
	gw *gatewayv1.Gateway,
	allocator *portAllocator,
) []*listenerState {
	listeners := make([]*listenerState, 0, len(gw.Spec.Listeners))
	tcpPorts := map[gatewayv1.PortNumber]bool{}

	for _, spec := range gw.Spec.Listeners {
		state := &listenerState{
			spec:           spec,
			accepted:       true,
			acceptedReason: string(gatewayv1.ListenerReasonAccepted),
			refsResolved:   true,
			refsReason:     string(gatewayv1.ListenerReasonResolvedRefs),
			certData:       map[string][]byte{},
		}

		switch spec.Protocol {
		case gatewayv1.HTTPProtocolType, gatewayv1.HTTPSProtocolType:

		case gatewayv1.TLSProtocolType:
			// Passthrough only (docs/spec/overview.md): krouter routes on the
			// SNI value and never holds the certificate. Terminate is a
			// valid protocol with an unsupported mode value.
			if spec.TLS == nil || spec.TLS.Mode == nil ||
				*spec.TLS.Mode != gatewayv1.TLSModePassthrough {
				state.accepted = false
				state.acceptedReason = string(gatewayv1.ListenerReasonUnsupportedValue)
			}

		case gatewayv1.TCPProtocolType:
			// TCP listeners carry no hostname, so a Gateway MUST NOT declare
			// more than one TCP listener per external port (docs/spec/frontend.md).
			if tcpPorts[spec.Port] {
				state.accepted = false
				state.acceptedReason = string(gatewayv1.ListenerReasonProtocolConflict)
			}
			tcpPorts[spec.Port] = true

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

		listeners = append(listeners, state)
	}

	return listeners
}

// protocolRouteKinds returns the route kinds a listener protocol can serve
// (docs/spec/frontend.md).
func protocolRouteKinds(protocol gatewayv1.ProtocolType) []string {
	switch protocol {
	case gatewayv1.HTTPProtocolType, gatewayv1.HTTPSProtocolType:
		return []string{"HTTPRoute", "GRPCRoute"}

	case gatewayv1.TCPProtocolType:
		return []string{"TCPRoute"}

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
// applicable ReferenceGrants (docs/spec/security.md).
func (r *Engine) resolveCertificates(
	ctx context.Context,
	w *world,
	gw *gatewayv1.Gateway,
	state *listenerState,
) {
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

		namespace := gw.Namespace
		if ref.Namespace != nil {
			namespace = string(*ref.Namespace)
		}

		if namespace != gw.Namespace {
			allowed := referenceGrantAllows(
				w.grants,
				gatewayv1.GroupName, "Gateway", gw.Namespace,
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

		// Only referenced material is copied into the generated Secret
		// (docs/spec/security.md); the data plane never reads source Secrets.
		state.certData[string(state.spec.Name)+".tls.crt"] = cert
		state.certData[string(state.spec.Name)+".tls.key"] = key
	}
}

// ---------------------------------------------------------------- routes --

// attachRoutes computes every (route, gateway) attachment outcome and
// increments per-listener attachedRoutes counts (docs/spec/status.md).
func (r *Engine) attachRoutes(
	w *world,
	gw *gatewayv1.Gateway,
	listeners []*listenerState,
) []*routeParentOutcome {
	var outcomes []*routeParentOutcome

	for i := range w.routes {
		route := &w.routes[i]

		for _, parentRef := range route.Spec.ParentRefs {
			if !parentRefMatches(parentRef, route.Namespace, gw) {
				continue
			}

			outcome := r.attachRoute(w, gw, listeners, route, parentRef)
			outcomes = append(outcomes, outcome)
		}
	}

	return outcomes
}

func parentRefMatches(ref gatewayv1.ParentReference, routeNamespace string, gw *gatewayv1.Gateway) bool {
	if ref.Group != nil && *ref.Group != gatewayv1.GroupName && *ref.Group != "" {
		return false
	}

	if ref.Kind != nil && *ref.Kind != "Gateway" {
		return false
	}

	namespace := routeNamespace
	if ref.Namespace != nil {
		namespace = string(*ref.Namespace)
	}

	return namespace == gw.Namespace && string(ref.Name) == gw.Name
}

// admitListeners applies the attachment admission ladder shared by every
// route kind (docs/spec/status.md): sectionName narrowing first, then
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

	outcome.accepted = true
	outcome.acceptedReason = string(gatewayv1.RouteReasonAccepted)

	for _, lst := range admitted {
		lst.attachedRoutes++
	}

	outcome.config = r.compileRoute(w, gw, route, admitted, outcome)

	return outcome
}

// attachTCPRoutes computes every (TCPRoute, gateway) attachment outcome
// (docs/spec/traffic.md): TCPRoutes attach to TCP listeners only and carry
// no hostname, path or filter semantics.
func (r *Engine) attachTCPRoutes(
	w *world,
	gw *gatewayv1.Gateway,
	listeners []*listenerState,
) []*routeParentOutcome {
	var outcomes []*routeParentOutcome

	for i := range w.tcpRoutes {
		route := &w.tcpRoutes[i]

		for _, parentRef := range route.Spec.ParentRefs {
			if !parentRefMatches(parentRef, route.Namespace, gw) {
				continue
			}

			outcome := r.attachTCPRoute(w, gw, listeners, route, parentRef)
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
			config.Listeners = append(config.Listeners, string(lst.spec.Name))
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

// attachTLSRoutes computes every (TLSRoute, gateway) attachment outcome
// (docs/spec/traffic.md): TLSRoutes attach to TLS passthrough listeners,
// matched by SNI hostname intersection.
func (r *Engine) attachTLSRoutes(
	w *world,
	gw *gatewayv1.Gateway,
	listeners []*listenerState,
) []*routeParentOutcome {
	var outcomes []*routeParentOutcome

	for i := range w.tlsRoutes {
		route := &w.tlsRoutes[i]

		for _, parentRef := range route.Spec.ParentRefs {
			if !parentRefMatches(parentRef, route.Namespace, gw) {
				continue
			}

			outcome := r.attachTLSRoute(w, gw, listeners, route, parentRef)
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
			config.Listeners = append(config.Listeners, string(lst.spec.Name))
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
	listeners []*listenerState,
) []*routeParentOutcome {
	var outcomes []*routeParentOutcome

	for i := range w.grpcRoutes {
		route := &w.grpcRoutes[i]

		for _, parentRef := range route.Spec.ParentRefs {
			if !parentRefMatches(parentRef, route.Namespace, gw) {
				continue
			}

			outcome := r.attachGRPCRoute(w, gw, listeners, route, parentRef)
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
			config.Listeners = append(config.Listeners, string(lst.spec.Name))
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
		if filter.Type != gatewayv1.GRPCRouteFilterRequestHeaderModifier ||
			filter.RequestHeaderModifier == nil {
			continue
		}

		entry := compiled.Filter{
			Type:       "RequestHeaderModifier",
			SetHeaders: map[string]string{},
			AddHeaders: map[string]string{},
		}

		for _, header := range filter.RequestHeaderModifier.Set {
			entry.SetHeaders[string(header.Name)] = header.Value
		}

		for _, header := range filter.RequestHeaderModifier.Add {
			entry.AddHeaders[string(header.Name)] = header.Value
		}

		entry.RemoveHeaders = filter.RequestHeaderModifier.Remove

		compiledRule.Filters = append(compiledRule.Filters, entry)
	}

	for _, backendRef := range rule.BackendRefs {
		compiledRule.Backends = append(compiledRule.Backends,
			r.compileBackend(w, route.Namespace, "GRPCRoute", backendRef.BackendRef, outcome))
	}

	return compiledRule, nil
}

// compileRoute builds the (Gateway, Route) attachment payload, validating
// backend references and ReferenceGrants (docs/spec/traffic.md).
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
			config.Listeners = append(config.Listeners, string(lst.spec.Name))
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
			if filter.Type != gatewayv1.HTTPRouteFilterRequestHeaderModifier ||
				filter.RequestHeaderModifier == nil {
				continue
			}

			entry := compiled.Filter{
				Type:       "RequestHeaderModifier",
				SetHeaders: map[string]string{},
				AddHeaders: map[string]string{},
			}

			for _, header := range filter.RequestHeaderModifier.Set {
				entry.SetHeaders[string(header.Name)] = header.Value
			}

			for _, header := range filter.RequestHeaderModifier.Add {
				entry.AddHeaders[string(header.Name)] = header.Value
			}

			entry.RemoveHeaders = filter.RequestHeaderModifier.Remove

			compiledRule.Filters = append(compiledRule.Filters, entry)
		}

		for _, backendRef := range rule.BackendRefs {
			compiledRule.Backends = append(compiledRule.Backends,
				r.compileBackend(w, route.Namespace, "HTTPRoute", backendRef.BackendRef, outcome))
		}

		config.Rules = append(config.Rules, compiledRule)
	}

	return config
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

	return backend
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
