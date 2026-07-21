package gatewayapi

import (
	"context"
	"fmt"

	"strings"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
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

		default:
			state.accepted = false
			state.acceptedReason = string(gatewayv1.ListenerReasonUnsupportedProtocol)
		}

		if spec.Protocol == gatewayv1.HTTPSProtocolType {
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

	// Select candidate listeners (sectionName narrows them).
	var candidates []*listenerState
	for _, lst := range listeners {
		if parentRef.SectionName != nil && *parentRef.SectionName != lst.spec.Name {
			continue
		}

		candidates = append(candidates, lst)
	}

	if len(candidates) == 0 {
		outcome.acceptedReason = string(gatewayv1.RouteReasonNoMatchingParent)
		return outcome
	}

	// Listener admission: namespace policy, then hostname intersection.
	var namespaceAdmitted []*listenerState
	for _, lst := range candidates {
		if namespaceAllowed(lst.spec.AllowedRoutes, route.Namespace, gw.Namespace, w.namespaces) {
			namespaceAdmitted = append(namespaceAdmitted, lst)
		}
	}

	if len(namespaceAdmitted) == 0 {
		outcome.acceptedReason = string(gatewayv1.RouteReasonNotAllowedByListeners)
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
				r.compileBackend(w, route, backendRef, outcome))
		}

		config.Rules = append(config.Rules, compiledRule)
	}

	return config
}

func (r *Engine) compileBackend(
	w *world,
	route *gatewayv1.HTTPRoute,
	backendRef gatewayv1.HTTPBackendRef,
	outcome *routeParentOutcome,
) compiled.Backend {
	ref := backendRef.BackendRef

	backend := compiled.Backend{
		Name:   string(ref.Name),
		Weight: 1,
		Valid:  true,
	}

	if ref.Weight != nil {
		backend.Weight = *ref.Weight
	}

	backend.Namespace = route.Namespace
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
	if backend.Namespace != route.Namespace {
		allowed := referenceGrantAllows(
			w.grants,
			gatewayv1.GroupName, "HTTPRoute", route.Namespace,
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
	if allowed != nil && len(allowed.Kinds) > 0 {
		kindOK := false
		for _, kind := range allowed.Kinds {
			if string(kind.Kind) == "HTTPRoute" {
				kindOK = true
				break
			}
		}

		if !kindOK {
			return false
		}
	}

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
