package gatewayapi

import (
	"context"
	"fmt"

	"slices"
	"strings"

	"crypto/x509"
	"encoding/pem"

	stdtls "crypto/tls"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/link-society/krouter/internal/lib/k8s/compiled"
)

// backendClientCert is the resolved
// Gateway.spec.tls.backend.clientCertificateRef (docs/spec/traffic.md
// Backend TLS): the PEM keypair presented on backend TLS connections, and
// the Gateway ResolvedRefs condition outcome.
type backendClientCert struct {
	certPEM []byte
	keyPEM  []byte

	resolved bool
	reason   string
	message  string
}

// resolveBackendClientCert resolves the Gateway's backend client
// certificate reference (docs/spec/traffic.md Backend TLS). Invalid
// references degrade the Gateway ResolvedRefs condition; the Gateway stays
// accepted and backend connections proceed without a client certificate.
func (r *Engine) resolveBackendClientCert(
	ctx context.Context,
	w *world,
	gw *gatewayv1.Gateway,
) backendClientCert {
	resolved := backendClientCert{
		resolved: true,
		reason:   string(gatewayv1.GatewayReasonResolvedRefs),
		message:  "all references resolved",
	}

	if gw.Spec.TLS == nil || gw.Spec.TLS.Backend == nil ||
		gw.Spec.TLS.Backend.ClientCertificateRef == nil {
		return resolved
	}

	invalidate := func(reason, message string) backendClientCert {
		return backendClientCert{
			resolved: false,
			reason:   reason,
			message:  message,
		}
	}

	ref := gw.Spec.TLS.Backend.ClientCertificateRef

	if (ref.Group != nil && *ref.Group != "") ||
		(ref.Kind != nil && *ref.Kind != "Secret") {
		return invalidate(
			string(gatewayv1.GatewayReasonInvalidClientCertificateRef),
			"clientCertificateRef must reference a core Secret",
		)
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
			return invalidate(
				string(gatewayv1.GatewayReasonRefNotPermitted),
				fmt.Sprintf("reference to Secret %s/%s not permitted by any ReferenceGrant",
					namespace, ref.Name),
			)
		}
	}

	secret, err := r.client.CoreV1().Secrets(namespace).
		Get(ctx, string(ref.Name), metav1.GetOptions{})
	if err != nil {
		return invalidate(
			string(gatewayv1.GatewayReasonInvalidClientCertificateRef),
			fmt.Sprintf("Secret %s/%s not found", namespace, ref.Name),
		)
	}

	certPEM, keyPEM := secret.Data["tls.crt"], secret.Data["tls.key"]
	if _, err := stdtls.X509KeyPair(certPEM, keyPEM); err != nil {
		return invalidate(
			string(gatewayv1.GatewayReasonInvalidClientCertificateRef),
			fmt.Sprintf("Secret %s/%s holds no valid keypair", namespace, ref.Name),
		)
	}

	resolved.certPEM, resolved.keyPEM = certPEM, keyPEM

	return resolved
}

// backendTLSPolicyState is one BackendTLSPolicy after validation
// (docs/spec/traffic.md Backend TLS): its compiled verification parameters
// (Invalid marks fail-closed rejection), its conditions, and the Gateway
// ancestors referencing its targets.
type backendTLSPolicyState struct {
	policy *gatewayv1.BackendTLSPolicy

	tls *compiled.BackendTLS

	accepted       bool
	acceptedReason string
	resolvedOK     bool
	resolvedReason string

	// message explains a rejection on both conditions; empty when the
	// policy is accepted (docs/spec/status.md).
	message string

	ancestors map[string]gatewayv1.ParentReference
}

// backendTLSBinding attaches one policy state to one target Service.
type backendTLSBinding struct {
	state       *backendTLSPolicyState
	sectionName string // Service port name; "" targets every port
	conflicted  bool   // a newer policy lost the target: status only
}

// resolveBackendTLSPolicies validates every BackendTLSPolicy and indexes
// the bindings by target Service. Policies are processed oldest first so
// conflicting targets resolve deterministically: later policies on an
// already-claimed (Service, section) pair are rejected with Conflicted
// (docs/spec/traffic.md).
func (r *Engine) resolveBackendTLSPolicies(ctx context.Context, w *world) {
	w.backendTLS = map[string][]*backendTLSBinding{}

	ordered := make([]*gatewayv1.BackendTLSPolicy, 0, len(w.backendTLSPolicies))
	for i := range w.backendTLSPolicies {
		ordered = append(ordered, &w.backendTLSPolicies[i])
	}

	slices.SortFunc(ordered, func(a, b *gatewayv1.BackendTLSPolicy) int {
		if !a.CreationTimestamp.Equal(&b.CreationTimestamp) {
			if a.CreationTimestamp.Before(&b.CreationTimestamp) {
				return -1
			}

			return 1
		}

		return strings.Compare(nsName(a.Namespace, a.Name), nsName(b.Namespace, b.Name))
	})

	claimed := map[string]bool{}

	for _, policy := range ordered {
		state := r.resolvePolicyValidation(ctx, policy)
		w.backendTLSStates = append(w.backendTLSStates, state)

		for _, target := range policy.Spec.TargetRefs {
			if string(target.Kind) != "Service" || string(target.Group) != "" {
				state.accepted = false
				state.acceptedReason = string(gatewayv1.PolicyReasonInvalid)
				state.tls = &compiled.BackendTLS{Invalid: true}
				continue
			}

			section := ""
			if target.SectionName != nil {
				section = string(*target.SectionName)
			}

			claim := nsName(policy.Namespace, target.Name) + "|" + section
			conflicted := claimed[claim]
			if conflicted {
				// Oldest policy wins (docs/spec/traffic.md); the loser still
				// reports its Conflicted condition on its ancestors.
				state.accepted = false
				state.acceptedReason = string(gatewayv1.PolicyReasonConflicted)
			}
			claimed[claim] = true

			key := nsName(policy.Namespace, target.Name)
			w.backendTLS[key] = append(w.backendTLS[key], &backendTLSBinding{
				state:       state,
				sectionName: section,
				conflicted:  conflicted,
			})
		}
	}
}

// resolvePolicyValidation compiles one policy's validation block
// (docs/spec/traffic.md Backend TLS).
func (r *Engine) resolvePolicyValidation(
	ctx context.Context,
	policy *gatewayv1.BackendTLSPolicy,
) *backendTLSPolicyState {
	state := &backendTLSPolicyState{
		policy:         policy,
		accepted:       true,
		acceptedReason: string(gatewayv1.PolicyReasonAccepted),
		resolvedOK:     true,
		resolvedReason: string(gatewayv1.BackendTLSPolicyReasonResolvedRefs),
		ancestors:      map[string]gatewayv1.ParentReference{},
	}

	invalidate := func(acceptedReason, resolvedReason, message string) {
		state.accepted = false
		state.acceptedReason = acceptedReason
		if resolvedReason != "" {
			state.resolvedOK = false
			state.resolvedReason = resolvedReason
		}
		state.tls = &compiled.BackendTLS{Invalid: true}
		state.message = message
	}

	validation := policy.Spec.Validation

	// options is out of scope: reject rather than partially apply
	// (docs/spec/overview.md, docs/spec/traffic.md).
	if len(policy.Spec.Options) > 0 {
		invalidate(string(gatewayv1.PolicyReasonInvalid), "", "unsupported validation options")
		return state
	}

	tls := &compiled.BackendTLS{Hostname: string(validation.Hostname)}

	// subjectAltNames (docs/spec/traffic.md Backend TLS): the backend
	// certificate must match at least one; hostname is then SNI-only.
	for _, san := range validation.SubjectAltNames {
		entry := compiled.SubjectAltName{Type: string(san.Type)}

		switch san.Type {
		case gatewayv1.HostnameSubjectAltNameType:
			entry.Value = string(san.Hostname)

		case gatewayv1.URISubjectAltNameType:
			entry.Value = string(san.URI)
		}

		if entry.Value == "" {
			invalidate(string(gatewayv1.PolicyReasonInvalid), "", "invalid subjectAltName entry")
			return state
		}

		tls.SubjectAltNames = append(tls.SubjectAltNames, entry)
	}

	if validation.WellKnownCACertificates != nil {
		tls.SystemCAs = true
		state.tls = tls

		return state
	}

	var pemBundle []byte

	for _, ref := range validation.CACertificateRefs {
		if string(ref.Kind) != "ConfigMap" || string(ref.Group) != "" {
			invalidate(
				string(gatewayv1.BackendTLSPolicyReasonNoValidCACertificate),
				string(gatewayv1.BackendTLSPolicyReasonInvalidKind),
				"caCertificateRefs must reference core ConfigMaps",
			)

			return state
		}

		cm, err := r.client.CoreV1().ConfigMaps(policy.Namespace).
			Get(ctx, string(ref.Name), metav1.GetOptions{})
		if err != nil {
			invalidate(
				string(gatewayv1.BackendTLSPolicyReasonNoValidCACertificate),
				string(gatewayv1.BackendTLSPolicyReasonInvalidCACertificateRef),
				fmt.Sprintf("ConfigMap %s not found", ref.Name),
			)

			return state
		}

		pemBundle = append(pemBundle, []byte(cm.Data["ca.crt"])...)
		pemBundle = append(pemBundle, '\n')
	}

	if !validCAPem(pemBundle) {
		invalidate(
			string(gatewayv1.BackendTLSPolicyReasonNoValidCACertificate),
			string(gatewayv1.BackendTLSPolicyReasonInvalidCACertificateRef),
			"no valid CA certificate",
		)

		return state
	}

	tls.CAPem = string(pemBundle)
	state.tls = tls

	return state
}

// validCAPem reports whether the bundle holds at least one parseable
// certificate.
func validCAPem(bundle []byte) bool {
	rest := bundle
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return false
		}

		if block.Type != "CERTIFICATE" {
			continue
		}

		if _, err := x509.ParseCertificate(block.Bytes); err == nil {
			return true
		}
	}
}

// backendTLSFor returns the verification parameters applying to one
// backend: the binding narrowed to the backend's Service port name wins
// over an unsectioned one (docs/spec/traffic.md).
func backendTLSFor(w *world, namespace, name, portName string) *compiled.BackendTLS {
	var fallback *compiled.BackendTLS

	for _, binding := range w.backendTLS[nsName(namespace, name)] {
		if binding.conflicted {
			continue
		}

		if binding.sectionName == portName && portName != "" {
			return binding.state.tls
		}

		if binding.sectionName == "" && fallback == nil {
			fallback = binding.state.tls
		}
	}

	return fallback
}

// collectBackendTLSAncestors records, for every policy, the Gateways whose
// attached routes reference one of its target Services
// (docs/spec/status.md).
func collectBackendTLSAncestors(w *world, outcomes map[string][]*routeParentOutcome) {
	for _, list := range outcomes {
		for _, outcome := range list {
			if outcome.config == nil {
				continue
			}

			meta := outcome.routeMeta()

			gwNamespace := meta.Namespace
			if outcome.parentRef.Namespace != nil {
				gwNamespace = string(*outcome.parentRef.Namespace)
			}

			for _, rule := range outcome.config.Rules {
				for _, backend := range rule.Backends {
					for _, binding := range w.backendTLS[nsName(backend.Namespace, backend.Name)] {
						key := nsName(gwNamespace, outcome.parentRef.Name)
						binding.state.ancestors[key] = gatewayv1.ParentReference{
							Group:     ptrTo(gatewayv1.Group(gatewayv1.GroupName)),
							Kind:      ptrTo(gatewayv1.Kind("Gateway")),
							Namespace: ptrTo(gatewayv1.Namespace(gwNamespace)),
							Name:      gatewayv1.ObjectName(outcome.parentRef.Name),
						}
					}
				}
			}
		}
	}
}

func ptrTo[T any](v T) *T { return &v }

// writeBackendTLSPolicyStatuses reports each policy's conditions on every
// Gateway ancestor, keeping entries owned by other controllers
// (docs/spec/status.md).
func (r *Engine) writeBackendTLSPolicyStatuses(ctx context.Context, w *world) {
	controllerName := r.settings.ControllerName

	for _, state := range w.backendTLSStates {
		policy := state.policy

		accepted := condition(
			string(gatewayv1.PolicyConditionAccepted),
			boolStatus(state.accepted),
			state.acceptedReason, state.message,
			policy.Generation,
		)
		resolved := condition(
			string(gatewayv1.BackendTLSPolicyConditionResolvedRefs),
			boolStatus(state.resolvedOK),
			state.resolvedReason, state.message,
			policy.Generation,
		)

		ancestorKeys := make([]string, 0, len(state.ancestors))
		for key := range state.ancestors {
			ancestorKeys = append(ancestorKeys, key)
		}
		slices.Sort(ancestorKeys)

		err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			fresh, err := r.gwClient.GatewayV1().BackendTLSPolicies(policy.Namespace).
				Get(ctx, policy.Name, metav1.GetOptions{})
			if err != nil {
				return err
			}

			var desired []gatewayv1.PolicyAncestorStatus
			for _, current := range fresh.Status.Ancestors {
				if string(current.ControllerName) != controllerName {
					desired = append(desired, current)
				}
			}

			for _, key := range ancestorKeys {
				ref := state.ancestors[key]

				var existing []metav1.Condition
				for _, current := range fresh.Status.Ancestors {
					if string(current.ControllerName) == controllerName &&
						ancestorRefMatches(current.AncestorRef, ref) {
						existing = current.Conditions
						break
					}
				}

				desired = append(desired, gatewayv1.PolicyAncestorStatus{
					AncestorRef:    ref,
					ControllerName: gatewayv1.GatewayController(controllerName),
					Conditions: mergeConditions(existing,
						[]metav1.Condition{accepted, resolved}),
				})
			}

			// The API caps ancestors at 16 entries.
			if len(desired) > 16 {
				desired = desired[:16]
			}

			if ancestorsEqual(fresh.Status.Ancestors, desired) {
				return nil
			}

			fresh.Status.Ancestors = desired

			_, err = r.gwClient.GatewayV1().BackendTLSPolicies(policy.Namespace).
				UpdateStatus(ctx, fresh, metav1.UpdateOptions{})

			return err
		})
		if err != nil {
			logSyncError("backendtlspolicy status", nsName(policy.Namespace, policy.Name), err)
		}
	}
}

func ancestorRefMatches(a, b gatewayv1.ParentReference) bool {
	namespace := func(ref gatewayv1.ParentReference) string {
		if ref.Namespace == nil {
			return ""
		}

		return string(*ref.Namespace)
	}

	return string(a.Name) == string(b.Name) && namespace(a) == namespace(b)
}

func ancestorsEqual(a, b []gatewayv1.PolicyAncestorStatus) bool {
	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if !ancestorRefMatches(a[i].AncestorRef, b[i].AncestorRef) ||
			a[i].ControllerName != b[i].ControllerName ||
			len(a[i].Conditions) != len(b[i].Conditions) {
			return false
		}

		for j := range a[i].Conditions {
			x, y := a[i].Conditions[j], b[i].Conditions[j]
			if x.Type != y.Type || x.Status != y.Status || x.Reason != y.Reason ||
				x.Message != y.Message || x.ObservedGeneration != y.ObservedGeneration {
				return false
			}
		}
	}

	return true
}
