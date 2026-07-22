package gatewayapi

import (
	"context"
	"fmt"

	"reflect"
	"slices"
	"strings"

	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/util/retry"
	"k8s.io/utils/ptr"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/gateway-api/pkg/features"
)

func labelsSet(m map[string]string) labels.Set {
	return labels.Set(m)
}

// condition builds a metav1.Condition without a transition time; merge
// assigns times while preserving them for semantically unchanged conditions
// so status updates stay idempotent (docs/spec/failure-modes.md).
func condition(condType string, status metav1.ConditionStatus, reason, message string,
	observedGeneration int64) metav1.Condition {
	return metav1.Condition{
		Type:               condType,
		Status:             status,
		Reason:             reason,
		Message:            message,
		ObservedGeneration: observedGeneration,
	}
}

func mergeConditions(existing, desired []metav1.Condition) []metav1.Condition {
	now := metav1.NewTime(time.Now())

	merged := make([]metav1.Condition, 0, len(desired))
	for _, want := range desired {
		want.LastTransitionTime = now

		for _, have := range existing {
			if have.Type != want.Type {
				continue
			}

			if have.Status == want.Status {
				want.LastTransitionTime = have.LastTransitionTime
			}

			if have.Status == want.Status &&
				have.Reason == want.Reason &&
				have.Message == want.Message &&
				have.ObservedGeneration == want.ObservedGeneration {
				want = have
			}

			break
		}

		merged = append(merged, want)
	}

	return merged
}

// The control plane is the sole status writer (docs/spec/status.md). Every writer
// merges conditions (preserving transition times for unchanged conditions)
// and skips API updates when nothing changed, keeping reconciliation
// idempotent (docs/spec/failure-modes.md).

// ------------------------------------------------------------ GatewayClass --

// supportedFeatures is the exact Gateway API feature set implemented by
// krouter, published on GatewayClass status (docs/spec/status.md,
// docs/spec/overview.md) and consumed by conformance tooling. It MUST stay
// sorted by name.
var supportedFeatures = func() []gatewayv1.SupportedFeature {
	names := []features.FeatureName{
		features.SupportGateway,
		features.SupportHTTPRoute,
		features.SupportGRPCRoute,
		features.SupportTLSRoute,
		features.SupportUDPRoute,
		features.SupportReferenceGrant,
		features.SupportBackendTLSPolicy,
		features.SupportListenerSet,

		// Extended HTTPRoute filters (docs/spec/acceptance.md criterion 16).
		features.SupportHTTPRouteResponseHeaderModification,
		features.SupportHTTPRouteHostRewrite,
		features.SupportHTTPRoutePathRewrite,
		features.SupportHTTPRoutePathRedirect,
		features.SupportHTTPRouteSchemeRedirect,
		features.SupportHTTPRoutePortRedirect,
		features.SupportHTTPRoute303RedirectStatusCode,
		features.SupportHTTPRoute307RedirectStatusCode,
		features.SupportHTTPRoute308RedirectStatusCode,
		features.SupportHTTPRouteRequestMirror,
		features.SupportHTTPRouteRequestMultipleMirrors,
		features.SupportHTTPRouteRequestPercentageMirror,

		// HTTPRoute rule timeouts (docs/spec/acceptance.md criterion 17).
		features.SupportHTTPRouteRequestTimeout,
		features.SupportHTTPRouteBackendTimeout,
	}

	slices.Sort(names)

	entries := make([]gatewayv1.SupportedFeature, 0, len(names))
	for _, name := range names {
		entries = append(entries, gatewayv1.SupportedFeature{
			Name: gatewayv1.FeatureName(name),
		})
	}

	return entries
}()

func (r *Engine) writeClassStatus(ctx context.Context, w *world, name string) error {
	supported := strings.HasPrefix(w.bundleVersion, "v1.5")

	supportedCondition := condition(
		string(gatewayv1.GatewayClassConditionStatusSupportedVersion),
		metav1.ConditionTrue,
		string(gatewayv1.GatewayClassReasonSupportedVersion),
		fmt.Sprintf("Gateway API CRD bundle version %s is supported", w.bundleVersion),
		0,
	)
	if !supported {
		supportedCondition.Status = metav1.ConditionFalse
		supportedCondition.Reason = string(gatewayv1.GatewayClassReasonUnsupportedVersion)
		supportedCondition.Message = fmt.Sprintf(
			"Gateway API CRD bundle version %q is not supported", w.bundleVersion)
	}

	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		class, err := r.gwClient.GatewayV1().GatewayClasses().Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return err
		}

		accepted := condition(
			string(gatewayv1.GatewayClassConditionStatusAccepted),
			metav1.ConditionTrue,
			string(gatewayv1.GatewayClassReasonAccepted),
			"GatewayClass is accepted by this controller",
			class.Generation,
		)
		supportedCondition.ObservedGeneration = class.Generation

		desired := mergeConditions(class.Status.Conditions,
			[]metav1.Condition{accepted, supportedCondition})

		if reflect.DeepEqual(class.Status.Conditions, desired) &&
			reflect.DeepEqual(class.Status.SupportedFeatures, supportedFeatures) {
			return nil
		}

		class.Status.Conditions = desired
		class.Status.SupportedFeatures = supportedFeatures

		_, err = r.gwClient.GatewayV1().GatewayClasses().UpdateStatus(ctx, class, metav1.UpdateOptions{})

		return err
	})
}

// ---------------------------------------------------------------- Gateway --

func (r *Engine) writeGatewayStatus(
	ctx context.Context,
	gw *gatewayv1.Gateway,
	input gatewayStatusInput,
) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		fresh, err := r.gwClient.GatewayV1().Gateways(gw.Namespace).
			Get(ctx, gw.Name, metav1.GetOptions{})
		if err != nil {
			return err
		}

		desired := fresh.Status.DeepCopy()

		desired.Conditions = mergeConditions(fresh.Status.Conditions,
			[]metav1.Condition{input.accepted, input.programmed})

		desired.Addresses = nil
		if input.address != "" {
			desired.Addresses = []gatewayv1.GatewayStatusAddress{{
				Type:  ptr.To(gatewayv1.IPAddressType),
				Value: input.address,
			}}
		}

		desired.Listeners = nil
		for _, lst := range input.listeners {
			listenerConditions := []metav1.Condition{
				condition(
					string(gatewayv1.ListenerConditionAccepted),
					boolStatus(lst.accepted),
					lst.acceptedReason, "",
					fresh.Generation,
				),
				condition(
					string(gatewayv1.ListenerConditionResolvedRefs),
					boolStatus(lst.refsResolved),
					lst.refsReason, lst.refsMessage,
					fresh.Generation,
				),
			}

			programmed := condition(
				string(gatewayv1.ListenerConditionProgrammed),
				metav1.ConditionFalse,
				string(gatewayv1.ListenerReasonPending), "",
				fresh.Generation,
			)
			if lst.valid() && input.gatewayAcked {
				programmed.Status = metav1.ConditionTrue
				programmed.Reason = string(gatewayv1.ListenerReasonProgrammed)
			}
			listenerConditions = append(listenerConditions, programmed)

			var existingConditions []metav1.Condition
			for _, current := range fresh.Status.Listeners {
				if current.Name == lst.spec.Name {
					existingConditions = current.Conditions
					break
				}
			}

			desired.Listeners = append(desired.Listeners, gatewayv1.ListenerStatus{
				Name:           lst.spec.Name,
				SupportedKinds: lst.supportedKinds,
				AttachedRoutes: lst.attachedRoutes,
				Conditions:     mergeConditions(existingConditions, listenerConditions),
			})
		}

		if reflect.DeepEqual(&fresh.Status, desired) {
			return nil
		}

		fresh.Status = *desired

		_, err = r.gwClient.GatewayV1().Gateways(gw.Namespace).
			UpdateStatus(ctx, fresh, metav1.UpdateOptions{})

		return err
	})
}

func boolStatus(ok bool) metav1.ConditionStatus {
	if ok {
		return metav1.ConditionTrue
	}

	return metav1.ConditionFalse
}

// ----------------------------------------------------------------- Routes --

// writeRouteStatuses updates status.parents[] for every route touched by
// this controller, replacing only entries carrying our controller name
// (docs/spec/status.md).
func (r *Engine) writeRouteStatuses(
	ctx context.Context,
	w *world,
	outcomes map[string][]*routeParentOutcome,
) {
	controllerName := gatewayv1.GatewayController(r.settings.ControllerName)

	for i := range w.routes {
		route := &w.routes[i]
		key := outcomeKey("HTTPRoute", route.Namespace, route.Name)

		ours := parentStatuses(outcomes[key], controllerName, route.Generation)

		err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			fresh, err := r.gwClient.GatewayV1().HTTPRoutes(route.Namespace).
				Get(ctx, route.Name, metav1.GetOptions{})
			if err != nil {
				return err
			}

			desired, changed := mergeParentStatuses(fresh.Status.Parents, ours, controllerName)
			if !changed {
				return nil
			}

			fresh.Status.Parents = desired

			_, err = r.gwClient.GatewayV1().HTTPRoutes(route.Namespace).
				UpdateStatus(ctx, fresh, metav1.UpdateOptions{})

			return err
		})
		if err != nil {
			logSyncError("route status", fmtKey(route.Namespace, route.Name), err)
		}
	}

	for i := range w.grpcRoutes {
		route := &w.grpcRoutes[i]
		key := outcomeKey("GRPCRoute", route.Namespace, route.Name)

		ours := parentStatuses(outcomes[key], controllerName, route.Generation)

		err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			fresh, err := r.gwClient.GatewayV1().GRPCRoutes(route.Namespace).
				Get(ctx, route.Name, metav1.GetOptions{})
			if err != nil {
				return err
			}

			desired, changed := mergeParentStatuses(fresh.Status.Parents, ours, controllerName)
			if !changed {
				return nil
			}

			fresh.Status.Parents = desired

			_, err = r.gwClient.GatewayV1().GRPCRoutes(route.Namespace).
				UpdateStatus(ctx, fresh, metav1.UpdateOptions{})

			return err
		})
		if err != nil {
			logSyncError("grpcroute status", fmtKey(route.Namespace, route.Name), err)
		}
	}

	for i := range w.tcpRoutes {
		route := &w.tcpRoutes[i]
		key := outcomeKey("TCPRoute", route.Namespace, route.Name)

		ours := parentStatuses(outcomes[key], controllerName, route.Generation)

		err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			fresh, err := r.gwClient.GatewayV1alpha2().TCPRoutes(route.Namespace).
				Get(ctx, route.Name, metav1.GetOptions{})
			if err != nil {
				return err
			}

			desired, changed := mergeParentStatuses(fresh.Status.Parents, ours, controllerName)
			if !changed {
				return nil
			}

			fresh.Status.Parents = desired

			_, err = r.gwClient.GatewayV1alpha2().TCPRoutes(route.Namespace).
				UpdateStatus(ctx, fresh, metav1.UpdateOptions{})

			return err
		})
		if err != nil {
			logSyncError("tcproute status", fmtKey(route.Namespace, route.Name), err)
		}
	}

	for i := range w.tlsRoutes {
		route := &w.tlsRoutes[i]
		key := outcomeKey("TLSRoute", route.Namespace, route.Name)

		ours := parentStatuses(outcomes[key], controllerName, route.Generation)

		err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			fresh, err := r.gwClient.GatewayV1alpha2().TLSRoutes(route.Namespace).
				Get(ctx, route.Name, metav1.GetOptions{})
			if err != nil {
				return err
			}

			desired, changed := mergeParentStatuses(fresh.Status.Parents, ours, controllerName)
			if !changed {
				return nil
			}

			fresh.Status.Parents = desired

			_, err = r.gwClient.GatewayV1alpha2().TLSRoutes(route.Namespace).
				UpdateStatus(ctx, fresh, metav1.UpdateOptions{})

			return err
		})
		if err != nil {
			logSyncError("tlsroute status", fmtKey(route.Namespace, route.Name), err)
		}
	}

	for i := range w.udpRoutes {
		route := &w.udpRoutes[i]
		key := outcomeKey("UDPRoute", route.Namespace, route.Name)

		ours := parentStatuses(outcomes[key], controllerName, route.Generation)

		err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			fresh, err := r.gwClient.GatewayV1alpha2().UDPRoutes(route.Namespace).
				Get(ctx, route.Name, metav1.GetOptions{})
			if err != nil {
				return err
			}

			desired, changed := mergeParentStatuses(fresh.Status.Parents, ours, controllerName)
			if !changed {
				return nil
			}

			fresh.Status.Parents = desired

			_, err = r.gwClient.GatewayV1alpha2().UDPRoutes(route.Namespace).
				UpdateStatus(ctx, fresh, metav1.UpdateOptions{})

			return err
		})
		if err != nil {
			logSyncError("udproute status", fmtKey(route.Namespace, route.Name), err)
		}
	}
}

// parentStatuses renders this controller's status.parents[] entries for
// one route from its attachment outcomes.
func parentStatuses(
	outcomes []*routeParentOutcome,
	controllerName gatewayv1.GatewayController,
	generation int64,
) []gatewayv1.RouteParentStatus {
	var ours []gatewayv1.RouteParentStatus

	for _, outcome := range outcomes {
		conditions := []metav1.Condition{
			condition(
				string(gatewayv1.RouteConditionAccepted),
				boolStatus(outcome.accepted),
				outcome.acceptedReason, "",
				generation,
			),
			condition(
				string(gatewayv1.RouteConditionResolvedRefs),
				boolStatus(outcome.refsResolved),
				outcome.refsReason, outcome.refsMessage,
				generation,
			),
		}

		ours = append(ours, gatewayv1.RouteParentStatus{
			ParentRef:      outcome.parentRef,
			ControllerName: controllerName,
			Conditions:     conditions,
		})
	}

	return ours
}

// mergeParentStatuses replaces this controller's parent entries while
// preserving foreign controllers and unchanged transition times.
func mergeParentStatuses(
	existing []gatewayv1.RouteParentStatus,
	ours []gatewayv1.RouteParentStatus,
	controllerName gatewayv1.GatewayController,
) ([]gatewayv1.RouteParentStatus, bool) {
	var desired []gatewayv1.RouteParentStatus
	for _, parent := range existing {
		if parent.ControllerName != controllerName {
			desired = append(desired, parent)
		}
	}

	for _, parent := range ours {
		var existingConditions []metav1.Condition
		for _, current := range existing {
			if current.ControllerName == controllerName &&
				reflect.DeepEqual(current.ParentRef, parent.ParentRef) {
				existingConditions = current.Conditions
				break
			}
		}

		parent.Conditions = mergeConditions(existingConditions, parent.Conditions)

		desired = append(desired, parent)
	}

	return desired, !reflect.DeepEqual(existing, desired)
}

// gatewayConditions builds the top-level Gateway conditions.
func gatewayConditions(gw *gatewayv1.Gateway, paramsErr error, acked bool,
	validListeners int) (metav1.Condition, metav1.Condition) {
	if paramsErr != nil {
		// Invalid or missing parameters (docs/spec/parameters.md).
		accepted := condition(
			string(gatewayv1.GatewayConditionAccepted),
			metav1.ConditionFalse,
			string(gatewayv1.GatewayReasonInvalidParameters),
			paramsErr.Error(),
			gw.Generation,
		)
		programmed := condition(
			string(gatewayv1.GatewayConditionProgrammed),
			metav1.ConditionFalse,
			string(gatewayv1.GatewayReasonInvalidParameters),
			paramsErr.Error(),
			gw.Generation,
		)

		return accepted, programmed
	}

	accepted := condition(
		string(gatewayv1.GatewayConditionAccepted),
		metav1.ConditionTrue,
		string(gatewayv1.GatewayReasonAccepted),
		"Gateway is accepted",
		gw.Generation,
	)

	programmed := condition(
		string(gatewayv1.GatewayConditionProgrammed),
		metav1.ConditionFalse,
		string(gatewayv1.GatewayReasonPending),
		"waiting for every healthy data-plane pod to apply the desired generation",
		gw.Generation,
	)

	if validListeners == 0 {
		programmed.Reason = string(gatewayv1.GatewayReasonInvalid)
		programmed.Message = "no valid listeners"
	} else if acked {
		programmed.Status = metav1.ConditionTrue
		programmed.Reason = string(gatewayv1.GatewayReasonProgrammed)
		programmed.Message = "every healthy data-plane pod applied the desired generation"
	}

	return accepted, programmed
}
