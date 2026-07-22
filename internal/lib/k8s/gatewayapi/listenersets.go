package gatewayapi

import (
	"context"

	"slices"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// listenerSetState is one ListenerSet targeting a Gateway, after the
// allowedListeners gate (docs/spec/frontend.md Listener sets).
type listenerSetState struct {
	set *gatewayv1.ListenerSet

	accepted       bool
	acceptedReason string
}

// selectListenerSets returns the ListenerSets whose parentRef targets the
// Gateway, in precedence order (creation time, then name), each gated by
// the Gateway's allowedListeners field (docs/spec/frontend.md): the
// default admits none, and rejected sets report NotAllowed.
func selectListenerSets(w *world, gw *gatewayv1.Gateway) []*listenerSetState {
	var states []*listenerSetState

	for i := range w.listenerSets {
		set := &w.listenerSets[i]

		if !parentGatewayMatches(set, gw) {
			continue
		}

		state := &listenerSetState{
			set:            set,
			accepted:       true,
			acceptedReason: string(gatewayv1.ListenerSetReasonAccepted),
		}

		if !listenerSetAllowed(gw, set, w.namespaces) {
			state.accepted = false
			state.acceptedReason = string(gatewayv1.ListenerSetReasonNotAllowed)
		}

		states = append(states, state)
	}

	slices.SortFunc(states, func(a, b *listenerSetState) int {
		if !a.set.CreationTimestamp.Equal(&b.set.CreationTimestamp) {
			if a.set.CreationTimestamp.Before(&b.set.CreationTimestamp) {
				return -1
			}

			return 1
		}

		return strings.Compare(
			a.set.Namespace+"/"+a.set.Name,
			b.set.Namespace+"/"+b.set.Name,
		)
	})

	return states
}

func parentGatewayMatches(set *gatewayv1.ListenerSet, gw *gatewayv1.Gateway) bool {
	ref := set.Spec.ParentRef

	if ref.Group != nil && *ref.Group != gatewayv1.GroupName && *ref.Group != "" {
		return false
	}

	if ref.Kind != nil && *ref.Kind != "Gateway" {
		return false
	}

	namespace := set.Namespace
	if ref.Namespace != nil {
		namespace = string(*ref.Namespace)
	}

	return namespace == gw.Namespace && string(ref.Name) == gw.Name
}

// listenerSetAllowed applies Gateway.spec.allowedListeners: absent means no
// ListenerSets are allowed (docs/spec/frontend.md).
func listenerSetAllowed(
	gw *gatewayv1.Gateway,
	set *gatewayv1.ListenerSet,
	namespaces map[string]map[string]string,
) bool {
	allowed := gw.Spec.AllowedListeners
	if allowed == nil || allowed.Namespaces == nil || allowed.Namespaces.From == nil {
		return false
	}

	switch *allowed.Namespaces.From {
	case gatewayv1.NamespacesFromAll:
		return true

	case gatewayv1.NamespacesFromSame:
		return set.Namespace == gw.Namespace

	case gatewayv1.NamespacesFromSelector:
		if allowed.Namespaces.Selector == nil {
			return false
		}

		parsed, err := metav1.LabelSelectorAsSelector(allowed.Namespaces.Selector)
		if err != nil {
			return false
		}

		return parsed.Matches(labelsSet(namespaces[set.Namespace]))

	default:
		return false
	}
}

// writeListenerSetStatuses reports each set's conditions and per-listener
// entry statuses (docs/spec/status.md). A set is Accepted and Programmed
// through its valid listeners; rejected sets carry the gate's reason.
func (r *Engine) writeListenerSetStatuses(
	ctx context.Context,
	sets []*listenerSetState,
	listeners []*listenerState,
	gatewayAcked bool,
) {
	for _, state := range sets {
		set := state.set

		var owned []*listenerState
		for _, lst := range listeners {
			if lst.set == set {
				owned = append(owned, lst)
			}
		}

		validListeners := 0
		for _, lst := range owned {
			if lst.valid() {
				validListeners++
			}
		}

		accepted := condition(
			string(gatewayv1.ListenerSetConditionAccepted),
			boolStatus(state.accepted && validListeners > 0),
			state.acceptedReason, "",
			set.Generation,
		)
		if state.accepted && validListeners == 0 {
			accepted.Reason = string(gatewayv1.ListenerSetReasonListenersNotValid)
			accepted.Message = "no valid listeners"
		}

		programmed := condition(
			string(gatewayv1.ListenerSetConditionProgrammed),
			metav1.ConditionFalse,
			state.acceptedReason, "",
			set.Generation,
		)
		if !state.accepted {
			// Keep the gate's reason (NotAllowed).
		} else if validListeners == 0 {
			programmed.Reason = string(gatewayv1.ListenerSetReasonListenersNotValid)
			programmed.Message = "no valid listeners"
		} else if gatewayAcked {
			programmed.Status = metav1.ConditionTrue
			programmed.Reason = string(gatewayv1.ListenerSetReasonProgrammed)
			programmed.Message = "every healthy data-plane pod applied the desired generation"
		} else {
			programmed.Reason = string(gatewayv1.ListenerSetReasonPending)
			programmed.Message = "waiting for every healthy data-plane pod to apply the desired generation"
		}

		err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			fresh, err := r.gwClient.GatewayV1().ListenerSets(set.Namespace).
				Get(ctx, set.Name, metav1.GetOptions{})
			if err != nil {
				return err
			}

			desired := fresh.Status.DeepCopy()
			desired.Conditions = mergeConditions(fresh.Status.Conditions,
				[]metav1.Condition{accepted, programmed})

			desired.Listeners = nil
			for _, lst := range owned {
				entryConditions := []metav1.Condition{
					condition(
						string(gatewayv1.ListenerConditionAccepted),
						boolStatus(lst.accepted),
						lst.acceptedReason, "",
						fresh.Generation,
					),
					condition(
						string(gatewayv1.ListenerConditionConflicted),
						boolStatus(lst.conflicted),
						conflictedReason(lst),
						"",
						fresh.Generation,
					),
					condition(
						string(gatewayv1.ListenerConditionResolvedRefs),
						boolStatus(lst.refsResolved),
						lst.refsReason, lst.refsMessage,
						fresh.Generation,
					),
				}

				entryProgrammed := condition(
					string(gatewayv1.ListenerConditionProgrammed),
					metav1.ConditionFalse,
					lst.acceptedReason, "",
					fresh.Generation,
				)
				if lst.valid() && gatewayAcked {
					entryProgrammed.Status = metav1.ConditionTrue
					entryProgrammed.Reason = string(gatewayv1.ListenerReasonProgrammed)
				} else if lst.valid() {
					entryProgrammed.Reason = string(gatewayv1.ListenerReasonPending)
				}
				entryConditions = append(entryConditions, entryProgrammed)

				var existing []metav1.Condition
				for _, current := range fresh.Status.Listeners {
					if current.Name == lst.spec.Name {
						existing = current.Conditions
						break
					}
				}

				desired.Listeners = append(desired.Listeners, gatewayv1.ListenerEntryStatus{
					Name:           lst.spec.Name,
					SupportedKinds: lst.supportedKinds,
					AttachedRoutes: lst.attachedRoutes,
					Conditions:     mergeConditions(existing, entryConditions),
				})
			}

			if listenerSetStatusEqual(&fresh.Status, desired) {
				return nil
			}

			fresh.Status = *desired

			_, err = r.gwClient.GatewayV1().ListenerSets(set.Namespace).
				UpdateStatus(ctx, fresh, metav1.UpdateOptions{})

			return err
		})
		if err != nil {
			logSyncError("listenerset status", fmtKey(set.Namespace, set.Name), err)
		}
	}
}

// conflictedReason gives the Conflicted condition's reason: the conflict
// cause when rejected by the merge, NoConflicts otherwise.
func conflictedReason(lst *listenerState) string {
	if lst.conflicted {
		return lst.acceptedReason
	}

	return string(gatewayv1.ListenerReasonNoConflicts)
}

func listenerSetStatusEqual(a, b *gatewayv1.ListenerSetStatus) bool {
	if len(a.Conditions) != len(b.Conditions) || len(a.Listeners) != len(b.Listeners) {
		return false
	}

	conditionsEqual := func(x, y []metav1.Condition) bool {
		if len(x) != len(y) {
			return false
		}

		for i := range x {
			if x[i].Type != y[i].Type || x[i].Status != y[i].Status ||
				x[i].Reason != y[i].Reason || x[i].Message != y[i].Message ||
				x[i].ObservedGeneration != y[i].ObservedGeneration {
				return false
			}
		}

		return true
	}

	if !conditionsEqual(a.Conditions, b.Conditions) {
		return false
	}

	for i := range a.Listeners {
		x, y := a.Listeners[i], b.Listeners[i]
		if x.Name != y.Name || x.AttachedRoutes != y.AttachedRoutes ||
			len(x.SupportedKinds) != len(y.SupportedKinds) ||
			!conditionsEqual(x.Conditions, y.Conditions) {
			return false
		}

		for j := range x.SupportedKinds {
			if x.SupportedKinds[j].Kind != y.SupportedKinds[j].Kind {
				return false
			}
		}
	}

	return true
}
