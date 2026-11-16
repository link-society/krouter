package gatewayapi

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/version"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gwfake "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned/fake"
	gatewayconsts "sigs.k8s.io/gateway-api/pkg/consts"
)

func TestWriteClassStatusSupportedVersion(t *testing.T) {
	dependencyVersion, err := version.ParseSemantic(gatewayconsts.BundleVersion)
	if err != nil {
		t.Fatalf("parse Gateway API dependency bundle version: %v", err)
	}
	major, minor := dependencyVersion.Major(), dependencyVersion.Minor()
	supportedMinor := fmt.Sprintf("v%d.%d", major, minor)

	tests := []struct {
		name      string
		bundle    string
		supported bool
	}{
		{"dependency bundle", gatewayconsts.BundleVersion, true},
		{"initial patch", fmt.Sprintf("v%d.%d.0", major, minor), true},
		{"newer patch", fmt.Sprintf("v%d.%d.%d", major, minor, dependencyVersion.Patch()+1), true},
		{"different minor", fmt.Sprintf("v%d.%d.0", major, minor+1), false},
		{"different major", fmt.Sprintf("v%d.%d.0", major+1, minor), false},
		{"minor prefix collision", fmt.Sprintf("v%d.%d0.0", major, minor), false},
		{"missing annotation", "", false},
		{"malformed version", "not-a-version", false},
		{"malformed matching prefix", supportedMinor + "invalid", false},
		{"incomplete version", supportedMinor, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			class := &gatewayv1.GatewayClass{
				ObjectMeta: metav1.ObjectMeta{Name: "krouter", Generation: 7},
			}
			client := gwfake.NewSimpleClientset(class)
			engine := &Engine{gwClient: client}
			w := &world{bundleVersion: tt.bundle}

			if err := engine.writeClassStatus(ctx, w, class.Name); err != nil {
				t.Fatalf("write GatewayClass status: %v", err)
			}
			updated, err := client.GatewayV1().GatewayClasses().Get(ctx, class.Name, metav1.GetOptions{})
			if err != nil {
				t.Fatalf("get GatewayClass: %v", err)
			}
			got := meta.FindStatusCondition(updated.Status.Conditions,
				string(gatewayv1.GatewayClassConditionStatusSupportedVersion))
			if got == nil {
				t.Fatal("SupportedVersion condition was not published")
			}

			wantStatus := metav1.ConditionFalse
			wantReason := gatewayv1.GatewayClassReasonUnsupportedVersion
			if tt.supported {
				wantStatus = metav1.ConditionTrue
				wantReason = gatewayv1.GatewayClassReasonSupportedVersion
			}
			if got.Status != wantStatus || got.Reason != string(wantReason) {
				t.Errorf("bundle %q: got %s/%s, want %s/%s", tt.bundle,
					got.Status, got.Reason, wantStatus, wantReason)
			}
			if got.ObservedGeneration != class.Generation {
				t.Errorf("observed generation = %d, want %d", got.ObservedGeneration, class.Generation)
			}
			if got.LastTransitionTime.IsZero() {
				t.Error("SupportedVersion condition has no transition time")
			}
			if !strings.Contains(got.Message, tt.bundle) {
				t.Errorf("condition message %q does not identify installed bundle %q", got.Message, tt.bundle)
			}
			if !tt.supported && !strings.Contains(got.Message, supportedMinor) {
				t.Errorf("condition message %q does not identify supported release %q", got.Message, supportedMinor)
			}
		})
	}
}

func TestWriteGatewayStatusPreservesForeignConditions(t *testing.T) {
	ctx := context.Background()
	previousTransition := metav1.NewTime(time.Unix(1, 0).UTC())
	foreignGateway := metav1.Condition{
		Type: "example.com/GatewayReady", Status: metav1.ConditionTrue,
		Reason: "ThirdPartyController", Message: "keep this condition unchanged",
		ObservedGeneration: 1, LastTransitionTime: previousTransition,
	}
	foreignListener := foreignGateway
	foreignListener.Type = "example.com/ListenerReady"
	previousAccepted := metav1.Condition{
		Type: "Accepted", Status: metav1.ConditionTrue, Reason: "Accepted",
		ObservedGeneration: 1, LastTransitionTime: previousTransition,
	}
	fallbackType := string(gatewayv1.GatewayConditionInsecureFrontendValidationMode)
	previousFallback := previousAccepted
	previousFallback.Type = fallbackType

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gateway", Namespace: "default", Generation: 2},
		Status: gatewayv1.GatewayStatus{
			Conditions: []metav1.Condition{foreignGateway, previousAccepted, previousFallback},
			Listeners: []gatewayv1.ListenerStatus{{
				Name:       "http",
				Conditions: []metav1.Condition{foreignListener, previousAccepted},
			}},
		},
	}
	client := gwfake.NewSimpleClientset()
	if _, err := client.GatewayV1().Gateways(gw.Namespace).Create(ctx, gw, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create Gateway: %v", err)
	}
	engine := &Engine{gwClient: client}
	input := gatewayStatusInput{
		accepted:     condition("Accepted", metav1.ConditionTrue, "Accepted", "", gw.Generation),
		programmed:   condition("Programmed", metav1.ConditionTrue, "Programmed", "", gw.Generation),
		resolvedRefs: condition("ResolvedRefs", metav1.ConditionTrue, "ResolvedRefs", "", gw.Generation),
		gatewayAcked: true,
		listeners: []*listenerState{{
			spec:     gatewayv1.Listener{Name: "http", Protocol: gatewayv1.HTTPProtocolType, Port: 80},
			accepted: true, acceptedReason: "Accepted",
			refsResolved: true, refsReason: "ResolvedRefs",
		}},
	}

	for _, step := range []struct {
		name     string
		fallback bool
	}{
		{"remove stale fallback", false},
		{"enable fallback", true},
		{"disable fallback", false},
	} {
		t.Run(step.name, func(t *testing.T) {
			input.insecureFallback = step.fallback
			if err := engine.writeGatewayStatus(ctx, gw, input); err != nil {
				t.Fatalf("write Gateway status: %v", err)
			}
			updated, err := client.GatewayV1().Gateways(gw.Namespace).Get(ctx, gw.Name, metav1.GetOptions{})
			if err != nil {
				t.Fatalf("get Gateway: %v", err)
			}
			if len(updated.Status.Listeners) != 1 {
				t.Fatalf("got %d listener statuses, want 1", len(updated.Status.Listeners))
			}

			for _, entry := range []struct {
				name       string
				conditions []metav1.Condition
				foreign    metav1.Condition
			}{
				{"Gateway", updated.Status.Conditions, foreignGateway},
				{"Listener", updated.Status.Listeners[0].Conditions, foreignListener},
			} {
				got := meta.FindStatusCondition(entry.conditions, entry.foreign.Type)
				if !reflect.DeepEqual(got, &entry.foreign) {
					t.Errorf("%s foreign condition changed: got %#v, want %#v", entry.name, got, entry.foreign)
				}
				if len(entry.conditions) == 0 || entry.conditions[0].Type != entry.foreign.Type {
					t.Errorf("%s foreign condition was reordered", entry.name)
				}
				for _, conditionType := range []string{"Accepted", "Programmed", "ResolvedRefs"} {
					got := meta.FindStatusCondition(entry.conditions, conditionType)
					if got == nil || got.Status != metav1.ConditionTrue || got.ObservedGeneration != gw.Generation {
						t.Errorf("%s %s condition did not catch up to generation %d: %#v", entry.name, conditionType, gw.Generation, got)
					}
				}
				accepted := meta.FindStatusCondition(entry.conditions, "Accepted")
				if accepted != nil && !accepted.LastTransitionTime.Equal(&previousTransition) {
					t.Errorf("%s Accepted transition time changed without a status change", entry.name)
				}
			}

			fallback := meta.FindStatusCondition(updated.Status.Conditions, fallbackType)
			if step.fallback {
				if fallback == nil || fallback.Status != metav1.ConditionTrue || fallback.ObservedGeneration != gw.Generation {
					t.Errorf("fallback condition not published: %#v", fallback)
				}
			} else if fallback != nil {
				t.Errorf("stale fallback condition retained: %#v", fallback)
			}

			client.ClearActions()
			if err := engine.writeGatewayStatus(ctx, gw, input); err != nil {
				t.Fatalf("repeat Gateway status write: %v", err)
			}
			for _, action := range client.Actions() {
				if action.GetVerb() == "update" {
					t.Error("unchanged reconciliation rewrote Gateway status")
				}
			}
		})
	}
}
