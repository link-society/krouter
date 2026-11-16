package gatewayapi

import (
	"context"
	"fmt"
	"strings"
	"testing"

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
