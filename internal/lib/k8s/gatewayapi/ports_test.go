package gatewayapi

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/link-society/krouter/internal/lib/k8s/compiled"
)

func TestAllocateIsStablePerGroup(t *testing.T) {
	allocator := newPortAllocator(10000, 10010, nil)

	first, err := allocator.Allocate("gw-1", 80, "HTTP")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	again, _ := allocator.Allocate("gw-1", 80, "HTTP")
	if first != again {
		t.Fatalf("same group must keep its port: %d != %d", first, again)
	}

	other, _ := allocator.Allocate("gw-2", 80, "HTTP")
	if other == first {
		t.Fatal("distinct gateways must not share an internal port (docs/spec/frontend.md)")
	}

	https, _ := allocator.Allocate("gw-1", 443, "HTTPS")
	if https == first {
		t.Fatal("HTTP and HTTPS groups must use different internal listeners (docs/spec/frontend.md)")
	}
}

func TestAllocateReconstructsFromServices(t *testing.T) {
	// docs/spec/frontend.md: allocations are persisted in generated Service state and
	// reconstructed after a control-plane restart.
	existing := []*corev1.Service{{
		ObjectMeta: metav1.ObjectMeta{
			Labels:      map[string]string{compiled.LabelGatewayUID: "gw-1"},
			Annotations: map[string]string{compiled.PortMapAnnotation: `{"80/HTTP":10005}`},
		},
	}}

	allocator := newPortAllocator(10000, 10010, existing)

	port, err := allocator.Allocate("gw-1", 80, "HTTP")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if port != 10005 {
		t.Fatalf("expected reconstructed port 10005, got %d", port)
	}

	fresh, _ := allocator.Allocate("gw-2", 80, "HTTP")
	if fresh == 10005 {
		t.Fatal("reconstructed ports must be reserved")
	}
}

func TestAllocateExhaustion(t *testing.T) {
	allocator := newPortAllocator(10000, 10001, nil)

	allocator.Allocate("gw-1", 80, "HTTP")
	allocator.Allocate("gw-1", 443, "HTTPS")

	if _, err := allocator.Allocate("gw-2", 80, "HTTP"); err == nil {
		t.Fatal("expected exhaustion error (docs/spec/failure-modes.md)")
	}
}
