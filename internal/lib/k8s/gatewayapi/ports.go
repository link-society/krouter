package gatewayapi

import (
	"fmt"

	"encoding/json"

	corev1 "k8s.io/api/core/v1"

	"github.com/link-society/krouter/internal/lib/k8s/compiled"
)

// portAllocator assigns a unique internal listener port to each
// (Gateway UID, external port, protocol) group (docs/spec/frontend.md). Allocations are
// persisted as an annotation on the generated Service and reconstructed
// from cluster state on every sync, so a control-plane restart never
// renumbers an active allocation.
type portAllocator struct {
	min, max int
	used     map[int32]bool
	assigned map[string]int32 // "<uid>|<extPort>/<proto>"
}

func newPortAllocator(min, max int, existingServices []*corev1.Service) *portAllocator {
	a := &portAllocator{
		min:      min,
		max:      max,
		used:     map[int32]bool{},
		assigned: map[string]int32{},
	}

	for _, svc := range existingServices {
		uid := svc.Labels[compiled.LabelGatewayUID]
		raw := svc.Annotations[compiled.PortMapAnnotation]
		if uid == "" || raw == "" {
			continue
		}

		portMap := map[string]int32{}
		if err := json.Unmarshal([]byte(raw), &portMap); err != nil {
			continue
		}

		for key, port := range portMap {
			a.assigned[uid+"|"+key] = port
			a.used[port] = true
		}
	}

	return a
}

// Allocate returns the stable internal port for a listener group.
func (a *portAllocator) Allocate(gatewayUID string, extPort int32, protocol string) (int32, error) {
	key := fmt.Sprintf("%s|%d/%s", gatewayUID, extPort, protocol)

	if port, ok := a.assigned[key]; ok {
		return port, nil
	}

	for candidate := a.min; candidate <= a.max; candidate++ {
		port := int32(candidate)
		if a.used[port] {
			continue
		}

		a.used[port] = true
		a.assigned[key] = port

		return port, nil
	}

	return 0, fmt.Errorf("internal listener port range %d-%d exhausted", a.min, a.max)
}

// PortMap renders the persisted annotation value for one Gateway.
func (a *portAllocator) PortMap(gatewayUID string) string {
	portMap := map[string]int32{}
	prefix := gatewayUID + "|"

	for key, port := range a.assigned {
		if len(key) > len(prefix) && key[:len(prefix)] == prefix {
			portMap[key[len(prefix):]] = port
		}
	}

	raw, _ := json.Marshal(portMap)

	return string(raw)
}
