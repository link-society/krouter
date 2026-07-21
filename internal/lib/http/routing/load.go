package routing

import (
	"fmt"

	"encoding/json"

	corev1 "k8s.io/api/core/v1"

	"github.com/link-society/krouter/internal/lib/k8s/compiled"
)

// LoadGeneration verifies every object listed in a manifest before building
// tables: a generation activates only when it is complete, has the expected
// identity, and matches its checksums (docs/spec/configuration.md).
func LoadGeneration(
	manifest *compiled.Manifest,
	configMaps map[string]*corev1.ConfigMap,
	secrets map[string]*corev1.Secret,
) (*GatewayTable, error) {
	var gatewayConfig *compiled.GatewayConfig
	var routes []*compiled.RouteConfig
	var secret *corev1.Secret

	for _, ref := range manifest.Objects {
		switch ref.Kind {
		case compiled.ObjectKindConfigMap:
			cm, ok := configMaps[ref.Name]
			if !ok {
				return nil, fmt.Errorf("missing object %s", ref.Name)
			}

			if cm.Labels[compiled.LabelGatewayUID] != manifest.GatewayUID {
				return nil, fmt.Errorf("object %s has unexpected identity", ref.Name)
			}

			payload := []byte(cm.Data[compiled.DataKey])
			if compiled.ChecksumBytes(payload) != ref.Checksum {
				return nil, fmt.Errorf("checksum mismatch for %s", ref.Name)
			}

			switch cm.Labels[compiled.LabelRole] {
			case compiled.RoleGatewayCfg:
				gatewayConfig = &compiled.GatewayConfig{}
				if err := json.Unmarshal(payload, gatewayConfig); err != nil {
					return nil, fmt.Errorf("invalid gateway config %s: %w", ref.Name, err)
				}

			case compiled.RoleAttachment:
				route := &compiled.RouteConfig{}
				if err := json.Unmarshal(payload, route); err != nil {
					return nil, fmt.Errorf("invalid attachment %s: %w", ref.Name, err)
				}

				routes = append(routes, route)

			default:
				return nil, fmt.Errorf("object %s has unexpected role", ref.Name)
			}

		case compiled.ObjectKindSecret:
			obj, ok := secrets[ref.Name]
			if !ok {
				return nil, fmt.Errorf("missing secret %s", ref.Name)
			}

			if obj.Labels[compiled.LabelGatewayUID] != manifest.GatewayUID {
				return nil, fmt.Errorf("secret %s has unexpected identity", ref.Name)
			}

			if compiled.ChecksumSecret(obj.Data) != ref.Checksum {
				return nil, fmt.Errorf("checksum mismatch for secret %s", ref.Name)
			}

			secret = obj

		default:
			return nil, fmt.Errorf("unknown object kind %q", ref.Kind)
		}
	}

	if gatewayConfig == nil {
		return nil, fmt.Errorf("manifest lists no gateway configuration")
	}

	return BuildGatewayTable(manifest.Generation, gatewayConfig, routes, secret)
}
