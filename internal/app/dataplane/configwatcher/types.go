package configwatcher

import (
	corev1 "k8s.io/api/core/v1"
)

// RawConfig is one consistent read of the generated objects; it is the
// message this actor sends to the loader.
type RawConfig struct {
	ConfigMaps map[string]*corev1.ConfigMap
	Secrets    map[string]*corev1.Secret
}
