// Package client provides the Kubernetes API client constructors.
package client

import (
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	extclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"

	gwclient "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned"
)

func NewRestConfig() (*rest.Config, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}

	config.QPS = 50
	config.Burst = 100

	return config, nil
}

func NewKubernetesClient(config *rest.Config) (kubernetes.Interface, error) {
	return kubernetes.NewForConfig(config)
}

func NewGatewayClient(config *rest.Config) (gwclient.Interface, error) {
	return gwclient.NewForConfig(config)
}

func NewExtensionsClient(config *rest.Config) (extclient.Interface, error) {
	return extclient.NewForConfig(config)
}
