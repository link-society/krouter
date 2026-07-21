package gatewayapi

import (
	"context"
	"fmt"

	"sort"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/link-society/krouter/internal/config/hclparams"
	"github.com/link-society/krouter/internal/lib/k8s/compiled"
)

// frontendName is the generated Service name for a Gateway (docs/spec/frontend.md).
// The UID suffix disambiguates delete-and-recreate (docs/spec/configuration.md).
func frontendName(gw *gatewayv1.Gateway) string {
	name := "krouter-" + gw.Name
	if len(name) > 54 {
		name = name[:54]
	}

	return name + "-" + string(gw.UID)[:8]
}

// desiredServicePorts groups valid listeners by (external port, protocol)
// (docs/spec/frontend.md) and applies requested NodePorts (docs/spec/parameters.md).
func desiredServicePorts(
	listeners []*listenerState,
	infra *hclparams.InfraParams,
) []servicePort {
	seen := map[string]*servicePort{}
	var order []string

	for _, lst := range listeners {
		if !lst.valid() {
			continue
		}

		key := fmt.Sprintf("p%d-%s", lst.spec.Port, protoSuffix(string(lst.spec.Protocol)))

		port, ok := seen[key]
		if !ok {
			port = &servicePort{
				name:         key,
				externalPort: int32(lst.spec.Port),
				internalPort: lst.internalPort,
			}
			seen[key] = port
			order = append(order, key)
		}

		if requested, ok := infra.Service.NodePorts[string(lst.spec.Name)]; ok {
			port.nodePort = requested
		}
	}

	sort.Strings(order)

	ports := make([]servicePort, 0, len(order))
	for _, key := range order {
		ports = append(ports, *seen[key])
	}

	return ports
}

func protoSuffix(protocol string) string {
	switch protocol {
	case string(gatewayv1.HTTPSProtocolType):
		return "https"

	default:
		return "http"
	}
}

// ensureFrontend reconciles the per-Gateway Service and its mirrored
// EndpointSlices (docs/spec/frontend.md). It returns the Service's cluster IP for the
// Gateway address status.
func (r *Engine) ensureFrontend(
	ctx context.Context,
	w *world,
	gw *gatewayv1.Gateway,
	ports []servicePort,
	infra *hclparams.InfraParams,
	portMapJSON string,
) (string, error) {
	services := r.client.CoreV1().Services(gw.Namespace)
	name := frontendName(gw)

	ownerRef := metav1.OwnerReference{
		APIVersion: gatewayv1.GroupVersion.String(),
		Kind:       "Gateway",
		Name:       gw.Name,
		UID:        gw.UID,
		Controller: ptr.To(true),
	}

	annotations := map[string]string{compiled.PortMapAnnotation: portMapJSON}
	for key, value := range infra.Service.Annotations {
		annotations[key] = value
	}

	existing, err := services.Get(ctx, name, metav1.GetOptions{})

	desired := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:            name,
			Namespace:       gw.Namespace,
			Labels:          compiled.BaseLabels(string(gw.UID)),
			Annotations:     annotations,
			OwnerReferences: []metav1.OwnerReference{ownerRef},
		},
		Spec: corev1.ServiceSpec{
			Type: corev1.ServiceType(infra.Service.Type),
		},
	}

	if infra.Service.ExternalTrafficPolicy != "" &&
		desired.Spec.Type != corev1.ServiceTypeClusterIP {
		desired.Spec.ExternalTrafficPolicy =
			corev1.ServiceExternalTrafficPolicy(infra.Service.ExternalTrafficPolicy)
	}

	if infra.Service.LoadBalancerClass != nil &&
		desired.Spec.Type == corev1.ServiceTypeLoadBalancer {
		desired.Spec.LoadBalancerClass = infra.Service.LoadBalancerClass
	}

	for _, port := range ports {
		entry := corev1.ServicePort{
			Name:       port.name,
			Protocol:   corev1.ProtocolTCP,
			Port:       port.externalPort,
			TargetPort: intstr.FromInt32(port.internalPort),
		}

		if desired.Spec.Type != corev1.ServiceTypeClusterIP {
			entry.NodePort = port.nodePort

			// Keep the Kubernetes-allocated NodePort stable across syncs
			// when none is explicitly requested.
			if entry.NodePort == 0 && existing != nil {
				for _, current := range existing.Spec.Ports {
					if current.Name == entry.Name {
						entry.NodePort = current.NodePort
						break
					}
				}
			}
		}

		desired.Spec.Ports = append(desired.Spec.Ports, entry)
	}

	if errors.IsNotFound(err) {
		created, err := services.Create(ctx, desired, metav1.CreateOptions{})
		if err != nil {
			return "", err
		}

		return created.Spec.ClusterIP, r.ensureEndpointSlice(ctx, w, gw, created, ports)
	}
	if err != nil {
		return "", err
	}

	updated := existing.DeepCopy()
	updated.Labels = desired.Labels
	updated.Annotations = desired.Annotations
	updated.OwnerReferences = desired.OwnerReferences
	updated.Spec.Type = desired.Spec.Type
	updated.Spec.Ports = desired.Spec.Ports
	updated.Spec.Selector = nil
	updated.Spec.ExternalTrafficPolicy = desired.Spec.ExternalTrafficPolicy

	if !serviceEqual(existing, updated) {
		updated, err = services.Update(ctx, updated, metav1.UpdateOptions{})
		if err != nil {
			return "", err
		}
	}

	return updated.Spec.ClusterIP, r.ensureEndpointSlice(ctx, w, gw, updated, ports)
}

func serviceEqual(a, b *corev1.Service) bool {
	return equalStringMaps(a.Labels, b.Labels) &&
		equalStringMaps(a.Annotations, b.Annotations) &&
		a.Spec.Type == b.Spec.Type &&
		a.Spec.ExternalTrafficPolicy == b.Spec.ExternalTrafficPolicy &&
		len(a.Spec.Selector) == 0 == (len(b.Spec.Selector) == 0) &&
		servicePortsEqual(a.Spec.Ports, b.Spec.Ports) &&
		len(a.OwnerReferences) == len(b.OwnerReferences)
}

func servicePortsEqual(a, b []corev1.ServicePort) bool {
	if len(a) != len(b) {
		return false
	}

	for i := range a {
		if a[i].Name != b[i].Name ||
			a[i].Port != b[i].Port ||
			a[i].TargetPort != b[i].TargetPort ||
			a[i].NodePort != b[i].NodePort {
			return false
		}
	}

	return true
}

// ensureEndpointSlice mirrors ready data-plane pods into the generated
// Service's EndpointSlice (docs/spec/frontend.md).
func (r *Engine) ensureEndpointSlice(
	ctx context.Context,
	w *world,
	gw *gatewayv1.Gateway,
	svc *corev1.Service,
	ports []servicePort,
) error {
	slices := r.client.DiscoveryV1().EndpointSlices(gw.Namespace)
	name := svc.Name + "-krouter"

	labels := compiled.BaseLabels(string(gw.UID))
	labels[discoveryv1.LabelServiceName] = svc.Name
	labels[discoveryv1.LabelManagedBy] = compiled.EndpointSliceManagedBy

	desired := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: gw.Namespace,
			Labels:    labels,
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "v1",
				Kind:       "Service",
				Name:       svc.Name,
				UID:        svc.UID,
				Controller: ptr.To(true),
			}},
		},
		AddressType: discoveryv1.AddressTypeIPv4,
	}

	for _, port := range ports {
		desired.Ports = append(desired.Ports, discoveryv1.EndpointPort{
			Name:     ptr.To(port.name),
			Protocol: ptr.To(corev1.ProtocolTCP),
			Port:     ptr.To(port.internalPort),
		})
	}

	// Mirror ready pods only: unhealthy pods stop receiving new Service
	// traffic (docs/spec/status.md, docs/spec/failure-modes.md). Node names enable
	// externalTrafficPolicy: Local (docs/spec/frontend.md).
	podNames := make([]string, 0, len(w.acks.Pods))
	for podName := range w.acks.Pods {
		podNames = append(podNames, podName)
	}
	sort.Strings(podNames)

	for _, podName := range podNames {
		pod := w.acks.Pods[podName]
		if !pod.Healthy {
			continue
		}

		desired.Endpoints = append(desired.Endpoints, discoveryv1.Endpoint{
			Addresses: []string{pod.IP},
			NodeName:  ptr.To(pod.NodeName),
			Conditions: discoveryv1.EndpointConditions{
				Ready: ptr.To(true),
			},
		})
	}

	existing, err := slices.Get(ctx, name, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		_, err := slices.Create(ctx, desired, metav1.CreateOptions{})

		return err
	}
	if err != nil {
		return err
	}

	updated := existing.DeepCopy()
	updated.Labels = desired.Labels
	updated.OwnerReferences = desired.OwnerReferences
	updated.AddressType = desired.AddressType
	updated.Ports = desired.Ports
	updated.Endpoints = desired.Endpoints

	if endpointSliceEqual(existing, updated) {
		return nil
	}

	_, err = slices.Update(ctx, updated, metav1.UpdateOptions{})

	return err
}

func endpointSliceEqual(a, b *discoveryv1.EndpointSlice) bool {
	if !equalStringMaps(a.Labels, b.Labels) ||
		len(a.Ports) != len(b.Ports) ||
		len(a.Endpoints) != len(b.Endpoints) {
		return false
	}

	for i := range a.Ports {
		if !ptr.Equal(a.Ports[i].Name, b.Ports[i].Name) ||
			!ptr.Equal(a.Ports[i].Port, b.Ports[i].Port) {
			return false
		}
	}

	for i := range a.Endpoints {
		if len(a.Endpoints[i].Addresses) != len(b.Endpoints[i].Addresses) ||
			a.Endpoints[i].Addresses[0] != b.Endpoints[i].Addresses[0] ||
			!ptr.Equal(a.Endpoints[i].NodeName, b.Endpoints[i].NodeName) ||
			!ptr.Equal(a.Endpoints[i].Conditions.Ready, b.Endpoints[i].Conditions.Ready) {
			return false
		}
	}

	return true
}
