// Package gatewayapi implements the Gateway API semantics of the control
// plane: validation, attachment, compilation, generation publication,
// frontend provisioning and status reporting. It is deliberately not an
// actor — it is the domain engine driven by the reconciler actor. Every
// operation is idempotent and tolerant of duplicate events (docs/spec/failure-modes.md).
package gatewayapi

import (
	"context"
	"fmt"
	"log/slog"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	corev1 "k8s.io/api/core/v1"

	extclient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gwclient "sigs.k8s.io/gateway-api/pkg/client/clientset/versioned"

	"github.com/link-society/krouter/internal/config"
	"github.com/link-society/krouter/internal/config/hclparams"
	"github.com/link-society/krouter/internal/lib/k8s/compiled"
)

// Engine is the single-writer reconciliation engine. Exactly one actor
// drives it, so no synchronization is needed.
type Engine struct {
	settings  *config.Settings
	client    kubernetes.Interface
	gwClient  gwclient.Interface
	extClient extclient.Interface

	cachedBundleVersion string
}

func NewEngine(
	cfg *config.Settings,
	client kubernetes.Interface,
	gwClient gwclient.Interface,
	extClient extclient.Interface,
) *Engine {
	return &Engine{
		settings:  cfg,
		client:    client,
		gwClient:  gwClient,
		extClient: extClient,
	}
}

func logSyncError(step, subject string, err error) {
	slog.Error("reconciliation step failed", "step", step, "subject", subject, "error", err)
}

// Sync runs one level-triggered reconciliation pass: it gathers a full
// cluster snapshot, validates Gateway API semantics, compiles and publishes
// configuration generations, provisions frontends and writes statuses.
// It returns the topology projection of the pass for the dashboard, or
// nil when the cluster snapshot could not be gathered.
func (r *Engine) Sync(ctx context.Context, acks AckState) *Topology {
	w, err := r.gatherWorld(ctx, acks)
	if err != nil {
		logSyncError("gather", "world", err)
		return nil
	}

	return r.sync(ctx, w)
}

func (r *Engine) gatherWorld(ctx context.Context, acks AckState) (*world, error) {
	w := &world{
		namespaces: map[string]map[string]string{},
		services:   map[string]*corev1.Service{},
		acks:       acks,
	}

	classList, err := r.gwClient.GatewayV1().GatewayClasses().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	w.classes = classList.Items

	gatewayList, err := r.gwClient.GatewayV1().Gateways(metav1.NamespaceAll).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	w.gateways = gatewayList.Items

	routeList, err := r.gwClient.GatewayV1().HTTPRoutes(metav1.NamespaceAll).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	w.routes = routeList.Items

	grpcRouteList, err := r.gwClient.GatewayV1().GRPCRoutes(metav1.NamespaceAll).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	w.grpcRoutes = grpcRouteList.Items

	// TCPRoute and TLSRoute require the Experimental-channel CRDs; their
	// absence MUST NOT crash or degrade HTTP behavior (docs/spec/overview.md).
	tcpRouteList, err := r.gwClient.GatewayV1alpha2().TCPRoutes(metav1.NamespaceAll).
		List(ctx, metav1.ListOptions{})
	if err == nil {
		w.tcpRoutes = tcpRouteList.Items
	} else if !apierrors.IsNotFound(err) {
		return nil, err
	}

	tlsRouteList, err := r.gwClient.GatewayV1alpha2().TLSRoutes(metav1.NamespaceAll).
		List(ctx, metav1.ListOptions{})
	if err == nil {
		w.tlsRoutes = tlsRouteList.Items
	} else if !apierrors.IsNotFound(err) {
		return nil, err
	}

	udpRouteList, err := r.gwClient.GatewayV1alpha2().UDPRoutes(metav1.NamespaceAll).
		List(ctx, metav1.ListOptions{})
	if err == nil {
		w.udpRoutes = udpRouteList.Items
	} else if !apierrors.IsNotFound(err) {
		return nil, err
	}

	backendTLSList, err := r.gwClient.GatewayV1().BackendTLSPolicies(metav1.NamespaceAll).
		List(ctx, metav1.ListOptions{})
	if err == nil {
		w.backendTLSPolicies = backendTLSList.Items
	} else if !apierrors.IsNotFound(err) {
		return nil, err
	}

	listenerSetList, err := r.gwClient.GatewayV1().ListenerSets(metav1.NamespaceAll).
		List(ctx, metav1.ListOptions{})
	if err == nil {
		w.listenerSets = listenerSetList.Items
	} else if !apierrors.IsNotFound(err) {
		return nil, err
	}

	grantList, err := r.gwClient.GatewayV1beta1().ReferenceGrants(metav1.NamespaceAll).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	w.grants = grantList.Items

	nsList, err := r.client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	for _, ns := range nsList.Items {
		w.namespaces[ns.Name] = ns.Labels
	}

	svcList, err := r.client.CoreV1().Services(metav1.NamespaceAll).
		List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	for i := range svcList.Items {
		svc := &svcList.Items[i]
		w.services[fmtKey(svc.Namespace, svc.Name)] = svc

		if svc.Labels[compiled.LabelManagedBy] == compiled.ManagedByValue {
			w.krouterServices = append(w.krouterServices, svc)
		}
	}

	selector := compiled.LabelManagedBy + "=" + compiled.ManagedByValue

	cmList, err := r.client.CoreV1().ConfigMaps(r.settings.SystemNamespace).
		List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return nil, err
	}
	w.generatedCMs = cmList.Items

	secretList, err := r.client.CoreV1().Secrets(r.settings.SystemNamespace).
		List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return nil, err
	}
	w.generatedSecrets = secretList.Items

	w.bundleVersion = r.bundleVersion(ctx)

	return w, nil
}

func (r *Engine) bundleVersion(ctx context.Context) string {
	if r.cachedBundleVersion != "" {
		return r.cachedBundleVersion
	}

	crd, err := r.extClient.ApiextensionsV1().CustomResourceDefinitions().
		Get(ctx, "gateways.gateway.networking.k8s.io", metav1.GetOptions{})
	if err != nil {
		return ""
	}

	r.cachedBundleVersion = crd.Annotations["gateway.networking.k8s.io/bundle-version"]

	return r.cachedBundleVersion
}

func (r *Engine) sync(ctx context.Context, w *world) *Topology {
	// GatewayClasses: reconcile exactly the classes whose controllerName
	// matches this installation (docs/spec/deployment.md); never touch foreign classes.
	ownedClasses := map[string]bool{}
	for i := range w.classes {
		class := &w.classes[i]

		if string(class.Spec.ControllerName) != r.settings.ControllerName {
			continue
		}

		ownedClasses[class.Name] = true

		if err := r.writeClassStatus(ctx, w, class.Name); err != nil {
			logSyncError("gatewayclass status", class.Name, err)
		}
	}

	allocator := newPortAllocator(
		r.settings.InternalPortMin, r.settings.InternalPortMax, w.krouterServices)

	r.resolveBackendTLSPolicies(ctx, w)

	ownedUIDs := map[string]bool{}
	routeOutcomes := map[string][]*routeParentOutcome{}
	topo := newTopologyBuilder(w.services)

	for i := range w.gateways {
		gw := &w.gateways[i]

		if !ownedClasses[string(gw.Spec.GatewayClassName)] {
			continue
		}

		ownedUIDs[string(gw.UID)] = true

		r.reconcileGateway(ctx, w, gw, allocator, routeOutcomes, topo)
	}

	r.writeRouteStatuses(ctx, w, routeOutcomes)

	collectBackendTLSAncestors(w, routeOutcomes)
	r.writeBackendTLSPolicyStatuses(ctx, w)

	r.gcOrphans(ctx, w, ownedUIDs)

	return topo.finish()
}

func (r *Engine) reconcileGateway(
	ctx context.Context,
	w *world,
	gw *gatewayv1.Gateway,
	allocator *portAllocator,
	routeOutcomes map[string][]*routeParentOutcome,
	topo *topologyBuilder,
) {
	infra, paramsErr := r.loadInfraParams(ctx, gw)

	if paramsErr != nil {
		accepted, programmed := gatewayConditions(gw, paramsErr, false, 0)

		input := gatewayStatusInput{
			accepted:   accepted,
			programmed: programmed,
		}

		topo.addGateway(gw, input, "")

		if err := r.writeGatewayStatus(ctx, gw, input); err != nil {
			logSyncError("gateway status", fmtKey(gw.Namespace, gw.Name), err)
		}

		return
	}

	listenerSets := selectListenerSets(w, gw)

	listeners := r.validateListeners(ctx, w, gw, listenerSets, allocator)

	outcomes := r.attachRoutes(w, gw, listenerSets, listeners)
	outcomes = append(outcomes, r.attachGRPCRoutes(w, gw, listenerSets, listeners)...)
	outcomes = append(outcomes, r.attachTCPRoutes(w, gw, listenerSets, listeners)...)
	outcomes = append(outcomes, r.attachTLSRoutes(w, gw, listenerSets, listeners)...)
	outcomes = append(outcomes, r.attachUDPRoutes(w, gw, listenerSets, listeners)...)

	for _, outcome := range outcomes {
		meta := outcome.routeMeta()
		key := outcomeKey(outcome.routeKind(), meta.Namespace, meta.Name)
		routeOutcomes[key] = append(routeOutcomes[key], outcome)

		topo.addRouteParent(gw, outcome)
	}

	validListeners := 0
	for _, lst := range listeners {
		if lst.valid() {
			validListeners++
		}
	}

	generation, err := r.publishGeneration(ctx, w, gw, listeners, outcomes)
	if err != nil {
		logSyncError("publish generation", fmtKey(gw.Namespace, gw.Name), err)
		return
	}

	address := ""
	ports := desiredServicePorts(listeners, infra)
	if len(ports) > 0 {
		address, err = r.ensureFrontend(ctx, w, gw, ports, infra,
			allocator.PortMap(string(gw.UID)))
		if err != nil {
			logSyncError("frontend", fmtKey(gw.Namespace, gw.Name), err)
		}
	}

	acked := validListeners > 0 && w.acks.AllAcked(string(gw.UID), generation)

	accepted, programmed := gatewayConditions(gw, nil, acked, validListeners)

	// ListenerSet statuses and the attachedListenerSets count
	// (docs/spec/frontend.md Listener sets, docs/spec/status.md).
	r.writeListenerSetStatuses(ctx, listenerSets, listeners, acked)

	// A set counts as attached when its Accepted condition is True: gate
	// passed and at least one of its listeners is valid.
	attachedSets := int32(0)
	for _, set := range listenerSets {
		if !set.accepted {
			continue
		}

		for _, lst := range listeners {
			if lst.set == set.set && lst.valid() {
				attachedSets++
				break
			}
		}
	}

	input := gatewayStatusInput{
		accepted:     accepted,
		programmed:   programmed,
		address:      address,
		listeners:    listeners,
		gatewayAcked: acked,
	}

	if gw.Spec.AllowedListeners != nil {
		input.attachedListenerSets = &attachedSets
	}

	topo.addGateway(gw, input, generation)

	if err := r.writeGatewayStatus(ctx, gw, input); err != nil {
		logSyncError("gateway status", fmtKey(gw.Namespace, gw.Name), err)
	}
}

// loadInfraParams resolves Gateway.spec.infrastructure.parametersRef
// (docs/spec/parameters.md). Any failure surfaces as InvalidParameters and never crashes
// the controller (docs/spec/parameters.md).
func (r *Engine) loadInfraParams(
	ctx context.Context,
	gw *gatewayv1.Gateway,
) (*hclparams.InfraParams, error) {
	defaults, _ := hclparams.ParseInfra("version = 1\n")

	infrastructure := gw.Spec.Infrastructure
	if infrastructure == nil || infrastructure.ParametersRef == nil {
		return defaults, nil
	}

	ref := infrastructure.ParametersRef
	if ref.Kind != "ConfigMap" || ref.Group != "" {
		return nil, errInvalidParams("parametersRef must target a core ConfigMap")
	}

	cm, err := r.client.CoreV1().ConfigMaps(gw.Namespace).
		Get(ctx, string(ref.Name), metav1.GetOptions{})
	if err != nil {
		return nil, errInvalidParams("parameters ConfigMap %q not found", ref.Name)
	}

	src, ok := cm.Data["krouter.hcl"]
	if !ok {
		return nil, errInvalidParams("parameters ConfigMap %q has no krouter.hcl key", ref.Name)
	}

	params, err := hclparams.ParseInfra(src)
	if err != nil {
		return nil, errInvalidParams("invalid parameters: %v", err)
	}

	return params, nil
}

func errInvalidParams(format string, args ...any) error {
	return &paramsError{message: fmt.Sprintf(format, args...)}
}
