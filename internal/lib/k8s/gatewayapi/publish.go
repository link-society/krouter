package gatewayapi

import (
	"context"

	"slices"

	"encoding/json"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/link-society/krouter/internal/lib/k8s/compiled"
)

// publishGeneration compiles and publishes one Gateway's configuration
// following the atomic publication protocol (docs/spec/configuration.md): immutable
// generation objects first, then the manifest commit marker.
func (r *Engine) publishGeneration(
	ctx context.Context,
	w *world,
	gw *gatewayv1.Gateway,
	listeners []*listenerState,
	outcomes []*routeParentOutcome,
	clientCert backendClientCert,
) (string, error) {
	uid := string(gw.UID)

	gatewayConfig := &compiled.GatewayConfig{
		UID:       uid,
		Namespace: gw.Namespace,
		Name:      gw.Name,
		Listeners: []compiled.Listener{},
	}

	secretData := map[string][]byte{}

	// Backend client certificate (docs/spec/traffic.md Backend TLS).
	if clientCert.resolved && clientCert.certPEM != nil {
		gatewayConfig.BackendClientCert = true
		secretData[compiled.BackendClientCertKey] = clientCert.certPEM
		secretData[compiled.BackendClientKeyKey] = clientCert.keyPEM
	}

	for _, lst := range listeners {
		if !lst.valid() {
			continue
		}

		entry := compiled.Listener{
			Name:         lst.effectiveName(),
			Port:         int32(lst.spec.Port),
			InternalPort: lst.internalPort,
			Protocol:     string(lst.spec.Protocol),
			// TLS-protocol listeners with HasTLS terminate at the gateway
			// (docs/spec/traffic.md TLS passthrough and termination).
			HasTLS: lst.spec.Protocol == gatewayv1.HTTPSProtocolType ||
				listenerTerminatesTLS(lst.spec),
			// Frontend client certificate validation
			// (docs/spec/security.md).
			ClientCAMode: lst.clientCAMode,
		}

		if lst.spec.Hostname != nil {
			entry.Hostname = string(*lst.spec.Hostname)
		}

		for key, value := range lst.certData {
			secretData[key] = value
		}

		gatewayConfig.Listeners = append(gatewayConfig.Listeners, entry)
	}

	gatewayPayload := compiled.MarshalPayload(gatewayConfig)

	// A route may attach through several parentRefs to the same Gateway
	// (e.g. two sectionNames): the attachment payload is one per route, so
	// their listener sets are merged (docs/spec/configuration.md).
	routeConfigs := map[string]*compiled.RouteConfig{}
	for _, outcome := range outcomes {
		if outcome.config == nil || len(outcome.config.Listeners) == 0 {
			continue
		}

		existing, ok := routeConfigs[outcome.config.UID]
		if !ok {
			routeConfigs[outcome.config.UID] = outcome.config
			continue
		}

		for _, name := range outcome.config.Listeners {
			if !slices.Contains(existing.Listeners, name) {
				existing.Listeners = append(existing.Listeners, name)
			}
		}
	}

	attachments := map[string][]byte{}
	for uid, config := range routeConfigs {
		attachments[uid] = compiled.MarshalPayload(config)
	}

	secretChecksum := ""
	if len(secretData) > 0 {
		secretChecksum = compiled.ChecksumSecret(secretData)
	}

	generation := compiled.GenerationID(gatewayPayload, attachments, secretChecksum)

	manifest := &compiled.Manifest{
		GatewayUID: uid,
		Generation: generation,
		Objects: []compiled.ObjectRef{
			{
				Kind:     compiled.ObjectKindConfigMap,
				Name:     compiled.GatewayConfigName(uid, generation),
				Checksum: compiled.ChecksumBytes(gatewayPayload),
			},
		},
	}

	// 1. Write immutable generation objects (docs/spec/configuration.md step 2).
	err := r.ensureImmutableCM(ctx,
		compiled.GatewayConfigName(uid, generation),
		compiled.ObjectLabels(uid, generation, compiled.RoleGatewayCfg),
		gatewayPayload,
	)
	if err != nil {
		return "", err
	}

	for routeUID, payload := range attachments {
		name := compiled.AttachmentName(uid, routeUID, generation)

		labels := compiled.ObjectLabels(uid, generation, compiled.RoleAttachment)
		labels[compiled.LabelSourceUID] = routeUID

		if err := r.ensureImmutableCM(ctx, name, labels, payload); err != nil {
			return "", err
		}

		manifest.Objects = append(manifest.Objects, compiled.ObjectRef{
			Kind:     compiled.ObjectKindConfigMap,
			Name:     name,
			Checksum: compiled.ChecksumBytes(payload),
		})
	}

	if len(secretData) > 0 {
		name := compiled.TLSSecretName(uid, generation)

		if err := r.ensureGeneratedSecret(ctx, name, uid, generation, secretData); err != nil {
			return "", err
		}

		manifest.Objects = append(manifest.Objects, compiled.ObjectRef{
			Kind:     compiled.ObjectKindSecret,
			Name:     name,
			Checksum: secretChecksum,
		})
	}

	// 2. Commit through the manifest ConfigMap (docs/spec/configuration.md step 4).
	if err := r.ensureManifest(ctx, uid, manifest); err != nil {
		return "", err
	}

	// 3. Garbage-collect generations that are neither desired, previous,
	// nor still applied by a pod (docs/spec/configuration.md retention).
	r.gcGenerations(ctx, w, uid, manifest)

	return generation, nil
}

func (r *Engine) ensureImmutableCM(
	ctx context.Context,
	name string,
	labels map[string]string,
	payload []byte,
) error {
	cms := r.client.CoreV1().ConfigMaps(r.settings.SystemNamespace)

	_, err := cms.Get(ctx, name, metav1.GetOptions{})
	if err == nil {
		return nil
	}

	if !errors.IsNotFound(err) {
		return err
	}

	_, err = cms.Create(ctx, &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels},
		Immutable:  ptr.To(true),
		Data:       map[string]string{compiled.DataKey: string(payload)},
	}, metav1.CreateOptions{})

	if errors.IsAlreadyExists(err) {
		return nil
	}

	return err
}

func (r *Engine) ensureGeneratedSecret(
	ctx context.Context,
	name, gatewayUID, generation string,
	data map[string][]byte,
) error {
	secrets := r.client.CoreV1().Secrets(r.settings.SystemNamespace)

	_, err := secrets.Get(ctx, name, metav1.GetOptions{})
	if err == nil {
		return nil
	}

	if !errors.IsNotFound(err) {
		return err
	}

	_, err = secrets.Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:   name,
			Labels: compiled.ObjectLabels(gatewayUID, generation, compiled.RoleTLS),
		},
		Immutable: ptr.To(true),
		Data:      data,
	}, metav1.CreateOptions{})

	if errors.IsAlreadyExists(err) {
		return nil
	}

	return err
}

func (r *Engine) ensureManifest(
	ctx context.Context,
	gatewayUID string,
	manifest *compiled.Manifest,
) error {
	cms := r.client.CoreV1().ConfigMaps(r.settings.SystemNamespace)
	name := compiled.ManifestName(gatewayUID)

	existing, err := cms.Get(ctx, name, metav1.GetOptions{})
	if errors.IsNotFound(err) {
		payload, _ := json.Marshal(manifest)

		labels := compiled.BaseLabels(gatewayUID)
		labels[compiled.LabelRole] = compiled.RoleManifest

		_, err := cms.Create(ctx, &corev1.ConfigMap{
			ObjectMeta: metav1.ObjectMeta{Name: name, Labels: labels},
			Data:       map[string]string{compiled.ManifestKey: string(payload)},
		}, metav1.CreateOptions{})

		return err
	}
	if err != nil {
		return err
	}

	previous := &compiled.Manifest{}
	if err := json.Unmarshal([]byte(existing.Data[compiled.ManifestKey]), previous); err != nil {
		// A corrupted manifest is replaced wholesale: the generation
		// objects it pointed at are re-collected by the next GC pass
		// (docs/spec/configuration.md).
		*previous = compiled.Manifest{}
	}

	if previous.Generation == manifest.Generation {
		manifest.Previous = previous.Previous
	} else {
		manifest.Previous = previous.Generation
	}

	payload, _ := json.Marshal(manifest)
	desired := map[string]string{compiled.ManifestKey: string(payload)}

	if equalStringMaps(existing.Data, desired) &&
		existing.Labels[compiled.LabelRole] == compiled.RoleManifest {
		return nil
	}

	// Repair any drift idempotently, including manual edits (docs/spec/failure-modes.md).
	updated := existing.DeepCopy()
	updated.Data = desired

	if updated.Labels == nil {
		updated.Labels = map[string]string{}
	}
	for key, value := range compiled.BaseLabels(gatewayUID) {
		updated.Labels[key] = value
	}
	updated.Labels[compiled.LabelRole] = compiled.RoleManifest

	_, err = cms.Update(ctx, updated, metav1.UpdateOptions{})

	return err
}

// gcGenerations removes generation objects that are no longer desired,
// previous, or applied by any data-plane pod.
func (r *Engine) gcGenerations(ctx context.Context, w *world, gatewayUID string, manifest *compiled.Manifest) {
	if !w.acks.AllAcked(gatewayUID, manifest.Generation) {
		return
	}

	keep := map[string]bool{manifest.Generation: true}
	if manifest.Previous != "" {
		keep[manifest.Previous] = true
	}
	for generation := range w.acks.AckedGenerations(gatewayUID) {
		keep[generation] = true
	}

	for i := range w.generatedCMs {
		cm := &w.generatedCMs[i]

		if cm.Labels[compiled.LabelGatewayUID] != gatewayUID {
			continue
		}

		generation := cm.Labels[compiled.LabelGeneration]
		if generation == "" || keep[generation] {
			continue
		}

		r.client.CoreV1().ConfigMaps(r.settings.SystemNamespace).
			Delete(ctx, cm.Name, metav1.DeleteOptions{})
	}

	for i := range w.generatedSecrets {
		secret := &w.generatedSecrets[i]

		if secret.Labels[compiled.LabelGatewayUID] != gatewayUID {
			continue
		}

		generation := secret.Labels[compiled.LabelGeneration]
		if generation == "" || keep[generation] {
			continue
		}

		r.client.CoreV1().Secrets(r.settings.SystemNamespace).
			Delete(ctx, secret.Name, metav1.DeleteOptions{})
	}
}

// gcOrphans removes central generated configuration for Gateways that no
// longer exist; cross-namespace owner references are not valid, so this is
// explicit garbage collection (docs/spec/configuration.md).
func (r *Engine) gcOrphans(ctx context.Context, w *world, ownedUIDs map[string]bool) {
	for i := range w.generatedCMs {
		cm := &w.generatedCMs[i]

		uid := cm.Labels[compiled.LabelGatewayUID]
		if uid != "" && !ownedUIDs[uid] {
			r.client.CoreV1().ConfigMaps(r.settings.SystemNamespace).
				Delete(ctx, cm.Name, metav1.DeleteOptions{})
		}
	}

	for i := range w.generatedSecrets {
		secret := &w.generatedSecrets[i]

		uid := secret.Labels[compiled.LabelGatewayUID]
		if uid != "" && !ownedUIDs[uid] {
			r.client.CoreV1().Secrets(r.settings.SystemNamespace).
				Delete(ctx, secret.Name, metav1.DeleteOptions{})
		}
	}
}

func equalStringMaps(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}

	for key, value := range a {
		if b[key] != value {
			return false
		}
	}

	return true
}
