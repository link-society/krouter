package gatewayapi

import (
	"encoding/json"
	"fmt"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/link-society/krouter/internal/extensions/auth"
	"github.com/link-society/krouter/internal/extensions/ratelimiting"
	"github.com/link-society/krouter/internal/extensions/waf"
	"github.com/link-society/krouter/internal/lib/k8s/compiled"
)

// reasonInvalidExtensionRef degrades ResolvedRefs when an ExtensionRef
// target is broken: the filter type is supported, its target is not
// (docs/spec/extensions.md Resolution and status).
const reasonInvalidExtensionRef = "InvalidExtensionRef"

// ruleExtensions is the compiled extension configuration of one route
// rule (docs/spec/extensions.md).
type ruleExtensions struct {
	rateLimit *compiled.RateLimit
	waf       string
	auth      *compiled.Auth
	invalid   bool
}

// compileExtensions resolves the ExtensionRef filters of one rule in
// filter list order (docs/spec/extensions.md Resolution and status):
// `ratelimit.hcl` and `auth.hcl` documents merge attribute by attribute.
//
// A reference outside core ConfigMaps and Secrets returns an error,
// rejecting the route with UnsupportedValue. A broken target (missing
// object, misplaced key, invalid document, incomplete merge) keeps the
// route accepted but degrades ResolvedRefs to InvalidExtensionRef and
// marks the rule fail-closed: matching requests are answered 500, per
// the upstream unresolvable-filter contract.
func (r *Engine) compileExtensions(
	w *world,
	namespace string,
	refs []gatewayv1.LocalObjectReference,
	grpcRoute bool,
	outcome *routeParentOutcome,
) (ruleExtensions, error) {
	var ext ruleExtensions
	if len(refs) == 0 {
		return ext, nil
	}

	invalidate := func(message string) {
		outcome.refsResolved = false
		outcome.refsReason = reasonInvalidExtensionRef
		outcome.refsMessage = message
		ext.invalid = true
		ext.rateLimit = nil
		ext.waf = ""
		ext.auth = nil
	}

	var rateLimitDocs []*ratelimiting.Document
	var wafDocs []*waf.Document
	var authDocs []*auth.Document
	var authSecretUIDs []string

	for _, ref := range refs {
		if string(ref.Group) != "" ||
			(string(ref.Kind) != "ConfigMap" && string(ref.Kind) != "Secret") {
			return ext, fmt.Errorf(
				"unsupported extensionRef kind %s/%s", ref.Group, ref.Kind)
		}

		if string(ref.Kind) == "Secret" {
			secret, err := w.extensionSecret(namespace, string(ref.Name))
			if err != nil {
				invalidate(fmt.Sprintf(
					"extension Secret %s: %v", nsName(namespace, ref.Name), err))
				return ext, nil
			}

			// Enforcement keys in a Secret are misplaced
			// (docs/spec/extensions.md kind and key matrix).
			if _, has := secret.Data[compiled.RateLimitKey]; has {
				invalidate(fmt.Sprintf(
					"extension Secret %s carries %s: enforcement keys live in ConfigMaps",
					nsName(namespace, ref.Name), compiled.RateLimitKey))
				return ext, nil
			}

			if _, has := secret.Data[compiled.WAFKey]; has {
				invalidate(fmt.Sprintf(
					"extension Secret %s carries %s: enforcement keys live in ConfigMaps",
					nsName(namespace, ref.Name), compiled.WAFKey))
				return ext, nil
			}

			authSrc, hasAuth := secret.Data[compiled.AuthKey]
			if !hasAuth {
				invalidate(fmt.Sprintf(
					"extension Secret %s carries no %s",
					nsName(namespace, ref.Name), compiled.AuthKey))
				return ext, nil
			}

			doc, err := auth.Parse(string(authSrc))
			if err != nil {
				// The status message names the Secret and the error, never
				// its contents (docs/spec/security.md).
				invalidate(fmt.Sprintf(
					"extension Secret %s: invalid %s: %v",
					nsName(namespace, ref.Name), compiled.AuthKey, err))
				return ext, nil
			}

			authDocs = append(authDocs, doc)
			authSecretUIDs = append(authSecretUIDs, string(secret.UID))

			continue
		}

		cm, err := w.extensionCM(namespace, string(ref.Name))
		if err != nil {
			invalidate(fmt.Sprintf(
				"extension ConfigMap %s: %v", nsName(namespace, ref.Name), err))
			return ext, nil
		}

		// auth.hcl in a ConfigMap is misplaced: credentials MUST NOT live
		// in ConfigMaps (docs/spec/extensions.md kind and key matrix).
		if _, has := cm.Data[compiled.AuthKey]; has {
			invalidate(fmt.Sprintf(
				"extension ConfigMap %s carries %s: authentication lives in Secrets",
				nsName(namespace, ref.Name), compiled.AuthKey))
			return ext, nil
		}

		rateLimitSrc, hasRateLimit := cm.Data[compiled.RateLimitKey]
		wafSrc, hasWAF := cm.Data[compiled.WAFKey]

		if !hasRateLimit && !hasWAF {
			invalidate(fmt.Sprintf(
				"extension ConfigMap %s carries neither %s nor %s",
				nsName(namespace, ref.Name), compiled.RateLimitKey, compiled.WAFKey))
			return ext, nil
		}

		if hasRateLimit {
			doc, err := ratelimiting.Parse(rateLimitSrc)
			if err != nil {
				invalidate(fmt.Sprintf(
					"extension ConfigMap %s: invalid %s: %v",
					nsName(namespace, ref.Name), compiled.RateLimitKey, err))
				return ext, nil
			}

			rateLimitDocs = append(rateLimitDocs, doc)
		}

		if hasWAF {
			doc, err := waf.Parse(wafSrc)
			if err != nil {
				invalidate(fmt.Sprintf(
					"extension ConfigMap %s: invalid %s: %v",
					nsName(namespace, ref.Name), compiled.WAFKey, err))
				return ext, nil
			}

			wafDocs = append(wafDocs, doc)
		}
	}

	if len(rateLimitDocs) > 0 {
		config, err := ratelimiting.Merge(rateLimitDocs)
		if err != nil {
			invalidate(fmt.Sprintf("merged %s invalid: %v", compiled.RateLimitKey, err))
			return ext, nil
		}

		ext.rateLimit = config
	}

	if len(wafDocs) > 0 {
		program := waf.Concat(wafDocs)

		// The control plane validates the concatenated program by building
		// the engine once at compile time (docs/spec/extensions.md Web
		// application firewall).
		if _, err := waf.NewEngine(program); err != nil {
			invalidate(fmt.Sprintf("concatenated %s invalid: %v", compiled.WAFKey, err))
			return ext, nil
		}

		ext.waf = program
	}

	if len(authDocs) > 0 {
		config, err := auth.Merge(authDocs)
		if err != nil {
			invalidate(fmt.Sprintf("merged %s invalid: %v", compiled.AuthKey, err))
			return ext, nil
		}

		// On GRPCRoute rules only the jwt provider is valid: redirect,
		// form, and Basic flows have no meaning for gRPC clients
		// (docs/spec/authentication.md Resolution and status).
		if grpcRoute && (config.OIDC != nil || config.SAML != nil || config.LDAP != nil) {
			invalidate(fmt.Sprintf(
				"merged %s invalid: only the jwt provider is valid on GRPCRoute rules",
				compiled.AuthKey))
			return ext, nil
		}

		config.Identity = compiled.AuthIdentity(authSecretUIDs)

		payload, err := json.Marshal(config)
		if err != nil {
			invalidate(fmt.Sprintf("merged %s invalid: %v", compiled.AuthKey, err))
			return ext, nil
		}

		if outcome.authDocs == nil {
			outcome.authDocs = map[string][]byte{}
		}

		outcome.authDocs[config.Identity] = payload
		ext.auth = config
	}

	return ext, nil
}
