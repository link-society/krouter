package gatewayapi

import (
	"fmt"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

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
	invalid   bool
}

// compileExtensions resolves the ExtensionRef filters of one rule in
// filter list order (docs/spec/extensions.md Resolution and status):
// `ratelimit.hcl` documents merge attribute by attribute.
//
// A reference outside core/ConfigMap returns an error, rejecting the
// route with UnsupportedValue. A broken target (missing ConfigMap,
// carrying neither key, invalid document, incomplete merge) keeps the
// route accepted but degrades ResolvedRefs to InvalidExtensionRef and
// marks the rule fail-closed: matching requests are answered 500, per
// the upstream unresolvable-filter contract.
func (r *Engine) compileExtensions(
	w *world,
	namespace string,
	refs []gatewayv1.LocalObjectReference,
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
	}

	var rateLimitDocs []*ratelimiting.Document
	var wafDocs []*waf.Document

	for _, ref := range refs {
		if string(ref.Group) != "" || string(ref.Kind) != "ConfigMap" {
			return ext, fmt.Errorf(
				"unsupported extensionRef kind %s/%s", ref.Group, ref.Kind)
		}

		cm, err := w.extensionCM(namespace, string(ref.Name))
		if err != nil {
			invalidate(fmt.Sprintf(
				"extension ConfigMap %s: %v", nsName(namespace, ref.Name), err))
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

	return ext, nil
}
