package proxy

import (
	"math"

	"strconv"

	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/link-society/krouter/internal/lib/transports/http/routing"
)

var ratelimitDecisions = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "krouter_dataplane_ratelimit_decisions_total",
		Help: "Rate limiting decisions, by result (docs/spec/extensions.md).",
	},
	[]string{"result"}, // allowed | limited
)

// serveExtensions enforces the rule's extensions before any other filter
// or gateway-produced response (docs/spec/extensions.md Request path
// integration): fail-closed 500 for broken ExtensionRef targets, then
// rate limiting. On upgrade requests this runs on the handshake, before
// any connection hijack. It returns the produced status and the
// rejecting extension name, or 0 to continue serving.
func serveExtensions(
	w http.ResponseWriter,
	r *http.Request,
	rule *routing.RuleTable,
) (int, string) {
	if rule.ExtensionsInvalid() {
		// An unresolvable filter is never skipped
		// (docs/spec/extensions.md Resolution and status).
		http.Error(w, "invalid route extension", http.StatusInternalServerError)

		return http.StatusInternalServerError, "extensionref"
	}

	if limiter := rule.RateLimiter(); limiter != nil {
		allowed, wait := limiter.Allow(limiter.KeyFor(r))
		if !allowed {
			ratelimitDecisions.WithLabelValues("limited").Inc()

			seconds := int(math.Ceil(wait.Seconds()))
			if seconds < 1 {
				seconds = 1
			}

			status := int(limiter.Status())
			w.Header().Set("Retry-After", strconv.Itoa(seconds))
			http.Error(w, "rate limited", status)

			return status, "ratelimit"
		}

		ratelimitDecisions.WithLabelValues("allowed").Inc()
	}

	return 0, ""
}
