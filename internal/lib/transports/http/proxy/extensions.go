package proxy

import (
	"math"

	"strconv"
	"strings"

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

var wafDecisions = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "krouter_dataplane_waf_decisions_total",
		Help: "WAF decisions, by result (docs/spec/extensions.md).",
	},
	[]string{"result"}, // allowed | denied | error
)

// serveExtensions enforces the rule's extensions before any other filter
// or gateway-produced response (docs/spec/extensions.md Request path
// integration): fail-closed 500 for broken ExtensionRef targets, then
// rate limiting (cheapest first), then the WAF request phases. On upgrade
// requests this runs on the handshake, before any connection hijack. It
// returns the produced status, the rejecting extension name, and the
// interrupting WAF rule identifier, or 0 to continue serving.
func serveExtensions(
	w http.ResponseWriter,
	r *http.Request,
	rule *routing.RuleTable,
) (int, string, int) {
	if rule.ExtensionsInvalid() {
		// An unresolvable filter is never skipped
		// (docs/spec/extensions.md Resolution and status).
		http.Error(w, "invalid route extension", http.StatusInternalServerError)

		return http.StatusInternalServerError, "extensionref", 0
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

			return status, "ratelimit", 0
		}

		ratelimitDecisions.WithLabelValues("allowed").Inc()
	}

	if engine := rule.WAF(); engine != nil {
		// gRPC rules and upgrade handshakes forward payloads without body
		// inspection: only the request-header phase is enforced
		// (docs/spec/extensions.md Web application firewall, WebSocket and
		// upgrade requests).
		headersOnly := rule.GRPC() || isUpgrade(r)

		denial, err := engine.Evaluate(r, headersOnly)
		if err != nil {
			wafDecisions.WithLabelValues("error").Inc()
			http.Error(w, "web application firewall error", http.StatusInternalServerError)

			return http.StatusInternalServerError, "waf", 0
		}

		if denial != nil {
			wafDecisions.WithLabelValues("denied").Inc()
			http.Error(w, "forbidden", denial.Status)

			return denial.Status, "waf", denial.RuleID
		}

		wafDecisions.WithLabelValues("allowed").Inc()
	}

	return 0, "", 0
}

// isUpgrade reports whether the request asks to switch protocols (e.g. a
// WebSocket handshake): the WAF inspects the handshake but not the tunnel
// that follows (docs/spec/extensions.md WebSocket and upgrade requests).
func isUpgrade(r *http.Request) bool {
	if r.Header.Get("Upgrade") == "" {
		return false
	}

	for _, value := range r.Header.Values("Connection") {
		if strings.Contains(strings.ToLower(value), "upgrade") {
			return true
		}
	}

	return false
}
