package proxy

import (
	"math"

	"strconv"
	"strings"

	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/link-society/krouter/internal/extensions/auth"
	"github.com/link-society/krouter/internal/lib/transports/grpc"
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

var authDecisions = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "krouter_dataplane_auth_decisions_total",
		Help: "Authentication decisions, by provider and result (docs/spec/authentication.md).",
	},
	[]string{"provider", "result"}, // provider oidc|saml|ldap|jwt|none
)

// serveExtensions enforces the rule's extensions before any other filter
// or gateway-produced response (docs/spec/extensions.md Request path
// integration): fail-closed 500 for broken ExtensionRef targets, then
// rate limiting (cheapest first), then authentication and authorization,
// then the WAF request phases. On upgrade requests this runs on the
// handshake, before any connection hijack. It returns the produced
// status, the rejecting extension name, the interrupting WAF rule
// identifier (or 0 to continue serving), and the authenticated user.
func serveExtensions(
	w http.ResponseWriter,
	r *http.Request,
	rule *routing.RuleTable,
	clientIP string,
) (int, string, int, string) {
	grpcRule := rule.GRPC()

	if rule.ExtensionsInvalid() {
		// An unresolvable filter is never skipped
		// (docs/spec/extensions.md Resolution and status).
		status := deny(w, grpcRule, http.StatusInternalServerError,
			grpc.StatusInternal, "invalid route extension")

		return status, "extensionref", 0, ""
	}

	if limiter := rule.RateLimiter(); limiter != nil {
		allowed, wait := limiter.Allow(limiter.KeyFor(r, clientIP))
		if !allowed {
			ratelimitDecisions.WithLabelValues("limited").Inc()

			seconds := int(math.Ceil(wait.Seconds()))
			if seconds < 1 {
				seconds = 1
			}

			w.Header().Set("Retry-After", strconv.Itoa(seconds))
			status := deny(w, grpcRule, int(limiter.Status()),
				grpc.StatusResourceExhausted, "rate limited")

			return status, "ratelimit", 0, ""
		}

		ratelimitDecisions.WithLabelValues("allowed").Inc()
	}

	// Authentication runs after rate limiting and before the WAF: denied
	// clients spend no WAF CPU, and the WAF only ever inspects
	// authenticated traffic (docs/spec/authentication.md Request path
	// integration).
	user := ""
	if enforcer := rule.Auth(); enforcer != nil {
		// CORS preflights carry no credentials: on rules with a CORS
		// filter they skip authentication and continue down the chain
		// (docs/spec/authentication.md).
		if rule.CORS() == nil || !isCORSPreflight(r) {
			status, decidedUser := serveAuth(w, r, enforcer, grpcRule)
			if status != 0 {
				return status, "auth", 0, ""
			}

			user = decidedUser
		}
	}

	if engine := rule.WAF(); engine != nil {
		// Upgrade handshakes forward the tunnel without body inspection:
		// only the request-header phase is enforced (docs/spec/extensions.md
		// WebSocket and upgrade requests). gRPC request bodies are buffered
		// and inspected like HTTP bodies, bounded by the engine's body limit
		// so a long-lived stream is forwarded once the limit is reached.
		headersOnly := isUpgrade(r)

		denial, err := engine.Evaluate(r, clientIP, headersOnly)
		if err != nil {
			wafDecisions.WithLabelValues("error").Inc()
			status := deny(w, grpcRule, http.StatusInternalServerError,
				grpc.StatusInternal, "web application firewall error")

			return status, "waf", 0, ""
		}

		if denial != nil {
			wafDecisions.WithLabelValues("denied").Inc()
			status := deny(w, grpcRule, denial.Status,
				grpc.StatusPermissionDenied, "forbidden")

			return status, "waf", denial.RuleID, ""
		}

		wafDecisions.WithLabelValues("allowed").Inc()
	}

	return 0, "", 0, user
}

// serveAuth renders one authentication decision
// (docs/spec/authentication.md Request path integration): 0 to continue
// with the identity injected, or the produced status.
func serveAuth(
	w http.ResponseWriter,
	r *http.Request,
	enforcer *auth.Enforcer,
	grpcRule bool,
) (int, string) {
	decision := enforcer.Evaluate(w, r, grpcRule)

	provider := decision.Provider
	if provider == "" {
		provider = "none"
	}

	authDecisions.WithLabelValues(provider, decision.Result).Inc()

	if decision.Allowed {
		decision.Identity.Apply(r)

		return 0, decision.Identity.User
	}

	if decision.RedirectTo != "" {
		http.Redirect(w, r, decision.RedirectTo, decision.Status)

		return decision.Status, ""
	}

	for _, challenge := range decision.Challenges {
		w.Header().Add("WWW-Authenticate", challenge)
	}

	return deny(w, grpcRule, decision.Status, decision.GRPCCode, decision.Message), ""
}

// deny writes an extension rejection in the transport-appropriate form and
// returns the status to record: a gRPC rule receives a trailers-only status
// response (HTTP 200 carrying the gRPC code, matching the other gRPC
// rejection paths), everything else a plain HTTP error
// (docs/spec/extensions.md Request path integration).
func deny(w http.ResponseWriter, grpcRule bool, httpStatus int, grpcCode, message string) int {
	if grpcRule {
		grpc.WriteStatus(w, grpcCode, message)

		return http.StatusOK
	}

	http.Error(w, message, httpStatus)

	return httpStatus
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
