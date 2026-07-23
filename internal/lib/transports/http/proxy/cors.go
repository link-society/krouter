// CORS filter handling for the data-plane request path
// (docs/spec/traffic.md Routing and filters): preflight requests are
// answered directly by the gateway, matching requests receive the
// configured Access-Control-* headers, and non-matching origins receive
// no CORS headers at all.
package proxy

import (
	"strconv"
	"strings"

	"net/http"

	"github.com/link-society/krouter/internal/lib/k8s/compiled"
)

// isCORSPreflight reports a CORS preflight request: OPTIONS with an Origin
// and a requested method.
func isCORSPreflight(r *http.Request) bool {
	return r.Method == http.MethodOptions &&
		r.Header.Get("Origin") != "" &&
		r.Header.Get("Access-Control-Request-Method") != ""
}

// serveCORSPreflight answers a preflight request at the gateway without
// forwarding it to any backend.
func serveCORSPreflight(w http.ResponseWriter, r *http.Request, cors *compiled.CORS) int {
	header := w.Header()
	header.Add("Vary", "Origin")

	origin := r.Header.Get("Origin")
	if corsOriginAllowed(cors.AllowOrigins, origin) {
		header.Set("Access-Control-Allow-Origin", origin)

		if cors.AllowCredentials {
			header.Set("Access-Control-Allow-Credentials", "true")
		}

		// Wildcard allow-lists are answered by echoing the requested
		// values, so the reply stays valid for credentialed requests.
		methods := strings.Join(cors.AllowMethods, ", ")
		if corsWildcard(cors.AllowMethods) {
			methods = r.Header.Get("Access-Control-Request-Method")
		}
		if methods != "" {
			header.Set("Access-Control-Allow-Methods", methods)
		}

		headers := strings.Join(cors.AllowHeaders, ", ")
		if corsWildcard(cors.AllowHeaders) {
			headers = r.Header.Get("Access-Control-Request-Headers")
		}
		if headers != "" {
			header.Set("Access-Control-Allow-Headers", headers)
		}

		if len(cors.ExposeHeaders) > 0 {
			header.Set("Access-Control-Expose-Headers",
				strings.Join(cors.ExposeHeaders, ", "))
		}

		header.Set("Access-Control-Max-Age",
			strconv.Itoa(int(cors.MaxAgeSeconds)))
	}

	w.WriteHeader(http.StatusNoContent)

	return http.StatusNoContent
}

// applyCORSResponse decorates a proxied (non-preflight) response for a
// request carrying a matching Origin.
func applyCORSResponse(resp *http.Response, origin string, cors *compiled.CORS) {
	resp.Header.Add("Vary", "Origin")

	if origin == "" || !corsOriginAllowed(cors.AllowOrigins, origin) {
		return
	}

	resp.Header.Set("Access-Control-Allow-Origin", origin)

	if cors.AllowCredentials {
		resp.Header.Set("Access-Control-Allow-Credentials", "true")
	}

	if len(cors.ExposeHeaders) > 0 {
		resp.Header.Set("Access-Control-Expose-Headers",
			strings.Join(cors.ExposeHeaders, ", "))
	}
}

func corsWildcard(values []string) bool {
	return len(values) == 1 && values[0] == "*"
}

// corsOriginAllowed matches a request origin against the allowed origin
// patterns: exact origins, "*", or wildcard host patterns such as
// https://*.example.com matching one or more leading labels.
func corsOriginAllowed(patterns []string, origin string) bool {
	for _, pattern := range patterns {
		if pattern == "*" || pattern == origin {
			return true
		}

		scheme, host, ok := strings.Cut(pattern, "://")
		if !ok || !strings.HasPrefix(host, "*.") {
			continue
		}

		originScheme, originHost, ok := strings.Cut(origin, "://")
		if !ok || originScheme != scheme {
			continue
		}

		suffix := host[1:] // ".example.com"
		if len(originHost) > len(suffix) && strings.HasSuffix(originHost, suffix) {
			return true
		}
	}

	return false
}
