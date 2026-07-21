// Package proxy is the data-plane request path: it forwards downstream
// requests to backend endpoints using the snapshots published by the
// loader and resolver actors. It is deliberately not an actor — it is the
// engine the portserver actors drive.
package proxy

import (
	"fmt"
	"log/slog"

	"crypto/tls"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"

	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/link-society/krouter/internal/lib/http/routing"
	"github.com/link-society/krouter/internal/lib/k8s/compiled"
)

var requestsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "krouter_dataplane_requests_total",
		Help: "Requests handled by the data plane, by response class.",
	},
	[]string{"class"},
)

// Handler is the request path shared by every port server. It only reads
// the snapshots published by the loader and resolver actors.
type Handler struct {
	state     *routing.State
	transport *http.Transport
}

func NewHandler(state *routing.State) *Handler {
	return &Handler{
		state: state,
		transport: &http.Transport{
			// Backend protocol is HTTP/1.1 for the POC (docs/spec/overview.md).
			ForceAttemptHTTP2:   false,
			MaxIdleConns:        1024,
			MaxIdleConnsPerHost: 256,
			IdleConnTimeout:     90 * time.Second,
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
		},
	}
}

// CertificateFor selects the certificate for an SNI value on a port, so a
// rotated certificate serves new handshakes without terminating
// connections using the previous one (docs/spec/security.md).
func (h *Handler) CertificateFor(port int32, serverName string) (*tls.Certificate, error) {
	listener := h.state.Tables.Load().CertificateFor(port, serverName)

	cert := listener.Certificate()
	if cert == nil {
		return nil, fmt.Errorf("no certificate for port %d", port)
	}

	return cert, nil
}

// Serve handles one downstream request on an internal listener port.
func (h *Handler) Serve(w http.ResponseWriter, r *http.Request, port int32, withTLS bool) {
	start := time.Now()
	host := hostOnly(r.Host)

	rule, listener, route := h.state.Tables.Load().Match(port, host, r)
	if rule == nil {
		http.Error(w, "not found", http.StatusNotFound)
		requestsTotal.WithLabelValues("4xx").Inc()
		return
	}

	status := h.forward(w, r, rule, withTLS)

	requestsTotal.WithLabelValues(fmt.Sprintf("%dxx", status/100)).Inc()

	// Access log event (docs/spec/observability.md).
	slog.Info("request",
		"listener", listener.Name(),
		"route", route.Key(),
		"method", r.Method,
		"authority", host,
		"status", status,
		"duration", time.Since(start),
		"proto", r.Proto,
		"client", r.RemoteAddr,
	)
}

// forward proxies one request to a selected backend endpoint.
func (h *Handler) forward(w http.ResponseWriter, r *http.Request, rule *routing.RuleTable, withTLS bool) int {
	backend := rule.PickBackend()
	if backend == nil {
		http.Error(w, "no available backend", http.StatusInternalServerError)
		return http.StatusInternalServerError
	}

	if !backend.Valid() {
		// Unresolvable refs answer 500 for their traffic share (Gateway API).
		http.Error(w, "invalid backend reference", http.StatusInternalServerError)
		return http.StatusInternalServerError
	}

	target, ok := backend.Pick(h.state.Endpoints.Load())
	if !ok {
		// Required unavailable response (docs/spec/failure-modes.md).
		http.Error(w, "no ready endpoints", http.StatusServiceUnavailable)
		return http.StatusServiceUnavailable
	}

	status := http.StatusOK
	reverseProxy := &httputil.ReverseProxy{
		Transport:     h.transport,
		FlushInterval: -1, // preserve streaming, never buffer bodies (docs/spec/traffic.md)
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(&url.URL{
				Scheme: "http",
				Host:   fmt.Sprintf("%s:%d", target.Address, target.Port),
			})
			pr.Out.Host = pr.In.Host

			rewriteForwardingHeaders(pr, withTLS)

			for _, filter := range rule.Filters() {
				applyFilter(pr, filter)
			}
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			slog.Warn("backend request failed", "error", err)
			status = http.StatusBadGateway
			http.Error(w, "bad gateway", http.StatusBadGateway)
		},
		ModifyResponse: func(resp *http.Response) error {
			status = resp.StatusCode
			return nil
		},
	}

	reverseProxy.ServeHTTP(w, r)

	return status
}

// rewriteForwardingHeaders regenerates spoof-sensitive values from the
// actual downstream connection (docs/spec/traffic.md).
func rewriteForwardingHeaders(pr *httputil.ProxyRequest, withTLS bool) {
	pr.Out.Header.Del("Forwarded")
	pr.Out.Header.Del("X-Forwarded-For")
	pr.Out.Header.Del("X-Forwarded-Host")
	pr.Out.Header.Del("X-Forwarded-Proto")

	clientIP := pr.In.RemoteAddr
	if host, _, err := net.SplitHostPort(clientIP); err == nil {
		clientIP = host
	}

	proto := "http"
	if withTLS {
		proto = "https"
	}

	pr.Out.Header.Set("X-Forwarded-For", clientIP)
	pr.Out.Header.Set("X-Forwarded-Host", hostOnly(pr.In.Host))
	pr.Out.Header.Set("X-Forwarded-Proto", proto)
	pr.Out.Header.Set("Forwarded", fmt.Sprintf("for=%s;host=%s;proto=%s",
		clientIP, hostOnly(pr.In.Host), proto))
}

// applyFilter runs a compiled HTTPRoute filter after header regeneration:
// RequestHeaderModifier may override regenerated values (docs/spec/traffic.md).
func applyFilter(pr *httputil.ProxyRequest, filter compiled.Filter) {
	if filter.Type != "RequestHeaderModifier" {
		return
	}

	for name, value := range filter.SetHeaders {
		pr.Out.Header.Set(name, value)
	}

	for name, value := range filter.AddHeaders {
		pr.Out.Header.Add(name, value)
	}

	for _, name := range filter.RemoveHeaders {
		pr.Out.Header.Del(name)
	}
}

func hostOnly(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}

	return host
}
