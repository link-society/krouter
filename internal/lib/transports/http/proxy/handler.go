// Package proxy is the data-plane request path: it forwards downstream
// requests to backend endpoints using the snapshots published by the
// loader and resolver actors. It is deliberately not an actor — it is the
// engine the portserver actors drive.
package proxy

import (
	"errors"
	"fmt"
	"log/slog"

	"strconv"
	"strings"

	"bytes"
	"io"

	"context"
	"math/rand/v2"

	"crypto/tls"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"

	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/link-society/krouter/internal/lib/k8s/compiled"
	"github.com/link-society/krouter/internal/lib/transports/grpc"
	"github.com/link-society/krouter/internal/lib/transports/http/routing"
)

var requestsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "krouter_dataplane_requests_total",
		Help: "Requests handled by the data plane, by response class.",
	},
	[]string{"class"},
)

var activeRequests = promauto.NewGauge(
	prometheus.GaugeOpts{
		Name: "krouter_dataplane_active_requests",
		Help: "HTTP and gRPC requests currently in flight in the data plane.",
	},
)

var requestDuration = promauto.NewHistogramVec(
	prometheus.HistogramOpts{
		Name:    "krouter_dataplane_request_duration_seconds",
		Help:    "Request duration, by response class.",
		Buckets: prometheus.DefBuckets,
	},
	[]string{"class"},
)

var httpBytesTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "krouter_dataplane_http_bytes_total",
		Help: "Bytes transferred on HTTP and gRPC routes, by direction.",
	},
	[]string{"direction"}, // downstream_to_backend | backend_to_downstream
)

var backendErrors = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "krouter_dataplane_backend_errors_total",
		Help: "Backend failures on HTTP and gRPC routes, by kind: selection covers rules without a usable backend or ready endpoint, connection covers failed backend requests.",
	},
	[]string{"kind"}, // selection | connection
)

// countingWriter counts response bytes without hiding the wrapped
// writer's Flusher and Hijacker (http.ResponseController unwraps it, so
// streaming responses and upgrades keep working).
type countingWriter struct {
	http.ResponseWriter
}

func (w *countingWriter) Write(b []byte) (int, error) {
	n, err := w.ResponseWriter.Write(b)
	httpBytesTotal.WithLabelValues("backend_to_downstream").Add(float64(n))

	return n, err
}

func (w *countingWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// countingBody counts request-body bytes actually read, whether by the
// WAF buffering them or by the backend request streaming them.
type countingBody struct {
	io.ReadCloser
}

func (b countingBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	httpBytesTotal.WithLabelValues("downstream_to_backend").Add(float64(n))

	return n, err
}

// observeRequest records the response-class counter and the duration
// histogram for one finished request, so their series always agree.
func observeRequest(status int, start time.Time) {
	class := fmt.Sprintf("%dxx", status/100)

	requestsTotal.WithLabelValues(class).Inc()
	requestDuration.WithLabelValues(class).Observe(time.Since(start).Seconds())
}

// Handler is the request path shared by every port server. It only reads
// the snapshots published by the loader and resolver actors.
type Handler struct {
	state         *routing.State
	transport     *http.Transport
	grpcTransport *http.Transport
}

func NewHandler(state *routing.State) *Handler {
	return &Handler{
		state: state,
		transport: &http.Transport{
			// Backend protocol is HTTP/1.1 (docs/spec/overview.md).
			ForceAttemptHTTP2:   false,
			MaxIdleConns:        1024,
			MaxIdleConnsPerHost: 256,
			IdleConnTimeout:     90 * time.Second,
			DialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
		},
		// gRPC backends speak cleartext HTTP/2 (docs/spec/traffic.md).
		grpcTransport: grpc.NewTransport(),
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

// TLSConfigFor builds the per-connection TLS configuration of an HTTPS
// listener selected by SNI: its certificate and, when configured, its
// frontend client-certificate validation (docs/spec/security.md).
func (h *Handler) TLSConfigFor(port int32, serverName string) (*tls.Config, error) {
	listener := h.state.Tables.Load().CertificateFor(port, serverName)

	cert := listener.Certificate()
	if cert == nil {
		return nil, fmt.Errorf("no certificate for port %d", port)
	}

	config := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		// Configs returned from GetConfigForClient are used verbatim:
		// ALPN must offer h2 explicitly or downstream HTTP/2 breaks
		// (docs/spec/traffic.md Protocol handling).
		NextProtos: []string{"h2", "http/1.1"},
	}

	if pool, auth := listener.ClientValidation(); auth != tls.NoClientCert {
		config.ClientAuth = auth
		config.ClientCAs = pool
	}

	return config, nil
}

// Serve handles one downstream request on an internal listener port.
func (h *Handler) Serve(w http.ResponseWriter, r *http.Request, port int32, withTLS bool) {
	start := time.Now()
	host := hostOnly(r.Host)

	activeRequests.Inc()
	defer activeRequests.Dec()

	// Transferred bytes (docs/spec/observability.md): everything written
	// downstream and every request-body byte read, whoever reads it.
	w = &countingWriter{ResponseWriter: w}
	if r.Body != nil {
		r.Body = countingBody{ReadCloser: r.Body}
	}

	tables := h.state.Tables.Load()

	// Misdirected-request detection (docs/spec/traffic.md): the authority
	// must be owned by the listener the connection's SNI selected.
	if withTLS && r.TLS != nil && tables.Misdirected(port, r.TLS.ServerName, host) {
		http.Error(w, "misdirected request", http.StatusMisdirectedRequest)
		observeRequest(http.StatusMisdirectedRequest, start)
		return
	}

	rule, listener, route := tables.Match(port, host, r)
	if rule == nil {
		if grpc.IsRequest(r) {
			// docs/spec/traffic.md gRPC routing: unmatched gRPC requests
			// receive UNIMPLEMENTED.
			grpc.Unimplemented(w)
			observeRequest(http.StatusOK, start)
			return
		}

		http.Error(w, "not found", http.StatusNotFound)
		observeRequest(http.StatusNotFound, start)
		return
	}

	// Extensions run first (docs/spec/extensions.md Request path
	// integration): a rejected request is never mirrored, redirected,
	// answered with CORS headers, or forwarded.
	status, extension, wafRule := serveExtensions(w, r, rule)

	if status == 0 {
		if cors := rule.CORS(); cors != nil && isCORSPreflight(r) {
			// Preflight requests are answered at the gateway
			// (docs/spec/traffic.md Routing and filters).
			status = serveCORSPreflight(w, r, cors)
		} else if redirect, ok := redirectFilter(rule); ok {
			status = serveRedirect(w, r, redirect, withTLS)
		} else {
			status = h.forward(w, r, rule, withTLS)
		}
	}

	observeRequest(status, start)

	// Access log event (docs/spec/observability.md); gRPC requests
	// additionally carry the gRPC status code.
	attrs := []any{
		"listener", listener.Name(),
		"route", route.Key(),
		"method", r.Method,
		"authority", host,
		"status", status,
		"duration", time.Since(start),
		"proto", r.Proto,
		"client", r.RemoteAddr,
	}

	if extension != "" {
		// The rejecting extension (docs/spec/extensions.md Observability).
		attrs = append(attrs, "extension", extension)
	}

	if wafRule != 0 {
		// The interrupting WAF rule (docs/spec/extensions.md Observability).
		attrs = append(attrs, "waf_rule", wafRule)
	}

	if rule.GRPC() {
		if grpcStatus, ok := grpc.StatusFromHeader(w.Header()); ok {
			attrs = append(attrs, "grpc_status", grpcStatus)
		}
	}

	slog.Info("request", attrs...)
}

// redirectFilter returns the rule's RequestRedirect filter, if any.
func redirectFilter(rule *routing.RuleTable) (compiled.Filter, bool) {
	for _, filter := range rule.Filters() {
		if filter.Type == compiled.FilterRequestRedirect {
			return filter, true
		}
	}

	return compiled.Filter{}, false
}

// serveRedirect answers a RequestRedirect rule (docs/spec/traffic.md):
// unset filter values inherit from the incoming request — an unset port
// inherits the incoming listener port unless the scheme is changed, in
// which case the new scheme's default port applies — and default scheme
// ports are omitted from the Location header.
func serveRedirect(w http.ResponseWriter, r *http.Request, filter compiled.Filter, withTLS bool) int {
	scheme := "http"
	if withTLS {
		scheme = "https"
	}
	if filter.Scheme != "" {
		scheme = filter.Scheme
	}

	host := hostOnly(r.Host)
	if filter.Hostname != "" {
		host = filter.Hostname
	}

	port := filter.Port
	if port == 0 && filter.Scheme == "" {
		port = requestPort(r, withTLS)
	}

	if port != 0 &&
		!(scheme == "http" && port == 80) &&
		!(scheme == "https" && port == 443) {
		host = fmt.Sprintf("%s:%d", host, port)
	}

	location := url.URL{
		Scheme:   scheme,
		Host:     host,
		Path:     rewrittenPath(r.URL.Path, filter),
		RawQuery: r.URL.RawQuery,
	}

	status := filter.StatusCode
	if status == 0 {
		status = http.StatusFound
	}

	http.Redirect(w, r, location.String(), status)

	return status
}

// rewrittenPath applies the path replacement shared by RequestRedirect and
// URLRewrite (docs/spec/traffic.md): the whole path, or the rule's matched
// PathPrefix segment-wise.
func rewrittenPath(path string, filter compiled.Filter) string {
	switch filter.PathRewriteType {
	case "ReplaceFullPath":
		return filter.PathRewriteValue

	case "ReplacePrefixMatch":
		prefix := strings.TrimSuffix(filter.PathPrefix, "/")
		rest := strings.TrimPrefix(path, prefix)

		replacement := filter.PathRewriteValue
		if replacement == "" {
			replacement = "/"
		}

		if rest == "" || rest == "/" {
			return replacement
		}

		return strings.TrimSuffix(replacement, "/") + rest

	default:
		return path
	}
}

// forward proxies one request to a selected backend endpoint.
func (h *Handler) forward(w http.ResponseWriter, r *http.Request, rule *routing.RuleTable, withTLS bool) int {
	backend := rule.PickBackend()
	if backend == nil {
		backendErrors.WithLabelValues("selection").Inc()

		if rule.GRPC() {
			grpc.Unavailable(w)
			return http.StatusOK
		}

		http.Error(w, "no available backend", http.StatusInternalServerError)
		return http.StatusInternalServerError
	}

	if !backend.Valid() {
		backendErrors.WithLabelValues("selection").Inc()

		// Unresolvable refs answer for their traffic share (Gateway API).
		if rule.GRPC() {
			grpc.Internal(w)
			return http.StatusOK
		}

		http.Error(w, "invalid backend reference", http.StatusInternalServerError)
		return http.StatusInternalServerError
	}

	// Fail closed for a rejected BackendTLSPolicy (docs/spec/traffic.md
	// Backend TLS): never fall back to cleartext.
	if backend.TLSInvalid() {
		backendErrors.WithLabelValues("selection").Inc()

		http.Error(w, "bad gateway", http.StatusBadGateway)
		return http.StatusBadGateway
	}

	target, ok := backend.Pick(h.state.Endpoints.Load())
	if !ok {
		backendErrors.WithLabelValues("selection").Inc()

		// Required unavailable response (docs/spec/failure-modes.md).
		if rule.GRPC() {
			grpc.Unavailable(w)
			return http.StatusOK
		}

		http.Error(w, "no ready endpoints", http.StatusServiceUnavailable)
		return http.StatusServiceUnavailable
	}

	transport := h.transport
	if rule.GRPC() || backend.H2C() {
		// Cleartext HTTP/2 backends (docs/spec/traffic.md Protocol handling).
		transport = h.grpcTransport
	}

	// BackendTLSPolicy transport (docs/spec/traffic.md Backend TLS).
	scheme := "http"
	if tlsTransport := backend.TLSTransport(); tlsTransport != nil {
		transport = tlsTransport
		scheme = "https"
	}

	// Request mirroring (docs/spec/traffic.md): sample the targets now,
	// capture the request body while the primary request streams it, and
	// snapshot the filtered outbound request for the mirror copies.
	mirrors := sampleMirrors(rule.Mirrors())

	var mirrorBody *cappedBuffer
	var mirrorReq *http.Request

	if len(mirrors) > 0 && r.Body != nil && r.ContentLength != 0 {
		mirrorBody = &cappedBuffer{limit: mirrorBodyLimit}
		r.Body = readCloser{
			Reader: io.TeeReader(r.Body, mirrorBody),
			Closer: r.Body,
		}
	}

	// Rule timeouts (docs/spec/traffic.md): the deadline covers the
	// backend request; exceeding it answers 504 Gateway Timeout.
	if timeout := rule.Timeout(); timeout > 0 {
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()

		r = r.WithContext(ctx)
	}

	status := http.StatusOK
	reverseProxy := &httputil.ReverseProxy{
		Transport:     transport,
		FlushInterval: -1, // preserve streaming, never buffer bodies (docs/spec/traffic.md)
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(&url.URL{
				Scheme: scheme,
				Host:   fmt.Sprintf("%s:%d", target.Address, target.Port),
			})
			pr.Out.Host = pr.In.Host

			rewriteForwardingHeaders(pr, withTLS)

			for _, filter := range rule.Filters() {
				applyFilter(pr, filter)
			}

			if len(mirrors) > 0 {
				mirrorReq = pr.Out.Clone(context.WithoutCancel(pr.In.Context()))
			}

			// Per-backendRef filters apply only to the selected backend,
			// never to mirror copies (docs/spec/traffic.md).
			for _, filter := range backend.Filters() {
				applyFilter(pr, filter)
			}
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			if errors.Is(err, context.DeadlineExceeded) {
				// Rule timeout exceeded (docs/spec/traffic.md).
				status = http.StatusGatewayTimeout
				http.Error(w, "gateway timeout", http.StatusGatewayTimeout)
				return
			}

			backendErrors.WithLabelValues("connection").Inc()

			slog.Warn("backend request failed", "error", err)
			status = http.StatusBadGateway
			http.Error(w, "bad gateway", http.StatusBadGateway)
		},
		ModifyResponse: func(resp *http.Response) error {
			for _, filter := range rule.Filters() {
				applyResponseFilter(resp, filter)
			}

			for _, filter := range backend.Filters() {
				applyResponseFilter(resp, filter)
			}

			if cors := rule.CORS(); cors != nil {
				applyCORSResponse(resp, r.Header.Get("Origin"), cors)
			}

			status = resp.StatusCode
			return nil
		},
	}

	reverseProxy.ServeHTTP(w, r)

	h.fireMirrors(mirrors, mirrorReq, mirrorBody, transport)

	return status
}

const mirrorBodyLimit = 1 << 20

// sampleMirrors applies percentage sampling to the rule's mirror targets
// (docs/spec/traffic.md).
func sampleMirrors(mirrors []*routing.MirrorTable) []*routing.MirrorTable {
	var sampled []*routing.MirrorTable
	for _, mirror := range mirrors {
		if mirror.Percent() >= 100 || rand.Float64()*100 < mirror.Percent() {
			sampled = append(sampled, mirror)
		}
	}

	return sampled
}

// fireMirrors delivers a copy of the request to a single endpoint of each
// sampled mirror backend, after the primary request completed. Responses
// and failures are ignored and MUST NOT affect the client response
// (docs/spec/traffic.md).
func (h *Handler) fireMirrors(
	mirrors []*routing.MirrorTable,
	req *http.Request,
	body *cappedBuffer,
	transport *http.Transport,
) {
	if len(mirrors) == 0 || req == nil {
		return
	}

	// A body larger than the capture limit cannot be mirrored faithfully;
	// the mirrors are skipped rather than sending a truncated request.
	if body != nil && body.overflowed {
		return
	}

	index := h.state.Endpoints.Load()

	for _, mirror := range mirrors {
		if mirror.Backend().TLSInvalid() {
			continue
		}

		endpoint, ok := mirror.Backend().Pick(index)
		if !ok {
			continue
		}

		mirrorTransport := transport
		mirrorScheme := "http"
		if tlsTransport := mirror.Backend().TLSTransport(); tlsTransport != nil {
			mirrorTransport = tlsTransport
			mirrorScheme = "https"
		}

		mirrored := req.Clone(req.Context())
		mirrored.URL.Scheme = mirrorScheme
		mirrored.URL.Host = fmt.Sprintf("%s:%d", endpoint.Address, endpoint.Port)
		mirrored.Body = nil
		mirrored.ContentLength = 0

		if body != nil {
			mirrored.Body = io.NopCloser(bytes.NewReader(body.buf.Bytes()))
			mirrored.ContentLength = int64(body.buf.Len())
		}

		go func() {
			ctx, cancel := context.WithTimeout(mirrored.Context(), 10*time.Second)
			defer cancel()

			resp, err := mirrorTransport.RoundTrip(mirrored.WithContext(ctx))
			if err != nil {
				slog.Debug("mirror request failed", "error", err)
				return
			}

			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}()
	}
}

// cappedBuffer captures a streamed request body up to a limit for
// mirroring, without slowing the primary request path.
type cappedBuffer struct {
	buf        bytes.Buffer
	limit      int
	overflowed bool
}

var _ io.Writer = (*cappedBuffer)(nil)

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if c.buf.Len()+len(p) > c.limit {
		c.overflowed = true
		return len(p), nil
	}

	c.buf.Write(p)

	return len(p), nil
}

type readCloser struct {
	io.Reader
	io.Closer
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

// applyFilter runs a compiled request filter after header regeneration:
// RequestHeaderModifier may override regenerated values, URLRewrite
// replaces the authority and path seen by the backend
// (docs/spec/traffic.md).
func applyFilter(pr *httputil.ProxyRequest, filter compiled.Filter) {
	switch filter.Type {
	case compiled.FilterRequestHeaderModifier:
		for name, value := range filter.SetHeaders {
			pr.Out.Header.Set(name, value)
		}

		for name, value := range filter.AddHeaders {
			pr.Out.Header.Add(name, value)
		}

		for _, name := range filter.RemoveHeaders {
			pr.Out.Header.Del(name)
		}

	case compiled.FilterURLRewrite:
		if filter.Hostname != "" {
			pr.Out.Host = filter.Hostname
		}

		if filter.PathRewriteType != "" {
			pr.Out.URL.Path = rewrittenPath(pr.Out.URL.Path, filter)
		}
	}
}

// applyResponseFilter runs a compiled ResponseHeaderModifier filter on the
// backend response (docs/spec/traffic.md).
func applyResponseFilter(resp *http.Response, filter compiled.Filter) {
	if filter.Type != compiled.FilterResponseHeaderModifier {
		return
	}

	for name, value := range filter.SetHeaders {
		resp.Header.Set(name, value)
	}

	for name, value := range filter.AddHeaders {
		resp.Header.Add(name, value)
	}

	for _, name := range filter.RemoveHeaders {
		resp.Header.Del(name)
	}
}

func hostOnly(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		return h
	}

	return host
}

// requestPort is the port the client addressed: the explicit port of the
// Host header, or the default port of the listener scheme.
func requestPort(r *http.Request, withTLS bool) int32 {
	if _, p, err := net.SplitHostPort(r.Host); err == nil {
		if port, err := strconv.Atoi(p); err == nil {
			return int32(port)
		}
	}

	if withTLS {
		return 443
	}

	return 80
}
