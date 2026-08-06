// Package grpc holds the gRPC-specific pieces of the data-plane HTTP
// request path (docs/spec/traffic.md gRPC routing): request detection,
// the cleartext HTTP/2 backend transport, and the required gRPC status
// responses. gRPC traffic rides the HTTP proxy — this package is
// deliberately not an actor.
package grpc

import (
	"strings"

	"net"
	"net/http"

	"time"
)

// Status codes from the gRPC specification.
const (
	StatusPermissionDenied  = "7"
	StatusResourceExhausted = "8"
	StatusUnimplemented     = "12"
	StatusInternal          = "13"
	StatusUnavailable       = "14"
	StatusUnauthenticated   = "16"
)

// IsRequest reports whether the request is a gRPC request.
func IsRequest(r *http.Request) bool {
	return strings.HasPrefix(r.Header.Get("Content-Type"), "application/grpc")
}

// NewTransport builds the backend transport for gRPC rules: cleartext
// HTTP/2 (h2c) with preserved trailers (docs/spec/traffic.md).
func NewTransport() *http.Transport {
	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)

	return &http.Transport{
		Protocols:       protocols,
		IdleConnTimeout: 90 * time.Second,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}
}

// WriteStatus writes a trailers-only gRPC response: HTTP 200 with the
// status delivered in the initial metadata, per the gRPC HTTP/2 protocol.
func WriteStatus(w http.ResponseWriter, code, message string) {
	header := w.Header()
	header.Set("Content-Type", "application/grpc")
	header.Set("Grpc-Status", code)
	header.Set("Grpc-Message", message)

	w.WriteHeader(http.StatusOK)
}

// Unimplemented answers a gRPC request matching no rule
// (docs/spec/traffic.md gRPC routing).
func Unimplemented(w http.ResponseWriter) {
	WriteStatus(w, StatusUnimplemented, "no matching rule")
}

// Unavailable answers a gRPC request whose backend has no ready endpoint
// (docs/spec/failure-modes.md).
func Unavailable(w http.ResponseWriter) {
	WriteStatus(w, StatusUnavailable, "no ready endpoints")
}

// Internal answers a gRPC request whose backend reference is unresolvable,
// keeping its weight share per the Gateway API.
func Internal(w http.ResponseWriter) {
	WriteStatus(w, StatusInternal, "invalid backend reference")
}

// StatusFromHeader extracts the gRPC status written to a response, whether
// it arrived as initial metadata (trailers-only responses) or as a real
// trailer copied by the reverse proxy.
func StatusFromHeader(header http.Header) (string, bool) {
	if status := header.Get("Grpc-Status"); status != "" {
		return status, true
	}

	if status := header.Get(http.TrailerPrefix + "Grpc-Status"); status != "" {
		return status, true
	}

	return "", false
}
