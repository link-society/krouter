package routing

import (
	"bytes"
	"io"
	"testing"

	"math/big"

	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"

	"encoding/pem"

	"net/http"
	"net/http/httptest"

	"github.com/link-society/krouter/internal/lib/k8s/compiled"
)

func TestBackendTLSTransportProtocols(t *testing.T) {
	for _, tt := range []struct {
		name        string
		http2       bool
		badHostname bool
	}{
		{name: "gRPC over TLS", http2: true},
		{name: "HTTP1 over TLS"},
		{name: "reject invalid hostname", http2: true, badHostname: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			// A framed gRPC message and trailers must survive HTTP/2 over TLS.
			payload := []byte{0, 0, 0, 0, 5, 'h', 'e', 'l', 'l', 'o'}
			backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				wantProtocol := 1
				if tt.http2 {
					wantProtocol = 2
				}
				if r.ProtoMajor != wantProtocol {
					http.Error(w, "wrong backend protocol", http.StatusHTTPVersionNotSupported)
					return
				}
				w.Header().Set("Content-Type", "application/grpc")
				w.Header().Set("Trailer", "Grpc-Status")
				io.Copy(w, r.Body)
				w.Header().Set("Grpc-Status", "0")
			}))
			backend.EnableHTTP2 = tt.http2
			backend.StartTLS()
			defer backend.Close()

			hostname := "example.com" // httptest's certificate includes example.com.
			if tt.badHostname {
				hostname = "invalid.example.org"
			}
			entry := buildBackendTable(compiled.Backend{
				Namespace: "ns", Name: "grpc", Port: 443, Weight: 1, Valid: true,
				TLS: &compiled.BackendTLS{
					Hostname: hostname,
					CAPem: string(pem.EncodeToMemory(&pem.Block{
						Type: "CERTIFICATE", Bytes: backend.Certificate().Raw,
					})),
				},
			}, nil, "", map[string]*http.Transport{})
			if entry.tlsTransport == nil {
				t.Fatal("expected a valid BackendTLSPolicy transport")
			}
			defer entry.tlsTransport.CloseIdleConnections()

			request, err := http.NewRequest(http.MethodPost, backend.URL, bytes.NewReader(payload))
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Content-Type", "application/grpc")
			response, err := entry.tlsTransport.RoundTrip(request)
			if tt.badHostname {
				if err == nil {
					response.Body.Close()
					t.Fatal("backend certificate hostname mismatch must fail")
				}
				return
			}
			if err != nil {
				t.Fatalf("proxying to TLS backend: %v", err)
			}
			defer response.Body.Close()
			body, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != http.StatusOK || !bytes.Equal(body, payload) {
				t.Fatalf("backend response: status=%d body=%q", response.StatusCode, body)
			}
			if response.Trailer.Get("Grpc-Status") != "0" {
				t.Fatalf("missing successful gRPC trailer: %v", response.Trailer)
			}
		})
	}
}

// testCAPem generates a self-signed CA certificate in PEM form.
func testCAPem(t *testing.T) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}

	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestBuildBackendTableReusesTransports(t *testing.T) {
	// docs/spec/configuration.md: transports with equal TLS fingerprints
	// are interchangeable, so pooled connections survive table swaps.
	caPem := testCAPem(t)

	backend := compiled.Backend{
		Namespace: "ns", Name: "svc", Port: 443, Weight: 1, Valid: true,
		TLS: &compiled.BackendTLS{Hostname: "svc.example.com", CAPem: caPem},
	}

	transports := map[string]*http.Transport{}

	first := buildBackendTable(backend, nil, "", transports)
	if first.tlsTransport == nil {
		t.Fatal("expected a TLS transport")
	}

	second := buildBackendTable(backend, nil, "", transports)
	if second.tlsTransport != first.tlsTransport {
		t.Error("identical TLS configurations must share one transport")
	}

	other := backend
	other.TLS = &compiled.BackendTLS{Hostname: "other.example.com", CAPem: caPem}

	third := buildBackendTable(other, nil, "", transports)
	if third.tlsTransport == first.tlsTransport {
		t.Error("distinct TLS configurations must not share a transport")
	}
}

func TestPreviousTransportsIndexesByFingerprint(t *testing.T) {
	transport := &http.Transport{}

	previous := &GatewayTable{byPort: map[int32]*PortTable{
		443: {listeners: []*ListenerTable{{
			routes: []*RouteTable{{
				rules: []*RuleTable{{
					backends: []*BackendTable{{tlsKey: "key", tlsTransport: transport}},
				}},
			}},
		}}},
	}}

	cache := previousTransports(previous)
	if cache["key"] != transport {
		t.Error("previous transports must be indexed by fingerprint")
	}

	if len(previousTransports(nil)) != 0 {
		t.Error("nil previous table must yield an empty cache")
	}
}
