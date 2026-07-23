package routing

import (
	"testing"

	"math/big"

	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"

	"encoding/pem"

	"net/http"

	"github.com/link-society/krouter/internal/lib/k8s/compiled"
)

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
