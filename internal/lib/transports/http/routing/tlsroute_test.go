package routing

import (
	"crypto/tls"
	"net/http"
	"testing"

	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/utils/ptr"

	"github.com/link-society/krouter/internal/lib/k8s/compiled"
)

func TestPickTLSBackendPolicy(t *testing.T) {
	policy := &compiled.BackendTLS{Hostname: "backend.example.com", CAPem: testCAPem(t)}
	for _, tt := range []struct {
		name      string
		terminate bool
		policy    *compiled.BackendTLS
		wantOK    bool
		wantTLS   bool
	}{
		{"terminate with policy", true, policy, true, true},
		{"terminate without policy", true, nil, true, false},
		{"terminate with rejected policy", true, &compiled.BackendTLS{Invalid: true}, false, false},
		{"terminate with invalid CA", true, &compiled.BackendTLS{CAPem: "invalid"}, false, false},
		{"passthrough with policy", false, policy, true, false},
		{"passthrough with rejected policy", false, &compiled.BackendTLS{Invalid: true}, true, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			backend := buildBackendTable(compiled.Backend{
				Namespace: "ns", Name: "backend", Port: 443, Weight: 1, Valid: true, TLS: tt.policy,
			}, nil, "", map[string]*http.Transport{})
			certificate := &tls.Certificate{}
			tables := &Tables{byPort: map[int32]*PortTable{
				8443: {
					tlsPassthrough: true,
					listeners: []*ListenerTable{{
						hostname: "frontend.example.com", terminate: tt.terminate, cert: certificate,
						routes: []*RouteTable{{
							hostnames: []string{"frontend.example.com"},
							rules:     []*RuleTable{{backends: []*BackendTable{backend}, total: 1}},
						}},
					}},
				},
			}}
			index := NewEndpointsIndex()
			index.Services["ns/backend"] = &corev1.Service{Spec: corev1.ServiceSpec{
				Ports: []corev1.ServicePort{{Port: 443}},
			}}
			index.Slices["ns/backend"] = []*discoveryv1.EndpointSlice{{
				AddressType: discoveryv1.AddressTypeIPv4,
				Ports:       []discoveryv1.EndpointPort{{Port: ptr.To(int32(9443))}},
				Endpoints:   []discoveryv1.Endpoint{{Addresses: []string{"127.0.0.1"}}},
			}}

			selection, ok := tables.PickTLS(8443, "frontend.example.com", index)
			if ok != tt.wantOK {
				t.Fatalf("selection available = %v, want %v", ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if selection.Endpoint != "127.0.0.1:9443" || selection.Terminate != tt.terminate {
				t.Errorf("unexpected TLS selection: %+v", selection)
			}
			if (selection.BackendTLS != nil) != tt.wantTLS {
				t.Fatalf("backend TLS configured = %v, want %v", selection.BackendTLS != nil, tt.wantTLS)
			}
			if tt.wantTLS && (selection.BackendTLS.ServerName != policy.Hostname || selection.BackendTLS.RootCAs == nil) {
				t.Error("backend TLS selection lost its verification settings")
			}
		})
	}
}

func TestBackendTLSConfigIsIndependentOfHTTP(t *testing.T) {
	backend := compiled.Backend{
		Namespace: "ns", Name: "backend", Port: 443, Weight: 1, Valid: true,
		TLS: &compiled.BackendTLS{Hostname: "backend.example.com", CAPem: testCAPem(t)},
	}
	cache := map[string]*http.Transport{}
	first := buildBackendTable(backend, nil, "", cache)
	first.tlsTransport.TLSClientConfig.NextProtos = []string{"h2", "http/1.1"}
	second := buildBackendTable(backend, nil, "", cache)
	if second.tlsTransport != first.tlsTransport {
		t.Fatal("expected cached HTTP transport")
	}
	for _, entry := range []*BackendTable{first, second} {
		if entry.tlsConfig == nil || entry.tlsConfig.ServerName != backend.TLS.Hostname {
			t.Fatal("missing independent backend TLS configuration")
		}
		if len(entry.tlsConfig.NextProtos) != 0 {
			t.Error("HTTP protocol negotiation leaked into raw TLSRoute configuration")
		}
	}
}
