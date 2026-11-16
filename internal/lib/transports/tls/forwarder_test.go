package tls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdtls "crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

type fixedPicker struct{ selection Selection }

func (p fixedPicker) PickTLS(int32, string) (Selection, bool) { return p.selection, true }

func testCertificate(t *testing.T, hostname string) (stdtls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		DNSNames:              []string{hostname},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return stdtls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

func TestForwarderBackendTLS(t *testing.T) {
	frontendCert, frontendRoots := testCertificate(t, "frontend.example.com")
	backendCert, backendRoots := testCertificate(t, "backend.example.com")
	for _, tt := range []struct {
		name        string
		terminate   bool
		backendTLS  *stdtls.Config
		wantSuccess bool
	}{
		{"re-encrypt", true, &stdtls.Config{ServerName: "backend.example.com", RootCAs: backendRoots}, true},
		{"hostname mismatch", true, &stdtls.Config{ServerName: "other.example.com", RootCAs: backendRoots}, false},
		{"untrusted certificate", true, &stdtls.Config{ServerName: "backend.example.com", RootCAs: frontendRoots}, false},
		{"plaintext without policy", true, nil, true},
		{"passthrough preserves original TLS", false, &stdtls.Config{ServerName: "other.example.com", RootCAs: backendRoots}, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			backend, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { backend.Close() })
			backendDone := make(chan error, 1)
			go func() {
				conn, err := backend.Accept()
				if err != nil {
					backendDone <- err
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				if tt.backendTLS != nil {
					certificate, hostname := backendCert, "backend.example.com"
					if !tt.terminate {
						certificate, hostname = frontendCert, "frontend.example.com"
					}
					server := stdtls.Server(conn, &stdtls.Config{Certificates: []stdtls.Certificate{certificate}})
					if err := server.Handshake(); err != nil {
						backendDone <- err
						return
					}
					if got := server.ConnectionState().ServerName; got != hostname {
						backendDone <- fmt.Errorf("backend SNI = %q, want %q", got, hostname)
						return
					}
					conn = server
				}
				payload := make([]byte, len("hello"))
				if _, err := io.ReadFull(conn, payload); err != nil {
					backendDone <- err
					return
				}
				_, err = conn.Write(payload)
				backendDone <- err
			}()

			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { listener.Close() })
			forwarder := NewForwarder(fixedPicker{Selection{
				Endpoint: backend.Addr().String(), Terminate: tt.terminate,
				Certificate: &frontendCert, BackendTLS: tt.backendTLS,
			}})
			forwarder.dialTimeout = time.Second
			proxyDone := make(chan struct{})
			go func() {
				defer close(proxyDone)
				conn, err := listener.Accept()
				if err == nil {
					forwarder.Serve(conn, 8443)
				}
			}()

			client, err := stdtls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second},
				"tcp", listener.Addr().String(), &stdtls.Config{
					ServerName: "frontend.example.com", RootCAs: frontendRoots,
				})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { client.Close() })
			client.SetDeadline(time.Now().Add(3 * time.Second))
			_, exchangeErr := client.Write([]byte("hello"))
			response := make([]byte, len("hello"))
			if exchangeErr == nil {
				_, exchangeErr = io.ReadFull(client, response)
			}
			client.Close()
			if tt.wantSuccess {
				if exchangeErr != nil || string(response) != "hello" {
					t.Errorf("forwarded response = %q, error = %v", response, exchangeErr)
				}
			} else if exchangeErr == nil {
				t.Error("backend TLS verification failure must not forward application data")
			}

			select {
			case err := <-backendDone:
				if tt.wantSuccess && err != nil {
					t.Errorf("backend: %v", err)
				}
				if !tt.wantSuccess && err == nil {
					t.Error("backend accepted a connection with invalid TLS verification")
				}
			case <-time.After(5 * time.Second):
				t.Error("backend did not finish")
			}
			select {
			case <-proxyDone:
			case <-time.After(5 * time.Second):
				t.Error("forwarder did not finish")
			}
		})
	}
}
