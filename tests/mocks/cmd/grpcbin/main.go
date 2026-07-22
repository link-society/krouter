// Command grpcbin is a small gRPC backend in the spirit of grpcbin.com,
// used by the demo topology (tests/config/mocks/manifest.yml). It serves
// the standard helloworld.Greeter and grpc.health.v1.Health services with
// server reflection enabled (so grpcurl works out of the box) on two
// listeners:
//
//	:9000 (PORT)      plaintext h2c
//	:9001 (TLS_PORT)  TLS with a self-signed certificate generated at boot
//
// The TLS listener exists to back TLS passthrough routes; clients are
// expected to skip verification. Greeter replies include the serving pod's
// hostname so load balancing is observable.
package main

import (
	"context"
	"fmt"
	"log"

	"os"

	"strings"

	"time"

	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"

	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"

	helloworldpb "google.golang.org/grpc/examples/helloworld/helloworld"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "9000"
	}

	tlsPort := os.Getenv("TLS_PORT")
	if tlsPort == "" {
		tlsPort = "9001"
	}

	serverNames := strings.Split(os.Getenv("TLS_SERVER_NAMES"), ",")

	hostname, err := os.Hostname()
	if err != nil {
		log.Fatalf("hostname: %v", err)
	}

	cert, err := selfSignedCert(append(serverNames, hostname, "localhost"))
	if err != nil {
		log.Fatalf("self-signed certificate: %v", err)
	}

	errs := make(chan error, 2)

	go func() {
		log.Printf("grpcbin %s listening on :%s (h2c)", hostname, port)
		errs <- serve(port, hostname)
	}()

	go func() {
		log.Printf("grpcbin %s listening on :%s (tls)", hostname, tlsPort)
		errs <- serve(tlsPort, hostname, grpc.Creds(credentials.NewServerTLSFromCert(&cert)))
	}()

	log.Fatal(<-errs)
}

func serve(port, hostname string, opts ...grpc.ServerOption) error {
	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		return fmt.Errorf("listen :%s: %w", port, err)
	}

	server := grpc.NewServer(opts...)
	helloworldpb.RegisterGreeterServer(server, &greeter{hostname: hostname})

	healthServer := health.NewServer()
	healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	healthpb.RegisterHealthServer(server, healthServer)

	reflection.Register(server)

	return server.Serve(ln)
}

type greeter struct {
	helloworldpb.UnimplementedGreeterServer

	hostname string
}

func (g *greeter) SayHello(
	ctx context.Context,
	req *helloworldpb.HelloRequest,
) (*helloworldpb.HelloReply, error) {
	return &helloworldpb.HelloReply{
		Message: fmt.Sprintf("Hello %s from %s", req.GetName(), g.hostname),
	}, nil
}

func selfSignedCert(dnsNames []string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	names := make([]string, 0, len(dnsNames))
	for _, name := range dnsNames {
		if name = strings.TrimSpace(name); name != "" {
			names = append(names, name)
		}
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "grpcbin"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     names,
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}, nil
}
