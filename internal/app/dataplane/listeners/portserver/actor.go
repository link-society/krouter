// Package portserver is the child actor owning one internal listener port
// (docs/spec/architecture.md). It implements actor.Actor directly: Start begins accepting,
// Stop drains gracefully. Its request handling only reads snapshots
// published by its sibling actors, so table swaps never disturb established
// connections (docs/spec/traffic.md).
package portserver

import (
	"context"
	"fmt"
	"log/slog"

	"crypto/tls"
	"net"
	"net/http"

	"time"

	"github.com/vladopajic/go-actor/actor"

	"github.com/link-society/krouter/internal/lib/transports/http/proxy"
)

// Server is one internal listener actor. The socket is bound before the
// actor starts, so a failing port is reported to the supervisor instead of
// crash-looping.
type Server struct {
	port     int32
	withTLS  bool
	listener net.Listener
	server   *http.Server
}

var _ actor.Actor = (*Server)(nil)

func New(port int32, withTLS bool, handler *proxy.Handler) (*Server, error) {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, err
	}

	httpHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handler.Serve(w, r, port, withTLS)
	})

	// Downstream connections speak HTTP/1.1 and HTTP/2 (docs/spec/traffic.md),
	// including cleartext HTTP/2 on HTTP listeners — handled natively by
	// net/http.
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetHTTP2(true)
	protocols.SetUnencryptedHTTP2(!withTLS)

	server := &http.Server{
		// No read/idle timeouts: downstream connections are long-lived by
		// design and must survive arbitrarily long holds (docs/spec/performance.md).
		Handler:   httpHandler,
		Protocols: protocols,
	}

	if withTLS {
		server.TLSConfig = &tls.Config{
			// Per-connection configuration: the SNI-selected listener
			// provides the certificate and its client-certificate
			// validation (docs/spec/security.md).
			GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
				return handler.TLSConfigFor(port, hello.ServerName)
			},
		}
	}

	return &Server{
		port:     port,
		withTLS:  withTLS,
		listener: ln,
		server:   server,
	}, nil
}

// Start begins accepting downstream connections.
func (s *Server) Start() {
	go func() {
		var err error
		if s.withTLS {
			err = s.server.ServeTLS(s.listener, "", "")
		} else {
			err = s.server.Serve(s.listener)
		}

		if err != nil && err != http.ErrServerClosed {
			slog.Error("listener terminated", "port", s.port, "error", err)
		}
	}()

	slog.Info("listener started", "port", s.port, "tls", s.withTLS)
}

// Stop stops new accepts immediately and drains active connections within
// normal server limits (docs/spec/traffic.md) before returning.
func (s *Server) Stop() {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s.server.Shutdown(shutdownCtx)
}
