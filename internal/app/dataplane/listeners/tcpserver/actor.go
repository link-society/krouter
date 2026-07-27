// Package tcpserver is the child actor owning one internal TCP listener
// port (docs/spec/architecture.md). It implements actor.Actor directly:
// Start begins accepting, Stop drains gracefully. Each accepted connection
// is forwarded by the shared raw stream engine, so table swaps never
// disturb established connections (docs/spec/traffic.md).
package tcpserver

import (
	"fmt"
	"log/slog"

	"net"

	"sync"

	"time"

	"github.com/vladopajic/go-actor/actor"

	"github.com/link-society/krouter/internal/lib/transports/proxyproto"
	"github.com/link-society/krouter/internal/lib/transports/tcp"
)

// Server is one internal TCP listener actor. The socket is bound before
// the actor starts, so a failing port is reported to the supervisor
// instead of crash-looping.
type Server struct {
	port      int32
	listener  net.Listener
	forwarder *tcp.Forwarder

	active sync.WaitGroup
}

var _ actor.Actor = (*Server)(nil)

// New binds the port. When trusted is non-nil, every connection must carry
// a proxy protocol preamble from a peer it accepts (docs/spec/traffic.md
// Proxy protocol).
func New(port int32, forwarder *tcp.Forwarder, trusted proxyproto.TrustFunc) (*Server, error) {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, err
	}

	if trusted != nil {
		ln = proxyproto.Wrap(ln, trusted)
	}

	return &Server{
		port:      port,
		listener:  ln,
		forwarder: forwarder,
	}, nil
}

// Start begins accepting downstream connections.
func (s *Server) Start() {
	go func() {
		for {
			conn, err := s.listener.Accept()
			if err != nil {
				// The listener was closed by Stop.
				return
			}

			s.active.Go(func() {
				s.forwarder.Serve(conn, s.port)
			})
		}
	}()

	slog.Info("tcp listener started", "port", s.port)
}

// Stop stops new accepts immediately and waits for established connections
// to finish within normal server limits (docs/spec/traffic.md).
func (s *Server) Stop() {
	s.listener.Close()

	done := make(chan struct{})
	go func() {
		s.active.Wait()
		close(done)
	}()

	select {
	case <-done:

	case <-time.After(30 * time.Second):
		slog.Warn("tcp listener drain timed out", "port", s.port)
	}
}
