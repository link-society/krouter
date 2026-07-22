// Package udpserver is the child actor owning one internal UDP listener
// port (docs/spec/architecture.md). It implements actor.Actor directly:
// Start begins the datagram loop, Stop closes the socket and expires the
// flows. The shared datagram engine keeps flow-to-backend association, so
// table swaps never disturb established flows (docs/spec/traffic.md).
package udpserver

import (
	"fmt"
	"log/slog"

	"net"

	"sync"

	"time"

	"github.com/vladopajic/go-actor/actor"

	"github.com/link-society/krouter/internal/lib/transports/udp"
)

// Server is one internal UDP listener actor. The socket is bound before
// the actor starts, so a failing port is reported to the supervisor
// instead of crash-looping.
type Server struct {
	port      int32
	conn      *net.UDPConn
	forwarder *udp.Forwarder

	serving sync.WaitGroup
}

var _ actor.Actor = (*Server)(nil)

func New(port int32, forwarder *udp.Forwarder) (*Server, error) {
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, err
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return nil, err
	}

	return &Server{
		port:      port,
		conn:      conn,
		forwarder: forwarder,
	}, nil
}

// Start begins the datagram loop.
func (s *Server) Start() {
	s.serving.Go(func() {
		s.forwarder.Serve(s.conn, s.port)
	})

	slog.Info("udp listener started", "port", s.port)
}

// Stop closes the socket, ending the datagram loop and expiring the flows
// (docs/spec/traffic.md).
func (s *Server) Stop() {
	s.conn.Close()

	done := make(chan struct{})
	go func() {
		s.serving.Wait()
		close(done)
	}()

	select {
	case <-done:

	case <-time.After(30 * time.Second):
		slog.Warn("udp listener drain timed out", "port", s.port)
	}
}
