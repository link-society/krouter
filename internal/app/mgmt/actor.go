// Package mgmt is the management server actor (docs/spec/observability.md): it serves /livez,
// /readyz and /metrics on the management port for the lifetime of its
// supervision tree. Like any long-lived server, it implements actor.Actor
// directly: Start begins serving, Stop shuts down gracefully.
package mgmt

import (
	"context"
	"fmt"
	"log/slog"

	"net/http"

	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/vladopajic/go-actor/actor"

	"github.com/link-society/krouter/internal/config"
)

// ReadyFunc renders the /readyz response body and its HTTP status code.
type ReadyFunc func() ([]byte, int)

// Server is the management server actor.
type Server struct {
	server *http.Server
}

var _ actor.Actor = (*Server)(nil)

// New builds the management server actor. Each plane supervises one,
// providing its own readiness body.
func New(cfg *config.Settings, ready ReadyFunc) *Server {
	mux := http.NewServeMux()

	mux.HandleFunc("/livez", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"alive":true}`))
	})

	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		body, code := ready()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		w.Write(body)
	})

	mux.Handle("/metrics", promhttp.Handler())

	return &Server{
		server: &http.Server{
			Addr:              fmt.Sprintf(":%d", cfg.ManagementPort),
			Handler:           mux,
			ReadHeaderTimeout: 10 * time.Second,
		},
	}
}

func (s *Server) Start() {
	go func() {
		slog.Info("management server listening", "addr", s.server.Addr)

		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("management server terminated", "error", err)
		}
	}()
}

func (s *Server) Stop() {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s.server.Shutdown(shutdownCtx)
}
