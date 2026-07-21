// Package dashboard is the control-plane dashboard server actor: it serves
// the embedded web UI on the dashboard port for the lifetime of its
// supervision tree. Like any long-lived server, it implements actor.Actor
// directly: Start begins serving, Stop shuts down gracefully.
package dashboard

import (
	"context"
	"fmt"
	"log/slog"

	"net/http"

	"time"

	"github.com/vladopajic/go-actor/actor"

	"github.com/link-society/krouter/internal/config"
	webui "github.com/link-society/krouter/internal/dashboard"
	"github.com/link-society/krouter/internal/lib/k8s/gatewayapi"
	"github.com/link-society/krouter/internal/lib/snapshot"
)

// Server is the dashboard server actor.
type Server struct {
	server *http.Server
}

var _ actor.Actor = (*Server)(nil)

// New builds the dashboard server actor reading the topology snapshots
// published by the reconciler actor.
func New(cfg *config.Settings, topo *snapshot.Store[*gatewayapi.Topology]) *Server {
	return &Server{
		server: &http.Server{
			Addr:              fmt.Sprintf(":%d", cfg.DashboardPort),
			Handler:           webui.NewHandler(topo),
			ReadHeaderTimeout: 10 * time.Second,
		},
	}
}

func (s *Server) Start() {
	go func() {
		slog.Info("dashboard server listening", "addr", s.server.Addr)

		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("dashboard server terminated", "error", err)
		}
	}()
}

func (s *Server) Stop() {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s.server.Shutdown(shutdownCtx)
}
