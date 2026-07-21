// Package config loads the installation-level application settings from
// KROUTER_* environment variables (docs/spec/deployment.md).
package config

import (
	"fmt"
	"log/slog"

	"os"
	"strconv"
)

const (
	ModeControlPlane = "controlplane"
	ModeDataPlane    = "dataplane"
)

type Settings struct {
	Mode            string
	ControllerName  string
	SystemNamespace string
	InternalPortMin int
	InternalPortMax int
	ManagementPort  int
	DashboardPort   int
	LogLevel        slog.Level
}

func Load() (*Settings, error) {
	s := &Settings{
		Mode:            os.Getenv("KROUTER_MODE"),
		ControllerName:  envOr("KROUTER_CONTROLLER_NAME", "link-society.com/krouter"),
		SystemNamespace: envOr("KROUTER_SYSTEM_NAMESPACE", "krouter-system"),
	}

	var err error

	s.InternalPortMin, err = envInt("KROUTER_INTERNAL_PORT_MIN", 10000)
	if err != nil {
		return nil, err
	}

	s.InternalPortMax, err = envInt("KROUTER_INTERNAL_PORT_MAX", 29999)
	if err != nil {
		return nil, err
	}

	s.ManagementPort, err = envInt("KROUTER_MANAGEMENT_PORT", 9090)
	if err != nil {
		return nil, err
	}

	s.DashboardPort, err = envInt("KROUTER_DASHBOARD_PORT", 8080)
	if err != nil {
		return nil, err
	}

	if s.InternalPortMin > s.InternalPortMax {
		return nil, fmt.Errorf("invalid internal port range: %d-%d", s.InternalPortMin, s.InternalPortMax)
	}

	switch level := envOr("KROUTER_LOG_LEVEL", "info"); level {
	case "debug":
		s.LogLevel = slog.LevelDebug

	case "info":
		s.LogLevel = slog.LevelInfo

	case "warn":
		s.LogLevel = slog.LevelWarn

	case "error":
		s.LogLevel = slog.LevelError

	default:
		return nil, fmt.Errorf("invalid KROUTER_LOG_LEVEL: %q", level)
	}

	return s, nil
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}

	return fallback
}

func envInt(key string, fallback int) (int, error) {
	value := os.Getenv(key)
	if value == "" {
		return fallback, nil
	}

	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("invalid %s: %w", key, err)
	}

	return parsed, nil
}
