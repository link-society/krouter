package main

import (
	"fmt"
	"log/slog"

	"os"

	"github.com/link-society/krouter/internal/config"
	"github.com/link-society/krouter/internal/wiring"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "krouter: %v\n", err)
		os.Exit(64)
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: cfg.LogLevel,
	}))
	slog.SetDefault(logger)

	app, err := wiring.New(cfg, logger)
	if err != nil {
		fmt.Fprintf(os.Stderr, "krouter: %v\n", err)
		os.Exit(64)
	}

	app.Run()
}
