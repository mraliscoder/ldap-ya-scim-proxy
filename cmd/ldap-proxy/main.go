package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"yascimldapproxy/internal/config"
	"yascimldapproxy/internal/proxy"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, "config error:", err)
		os.Exit(2)
	}

	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		os.Exit(runHealthcheck(cfg.ProxyListen))
	}

	log := newLogger(cfg.LogLevel, cfg.LogFormat)

	srv := proxy.New(cfg, log)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Start(ctx) }()

	select {
	case <-ctx.Done():
		log.Info("shutdown signal received, stopping accept loop")
	case err := <-serveErr:
		if err != nil {
			log.Error("server failed", "err", err)
			os.Exit(1)
		}
	}

	srv.Shutdown(10 * time.Second)
	log.Info("shutdown complete")
}

func newLogger(level, format string) *slog.Logger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: lvl}
	var handler slog.Handler
	if format == "json" {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		handler = slog.NewTextHandler(os.Stdout, opts)
	}
	return slog.New(handler)
}

// runHealthcheck performs a TCP connect against the proxy's listen port on
// loopback. Used as the container HEALTHCHECK probe in the distroless image,
// where no shell is available.
func runHealthcheck(listen string) int {
	_, port, err := net.SplitHostPort(listen)
	if err != nil {
		return 1
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", port), 2*time.Second)
	if err != nil {
		return 1
	}
	_ = conn.Close()
	return 0
}
