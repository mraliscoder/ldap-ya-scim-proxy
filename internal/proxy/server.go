package proxy

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"
	"time"

	"yascimldapproxy/internal/config"
)

type Server struct {
	cfg      *config.Config
	log      *slog.Logger
	listener net.Listener

	wg       sync.WaitGroup
	mu       sync.Mutex
	sessions map[*session]struct{}
}

func New(cfg *config.Config, log *slog.Logger) *Server {
	return &Server{
		cfg:      cfg,
		log:      log,
		sessions: make(map[*session]struct{}),
	}
}

// Start binds the listener and serves connections until ctx is cancelled or
// the listener fails. Returns nil on graceful shutdown via context, otherwise
// the underlying error.
func (s *Server) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.cfg.ProxyListen)
	if err != nil {
		return err
	}
	s.listener = ln
	s.log.Info("ldap proxy listening",
		"addr", s.cfg.ProxyListen,
		"upstream", s.cfg.UpstreamAddr,
		"upstream_tls", s.cfg.UpstreamTLS,
	)

	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return err
		}
		s.log.Info("accepted connection", "remote", conn.RemoteAddr().String())
		s.wg.Add(1)
		go s.handleClient(ctx, conn)
	}
}

// Shutdown waits up to timeout for active sessions to finish, then forcibly
// closes any that remain.
func (s *Server) Shutdown(timeout time.Duration) {
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return
	case <-time.After(timeout):
	}

	s.log.Warn("forcing close of active sessions after grace period")
	s.mu.Lock()
	for sess := range s.sessions {
		sess.closeBoth()
	}
	s.mu.Unlock()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		s.log.Warn("some sessions did not exit cleanly")
	}
}

func (s *Server) handleClient(ctx context.Context, client net.Conn) {
	defer s.wg.Done()
	defer client.Close()

	logger := s.log.With("remote", client.RemoteAddr().String())

	upstream, err := dialUpstream(s.cfg)
	if err != nil {
		logger.Error("upstream dial failed", "err", err)
		return
	}
	defer upstream.Close()

	sess := newSession(client, upstream, s.cfg, logger)

	s.mu.Lock()
	s.sessions[sess] = struct{}{}
	s.mu.Unlock()

	logger.Info("client connected")
	sess.run(ctx)
	logger.Info("client disconnected")

	s.mu.Lock()
	delete(s.sessions, sess)
	s.mu.Unlock()
}
