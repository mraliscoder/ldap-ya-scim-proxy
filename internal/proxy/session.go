package proxy

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"yascimldapproxy/internal/config"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
)

type session struct {
	client   net.Conn
	upstream net.Conn
	cfg      *config.Config
	log      *slog.Logger

	mu         sync.Mutex
	addedAttrs map[int64][]string

	closeOnce sync.Once
}

func newSession(client, upstream net.Conn, cfg *config.Config, log *slog.Logger) *session {
	return &session{
		client:     client,
		upstream:   upstream,
		cfg:        cfg,
		log:        log,
		addedAttrs: make(map[int64][]string),
	}
}

// closeBoth shuts down both connections exactly once. Idempotent.
func (s *session) closeBoth() {
	s.closeOnce.Do(func() {
		_ = s.client.Close()
		_ = s.upstream.Close()
	})
}

func (s *session) run(ctx context.Context) {
	stopWatcher := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			s.closeBoth()
		case <-stopWatcher:
		}
	}()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		s.pumpClientToUpstream()
		s.closeBoth()
	}()

	go func() {
		defer wg.Done()
		s.pumpUpstreamToClient()
		s.closeBoth()
	}()

	wg.Wait()
	close(stopWatcher)
}

func (s *session) pumpClientToUpstream() {
	for {
		packet, err := ber.ReadPacket(s.client)
		if err != nil {
			s.logIOError("client read", err)
			return
		}

		messageID, opTag, opClass := getMessageInfo(packet)
		if opClass == ber.ClassApplication {
			switch opTag {
			case tagSearchRequest:
				filter := ""
				if len(packet.Children) >= 2 && len(packet.Children[1].Children) >= 7 {
					if f, fErr := ldap.DecompileFilter(packet.Children[1].Children[6]); fErr == nil {
						filter = f
					}
				}
				s.log.Debug("search request",
					"msg_id", messageID,
					"base", searchBaseDN(packet),
					"scope", searchScope(packet),
					"filter", filter,
				)
				if added := maybeRewriteSearchRequest(packet); len(added) > 0 {
					s.mu.Lock()
					s.addedAttrs[messageID] = added
					s.mu.Unlock()
					rebuildPacket(packet)
					s.log.Debug("search request rewritten", "msg_id", messageID, "added_attrs", added)
				}
			case tagBindRequest:
				s.log.Debug("bind request", "msg_id", messageID)
			case tagUnbindRequest:
				s.log.Debug("unbind request", "msg_id", messageID)
			case tagAbandonRequest:
				s.log.Debug("abandon request", "msg_id", messageID)
			}
		}

		if _, err := s.upstream.Write(packet.Bytes()); err != nil {
			s.logIOError("upstream write", err)
			return
		}
	}
}

func (s *session) pumpUpstreamToClient() {
	for {
		packet, err := ber.ReadPacket(s.upstream)
		if err != nil {
			s.logIOError("upstream read", err)
			return
		}

		messageID, opTag, opClass := getMessageInfo(packet)
		if opClass == ber.ClassApplication {
			switch opTag {
			case tagSearchResultEntry:
				s.mu.Lock()
				added := s.addedAttrs[messageID]
				s.mu.Unlock()
				if transformSearchResultEntry(packet, added, s.log) {
					rebuildPacket(packet)
				}
			case tagSearchResultDone:
				s.mu.Lock()
				delete(s.addedAttrs, messageID)
				s.mu.Unlock()
			}
		}

		if _, err := s.client.Write(packet.Bytes()); err != nil {
			s.logIOError("client write", err)
			return
		}
	}
}

func (s *session) logIOError(direction string, err error) {
	if err == nil {
		return
	}
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) ||
		strings.Contains(err.Error(), "use of closed network connection") {
		return
	}
	s.log.Debug("io error", "direction", direction, "err", err)
}

func dialUpstream(cfg *config.Config) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	if cfg.UpstreamTLS {
		return tls.DialWithDialer(dialer, "tcp", cfg.UpstreamAddr, &tls.Config{
			InsecureSkipVerify: cfg.UpstreamTLSSkipVerify,
		})
	}
	return dialer.Dial("tcp", cfg.UpstreamAddr)
}
