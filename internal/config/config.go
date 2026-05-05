package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
)

type Config struct {
	ProxyListen           string
	UpstreamAddr          string
	UpstreamTLS           bool
	UpstreamTLSSkipVerify bool
	LogLevel              string
	LogFormat             string
}

func Load() (*Config, error) {
	rawUpstream := getenv("UPSTREAM_ADDR", "1.2.3.4:389")
	upstreamAddr, schemeTLS, err := parseUpstream(rawUpstream)
	if err != nil {
		return nil, fmt.Errorf("UPSTREAM_ADDR: %w", err)
	}

	c := &Config{
		ProxyListen:           getenv("PROXY_LISTEN", "0.0.0.0:3389"),
		UpstreamAddr:          upstreamAddr,
		UpstreamTLS:           getenvBool("UPSTREAM_TLS", schemeTLS),
		UpstreamTLSSkipVerify: getenvBool("UPSTREAM_TLS_SKIP_VERIFY", false),
		LogLevel:              strings.ToLower(getenv("LOG_LEVEL", "info")),
		LogFormat:             strings.ToLower(getenv("LOG_FORMAT", "text")),
	}

	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return nil, fmt.Errorf("invalid LOG_LEVEL: %s (allowed: debug, info, warn, error)", c.LogLevel)
	}

	switch c.LogFormat {
	case "text", "json":
	default:
		return nil, fmt.Errorf("invalid LOG_FORMAT: %s (allowed: text, json)", c.LogFormat)
	}

	if c.ProxyListen == "" {
		return nil, fmt.Errorf("PROXY_LISTEN must not be empty")
	}
	if c.UpstreamAddr == "" {
		return nil, fmt.Errorf("UPSTREAM_ADDR must not be empty")
	}

	return c, nil
}

// parseUpstream accepts either a host:port string or an ldap:// / ldaps:// URL.
// Returns the host:port form for net.Dial and a boolean indicating whether the
// scheme implied TLS (ldaps). The TLS hint can be overridden by UPSTREAM_TLS.
func parseUpstream(s string) (addr string, tls bool, err error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", false, fmt.Errorf("must not be empty")
	}
	lower := strings.ToLower(s)
	if strings.HasPrefix(lower, "ldap://") || strings.HasPrefix(lower, "ldaps://") {
		u, perr := url.Parse(s)
		if perr != nil {
			return "", false, perr
		}
		host := u.Hostname()
		port := u.Port()
		if host == "" {
			return "", false, fmt.Errorf("missing host in %q", s)
		}
		if port == "" {
			if strings.EqualFold(u.Scheme, "ldaps") {
				port = "636"
			} else {
				port = "389"
			}
		}
		return net.JoinHostPort(host, port), strings.EqualFold(u.Scheme, "ldaps"), nil
	}
	if _, _, perr := net.SplitHostPort(s); perr != nil {
		return "", false, fmt.Errorf("expected host:port or ldap[s]://host[:port], got %q: %v", s, perr)
	}
	return s, false, nil
}

func getenv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}

func getenvBool(key string, fallback bool) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	switch v {
	case "":
		return fallback
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}
