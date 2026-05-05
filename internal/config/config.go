package config

import (
	"fmt"
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
	c := &Config{
		ProxyListen:           getenv("PROXY_LISTEN", "0.0.0.0:3389"),
		UpstreamAddr:          getenv("UPSTREAM_ADDR", "1.2.3.4:389"),
		UpstreamTLS:           getenvBool("UPSTREAM_TLS", false),
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
