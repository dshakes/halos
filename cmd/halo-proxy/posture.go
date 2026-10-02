package main

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/dshakes/halos/internal/gateway"
)

// PostureConfig points at halo-server's per-subject device posture verdicts.
type PostureConfig struct {
	URL       string `yaml:"url"`       // https://halo-server/api/v1/gateway/posture; empty disables
	TokenFile string `yaml:"tokenFile"` // halo-server --gateway-token-file value
	// CacheTTL is how long a verdict is reused per subject (default 1m).
	CacheTTL time.Duration `yaml:"cacheTTL"`
	// Grace is how long the last verdict keeps serving while halo-server is
	// unreachable (default 15m); after it the posture is unknown and requests pass.
	Grace time.Duration `yaml:"grace"`
	// AllowInsecureInCluster permits plain http to a non-loopback host.
	AllowInsecureInCluster bool `yaml:"allowInsecureInCluster"`
}

// build returns nil when posture is not configured.
func (c PostureConfig) build(log *slog.Logger) (*gateway.PostureClient, error) {
	if c.URL == "" {
		if c.TokenFile != "" {
			return nil, fmt.Errorf("halo-proxy: posture.url is required when posture.tokenFile is set")
		}
		return nil, nil
	}
	if c.TokenFile == "" {
		return nil, fmt.Errorf("halo-proxy: posture needs tokenFile")
	}
	tok, err := os.ReadFile(c.TokenFile)
	if err != nil {
		return nil, fmt.Errorf("halo-proxy: posture.tokenFile: %w", err)
	}
	pc, err := gateway.NewPostureClient(c.URL, strings.TrimSpace(string(tok)), c.CacheTTL, c.Grace, log, c.AllowInsecureInCluster)
	if err != nil {
		return nil, fmt.Errorf("halo-proxy: %w", err)
	}
	return pc, nil
}
