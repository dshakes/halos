package main

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/dshakes/halos/internal/bundle"
	"github.com/dshakes/halos/internal/gateway"
)

// KillSwitchConfig points at halo-server's signed kill list.
type KillSwitchConfig struct {
	URL        string        `yaml:"url"`        // https://halo-server/api/v1/gateway/killswitch; empty disables
	TokenFile  string        `yaml:"tokenFile"`  // halo-server --gateway-token-file value
	PubkeyFile string        `yaml:"pubkeyFile"` // public half of halo-server --killswitch-key-file
	Interval   time.Duration `yaml:"interval"`   // default 10s
	// AllowInsecureInCluster permits plain http to a non-loopback host (an
	// in-cluster Service URL on a trusted pod network). Default: https required.
	AllowInsecureInCluster bool `yaml:"allowInsecureInCluster"`
}

// build returns nil when the kill switch is not configured.
func (c KillSwitchConfig) build(log *slog.Logger) (*gateway.KillSwitch, error) {
	if c.URL == "" {
		if c.TokenFile != "" || c.PubkeyFile != "" {
			return nil, fmt.Errorf("halo-proxy: killSwitch.url is required when tokenFile/pubkeyFile are set")
		}
		return nil, nil
	}
	if c.TokenFile == "" || c.PubkeyFile == "" {
		return nil, fmt.Errorf("halo-proxy: killSwitch needs tokenFile and pubkeyFile")
	}
	tok, err := os.ReadFile(c.TokenFile)
	if err != nil {
		return nil, fmt.Errorf("halo-proxy: killSwitch.tokenFile: %w", err)
	}
	pem, err := os.ReadFile(c.PubkeyFile)
	if err != nil {
		return nil, fmt.Errorf("halo-proxy: killSwitch.pubkeyFile: %w", err)
	}
	v, err := bundle.ParseEd25519Verifier(pem)
	if err != nil {
		return nil, fmt.Errorf("halo-proxy: killSwitch.pubkeyFile: %w", err)
	}
	ks, err := gateway.NewKillSwitch(c.URL, strings.TrimSpace(string(tok)), v.Key, c.Interval, log, c.AllowInsecureInCluster)
	if err != nil {
		return nil, fmt.Errorf("halo-proxy: %w", err)
	}
	return ks, nil
}
