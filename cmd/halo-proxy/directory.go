package main

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/dshakes/halos/internal/gateway"
)

// DirectoryConfig points at halo-server's SCIM directory (ADR-0022). When set,
// the directory is authoritative: a verified caller's groups are the
// directory's, and a verified caller it does not list as active is refused
// (403); workload credentials skip the lookup (they are not in SCIM).
type DirectoryConfig struct {
	URL       string `yaml:"url"`       // https://halo-server/api/v1/gateway/directory; empty disables
	TokenFile string `yaml:"tokenFile"` // halo-server --gateway-directory-token-file value (else --gateway-token-file)
	// CacheTTL is how long an entry is reused per subject (default 1m): the
	// longest a deprovisioned user keeps their cohort at this gateway.
	CacheTTL time.Duration `yaml:"cacheTTL"`
	// Grace is how long the last entry keeps serving while halo-server is
	// unreachable (default 5m). After it, FailMode decides.
	Grace time.Duration `yaml:"grace"`
	// FailMode: open (default) keeps the verified caller with no groups
	// (default routing, no experiments; posture gate and per-user budgets
	// still apply); closed answers 503. A caller is never made anonymous.
	FailMode string `yaml:"failMode"`
	// Mode: full (default) resolves callers in SCIM and checks halo-server
	// credentials against the revocation list (ADR-0026); revocations checks
	// only the revocation list, for a halo-server without SCIM.
	Mode string `yaml:"mode"`
	// AllowInsecureInCluster permits plain http to a non-loopback host.
	AllowInsecureInCluster bool `yaml:"allowInsecureInCluster"`
}

// build returns nil when the directory is not configured.
func (c DirectoryConfig) build(log *slog.Logger) (*gateway.DirectoryClient, error) {
	if err := gateway.CheckDirectoryFailMode(c.FailMode); err != nil {
		return nil, fmt.Errorf("halo-proxy: %w", err)
	}
	if err := gateway.CheckDirectoryMode(c.Mode); err != nil {
		return nil, fmt.Errorf("halo-proxy: %w", err)
	}
	if c.URL == "" {
		if c.TokenFile != "" {
			return nil, fmt.Errorf("halo-proxy: directory.url is required when directory.tokenFile is set")
		}
		return nil, nil
	}
	if c.TokenFile == "" {
		return nil, fmt.Errorf("halo-proxy: directory needs tokenFile")
	}
	tok, err := os.ReadFile(c.TokenFile)
	if err != nil {
		return nil, fmt.Errorf("halo-proxy: directory.tokenFile: %w", err)
	}
	dc, err := gateway.NewDirectoryClient(c.URL, strings.TrimSpace(string(tok)), c.CacheTTL, c.Grace, log, c.AllowInsecureInCluster)
	if err != nil {
		return nil, fmt.Errorf("halo-proxy: %w", err)
	}
	dc.FailClosed = c.FailMode == gateway.DirectoryFailClosed
	dc.RevocationsOnly = c.Mode == gateway.DirectoryModeRevocations
	return dc, nil
}
