package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"

	"github.com/halos-dev/halos/internal/bundle"
	"github.com/halos-dev/halos/internal/gateway"
)

// keyring accepts a release signed by any one of its ed25519 keys.
type keyring []bundle.Ed25519Verifier

func (keyring) Type() string { return "ed25519" }

func (k keyring) Verify(ctx context.Context, digest string, sig []byte) error {
	for _, v := range k {
		if v.Verify(ctx, digest, sig) == nil {
			return nil
		}
	}
	return fmt.Errorf("halod: signature matches none of the %d trusted release keys", len(k))
}

// keyFingerprint is "sha256:<hex>" of the raw 32-byte ed25519 public key.
func keyFingerprint(v bundle.Ed25519Verifier) string {
	h := sha256.Sum256(v.Key)
	return "sha256:" + hex.EncodeToString(h[:])
}

// loadKeyring parses every configured key, drops revoked ones and fails if
// none is left. It returns the fingerprints it trusts, for the startup log.
func loadKeyring(cfg Config) (keyring, []string, error) {
	var ring keyring
	var fps []string
	revoked := func(fp string) bool {
		return slices.ContainsFunc(cfg.RevokedKeys, func(r string) bool { return strings.EqualFold(strings.TrimSpace(r), fp) })
	}
	for _, f := range cfg.KeyFiles() {
		pem, err := os.ReadFile(f)
		if err != nil {
			return nil, nil, fmt.Errorf("read pubkey: %w", err)
		}
		v, err := bundle.ParseEd25519Verifier(pem)
		if err != nil {
			return nil, nil, fmt.Errorf("pubkey %s: %w", f, err)
		}
		fp := keyFingerprint(v)
		if revoked(fp) || slices.Contains(fps, fp) {
			continue
		}
		ring, fps = append(ring, v), append(fps, fp)
	}
	if len(ring) == 0 {
		return nil, nil, errors.New("no trusted release key left after revokedKeys")
	}
	return ring, fps, nil
}

// loadKillSwitch returns the kill-list poller, or nil when killSwitch is not configured.
func loadKillSwitch(cfg Config, log *slog.Logger) (*gateway.KillSwitch, error) {
	if cfg.KillSwitch.PubKey == "" {
		return nil, nil
	}
	pem, err := os.ReadFile(cfg.KillSwitch.PubKey)
	if err != nil {
		return nil, fmt.Errorf("read killSwitch.pubkey: %w", err)
	}
	v, err := bundle.ParseEd25519Verifier(pem)
	if err != nil {
		return nil, fmt.Errorf("killSwitch.pubkey %s: %w", cfg.KillSwitch.PubKey, err)
	}
	iv, _ := cfg.KillIntervalD() // validated by LoadConfig
	ks, err := gateway.NewKillSwitch(cfg.KillSwitch.URL, cfg.DeviceToken, v.Key, iv, log, false)
	if err != nil {
		return nil, fmt.Errorf("halod: %w", err)
	}
	return ks, nil
}
