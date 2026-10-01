package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/halos-dev/halos/internal/bundle"
)

func TestKillSwitchConfig(t *testing.T) {
	dir := t.TempDir()
	_, pubPEM, err := bundle.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	write := func(name, v string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	tok, pub, junk := write("tok", "gw-token\n"), write("pub", string(pubPEM)), write("junk", "nope")
	cfgFile := write("proxy.yaml", "policy: /p.json\nkillSwitch:\n  url: https://halo.test/api/v1/gateway/killswitch\n  tokenFile: "+tok+"\n  pubkeyFile: "+pub+"\n  interval: 3s\n")
	cfg, err := loadConfig([]string{"--config", cfgFile}, func(string) string { return "" }, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	k, err := cfg.KillSwitch.build(log)
	if err != nil || k == nil || k.Token != "gw-token" || k.Interval != 3*time.Second {
		t.Fatalf("build: %+v %v", k, err)
	}
	if k, err := (KillSwitchConfig{}).build(log); k != nil || err != nil {
		t.Fatalf("unset: %v %v", k, err)
	}
	for name, c := range map[string]KillSwitchConfig{
		"files without url": {TokenFile: tok},
		"missing pubkey":    {URL: "https://h", TokenFile: tok},
		"unreadable token":  {URL: "https://h", TokenFile: filepath.Join(dir, "none"), PubkeyFile: pub},
		"bad pubkey":        {URL: "https://h", TokenFile: tok, PubkeyFile: junk},
		"bad url":           {URL: "::", TokenFile: tok, PubkeyFile: pub},
	} {
		if _, err := c.build(log); err == nil || !strings.Contains(err.Error(), "halo-proxy") {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}
