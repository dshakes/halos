package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/server"
)

// TestAdminAccessFlags (ADR-0036): session policy, token TTL and break-glass flags.
func TestAdminAccessFlags(t *testing.T) {
	base := []string{"--policy-dir", "p", "--token-file", "t"}
	for _, c := range []struct {
		name string
		args []string
		err  string
		chk  func(options) bool
	}{
		{"defaults", nil, "", func(o options) bool {
			return o.sessionTTL == 12*time.Hour && o.sessionIdle == time.Hour && o.serviceTokenMaxTTL == 90*24*time.Hour && !o.breakGlassEnabled && o.entraGraphURL == server.DefaultGraphURL
		}},
		{"idle 0 is off", []string{"--session-idle-timeout", "0"}, "", func(o options) bool { return o.sessionIdle < 0 }},
		{"custom", []string{"--session-ttl", "8h", "--session-idle-timeout", "20m", "--service-token-max-ttl", "720h"}, "", func(o options) bool {
			return o.sessionTTL == 8*time.Hour && o.sessionIdle == 20*time.Minute && o.serviceTokenMaxTTL == 720*time.Hour
		}},
		{"break-glass needs a hash", []string{"--breakglass-enabled"}, "--breakglass-hash-file", nil},
		{"break-glass needs allowed CIDRs", []string{"--breakglass-enabled", "--breakglass-hash-file", "h"}, "--breakglass-allowed-cidrs", nil},
		{"break-glass with CIDRs", []string{"--breakglass-enabled", "--breakglass-hash-file", "h", "--breakglass-allowed-cidrs", "10.8.0.0/16"}, "", func(o options) bool { return o.breakGlassCIDRs == "10.8.0.0/16" }},
	} {
		t.Run(c.name, func(t *testing.T) {
			o, err := parseFlags(append(append([]string{}, base...), c.args...))
			if c.err != "" {
				if err == nil || !strings.Contains(err.Error(), c.err) {
					t.Fatalf("err %v, want %q", err, c.err)
				}
				return
			}
			if err != nil || !c.chk(o) {
				t.Fatalf("%+v %v", o, err)
			}
		})
	}
}

func TestBreakGlassHashCommand(t *testing.T) {
	var out bytes.Buffer
	if err := runBreakGlassHash(strings.NewReader("a-long-enough-break-glass-password\n"), &out); err != nil {
		t.Fatal(err)
	}
	h := strings.TrimSpace(out.String())
	if !strings.HasPrefix(h, "pbkdf2-sha256$600000$") || strings.Contains(h, "a-long-enough") {
		t.Fatalf("hash %q", h)
	}
	if err := runBreakGlassHash(strings.NewReader("short\n"), &out); err == nil {
		t.Fatal("short password accepted")
	}
	f := filepath.Join(t.TempDir(), "h")
	if err := os.WriteFile(f, []byte(h+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	bg, err := breakGlassConfig(options{breakGlassEnabled: true, breakGlassUser: "bg", breakGlassHashFile: f, breakGlassCIDRs: "10.8.0.0/16"})
	if err != nil || bg.Hash != h || !bg.Enabled || bg.User != "bg" {
		t.Fatalf("%+v %v", bg, err)
	}
	if _, err := server.New(server.Config{PolicyDir: t.TempDir(), Token: "t", SessionKey: []byte(strings.Repeat("k", 32)), BreakGlass: bg}); err != nil {
		t.Fatalf("server refuses the generated hash: %v", err)
	}
}
