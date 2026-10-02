package main

import (
	"net"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
)

// win32Normalize approximates what Win32 path normalization does to a
// C:\ path before the filesystem sees it: trailing dots and spaces are
// stripped from every component, then "." and ".." are resolved.
func win32Normalize(p string) string {
	rest, _ := strings.CutPrefix(p, `C:\`)
	var out []string
	for _, c := range strings.Split(rest, `\`) {
		if c != "." && c != ".." {
			c = strings.TrimRight(c, ". ")
		}
		switch c {
		case "", ".":
		case "..":
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
		default:
			out = append(out, c)
		}
	}
	return `C:\` + strings.Join(out, `\`)
}

// TestAllowedWindowsWin32Normalization: components Win32 rewrites (".. "
// becomes "..", "x." becomes "x") and DOS device names must be refused, or a
// signed manifest could name a path that lands outside the managed directory.
func TestAllowedWindowsWin32Normalization(t *testing.T) {
	for _, p := range []string{
		`C:\Program Files\ClaudeCode\.. \.. \Halos\etc\halod.yaml`,
		`C:\Program Files\ClaudeCode\...\x.json`,
		`C:\Program Files\ClaudeCode\x.json.`,
		`C:\Program Files\ClaudeCode\x.json `,
		`C:\Program Files\ClaudeCode\NUL`,
		`C:\Program Files\ClaudeCode\con.json`,
		`C:\Program Files\ClaudeCode\COM1`,
		"C:\\Program Files\\ClaudeCode\\a\x00b",
	} {
		if err := allowedPath("claude-code", "windows", p); err == nil {
			t.Errorf("%q accepted", p)
		}
	}
	if err := allowedPath("claude-code", "windows", `C:\Program Files\ClaudeCode\managed-settings.d\10.json`); err != nil {
		t.Errorf("valid nested path refused: %v", err)
	}
}

// FuzzAllowedPath: whatever a (signed) manifest names, an accepted path must
// lie strictly under one of the harness's managed directories after the
// normalization the target OS applies, or match a managed single-file pattern.
func FuzzAllowedPath(f *testing.F) {
	for _, s := range []struct{ h, os, p string }{
		{"claude-code", "linux", "/etc/claude-code/managed-settings.json"},
		{"claude-code", "linux", "/etc/claude-code/../sudoers"},
		{"claude-code", "darwin", "/Library/Application Support/ClaudeCode/managed-settings.json"},
		{"claude-code", "windows", `C:\Program Files\ClaudeCode\managed-settings.json`},
		{"claude-code", "windows", `C:\Program Files\ClaudeCode\.. \Halos\etc\halod.yaml`},
		{"codex", "windows", `C:\ProgramData\OpenAI\Codex\requirements.toml`},
		{"gemini-cli", "linux", "/etc/profile.d/halos-gemini.sh"},
		{"copilot-cli", "darwin", "/Library/Application Support/GitHubCopilot/x"},
	} {
		f.Add(s.h, s.os, s.p)
	}
	f.Fuzz(func(t *testing.T, h, goos, p string) {
		if allowedPath(h, goos, p) != nil {
			return
		}
		if goos == "windows" {
			if n := win32Normalize(p); !strings.EqualFold(n, p) {
				t.Fatalf("accepted %q, which Win32 normalizes to %q", p, n)
			}
			for _, d := range managedDirs(h, goos) {
				if strings.HasPrefix(strings.ToLower(p), strings.ToLower(d)+`\`) {
					return
				}
			}
			t.Fatalf("accepted %q outside %s's managed dirs", p, h)
		}
		if path.Clean(p) != p || !path.IsAbs(p) || strings.ContainsAny(p, "\\\x00") {
			t.Fatalf("accepted non-canonical %q", p)
		}
		for _, d := range managedDirs(h, goos) {
			if strings.HasPrefix(p, d+"/") {
				return
			}
		}
		for _, pat := range managedFiles(h, goos) {
			if ok, _ := path.Match(pat, p); ok {
				return
			}
		}
		t.Fatalf("accepted %q outside %s's managed locations", p, h)
	})
}

// FuzzLoadConfig: halod.yaml is parsed as root. Whatever the bytes, LoadConfig
// must not panic, and an accepted config must name a registry, an org and a
// release key, and send credentials only over https (or http to loopback).
func FuzzLoadConfig(f *testing.F) {
	for _, s := range []string{
		"registry: ghcr.io/acme/halos\norg: acme\nring: ring1\npubkey: /etc/halos/release.pub\n",
		"registry: r\norg: o\nringEndpoint: https://halo.example/api/v1/fleet/ring\npubkeys: [/k1, /k2]\nrevokedKeys: [sha256:00]\ninterval: 5m\n",
		"registry: r\norg: o\nring: r\npubkey: /k\nreportURL: http://evil.example/\n",
		"registry: r\norg: o\nring: r\npubkey: /k\nkillSwitch: {pubkey: /kk, url: https://h/x, interval: 30s}\ndeviceToken: t\n",
		"registry: r\norg: o\nring: ../x\npubkey: /k\n",
		"{",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, doc string) {
		p := filepath.Join(t.TempDir(), "halod.yaml")
		if err := os.WriteFile(p, []byte(doc), 0o600); err != nil {
			t.Fatal(err)
		}
		c, err := LoadConfig(p)
		if err != nil {
			return
		}
		if c.Registry == "" || c.Org == "" || len(c.KeyFiles()) == 0 {
			t.Fatalf("accepted incomplete config %+v", c)
		}
		if c.Ring != "" && !ringRe.MatchString(c.Ring) {
			t.Fatalf("accepted ring %q", c.Ring)
		}
		for _, raw := range []string{c.RingEndpoint, c.ReportURL, c.KillSwitch.URL} {
			if raw == "" {
				continue
			}
			u, err := url.Parse(raw)
			if err != nil {
				t.Fatalf("accepted unparsable url %q", raw)
			}
			if h := u.Hostname(); u.Scheme != "https" && (u.Scheme != "http" || (h != "localhost" && !net.ParseIP(h).IsLoopback())) {
				t.Fatalf("accepted insecure url %q", raw)
			}
		}
		if c.KillSwitch.PubKey != "" && c.DeviceToken == "" {
			t.Fatal("kill switch accepted without a device token")
		}
	})
}
