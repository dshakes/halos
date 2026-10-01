package main

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"oras.land/oras-go/v2"

	"github.com/halos-dev/halos/internal/bundle"
)

func TestRunHelp(t *testing.T) {
	for _, tc := range []struct {
		args    []string
		wantErr bool
		want    string
	}{
		{[]string{"--help"}, false, "Commands:"},
		{[]string{"help"}, false, "status"},
		{[]string{"-h"}, false, "Commands:"},
		{[]string{"run", "-h"}, false, "-log-level"},
		{[]string{"once", "--help"}, false, "one pull/verify/apply"},
		{nil, true, ""},
		{[]string{"bogus"}, true, ""},
		{[]string{"status", "-log-level", "loud"}, true, ""},
	} {
		var out, errOut bytes.Buffer
		err := run(tc.args, &out, &errOut)
		if (err != nil) != tc.wantErr || !strings.Contains(out.String(), tc.want) {
			t.Errorf("%v: err=%v out=%q", tc.args, err, out.String())
		}
	}
}

func TestRunStatus(t *testing.T) {
	root := t.TempDir()
	st := "/state.json"
	if err := os.WriteFile(filepath.Join(root, st), []byte(`{"status":{"ring":"canary"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := run([]string{"status", "-root", root, "-state", st}, &out, io.Discard); err != nil || !strings.Contains(out.String(), `"ring": "canary"`) {
		t.Fatalf("%v %s", err, out.String())
	}
	if err := run([]string{"status", "-root", root, "-state", "/missing"}, io.Discard, io.Discard); err == nil {
		t.Fatal("missing state must fail")
	}
}

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestReport(t *testing.T) {
	var got atomic.Value
	var status atomic.Int32
	status.Store(204)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got.Store(r.Header.Get("Authorization") + " " + string(b))
		w.WriteHeader(int(status.Load()))
	}))
	defer srv.Close()
	var out, logs bytes.Buffer
	a := &Agent{Cfg: Config{ReportURL: srv.URL, DeviceToken: "dt"}, HTTP: srv.Client(), Stdout: &out,
		Log: slog.New(slog.NewTextHandler(&logs, nil))}
	a.report(context.Background(), Status{Ring: "canary", Drift: []string{}})
	if !strings.Contains(out.String(), `"ring":"canary"`) || !strings.HasSuffix(out.String(), "}\n") {
		t.Fatalf("stdout %q", out.String())
	}
	if g, _ := got.Load().(string); !strings.HasPrefix(g, "Bearer dt {") {
		t.Fatalf("posted %q", g)
	}
	status.Store(500)
	a.report(context.Background(), Status{})
	if !strings.Contains(logs.String(), "status=500") {
		t.Fatalf("rejected report not logged: %s", logs.String())
	}
	srv.Close()
	a.report(context.Background(), Status{})
	a.Cfg.ReportURL = "http://[::1"
	a.report(context.Background(), Status{})
	if n := strings.Count(logs.String(), "msg=report"); n != 2 {
		t.Fatalf("want 2 report errors logged, got %d: %s", n, logs.String())
	}
}

func TestReadTokenFile(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	if tok, err := readTokenFile(write("ok", " tok\n", 0o600)); err != nil || tok != "tok" {
		t.Fatalf("%q %v", tok, err)
	}
	for name, p := range map[string]string{
		"empty":   write("empty", "\n", 0o600),
		"missing": filepath.Join(dir, "missing"),
	} {
		if _, err := readTokenFile(p); err == nil {
			t.Errorf("%s: want error", name)
		}
	}
	if runtime.GOOS != "windows" {
		if _, err := readTokenFile(write("world", "tok", 0o644)); err == nil || !strings.Contains(err.Error(), "chmod 600") {
			t.Fatalf("group/other-readable token accepted: %v", err)
		}
	}
}

func TestNpmInstallArgs(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix layout")
	}
	root := t.TempDir()
	node, cli := "/usr/bin/node", "/usr/lib/node_modules/npm/bin/npm-cli.js"
	for _, p := range []string{node, cli} {
		f := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f, nil, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	var gotName string
	var gotArgs []string
	a := &Agent{Cfg: Config{OS: "linux"}, Root: root, Log: quietLog(),
		Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
			gotName, gotArgs = name, args
			return nil, nil
		}}
	tmp := t.TempDir()
	if err := a.npmInstall(context.Background(), tmp, filepath.Join(tmp, "artifact.tgz")); err != nil {
		t.Fatal(err)
	}
	realNode, _ := filepath.EvalSymlinks(filepath.Join(root, node))
	realCLI, _ := filepath.EvalSymlinks(filepath.Join(root, cli))
	want := []string{realCLI, "install", "--global", "--ignore-scripts", "--no-audit", "--no-fund",
		"--userconfig", filepath.Join(tmp, "empty-user-npmrc"), "--globalconfig", filepath.Join(tmp, "empty-global-npmrc"),
		"--prefix", filepath.Join(root, layouts["linux"].NPM), filepath.Join(tmp, "artifact.tgz")}
	if gotName != realNode || strings.Join(gotArgs, " ") != strings.Join(want, " ") {
		t.Fatalf("ran %s %v\nwant %s %v", gotName, gotArgs, realNode, want)
	}
	for _, rc := range []string{"empty-user-npmrc", "empty-global-npmrc"} {
		if b, err := os.ReadFile(filepath.Join(tmp, rc)); err != nil || len(b) != 0 {
			t.Fatalf("%s: %q %v", rc, b, err)
		}
	}
	// No root-owned node: refuse rather than fall back to PATH.
	a.Root = t.TempDir()
	if err := a.npmInstall(context.Background(), tmp, "x.tgz"); err == nil || !strings.Contains(err.Error(), "root-owned node") {
		t.Fatalf("want no-node error, got %v", err)
	}
}

// One real tick of the run loop with a fake clock: a cycle, the timer, a
// second cycle, then cancellation ends it.
func TestLoopTicks(t *testing.T) {
	var out bytes.Buffer
	a := &Agent{Cfg: Config{Ring: "canary", OS: "linux"}, Root: t.TempDir(), StatePath: "/state.json", Now: time.Now,
		Stdout: &out, Log: quietLog(), HTTP: http.DefaultClient,
		Open: func(context.Context) (oras.ReadOnlyTarget, error) { return nil, context.DeadlineExceeded }}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var waits []time.Duration
	after := func(d time.Duration) <-chan time.Time {
		waits = append(waits, d)
		c := make(chan time.Time, 1)
		if len(waits) == 1 {
			c <- time.Now() // first tick fires
		} else {
			cancel() // then shut down
		}
		return c
	}
	a.loop(ctx, 7*time.Minute, after)
	if n := strings.Count(out.String(), "\n"); n != 2 || len(waits) != 2 || waits[0] != 7*time.Minute {
		t.Fatalf("cycles=%d waits=%v", n, waits)
	}
	if !strings.Contains(out.String(), `"lastError":"open registry`) {
		t.Fatalf("status %s", out.String())
	}
}

func TestKeyringRotationAndRevocation(t *testing.T) {
	dir := t.TempDir()
	mk := func(name string) (bundle.Ed25519Signer, string, string) {
		priv, pub, err := bundle.GenerateKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		s, _ := bundle.ParseEd25519Signer(priv)
		v, _ := bundle.ParseEd25519Verifier(pub)
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, pub, 0o644); err != nil {
			t.Fatal(err)
		}
		return s, p, keyFingerprint(v)
	}
	oldS, oldP, oldFP := mk("old.pub")
	newS, newP, newFP := mk("new.pub")
	strangerS, _, _ := mk("stranger.pub")
	ctx := context.Background()
	sig := func(s bundle.Signer) []byte { b, _ := s.Sign(ctx, "sha256:d"); return b }

	ring, fps, err := loadKeyring(Config{PubKey: oldP, PubKeys: []string{newP, oldP}})
	if err != nil || len(ring) != 2 || fps[0] != oldFP || fps[1] != newFP || !strings.HasPrefix(oldFP, "sha256:") || len(oldFP) != 71 {
		t.Fatalf("ring %d fps %v err %v", len(ring), fps, err)
	}
	for name, s := range map[string]bundle.Signer{"old": oldS, "new": newS} {
		if err := ring.Verify(ctx, "sha256:d", sig(s)); err != nil {
			t.Errorf("%s key must verify during overlap: %v", name, err)
		}
	}
	if ring.Verify(ctx, "sha256:d", sig(strangerS)) == nil || ring.Verify(ctx, "sha256:other", sig(oldS)) == nil {
		t.Fatal("stranger key / wrong digest verified")
	}
	ring, _, err = loadKeyring(Config{PubKey: oldP, PubKeys: []string{newP}, RevokedKeys: []string{" " + strings.ToUpper(oldFP) + " "}})
	if err != nil || len(ring) != 1 || ring.Verify(ctx, "sha256:d", sig(oldS)) == nil || ring.Verify(ctx, "sha256:d", sig(newS)) != nil {
		t.Fatalf("revoked key still trusted: %d %v", len(ring), err)
	}
	if _, _, err := loadKeyring(Config{PubKey: oldP, RevokedKeys: []string{oldFP}}); err == nil {
		t.Fatal("all keys revoked must fail")
	}
	if _, _, err := loadKeyring(Config{PubKey: filepath.Join(dir, "missing")}); err == nil {
		t.Fatal("missing key file must fail")
	}
	bad := filepath.Join(dir, "bad.pub")
	_ = os.WriteFile(bad, []byte("nope"), 0o644)
	if _, _, err := loadKeyring(Config{PubKey: bad}); err == nil {
		t.Fatal("bad pem must fail")
	}
}

// Copilot CLI (and every future adapter) is known to halod via harness.Meta.
func TestHalodKnowsEveryHarness(t *testing.T) {
	if b, ok := binaryFor("copilot-cli"); !ok || b != "copilot" {
		t.Fatalf("copilot binary %q %v", b, ok)
	}
	for _, tc := range []struct{ h, os, p string }{
		{"copilot-cli", "linux", "/etc/github-copilot/managed-settings.json"},
		{"copilot-cli", "darwin", "/Library/Application Support/GitHubCopilot/managed-settings.json"},
		{"copilot-cli", "windows", `C:\Program Files\GitHubCopilot\managed-settings.json`},
		{"gemini-cli", "linux", "/etc/profile.d/halos-gemini.sh"},
	} {
		if err := allowedPath(tc.h, tc.os, tc.p); err != nil {
			t.Errorf("%s/%s: %v", tc.h, tc.os, err)
		}
	}
	if allowedPath("copilot-cli", "linux", "/etc/codex/x.toml") == nil {
		t.Fatal("copilot may not write codex's dir")
	}
	if _, ok := binaryFor("nope"); ok {
		t.Fatal("unknown harness has a binary")
	}
}

func TestCheckACEs(t *testing.T) {
	const users, everyone = "S-1-5-32-545", "S-1-1-0"
	allow := func(sid string, mask uint32) ace { return ace{SID: sid, Allow: true, Mask: mask} }
	inh := func(e ace) ace { e.InheritOnly, e.Inherits = true, true; return e }
	for _, tc := range []struct {
		name   string
		aces   []ace
		strict bool
		ok     bool
	}{
		{"admins full", []ace{allow(sidSystem, 0x1f01ff), allow(sidAdministrators, 0x1f01ff), allow(trustedInstallerID, genericAll)}, true, true},
		{"users read/execute", []ace{allow(users, 0x1200a9)}, true, true},
		{"users write on managed dir", []ace{allow(users, 0x1200a9|fileWriteData)}, true, false},
		{"everyone full", []ace{allow(everyone, 0x1f01ff)}, false, false},
		{"programdata create-only on ancestor", []ace{allow(users, fileWriteData|fileAppendData|fileWriteEA|fileWriteAttributes)}, false, true},
		{"create-only on managed dir", []ace{allow(users, fileWriteData|fileAppendData)}, true, false},
		{"delete child on ancestor", []ace{allow(users, fileDeleteChild)}, false, false},
		{"write dac on ancestor", []ace{allow(users, writeDAC)}, false, false},
		{"generic write", []ace{allow(users, genericWrite)}, false, false},
		{"creator owner inherit-only", []ace{inh(allow(sidCreatorOwner, genericAll))}, true, true},
		{"creator owner effective", []ace{allow(sidCreatorOwner, genericAll)}, true, false},
		{"inherit-only users write on ancestor", []ace{inh(allow(users, genericAll))}, false, true},
		{"inherit-only users write on managed dir", []ace{inh(allow(users, fileWriteData))}, true, false},
		{"deny ignored", []ace{{SID: users, Allow: false, Mask: genericAll}}, true, true},
	} {
		if err := checkACEs(`C:\x`, tc.aces, tc.strict); (err == nil) != tc.ok {
			t.Errorf("%s: err=%v want ok=%v", tc.name, err, tc.ok)
		}
	}
}

func TestStrictWindowsPath(t *testing.T) {
	for p, want := range map[string]bool{
		`C:\ProgramData\OpenAI\Codex`:                     true,
		`C:\ProgramData\OpenAI\Codex\requirements.toml`:   true,
		`c:\programdata\gemini-cli`:                       true,
		`C:\Program Files\Halos\bin`:                      true,
		`C:\Program Files\Halos\etc\halod.yaml`:           true,
		`C:\ProgramData`:                                  false,
		`C:\ProgramData\OpenAI`:                           false,
		`C:\ProgramData\OpenAI\CodexEvil`:                 false,
		`C:\Program Files\GitHubCopilot\managed-settings`: true,
	} {
		if got := strictWindowsPath(p); got != want {
			t.Errorf("%s: %v want %v", p, got, want)
		}
	}
}
