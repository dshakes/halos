package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/memory"

	"github.com/dshakes/halos/internal/bundle"
	"github.com/dshakes/halos/internal/harness"
	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/release"
)

func TestMain(m *testing.M) {
	trustedUID = uint32(os.Getuid()) // temp dirs are owned by the test user, not root
	os.Exit(m.Run())
}

type testAdapter struct {
	files func(ring string) []harness.File
	meta  harness.Meta // the real claude-code Meta (paths, binary)
}

func (t testAdapter) Meta() harness.Meta { return t.meta }

func (testAdapter) Name() string                       { return "claude-code" }
func (testAdapter) Capabilities() []harness.Capability { return nil }
func (testAdapter) InstallCommand(v string, _ harness.OS) string {
	return "install-claude " + v
}

// Render stamps the version pin into managed-settings.json (release.CheckRendered requires it).
func (t testAdapter) Render(p *policy.Profile, c harness.Context) ([]harness.File, []string, error) {
	v := p.Harnesses["claude-code"].Version
	out := append([]harness.File(nil), t.files(c.Ring)...) // Render may run more than once; never re-wrap shared data
	for i, f := range out {
		if strings.HasSuffix(f.Path, "managed-settings.json") {
			env := ""
			if len(p.Env) > 0 { // feature toggles add env; render it so fragments have something to differ by
				b, _ := json.Marshal(p.Env)
				env = `,"env":` + string(b)
			}
			f.Data = []byte(fmt.Sprintf(`{"requiredMinimumVersion":%q,"requiredMaximumVersion":%q,"x":%s%s}`, v, v, f.Data, env))
			out[i] = f
		}
	}
	return out, nil, nil
}

var (
	mu    sync.Mutex
	files = func(string) []harness.File { return nil }
)

func init() {
	real, _ := harness.MetaOf("claude-code")
	harness.Override(testAdapter{meta: real, files: func(r string) []harness.File { mu.Lock(); defer mu.Unlock(); return files(r) }})
}

type res struct{ ver string }

func (r res) ResolveProfile(string) (*policy.Profile, error) {
	return &policy.Profile{Harnesses: map[string]policy.HarnessSpec{"claude-code": {Version: r.ver}}}, nil
}

// vendor fakes downloads.claude.ai: manifest.json + a "binary" whose content
// is its own version string, so the --version probe reads what was installed.
type vendor struct {
	srv       *httptest.Server
	downloads atomic.Int32
	tamper    atomic.Bool
}

func fakeBinary(ver string) []byte { return []byte("fake-claude " + ver) }

func newVendor(t *testing.T) *vendor {
	v := &vendor{}
	v.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/claude/"), "/")
		switch {
		case len(parts) == 2 && parts[1] == "manifest.json":
			sum := sha256.Sum256(fakeBinary(parts[0]))
			fmt.Fprintf(w, `{"version":%q,"platforms":{"linux-x64":{"binary":"claude","checksum":%q,"size":%d}}}`,
				parts[0], hex.EncodeToString(sum[:]), len(fakeBinary(parts[0])))
		case len(parts) == 3 && parts[1] == "linux-x64":
			v.downloads.Add(1)
			b := fakeBinary(parts[0])
			if v.tamper.Load() {
				b = []byte("evil-claude " + parts[0][:len(parts[0])-1] + "X")
			}
			w.Write(b)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(v.srv.Close)
	return v
}

type env struct {
	a      *Agent
	root   string
	store  *memory.Store
	sign   bundle.Signer
	vendor *vendor
	cmds   []string
}

const managedBin = "/usr/local/lib/halos/bin/claude"

func newEnv(t *testing.T) *env {
	t.Helper()
	priv, pub, _ := bundle.GenerateKeyPair()
	s, _ := bundle.ParseEd25519Signer(priv)
	v, _ := bundle.ParseEd25519Verifier(pub)
	e := &env{root: t.TempDir(), store: memory.New(), sign: s, vendor: newVendor(t)}
	e.a = &Agent{
		Cfg: Config{Ring: "canary", OS: "linux", Org: "acme"}, Root: e.root, StatePath: "/var/lib/halos/state.json",
		Verifier: v, Install: true, Host: "h", User: "u", Arch: "amd64", Now: time.Now,
		HTTP: http.DefaultClient, Download: e.vendor.srv.Client(),
		Open: func(context.Context) (oras.ReadOnlyTarget, error) { return e.store, nil },
		Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
			e.cmds = append(e.cmds, name+" "+strings.Join(args, " "))
			if filepath.Base(name) == "claude" && len(args) == 1 && args[0] == "--version" {
				b, err := os.ReadFile(name)
				return append(b, " (Claude Code)\n"...), err
			}
			return nil, nil
		},
	}
	return e
}

// publish builds a release pinned to cliVer. withArtifacts resolves verified
// install artifacts from the fake vendor, as `halo release build` does.
func (e *env) publish(t *testing.T, ver, cliVer string, fs []harness.File, withArtifacts bool) *release.Release {
	t.Helper()
	mu.Lock()
	files = func(string) []harness.File { return fs }
	mu.Unlock()
	rel, err := release.Build(res{cliVer}, "p", "canary", release.Options{Version: ver, Org: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	if withArtifacts {
		rel, err = release.ArtifactResolver{HTTP: e.vendor.srv.Client(), ClaudeBase: e.vendor.srv.URL + "/claude"}.Resolve(context.Background(), rel)
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := bundle.Publish(context.Background(), e.store, rel, e.sign, "canary"); err != nil {
		t.Fatal(err)
	}
	return rel
}

func (e *env) read(p string) string {
	b, err := os.ReadFile(filepath.Join(e.root, p))
	if err != nil {
		return "<missing>"
	}
	return string(b)
}

func (e *env) ran(prefix string) bool {
	for _, c := range e.cmds {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

const settings = "/etc/claude-code/managed-settings.json"

func TestApplyInstallDriftAndRemoval(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.publish(t, "1", "2.0.0", []harness.File{
		{Path: settings, Mode: 0o644, Data: []byte(`1`)},
		{Path: "/etc/claude-code/old.json", Mode: 0o600, Data: []byte("{}")},
	}, true)
	st, err := e.a.Once(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(e.read(settings), `"x":1`) {
		t.Fatal("file not written")
	}
	if fi, _ := os.Stat(filepath.Join(e.root, "/etc/claude-code/old.json")); runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 { // no POSIX mode bits on Windows
		t.Fatalf("mode %v", fi.Mode())
	}
	if st.Harnesses["claude-code"].Installed != "2.0.0" || e.read(managedBin) != "fake-claude 2.0.0" || e.vendor.downloads.Load() != 1 {
		t.Fatalf("verified install not done: %+v downloads=%d", st, e.vendor.downloads.Load())
	}
	if fi, _ := os.Stat(filepath.Join(e.root, managedBin)); runtime.GOOS != "windows" && fi.Mode().Perm() != 0o755 { // no POSIX mode bits on Windows
		t.Fatalf("binary mode %v", fi.Mode())
	}
	if l, err := os.Readlink(filepath.Join(e.root, "/usr/local/bin/claude")); err != nil || l != filepath.Join(e.root, managedBin) {
		t.Fatalf("shim %q %v", l, err)
	}
	if e.ran("sh ") {
		t.Fatal("shell install ran although a verified artifact exists")
	}
	if len(st.Drift) != 0 {
		t.Fatalf("unexpected drift %v", st.Drift)
	}

	// tamper -> drift, re-applied
	os.WriteFile(filepath.Join(e.root, settings), []byte("hacked"), 0o644)
	st, err = e.a.Once(ctx)
	if err != nil || len(st.Drift) != 1 || !strings.Contains(e.read(settings), `"x":1`) {
		t.Fatalf("drift not healed: %v %+v", err, st)
	}
	// already at version -> no install
	e.a.Once(ctx)
	if e.vendor.downloads.Load() != 1 {
		t.Fatal("reinstalled although version matches")
	}

	// new release drops old.json, --install=false skips installer
	e.a.Install = false
	e.publish(t, "2", "3.0.0", []harness.File{{Path: settings, Mode: 0o644, Data: []byte(`2`)}}, true)
	st, err = e.a.Once(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if e.read("/etc/claude-code/old.json") != "<missing>" || !strings.Contains(e.read(settings), `"x":2`) {
		t.Fatal("stale file not removed / file not updated")
	}
	if e.read(managedBin) != "fake-claude 2.0.0" || len(st.Drift) != 0 {
		t.Fatalf("install=false must not install; drift=%v", st.Drift)
	}
}

func TestInstallBadHashRejected(t *testing.T) {
	e := newEnv(t)
	e.vendor.tamper.Store(true)
	e.publish(t, "1", "2.0.0", nil, true)
	st, err := e.a.Once(context.Background())
	if err == nil || !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("want sha256 mismatch, got %v", err)
	}
	if e.read(managedBin) != "<missing>" || st.Harnesses["claude-code"].Installed != "" {
		t.Fatal("tampered binary was installed")
	}
	if len(e.a.loadState().Installed) != 0 {
		t.Fatal("state records an install that failed")
	}
	// a verified-but-broken install is not retried forever (loop guard) ...
	e.vendor.tamper.Store(false)
	if _, err := e.a.Once(context.Background()); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(e.root, managedBin), []byte("prints no version"), 0o755)
	n := e.vendor.downloads.Load()
	e.a.Once(context.Background())
	if e.vendor.downloads.Load() != n {
		t.Fatal("re-install loop: same verified artifact downloaded again")
	}
}

func TestNoInstallWhenVersionMatches(t *testing.T) {
	e := newEnv(t)
	p := filepath.Join(e.root, managedBin)
	os.MkdirAll(filepath.Dir(p), 0o755)
	os.WriteFile(p, fakeBinary("2.0.0"), 0o755)
	e.publish(t, "1", "2.0.0", nil, true)
	st, err := e.a.Once(context.Background())
	if err != nil || st.Harnesses["claude-code"].Installed != "2.0.0" || e.vendor.downloads.Load() != 0 {
		t.Fatalf("installed although at version: %v %+v downloads=%d", err, st, e.vendor.downloads.Load())
	}
}

func TestLegacyShellInstallGated(t *testing.T) {
	e := newEnv(t)
	e.publish(t, "1", "2.0.0", nil, false) // no artifacts
	_, err := e.a.Once(context.Background())
	if err == nil || !strings.Contains(err.Error(), "allowShellInstall") || e.ran("sh ") {
		t.Fatalf("legacy install must be off by default: %v %v", err, e.cmds)
	}
	e.a.Cfg.AllowShellInstall = true
	e.a.Once(context.Background())
	if !e.ran("sh -c install-claude 2.0.0") {
		t.Fatalf("allowShellInstall should run installCommand: %v", e.cmds)
	}
}

// Untrusted bundle: nothing may execute or be written, last-good stays.
func TestRefusesUnverified(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.publish(t, "1", "2.0.0", []harness.File{{Path: "/etc/claude-code/x", Mode: 0o644, Data: []byte("good")}}, true)
	if _, err := e.a.Once(ctx); err != nil {
		t.Fatal(err)
	}
	good := e.a.loadState()
	e.cmds = nil

	// attacker publishes with their own key under the same ring tag
	priv, _, _ := bundle.GenerateKeyPair()
	evil, _ := bundle.ParseEd25519Signer(priv)
	e.store = memory.New() // fresh registry, so the attacker's pointer is not refused at publish
	e.sign = evil
	e.publish(t, "666", "9.9.9", []harness.File{{Path: "/etc/claude-code/x", Mode: 0o644, Data: []byte("evil")}}, true)
	st, err := e.a.Once(ctx)
	if err == nil || st.LastError == "" {
		t.Fatal("unsigned release accepted")
	}
	if len(e.cmds) != 0 {
		t.Fatalf("commands ran for unverified bundle: %v", e.cmds)
	}
	if e.read("/etc/claude-code/x") != "good" || e.a.loadState().Digest != good.Digest {
		t.Fatal("last-good not preserved")
	}
}

// H4: the registry replays an older validly signed pointer; halod refuses and
// keeps last-good. Expired pointers and foreign orgs are refused too.
func TestPointerFreshness(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.publish(t, "1", "2.0.0", []harness.File{{Path: "/etc/claude-code/x", Mode: 0o644, Data: []byte("v1")}}, true)
	if _, err := e.a.Once(ctx); err != nil {
		t.Fatal(err)
	}
	firstSeq := e.a.loadState().Pointers["canary"].Seq
	old, _ := e.store.Resolve(ctx, bundle.PointerTag("canary"))
	e.publish(t, "2", "2.0.0", []harness.File{{Path: "/etc/claude-code/x", Mode: 0o644, Data: []byte("v2")}}, true)
	latest, _ := e.store.Resolve(ctx, bundle.PointerTag("canary"))
	if _, err := e.a.Once(ctx); err != nil || e.read("/etc/claude-code/x") != "v2" {
		t.Fatalf("v2 not applied: %v", err)
	}
	if m := e.a.loadState().Pointers["canary"]; firstSeq == 0 || m.Seq <= firstSeq {
		t.Fatalf("seq not persisted/monotonic: first=%d now=%+v", firstSeq, m)
	}
	e.store.Tag(ctx, old, bundle.PointerTag("canary")) // replay seq 1
	if _, err := e.a.Once(ctx); err == nil || !strings.Contains(err.Error(), "rollback/replay") || e.read("/etc/claude-code/x") != "v2" {
		t.Fatalf("replayed pointer accepted: %v", err)
	}

	// signed rollback (higher seq, old digest) is accepted; the publisher
	// derives seq from the registry, so the replay is repaired first
	e.store.Tag(ctx, latest, bundle.PointerTag("canary"))
	if _, err := bundle.PromoteRing(ctx, e.store, bundle.Source{Version: "1"}, "canary", e.sign, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := e.a.Once(ctx); err != nil || e.read("/etc/claude-code/x") != "v1" {
		t.Fatalf("signed rollback refused: %v", err)
	}

	e.a.Now = func() time.Time { return time.Now().Add(bundle.DefaultPointerTTL + time.Hour) }
	if _, err := e.a.Once(ctx); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired pointer accepted: %v", err)
	}
	e.a.Now = time.Now
	e.a.Cfg.Org = "other"
	if _, err := e.a.Once(ctx); err == nil || !strings.Contains(err.Error(), "org") {
		t.Fatalf("foreign org accepted: %v", err)
	}
}

func TestAllowedPath(t *testing.T) {
	tests := []struct {
		h, os, p string
		ok       bool
	}{
		{"claude-code", "linux", "/etc/claude-code/managed-settings.json", true},
		{"claude-code", "linux", "/etc/claude-code/managed-settings.d/10.json", true},
		{"claude-code", "darwin", "/Library/Application Support/ClaudeCode/managed-settings.json", true},
		{"claude-code", "windows", `C:\Program Files\ClaudeCode\managed-settings.json`, true},
		{"claude-code", "windows", `c:\program files\claudecode\x.json`, false}, // drive must be C:\ as rendered
		{"claude-code", "windows", `C:\Program Files\ClaudeCode\..\Halos\etc\halod.yaml`, false},
		{"claude-code", "linux", "/etc/claude-code/../sudoers", false},
		{"claude-code", "linux", "/etc/claude-code", false},
		{"claude-code", "linux", "etc/claude-code/x", false},
		{"claude-code", "linux", "/etc/claude-codex/x", false},
		{"claude-code", "linux", "/etc/codex/requirements.toml", false}, // other harness's dir
		{"codex", "linux", "/etc/codex/requirements.toml", true},
		{"gemini-cli", "linux", "/etc/profile.d/halos-gemini.sh", true},
		{"gemini-cli", "linux", "/etc/profile.d/evil.sh", false},
		{"gemini-cli", "linux", "/etc/profile.d/halos-x/y.sh", false},
		{"copilot-cli", "linux", "/etc/claude-code/x", false},
		{"claude-code", "linux", "/etc/passwd", false},
	}
	for _, tt := range tests {
		if err := allowedPath(tt.h, tt.os, tt.p); (err == nil) != tt.ok {
			t.Errorf("%s %s %q: %v", tt.h, tt.os, tt.p, err)
		}
	}
}

func TestApplyRefusesUnsafeTargets(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix ownership/mode semantics")
	}
	e := newEnv(t)
	e.a.Install = false
	// symlinked parent planted by a non-root user
	elsewhere := filepath.Join(e.root, "elsewhere")
	os.MkdirAll(elsewhere, 0o755)
	os.MkdirAll(filepath.Join(e.root, "/etc"), 0o755)
	os.Symlink(elsewhere, filepath.Join(e.root, "/etc/codex"))
	// state from a previous run lists a file outside the allowlist
	os.WriteFile(filepath.Join(e.root, "/etc/passwd"), []byte("root"), 0o644)
	e.a.saveState(State{Files: []string{"/etc/passwd"}})

	e.publish(t, "1", "2.0.0", []harness.File{
		{Path: "/etc/sudoers.d/evil", Mode: 0o644, Data: []byte("x")},
		{Path: "/etc/claude-code/setuid", Mode: 0o4755, Data: []byte("x")},
		{Path: "/etc/claude-code/ok.json", Mode: 0o644, Data: []byte("{}")},
	}, false)
	// the codex path goes through the claude adapter here, so also test the symlink check directly
	_, err := e.a.Once(context.Background())
	if err == nil || !strings.Contains(err.Error(), "outside claude-code's managed locations") || !strings.Contains(err.Error(), "exceeds 0644") {
		t.Fatalf("unsafe targets: %v", err)
	}
	if e.read("/etc/sudoers.d/evil") != "<missing>" || e.read("/etc/claude-code/setuid") != "<missing>" || e.read("/etc/claude-code/ok.json") != "{}" {
		t.Fatal("wrong files written")
	}
	if e.read("/etc/passwd") != "root" {
		t.Fatal("stale removal escaped the allowlist")
	}
	if err := e.a.checkTarget("codex", release.FileEntry{Path: "/etc/codex/requirements.toml", Mode: 0o644}); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("symlinked parent accepted: %v", err)
	}
}

func TestOwnershipPreflight(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix ownership/mode semantics")
	}
	dir := t.TempDir()
	good := filepath.Join(dir, "release.pub")
	os.WriteFile(good, []byte("k"), 0o644)
	if err := preflight(Config{PubKey: good}, filepath.Join(dir, "var", "state.json")); err != nil {
		t.Fatalf("trusted files refused: %v", err)
	}
	loose := filepath.Join(dir, "loose.pub")
	os.WriteFile(loose, []byte("k"), 0o644)
	os.Chmod(loose, 0o666)
	if err := preflight(Config{PubKey: loose}, ""); err == nil || !strings.Contains(err.Error(), "group/other-writable") {
		t.Fatalf("world-writable pubkey accepted: %v", err)
	}
	wdir := filepath.Join(dir, "w")
	os.Mkdir(wdir, 0o777)
	os.Chmod(wdir, 0o777)
	if err := preflight(Config{}, filepath.Join(wdir, "state.json")); err == nil {
		t.Fatal("world-writable state dir accepted")
	}
	old := trustedUID
	trustedUID = 4242424 // as if the files belonged to someone other than root
	defer func() { trustedUID = old }()
	if err := checkChain(good); err == nil || !strings.Contains(err.Error(), "owned by uid") {
		t.Fatalf("non-root owner accepted: %v", err)
	}
}

func TestRingEndpoint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("user") != "u" {
			http.Error(w, "no", 400)
			return
		}
		if r.URL.Query().Get("host") == "bad" {
			w.Write([]byte(`{"ring":"canary","subject":"a\nb"}`))
			return
		}
		w.Write([]byte(`{"ring":"canary","subject":"dev@acme.com"}`))
	}))
	defer srv.Close()
	a := &Agent{Cfg: Config{RingEndpoint: srv.URL}, User: "u", Host: "h", HTTP: srv.Client()}
	if r, sub, err := a.resolveRing(context.Background()); err != nil || r != "canary" || sub != "dev@acme.com" {
		t.Fatalf("%q %q %v", r, sub, err)
	}
	a.Host = "bad"
	if _, _, err := a.resolveRing(context.Background()); err == nil || !strings.Contains(err.Error(), "invalid subject") {
		t.Fatalf("control char subject accepted: %v", err)
	}
	a.Host, a.User = "h", "x"
	if _, _, err := a.resolveRing(context.Background()); err == nil {
		t.Fatal("want error on 400")
	}
}

func TestVersionParse(t *testing.T) {
	for in, want := range map[string]string{
		"2.1.280 (Claude Code)": "2.1.280", "codex-cli 0.5.1-beta.2\n": "0.5.1-beta.2", "garbage": "",
	} {
		if got := versionRe.FindString(in); got != want {
			t.Errorf("%q: %q", in, got)
		}
	}
}

func TestSeat0User(t *testing.T) {
	out := "  3 0 root seat0 tty1\n  5 1000 alice seat0 tty2\n  7 1001 bob - pts/0\n"
	if u := seat0User(out); u != "alice" {
		t.Fatalf("got %q", u)
	}
	if seat0User("") != "" {
		t.Fatal("empty")
	}
}

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()
	base := "registry: r/x\npubkey: /k\norg: acme\n"
	tests := []struct{ name, body, want string }{
		{"ok", base + "ring: canary\ninterval: 5m\n", ""},
		{"no pubkey", "registry: r/x\norg: acme\nring: canary\n", "pubkey"},
		{"no org", "registry: r/x\npubkey: /k\nring: canary\n", "org is required"},
		{"no ring", base, "ring"},
		{"bad ring", base + "ring: '../x'\n", "invalid ring"},
		{"bad interval", base + "ring: a\ninterval: soon\n", "interval"},
		{"http ring endpoint", base + "ringEndpoint: http://halo.example.com/ring\n", "https"},
		{"http report", base + "ring: a\nreportURL: http://halo.example.com/r\n", "https"},
		{"loopback http ok", base + "ringEndpoint: http://127.0.0.1:8080/ring\nreportURL: http://localhost/r\n", ""},
		{"https ok", base + "ringEndpoint: https://halo.example.com/ring\n", ""},
		{"pubkeys only ok", "registry: r/x\norg: acme\nring: a\npubkeys: [/k1, /k2]\n", ""},
		{"subject ok", base + "ring: a\nsubject: dev@acme.com\n", ""},
		{"subject control char", base + "ring: a\nsubject: \"a\\tb\"\n", "invalid subject"},
		{"subject padded", base + "ring: a\nsubject: \" dev\"\n", "invalid subject"},
	}
	for _, tt := range tests {
		p := filepath.Join(dir, strings.ReplaceAll(tt.name, " ", "_"))
		os.WriteFile(p, []byte(tt.body), 0o600)
		_, err := LoadConfig(p)
		if (tt.want == "") != (err == nil) || (err != nil && !strings.Contains(err.Error(), tt.want)) {
			t.Errorf("%s: %v", tt.name, err)
		}
	}
}

func TestSandboxUnavailable(t *testing.T) {
	required := []byte(`1,"sandbox":{"enabled":true,"failIfUnavailable":true}`)
	for name, tc := range map[string]struct {
		data    []byte
		install []string // files created under root
		want    string   // ErrorCode
	}{
		"not required":         {[]byte(`1`), nil, ""},
		"required, missing":    {required, nil, "sandbox_unavailable"},
		"required, bwrap only": {required, []string{"/usr/bin/bwrap"}, "sandbox_unavailable"},
		"required, present":    {required, []string{"/usr/bin/bwrap", "/usr/bin/socat"}, ""},
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t)
			for _, p := range tc.install {
				full := filepath.Join(e.root, p)
				if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(full, nil, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			e.publish(t, "1", "2.0.0", []harness.File{{Path: settings, Mode: 0o644, Data: tc.data}}, true)
			st, err := e.a.Once(context.Background())
			if st.ErrorCode != tc.want || (tc.want != "") != (err != nil) {
				t.Fatalf("ErrorCode=%q err=%v, want code %q", st.ErrorCode, err, tc.want)
			}
		})
	}
}
