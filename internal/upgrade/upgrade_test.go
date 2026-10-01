package upgrade

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/dshakes/halos/internal/eval"
	"github.com/dshakes/halos/internal/promote"
	"github.com/dshakes/halos/internal/release"
)

// fakeNPM serves GET /<pkg>/latest from a map, like registry.npmjs.org.
func fakeNPM(t *testing.T, latest map[string]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pkg, ok := strings.CutSuffix(strings.TrimPrefix(r.URL.Path, "/"), "/latest")
		v, found := latest[pkg]
		if !ok || !found {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"name":"` + pkg + `","version":"` + v + `","dist":{"tarball":"x"}}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

type fakeVerifier map[string]int // harness@version -> artifacts; missing = error

func (f fakeVerifier) Verify(_ context.Context, h, v string) (int, error) {
	if n, ok := f[h+"@"+v]; ok {
		return n, nil
	}
	return 0, errors.New("manifest checksum missing")
}

type fakeModels []string

func (f fakeModels) List(context.Context) ([]string, error) { return f, nil }

type recordingPR struct {
	mu   sync.Mutex
	reqs []promote.PRRequest
}

func (r *recordingPR) OpenPR(_ context.Context, req promote.PRRequest) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.reqs = append(r.reqs, req)
	return "https://github.example/acme/policy/pull/" + string(rune('0'+len(r.reqs))), nil
}

func policyCopy(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "acme-corp")
	if err := os.CopyFS(dir, os.DirFS("../../examples/acme-corp")); err != nil {
		t.Fatal(err)
	}
	cfg := `profile: engineering-next
suite: evals/suites/upgrade-gate.yaml
harnesses: [claude-code, codex, gemini-cli]
models:
  - provider: openai
    url: https://gw.example/v1/models
    match: "^gpt-[0-9.]+-codex$"
    known: [gpt-5-codex-mini]
    alias: codex-default
`
	if err := os.MkdirAll(filepath.Join(dir, ".halos"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".halos", "upgrade-test.yaml"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func watcher(t *testing.T, dir string, npm *httptest.Server) *Watcher {
	t.Helper()
	cfg, err := LoadConfig(filepath.Join(dir, ".halos", "upgrade-test.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return &Watcher{PolicyDir: dir, Config: cfg,
		Registry: NPM{URL: npm.URL, HTTP: npm.Client()},
		Models:   map[string]ModelLister{"openai": fakeModels{"gpt-5-codex", "gpt-5.1-codex", "gpt-5-codex-mini", "text-embedding-3"}},
		Verifier: fakeVerifier{"claude-code@2.1.330": 6},
	}
}

func scorecard(verdict string) *eval.Scorecard {
	return &eval.Scorecard{Suite: "upgrade-gate", Control: "current", Gate: &eval.Gate{Verdict: verdict, Reasons: []string{"fixture"}}}
}

func TestCheckDryRun(t *testing.T) {
	dir := policyCopy(t)
	npm := fakeNPM(t, map[string]string{
		"@anthropic-ai/claude-code": "2.1.330", // newer than the 2.1.312 pin
		"@openai/codex":             "0.100.0", // same as pin: no candidate
		"@google/gemini-cli":        "0.36.0",  // newer, but artifacts do not verify
	})
	w := watcher(t, dir, npm)
	w.DryRun = true
	cs, err := w.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := Table(cs)
	t.Logf("halo upgrade check --dry-run:\n%s", got)
	if len(cs) != 3 {
		t.Fatalf("candidates:\n%s", got)
	}
	cl, gm, md := cs[0], cs[1], cs[2]
	if cl.Harness != "claude-code" || cl.From != "2.1.312" || cl.To != "2.1.330" || cl.Artifacts != 6 || cl.Package != "@anthropic-ai/claude-code" {
		t.Errorf("claude: %+v", cl)
	}
	if gm.Harness != "gemini-cli" || gm.Artifacts != 0 || !strings.Contains(gm.Note, "not verified") || !strings.Contains(got, "UNVERIFIED") {
		t.Errorf("gemini: %+v", gm)
	}
	if md.Kind != KindModel || md.From != "gpt-5-codex" || md.To != "gpt-5.1-codex" || md.Alias != "codex-default" {
		t.Errorf("model: %+v", md)
	}
	if _, err := os.Stat(filepath.Join(dir, ".halos", "upgrade-state.json")); !os.IsNotExist(err) {
		t.Error("dry run must not write state")
	}
}

func TestCheckOpensGatedPRs(t *testing.T) {
	dir := policyCopy(t)
	npm := fakeNPM(t, map[string]string{"@anthropic-ai/claude-code": "2.1.330", "@openai/codex": "0.100.0", "@google/gemini-cli": "0.36.0"})
	w := watcher(t, dir, npm)
	pr := &recordingPR{}
	var evals []string
	w.PR = pr
	w.Eval = func(_ context.Context, c Candidate) (*eval.Scorecard, error) {
		evals = append(evals, c.Key())
		if c.Kind == KindModel {
			return scorecard(eval.GateBlock), nil
		}
		return scorecard(eval.GateShip), nil
	}
	before, _ := os.ReadFile(filepath.Join(dir, "profiles/engineering-next.yaml"))
	cs, err := w.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("halo upgrade check:\n%s", Table(cs))
	if strings.Join(evals, ",") != "cli/claude-code@2.1.330,model/openai/gpt-5.1-codex" {
		t.Fatalf("evaluated %v (unverified gemini must be skipped)", evals)
	}
	if len(pr.reqs) != 1 {
		t.Fatalf("want exactly one PR (model blocked), got %d", len(pr.reqs))
	}
	req := pr.reqs[0]
	want := strings.Replace(string(before), "version: 2.1.312", "version: 2.1.330", 1)
	if string(req.Files["profiles/engineering-next.yaml"]) != want {
		t.Fatalf("pin edit:\n%s", req.Files["profiles/engineering-next.yaml"])
	}
	for _, s := range []string{"must be reviewed and merged by a human", "Eval scorecard: upgrade-gate", "6 verified", "+    version: 2.1.330", "SHIP"} {
		if !strings.Contains(req.Body, s) {
			t.Errorf("PR body missing %q:\n%s", s, req.Body)
		}
	}
	if !strings.HasPrefix(req.Branch, "halos/upgrade-claude-code-2.1.330") || !strings.Contains(req.Title, "(eval: ship)") {
		t.Errorf("branch %q title %q", req.Branch, req.Title)
	}
	// The PR re-applies the pin to the committed file, not the working tree.
	files, err := req.Edit(func(string) ([]byte, error) { return before, nil })
	if err != nil || string(files["profiles/engineering-next.yaml"]) != want {
		t.Fatalf("Edit: %v", err)
	}
	if _, err := req.Edit(func(string) ([]byte, error) {
		return []byte(strings.Replace(string(before), "2.1.312", "2.1.320", 1)), nil
	}); err == nil || !strings.Contains(err.Error(), "no longer") {
		t.Fatalf("a concurrent bump must not be overwritten: %v", err)
	}
	if cs[2].Verdict != eval.GateBlock || cs[2].PR != "" || !strings.Contains(cs[2].Note, "blocked") {
		t.Fatalf("model: %+v", cs[2])
	}
	now, _ := os.ReadFile(filepath.Join(dir, "profiles/engineering-next.yaml"))
	if string(now) != string(before) {
		t.Fatal("working tree must not be edited; the pin lives on the PR branch only")
	}

	// Memory on disk: a second check evaluates nothing new.
	evals = nil
	cs, err = w.Check(context.Background())
	if err != nil || len(evals) != 0 || len(pr.reqs) != 1 || !strings.Contains(cs[0].Note, "already handled") {
		t.Fatalf("second check: evals %v prs %d err %v cands %+v", evals, len(pr.reqs), err, cs)
	}
}

func TestCheckNeedsEvalAndPR(t *testing.T) {
	dir := policyCopy(t)
	w := watcher(t, dir, fakeNPM(t, map[string]string{"@anthropic-ai/claude-code": "2.1.312", "@openai/codex": "0.100.0", "@google/gemini-cli": "0.35.0"}))
	if _, err := w.Check(context.Background()); err == nil || !strings.Contains(err.Error(), "required unless DryRun") {
		t.Fatalf("got %v", err)
	}
}

func TestNPMRegistry(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/@openai/codex/latest":
			_, _ = w.Write([]byte(`{"name":"@openai/codex","version":"0.61.0"}`))
		case "/@evil/pkg/latest":
			_, _ = w.Write([]byte(`{"name":"@other/pkg","version":"1.0.0"}`))
		case "/bad/latest":
			_, _ = w.Write([]byte(`{"name":"bad","version":"latest; rm -rf /"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	n := NPM{URL: srv.URL, HTTP: srv.Client()}
	if v, err := n.Latest(context.Background(), "@openai/codex"); err != nil || v != "0.61.0" {
		t.Fatalf("%q %v", v, err)
	}
	for _, pkg := range []string{"@evil/pkg", "bad", "missing"} {
		if _, err := n.Latest(context.Background(), pkg); err == nil {
			t.Errorf("%s: want error", pkg)
		}
	}
}

func TestNewer(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{"2.1.330", "2.1.312", true}, {"2.1.312", "2.1.312", false}, {"2.1.99", "2.1.312", false},
		{"3.0.0", "2.9.9", true}, {"1.0.0-rc.1", "0.9.0", false}, {"1.0.0", "1.0.0-rc.1", true}, {"x", "1.0.0", false},
	} {
		if got := newer(tc.a, tc.b); got != tc.want {
			t.Errorf("newer(%s, %s) = %v", tc.a, tc.b, got)
		}
	}
}

func TestLoadConfigValidation(t *testing.T) {
	dir := t.TempDir()
	for i, body := range []string{
		"suite: s.yaml\n",
		"profile: p\nsuite: s\nmodels: [{provider: x, url: u}]\n",
		"profile: p\nsuite: s\nmodels: [{provider: x, url: u, alias: a, match: '('}]\n",
		"profile: p\nsuite: s\nbogus: 1\n",
		"profile: p\nsuite: s\nmodels: [{provider: x, url: 'http://gw.example/v1/models', alias: a}]\n",
	} {
		p := filepath.Join(dir, "c.yaml")
		_ = os.WriteFile(p, []byte(body), 0o644)
		if _, err := LoadConfig(p); err == nil {
			t.Errorf("case %d: want error", i)
		}
	}
}

// ArtifactVerifier runs the real release.ArtifactResolver: a version whose
// npm metadata fails its integrity/host checks is never verified.
func TestArtifactVerifierUsesReleaseResolver(t *testing.T) {
	sri := "sha512-" + base64.StdEncoding.EncodeToString(make([]byte, 64))
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/@openai/codex/0.61.0":
			_, _ = w.Write([]byte(`{"name":"@openai/codex","version":"0.61.0","bin":{"codex":"bin/codex.js"},"dist":{"tarball":"` + srv.URL + `/c.tgz","integrity":"` + sri + `"}}`))
		case "/@openai/codex/0.62.0": // off-registry tarball
			_, _ = w.Write([]byte(`{"name":"@openai/codex","version":"0.62.0","bin":{"codex":"x"},"dist":{"tarball":"https://evil.example/c.tgz","integrity":"` + sri + `"}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	v := ArtifactVerifier{Resolver: release.ArtifactResolver{HTTP: srv.Client(), NPMRegistry: srv.URL}}
	if n, err := v.Verify(context.Background(), "codex", "0.61.0"); err != nil || n != 1 {
		t.Fatalf("0.61.0: %d %v", n, err)
	}
	if _, err := v.Verify(context.Background(), "codex", "0.62.0"); err == nil || !strings.Contains(err.Error(), "registry host") {
		t.Fatalf("0.62.0: %v", err)
	}
	if _, err := v.Verify(context.Background(), "nosuch", "1.0.0"); err == nil {
		t.Fatal("unknown harness must not verify")
	}
}

func TestCheckContinuesPastFailedCandidate(t *testing.T) {
	dir := policyCopy(t)
	w := watcher(t, dir, fakeNPM(t, map[string]string{"@anthropic-ai/claude-code": "2.1.330", "@openai/codex": "0.100.0", "@google/gemini-cli": "0.35.0"}))
	pr := &recordingPR{}
	w.PR = pr
	w.Eval = func(_ context.Context, c Candidate) (*eval.Scorecard, error) {
		if c.Kind == KindCLI {
			return nil, errors.New("no eval driver")
		}
		return scorecard(eval.GateShip), nil
	}
	cs, err := w.Check(context.Background())
	if err == nil || !strings.Contains(err.Error(), "no eval driver") || len(pr.reqs) != 1 || !strings.HasPrefix(cs[0].Note, "error:") {
		t.Fatalf("err %v prs %d cands %+v", err, len(pr.reqs), cs)
	}
	// The failed candidate is retried next time; the handled one is not.
	w.Eval = func(context.Context, Candidate) (*eval.Scorecard, error) { return scorecard(eval.GateShip), nil }
	if _, err := w.Check(context.Background()); err != nil || len(pr.reqs) != 2 {
		t.Fatalf("retry: err %v prs %d", err, len(pr.reqs))
	}
}

func TestMalformedModelIDsSkipped(t *testing.T) {
	dir := policyCopy(t)
	w := watcher(t, dir, fakeNPM(t, map[string]string{"@anthropic-ai/claude-code": "2.1.312", "@openai/codex": "0.100.0", "@google/gemini-cli": "0.35.0"}))
	w.DryRun = true
	var warns []string
	w.Warn = func(m string) { warns = append(warns, m) }
	w.Models = map[string]ModelLister{"openai": fakeModels{"gpt-6-codex", "gpt-7-codex\n- [x] approved", "gpt-8-codex <img src=x>", strings.Repeat("a", 200), "gpt-9-codex`rm`"}}
	cs, err := w.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(cs) != 1 || cs[0].To != "gpt-6-codex" || len(warns) != 4 {
		t.Fatalf("candidates %+v warnings %q", cs, warns)
	}
}

func TestHTTPModelsRequiresHTTPS(t *testing.T) {
	if _, err := (HTTPModels{URL: "http://gw.example/v1/models", APIKey: "k"}).List(context.Background()); err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("got %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":[{"id":"a"}],"models":[{"name":"models/b"}]}`))
	}))
	defer srv.Close()
	ids, err := HTTPModels{URL: srv.URL, HTTP: srv.Client()}.List(context.Background()) // loopback http is allowed
	if err != nil || strings.Join(ids, ",") != "a,b" {
		t.Fatalf("%v %v", ids, err)
	}
}
