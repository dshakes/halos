package onboard

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dshakes/halos/internal/eval"
	"github.com/dshakes/halos/internal/intent"
	"github.com/dshakes/halos/internal/policy"
)

const secret = "fake-provider-key-THIS-MUST-NEVER-PRINT"

// fake is a machine with claude 2.1.280 on PATH and ANTHROPIC_API_KEY set;
// reply is what `claude -p` prints.
func fake(reply string, runErr error) Env {
	env := map[string]string{"ANTHROPIC_API_KEY": secret}
	return Env{
		GOOS:   "linux",
		Getenv: func(k string) string { return env[k] },
		LookPath: func(b string) (string, error) {
			if b == "claude" || b == "git" {
				return "/usr/bin/" + b, nil
			}
			return "", errors.New("not found")
		},
		Run: func(_ context.Context, _ string, args ...string) ([]byte, error) {
			if len(args) == 1 && args[0] == "--version" {
				return []byte("2.1.280 (Claude Code)\n"), nil
			}
			return []byte(reply), runErr
		},
	}
}

func TestDetectAndCredentialsNeverLeakValues(t *testing.T) {
	e := fake("", nil)
	hs := Detect(context.Background(), e)
	var claude Harness
	for _, h := range hs {
		if h.Name == "claude-code" {
			claude = h
		} else if h.Installed {
			t.Errorf("%s detected but not on PATH", h.Name)
		}
	}
	if !claude.Installed || claude.Version != "2.1.280" {
		t.Fatalf("claude = %+v", claude)
	}
	if got := SuggestTools(hs); len(got) != 1 || got["claude-code"] != "2.1.280" {
		t.Fatalf("SuggestTools = %v", got)
	}
	if p := SuggestProvider(e); p != "anthropic" {
		t.Fatalf("provider %s", p)
	}
	found := false
	for _, c := range Credentials(e) {
		found = found || (c.Env == "ANTHROPIC_API_KEY" && c.Present)
	}
	if !found {
		t.Fatal("ANTHROPIC_API_KEY not reported present")
	}
	b, err := json.Marshal(Doctor(context.Background(), e, ""))
	if err != nil || strings.Contains(string(b), secret) {
		t.Fatalf("doctor report leaks the secret (%v)", err)
	}
}

func initOpts() intent.InitOptions {
	return intent.InitOptions{Org: "me", Tools: map[string]string{"claude-code": "2.1.280"}, Provider: "anthropic", Safety: "standard", Rollout: "standard"}
}

func TestLocalIdempotentAndInstall(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "pol")
	o := LocalOptions{Dir: dir, Init: initOpts(), GOOS: "linux"}

	r, err := Local(o) // dry run from a directory that does not exist
	if err != nil {
		t.Fatal(err)
	}
	if !r.DryRun || r.Policy.Action != PolicyCreate || !r.Valid || r.Install == nil || len(r.Install.Files) == 0 {
		t.Fatalf("dry run = %+v", r)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("dry run wrote the policy dir")
	}
	if r.Install.Gateway != "http://"+DefaultLocalProxy {
		t.Fatalf("gateway %s", r.Install.Gateway)
	}

	o.Apply = true
	if r, err = Local(o); err != nil || r.Policy.Action != PolicyCreate {
		t.Fatalf("apply: %v %+v", err, r)
	}
	if r, err = Local(o); err != nil || r.Policy.Action != PolicyUnchanged {
		t.Fatalf("second apply: %v %+v", err, r.Policy)
	}
	o.Init.Org = "other"
	if r, err = Local(o); err != nil || r.Policy.Action != PolicyKept || len(r.Policy.Notes) == 0 {
		t.Fatalf("differing answers must keep the file: %v %+v", err, r.Policy)
	}

	root := t.TempDir()
	p, _, err := Install(dir, "", "linux", root, false, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range p.Files {
		if f.Action != ActionCreate || !strings.HasPrefix(f.Dest, root) {
			t.Fatalf("plan file %+v", f)
		}
		if _, err := os.Stat(f.Dest); err == nil {
			t.Fatal("dry run wrote", f.Dest)
		}
		if strings.Contains(f.Content, "bypassPermissions") || strings.Contains(f.Content, "danger-full-access") {
			t.Fatalf("%s renders a forbidden mode", f.Path)
		}
	}
	// A pre-existing file Halos did not write (an MDM-pushed one, say) is
	// foreign: apply refuses and writes nothing until replace is set.
	first := p.Files[0]
	if err := os.MkdirAll(filepath.Dir(first.Dest), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(first.Dest, []byte("mine\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pf, written, err := Install(dir, "", "linux", root, true, false)
	if !errors.Is(err, ErrForeign) || len(written) != 0 || pf.Files[0].Action != ActionForeign {
		t.Fatalf("foreign file: %v %v %+v", err, written, pf.Files[0])
	}
	if b, _ := os.ReadFile(first.Dest); string(b) != "mine\n" {
		t.Fatalf("refused apply touched the file: %q", b)
	}
	for _, f := range p.Files[1:] {
		if _, err := os.Stat(f.Dest); err == nil {
			t.Fatal("refused apply wrote", f.Dest)
		}
	}
	// With replace it is backed up once.
	_, written, err = Install(dir, "", "linux", root, true, true)
	if err != nil || len(written) != len(p.Files) {
		t.Fatalf("apply: %v %v", err, written)
	}
	if b, _ := os.ReadFile(first.Dest + backupSuffix); string(b) != "mine\n" {
		t.Fatalf("backup = %q", b)
	}
	p2, written, err := Install(dir, "", "linux", root, true, false)
	if err != nil || len(written) != 0 {
		t.Fatalf("second apply wrote %v (%v)", written, err)
	}
	for _, f := range p2.Files {
		if f.Action != ActionUnchanged {
			t.Fatalf("not idempotent: %+v", f)
		}
	}
	// A file Halos wrote is its own: a policy change updates it without replace.
	if err := os.WriteFile(first.Dest+ownerSuffix, []byte(sha256Hex([]byte("old\n"))+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(first.Dest, []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(first.Dest + backupSuffix); err != nil {
		t.Fatal(err)
	}
	if p3, _, err := Install(dir, "", "linux", root, false, false); err != nil || p3.Files[0].Action != ActionUpdate {
		t.Fatalf("own file must plan as update: %v %+v", err, p3.Files[0])
	}
	// Someone else rewrote it since: foreign again.
	if err := os.WriteFile(first.Dest, []byte("mdm\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if p4, _, err := Install(dir, "", "linux", root, false, false); err != nil || p4.Files[0].Action != ActionForeign {
		t.Fatalf("rewritten file must plan as foreign: %v %+v", err, p4.Files[0])
	}
	if _, _, err := Install(t.TempDir(), "", "linux", root, false, false); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing policy: %v", err)
	}
}

func TestUnderNeutralisesPaths(t *testing.T) {
	root := filepath.FromSlash("/r")
	for in, want := range map[string]string{
		"/etc/claude-code/managed-settings.json": "/r/etc/claude-code/managed-settings.json",
		`C:\ProgramData\x.json`:                  "/r/ProgramData/x.json",
		"/../../etc/passwd":                      "/r/etc/passwd",
	} {
		if got := filepath.ToSlash(under(root, in)); got != want {
			t.Errorf("under(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDoctor(t *testing.T) {
	e := fake("", nil)
	r := Doctor(context.Background(), e, t.TempDir())
	if !r.OK || status(r, "policy") != StatusWarn || status(r, "harness/claude-code") != StatusOK || status(r, "tool/docker") != StatusWarn {
		t.Fatalf("empty dir: %+v", r.Checks)
	}
	for _, c := range r.Checks {
		if c.Status != StatusOK && c.Fix == "" {
			t.Errorf("%s has no fix", c.ID)
		}
	}

	bad := t.TempDir()
	if err := os.WriteFile(filepath.Join(bad, policy.RootFile), []byte("apiVersion: halos.dev/v1alpha1\nkind: Halos\norg: x\ntools: {claude-code: 1.0.0}\nprovider: anthropic\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if r := Doctor(context.Background(), e, bad); r.OK || status(r, "policy") != StatusFail {
		t.Fatalf("invalid policy: %+v", r.Checks)
	}

	dir := filepath.Join(t.TempDir(), "p")
	o := initOpts()
	o.Tools["claude-code"] = "2.1.300"
	if _, err := Local(LocalOptions{Dir: dir, Init: o, GOOS: "linux", Apply: true}); err != nil {
		t.Fatal(err)
	}
	r = Doctor(context.Background(), e, dir)
	if !r.OK || status(r, "harness/claude-code") != StatusWarn || status(r, "credentials/anthropic") != StatusOK {
		t.Fatalf("pinned 2.1.300 vs installed 2.1.280: %+v", r.Checks)
	}
}

func status(r Report, id string) string {
	for _, c := range r.Checks {
		if c.ID == id {
			return c.Status
		}
	}
	return "missing"
}

func TestProxy(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "p")
	if _, err := Local(LocalOptions{Dir: dir, Init: initOpts(), GOOS: "linux", Apply: true}); err != nil {
		t.Fatal(err)
	}
	e := fake("", nil)
	r, err := Proxy(e, dir, "", false)
	if err != nil || !r.DryRun || len(r.Files) != 2 {
		t.Fatalf("%v %+v", err, r)
	}
	if _, err := os.Stat(filepath.Join(dir, LocalProxyDir)); !os.IsNotExist(err) {
		t.Fatal("dry run wrote")
	}
	if _, err := Proxy(e, dir, "", true); err != nil {
		t.Fatal(err)
	}
	cfg, _ := os.ReadFile(filepath.Join(dir, LocalProxyDir, "halo-proxy.yaml"))
	if !strings.Contains(string(cfg), "${ANTHROPIC_API_KEY}") || strings.Contains(string(cfg), secret) || !strings.Contains(string(cfg), `listen: "127.0.0.1:8088"`) {
		t.Fatalf("config:\n%s", cfg)
	}
	r, _ = Proxy(e, dir, "", true)
	for p, a := range r.Files {
		if a != ActionUnchanged {
			t.Errorf("%s %s on second apply", p, a)
		}
	}
	if _, err := Proxy(e, dir, "0.0.0.0:8088", false); err == nil {
		t.Fatal("non-loopback listen accepted")
	}
}

func TestVerify(t *testing.T) {
	ctx := context.Background()
	if r := Verify(ctx, fake("", nil), "codex", false, false, 0); r.Status != VerifySkipped {
		t.Fatalf("missing CLI: %+v", r)
	}
	noKey := fake("", nil)
	noKey.Getenv = func(string) string { return "" }
	if r := Verify(ctx, noKey, "claude-code", false, false, 0); r.Status != VerifySkipped || !strings.Contains(r.Detail, "--assume-auth") {
		t.Fatalf("no key: %+v", r)
	}
	if r := Verify(ctx, fake("", nil), "claude-code", false, true, 0); r.Status != VerifyDryRun || r.Command[0] != "claude" || r.Command[1] != "-p" {
		t.Fatalf("dry: %+v", r)
	}
	if r := Verify(ctx, fake("HALOS_OK\n", nil), "claude-code", false, false, time.Second); r.Status != VerifyPass {
		t.Fatalf("pass: %+v", r)
	}
	r := Verify(ctx, fake("bad key "+secret, errors.New("exit status 1")), "claude-code", false, false, time.Second)
	if r.Status != VerifyFail || strings.Contains(r.Output, secret) || !strings.Contains(r.Output, "[redacted ANTHROPIC_API_KEY]") {
		t.Fatalf("fail must redact: %+v", r)
	}
	if r := Verify(ctx, fake("nope", nil), "claude-code", false, false, time.Second); r.Status != VerifyFail {
		t.Fatalf("wrong reply: %+v", r)
	}
}

func companyOpts() CompanyOptions {
	in := initOpts()
	in.Org, in.Tools = "acme", map[string]string{"claude-code": "2.1.280", "codex": "0.99.0"}
	in.Gateway, in.Issuer, in.Admins = "https://ai.acme.example", "https://login.acme.example", []string{"ai-platform"}
	return CompanyOptions{Init: in, GatewayKind: "halo-proxy", Delivery: []string{"halod", "devcontainer"},
		Registry: "ghcr.io/acme/halos-releases", PolicyRepo: "https://github.com/acme/halos-policy.git", PortalURL: "https://halos.acme.example"}
}

func TestCompany(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "acme")
	o := companyOpts()
	r, err := WriteCompany(dir, o, false)
	if err != nil || !r.Valid || !r.DryRun {
		t.Fatalf("%v %+v", err, r)
	}
	for _, f := range []string{"halos.yaml", ".halos/helm-values.yaml", ".halos/oidc-client.yaml", ".halos/enroll/halod.yaml", ".halos/enroll/devcontainer.json", ".github/workflows/halos.yml", ".halos/evals/suites/onboarding-smoke.yaml", "README.md"} {
		if r.Files[f] != ActionCreate {
			t.Errorf("%s: %q", f, r.Files[f])
		}
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("dry run wrote")
	}
	if r, err = WriteCompany(dir, o, true); err != nil || !r.Valid {
		t.Fatal(err, r)
	}
	org, err := policy.Load(dir)
	if err != nil || policy.HasErrors(org.Validate()) {
		t.Fatalf("generated repo: %v", err)
	}
	s, err := eval.LoadSuite(filepath.Join(dir, ".halos/evals/suites/onboarding-smoke.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.LoadTasks(""); err != nil || len(s.Variants) != 2 {
		t.Fatalf("suite: %v %+v", err, s.Variants)
	}
	if r, err = WriteCompany(dir, o, true); err != nil {
		t.Fatalf("idempotent rerun: %v", err)
	}
	for f, a := range r.Files {
		if a != ActionUnchanged {
			t.Errorf("%s %s on rerun", f, a)
		}
	}
	o.Init.Org = "other"
	if _, err := WriteCompany(dir, o, true); err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("conflict: %v", err)
	}
	for _, mut := range []func(*CompanyOptions){
		func(c *CompanyOptions) { c.GatewayKind = "nginx" },
		func(c *CompanyOptions) { c.Init.Issuer = "http://login.acme.example" },
		func(c *CompanyOptions) { c.Delivery = nil },
		func(c *CompanyOptions) { c.Registry = "https://ghcr.io/x" },
	} {
		c := companyOpts()
		mut(&c)
		if _, err := Company(c); err == nil {
			t.Errorf("bad options accepted: %+v", c)
		}
	}
}
