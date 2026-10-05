package onboard

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/dshakes/halos/internal/intent"
	"github.com/dshakes/halos/internal/policy"
)

// FallbackTools is what a machine with no AI CLI on PATH starts with.
var FallbackTools = map[string]string{"claude-code": "2.1.280"}

// SuggestTools pins every installed CLI at the version found on PATH, so the
// first release changes no CLI binary. Empty when none is installed.
func SuggestTools(hs []Harness) map[string]string {
	out := map[string]string{}
	for _, h := range hs {
		if h.Installed && h.Version != "" {
			out[h.Name] = h.Version
		}
	}
	return out
}

// SuggestProvider picks the provider whose credential is already exported;
// anthropic when none is (ordering is the order checked).
func SuggestProvider(e Env) string {
	for _, p := range []string{"anthropic", "openai", "gemini", "bedrock", "vertex"} {
		if anySet(e, providerEnvs[p]) {
			return p
		}
	}
	return "anthropic"
}

// LocalOptions drive the "my machine" path.
type LocalOptions struct {
	Dir   string
	Init  intent.InitOptions // Gateway "" = the local halo-proxy on loopback
	Ring  string             // "" = the GA (last) ring
	GOOS  string
	Root  string // stage managed config under this directory instead of the real paths
	Apply bool   // write halos.yaml (never the managed config: see Install)
}

// LocalResult is one pass of init -> validate -> install plan.
type LocalResult struct {
	DryRun  bool         `json:"dryRun"`
	Policy  PolicyResult `json:"policy"`
	Valid   bool         `json:"valid"`
	Issues  []string     `json:"issues"`
	Install *InstallPlan `json:"install,omitempty"`
	Next    []string     `json:"next"`
}

// Local creates (or keeps) the policy in o.Dir, validates it as it would be
// written, and plans the managed-config install. It writes halos.yaml only
// when o.Apply and the policy validates; it never writes managed config.
// Idempotent: a second run reports the policy unchanged.
func Local(o LocalOptions) (*LocalResult, error) {
	if o.Init.Gateway == "" {
		o.Init.Gateway = "http://" + DefaultLocalProxy
	}
	ch, pr, err := InitPolicy(o.Dir, o.Init)
	if err != nil {
		return nil, err
	}
	res := &LocalResult{DryRun: !o.Apply, Policy: pr, Next: []string{}}
	org, issues, err := loadChange(ch)
	if err != nil {
		return nil, err
	}
	res.Issues, res.Valid = Issues(issues)
	if !res.Valid {
		res.Next = append(res.Next, "fix the validation errors above; nothing was written")
		return res, nil
	}
	if res.Install, err = PlanInstall(org, o.Ring, o.GOOS, o.Root); err != nil {
		return nil, err
	}
	if o.Apply && len(ch.Files) > 0 {
		if err := os.MkdirAll(o.Dir, 0o755); err != nil {
			return nil, err
		}
		if err := ch.Apply(); err != nil {
			return nil, err
		}
	}
	d := o.Dir
	if !o.Apply && pr.Action == PolicyCreate {
		res.Next = append(res.Next, "write the policy: halo onboard local --policy-dir "+d+" --apply (same flags)")
	}
	var foreign []string
	for _, f := range res.Install.Files {
		if f.Action == ActionForeign {
			foreign = append(foreign, f.Dest)
		}
	}
	if len(foreign) > 0 {
		res.Next = append(res.Next,
			"STOP: "+strings.Join(foreign, ", ")+" already exists and was not written by Halos (likely your IT/MDM): do not install over it on this machine",
			"compare instead: halo onboard install --policy-dir "+d+" --root ~/halo-eval --apply, then diff with the existing file; deliver the result through your MDM",
			"if your company has its own API gateway: halo onboard local --policy-dir "+d+" --gateway <its URL> --gateway-engine external")
	} else {
		res.Next = append(res.Next,
			"preview the managed config: halo onboard install --policy-dir "+d,
			"write it (admin-owned paths need sudo; --root DIR stages it): halo onboard install --policy-dir "+d+" --apply")
	}
	if IsLoopback(o.Init.Gateway) || (pr.Action != PolicyCreate && res.Install.Gateway != "" && IsLoopback(res.Install.Gateway)) {
		res.Next = append(res.Next, "run the local gateway the CLIs will call: halo onboard proxy --policy-dir "+d+" --apply")
	}
	res.Next = append(res.Next, "check a real round trip: halo onboard verify --policy-dir "+d)
	return res, nil
}

// loadChange loads and validates the policy as it would be after ch, even
// when ch.Dir does not exist yet (dry run from an empty directory).
func loadChange(ch *intent.Change) (*policy.Org, []policy.Issue, error) {
	c := *ch
	if _, err := os.Stat(c.Dir); os.IsNotExist(err) {
		tmp, err := os.MkdirTemp("", "halo-onboard-")
		if err != nil {
			return nil, nil, err
		}
		defer func() { _ = os.RemoveAll(tmp) }() // scratch dir
		c.Dir = tmp
	}
	org, err := c.Load()
	if err != nil {
		return nil, nil, fmt.Errorf("load policy %s: %w", ch.Dir, err)
	}
	return org, org.Validate(), nil
}

// Install plans the managed-config install for the policy in dir and, when
// apply, writes it. A file Halos did not write (ActionForeign) blocks the
// whole apply unless replace is set. Idempotent: a second apply writes nothing.
func Install(dir, ring, goos, root string, apply, replace bool) (*InstallPlan, []string, error) {
	if _, err := os.Stat(filepath.Join(dir, policy.RootFile)); err != nil {
		return nil, nil, fmt.Errorf("%w in %s: run halo onboard local --policy-dir %s --apply first", ErrNotFound, dir, dir)
	}
	org, err := policy.Load(dir)
	if err != nil {
		return nil, nil, fmt.Errorf("load policy %s: %w", dir, err)
	}
	if is, ok := Issues(org.Validate()); !ok {
		return nil, nil, fmt.Errorf("policy %s does not validate: %v", dir, is)
	}
	p, err := PlanInstall(org, ring, goos, root)
	if err != nil {
		return nil, nil, err
	}
	written := []string{}
	if apply && !replace {
		var foreign []string
		for _, f := range p.Files {
			if f.Action == ActionForeign {
				foreign = append(foreign, f.Dest)
			}
		}
		if len(foreign) > 0 {
			return p, written, fmt.Errorf("%w: %s (another tool, e.g. your MDM, manages them; nothing was written. Re-run with --replace-existing only if you own them: the originals are kept at <file>%s)", ErrForeign, strings.Join(foreign, ", "), backupSuffix)
		}
	}
	if apply {
		if written, err = p.Apply(); err != nil {
			return p, written, err
		}
		for i := range p.Files {
			if p.Files[i].Action != ActionUnchanged {
				p.Files[i].Action = ActionUnchanged // now on disk
			}
		}
	}
	return p, written, nil
}

// ProxyResult is what `halo onboard proxy` decided.
type ProxyResult struct {
	DryRun  bool              `json:"dryRun"`
	Files   map[string]string `json:"files"` // absolute path -> create | update | unchanged
	Command string            `json:"command"`
	Notes   []string          `json:"notes"`
}

// Proxy writes (when apply) the local halo-proxy config into dir/.halos/local.
func Proxy(e Env, dir, listen string, apply bool) (*ProxyResult, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	org, err := policy.Load(abs)
	if err != nil {
		return nil, fmt.Errorf("load policy %s: %w", dir, err)
	}
	if is, ok := Issues(org.Validate()); !ok {
		return nil, fmt.Errorf("policy %s does not validate: %v", dir, is)
	}
	files, cmd, err := LocalProxy(org, abs, listen)
	if err != nil {
		return nil, err
	}
	res := &ProxyResult{DryRun: !apply, Files: map[string]string{}, Command: cmd, Notes: []string{}}
	ch := &intent.Change{Dir: abs, Files: files}
	created, changed := ch.Paths()
	for _, p := range created {
		res.Files[filepath.Join(abs, p)] = ActionCreate
	}
	for _, p := range changed {
		act := ActionUpdate
		if b, err := os.ReadFile(filepath.Join(abs, p)); err == nil && string(b) == string(files[p]) {
			act = ActionUnchanged
		}
		res.Files[filepath.Join(abs, p)] = act
	}
	if apply {
		if err := ch.Apply(); err != nil {
			return nil, err
		}
	}
	if org.Gateway != nil && org.Gateway.BaseURL != "" && !IsLoopback(org.Gateway.BaseURL) {
		res.Notes = append(res.Notes, "the policy's gateway is "+org.Gateway.BaseURL+", so installed CLIs will not call this proxy: set gateway: http://"+orDefault(listen, DefaultLocalProxy)+" in halos.yaml for a local setup")
	}
	if _, err := e.LookPath("halo-proxy"); err != nil {
		res.Notes = append(res.Notes, "halo-proxy is not on PATH: go install github.com/dshakes/halos/cmd/halo-proxy@latest")
	}
	var kinds []string
	if org.Gateway != nil {
		for _, u := range org.Gateway.Upstreams {
			kinds = append(kinds, u.Kind)
		}
	}
	sort.Strings(kinds)
	for _, k := range kinds {
		if envs := providerEnvs[k]; len(envs) > 0 && !anySet(e, envs) {
			res.Notes = append(res.Notes, "export "+envs[0]+" in the shell that starts halo-proxy (it reads the key at startup; halo never stores it)")
		}
	}
	res.Notes = append(res.Notes, "start it in its own terminal: "+cmd)
	return res, nil
}

func orDefault(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

// CompanyResult is what `halo onboard company` decided per file.
type CompanyResult struct {
	DryRun bool              `json:"dryRun"`
	Dir    string            `json:"dir"`
	Files  map[string]string `json:"files"` // repo-relative path -> create | unchanged
	Valid  bool              `json:"valid"`
	Issues []string          `json:"issues"`
	Next   []string          `json:"next"`
}

// WriteCompany generates the company repo into dir, validates it, and writes
// it when apply. It never overwrites a file that differs (exit with a list).
func WriteCompany(dir string, o CompanyOptions, apply bool) (*CompanyResult, error) {
	files, err := Company(o)
	if err != nil {
		return nil, err
	}
	res := &CompanyResult{DryRun: !apply, Dir: dir, Files: map[string]string{}, Next: []string{}}
	var conflicts []string
	for rel, want := range files {
		cur, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
		switch {
		case os.IsNotExist(err):
			res.Files[rel] = ActionCreate
		case err != nil:
			return nil, err
		case string(cur) == string(want):
			res.Files[rel] = ActionUnchanged
		default:
			conflicts = append(conflicts, rel)
		}
	}
	if len(conflicts) > 0 {
		sort.Strings(conflicts)
		return nil, fmt.Errorf("%s already has different %v; refusing to overwrite: pick an empty --policy-dir", dir, conflicts)
	}
	ch := &intent.Change{Dir: dir, Files: files}
	_, issues, err := loadChange(ch)
	if err != nil {
		return nil, err
	}
	res.Issues, res.Valid = Issues(issues)
	if !res.Valid {
		return res, nil
	}
	if apply {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
		if err := ch.Apply(); err != nil {
			return nil, err
		}
	}
	ring := lastRing(o.Init.Rollout)
	res.Next = append(res.Next,
		"halo validate --policy-dir "+dir,
		"halo explain --policy-dir "+dir+" --kind Ring",
		"halo onboard install --policy-dir "+dir+" --ring "+ring+" --root /tmp/halos-preview   (what a laptop would get; writes only under /tmp)",
		"halo eval run "+filepath.Join(dir, ".halos/evals/suites/onboarding-smoke.yaml")+" --network bridge --pass-env <PROVIDER_KEY_VAR>   (Docker; one tiny task per CLI)",
		"git init, commit on a branch, push and open a PR: a human reviews and merges",
		"then the human steps in "+filepath.Join(dir, "README.md")+" (IdP client, signing key, helm install, publish, enroll)")
	return res, nil
}
