// Package upgrade watches upstream for new versions of the pinned coding CLIs
// and for new models in configured provider model lists, and turns each new
// candidate into an eval-gated pull request: it verifies the candidate's
// install artifacts (sha256 / npm integrity, via release.ArtifactResolver),
// writes the candidate pin on a branch, runs the eval suite, and opens a PR
// carrying the scorecard. It never merges, never publishes a release and
// never retags a ring: a human reviews and merges every PR.
//
// All network access sits behind Registry, ModelLister and Verifier, so the
// whole loop runs against fakes in tests.
package upgrade

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/dshakes/halos/internal/eval"
	"github.com/dshakes/halos/internal/fsutil"
	"github.com/dshakes/halos/internal/harness"
	_ "github.com/dshakes/halos/internal/harness/all" // register adapters (installer metadata)
	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/promote"
	"github.com/dshakes/halos/internal/release"
	"github.com/dshakes/halos/internal/yamledit"
)

// Config is the upgrade watcher's YAML, by default <policy-dir>/.halos/upgrade.yaml
// (a dot-dir: the policy loader skips it). Paths are relative to the policy dir.
type Config struct {
	// Profile is the profile whose harness pins are upgrade candidates
	// (typically the "-next" profile ring1 canaries).
	Profile string `yaml:"profile"`
	// Suite is the eval suite run for each candidate.
	Suite string `yaml:"suite"`
	// Harnesses limits which pinned harnesses are watched (default: all
	// pinned harnesses with a known package).
	Harnesses []string `yaml:"harnesses,omitempty"`
	// Models are provider model lists to watch.
	Models []ModelSource `yaml:"models,omitempty"`
	// Base is the PR base branch (default: repo default).
	Base string `yaml:"base,omitempty"`
	// State is the watcher's memory on disk (default .halos/upgrade-state.json).
	State string `yaml:"state,omitempty"`
}

// ModelSource is one provider's model list, read through the gateway.
type ModelSource struct {
	Provider  string `yaml:"provider"`
	URL       string `yaml:"url"` // e.g. https://ai.acme.example/v1/models
	APIKeyEnv string `yaml:"api_key_env,omitempty"`
	// Match filters ids worth evaluating (RE2), e.g. ^claude-(opus|sonnet)-.
	Match string `yaml:"match,omitempty"`
	// Known ids are never candidates (already evaluated or deliberately skipped).
	Known []string `yaml:"known,omitempty"`
	// Alias is the gateway model alias whose route the candidate pin edits
	// (models.<alias>.model in the Gateway document), e.g. sonnet-next.
	Alias string `yaml:"alias"`
}

// LoadConfig reads and validates the watcher config.
func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path) //nolint:gosec // operator-chosen config
	if err != nil {
		return nil, fmt.Errorf("upgrade config: %w", err)
	}
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if c.Profile == "" || c.Suite == "" {
		return nil, fmt.Errorf("%s: profile and suite are required", path)
	}
	for _, m := range c.Models {
		if m.Provider == "" || m.URL == "" || m.Alias == "" {
			return nil, fmt.Errorf("%s: models: provider, url and alias are required", path)
		}
		if err := eval.CheckSecureURL(m.URL); err != nil {
			return nil, fmt.Errorf("%s: models %s: %w", path, m.Provider, err)
		}
		if _, err := regexp.Compile(m.Match); err != nil {
			return nil, fmt.Errorf("%s: models %s: match: %w", path, m.Provider, err)
		}
	}
	if c.State == "" {
		c.State = ".halos/upgrade-state.json"
	}
	return &c, nil
}

// npmPackage is where a harness's versions are published. Claude Code installs
// from Anthropic's native manifest but publishes the same versions to npm.
func npmPackage(h string) string {
	if h == "claude-code" {
		return "@anthropic-ai/claude-code"
	}
	m, _ := harness.MetaOf(h)
	return m.NPMPackage
}

// Registry reports the latest published version of an npm package.
type Registry interface {
	Latest(ctx context.Context, pkg string) (string, error)
}

// ModelLister lists a provider's model ids.
type ModelLister interface {
	List(ctx context.Context) ([]string, error)
}

// Verifier checks that harness@version resolves to hash-pinned install
// artifacts and returns how many (one per platform, or one npm tarball).
type Verifier interface {
	Verify(ctx context.Context, harness, version string) (int, error)
}

var client = &http.Client{Timeout: 30 * time.Second}

func getJSON(ctx context.Context, hc *http.Client, u string, hdr map[string]string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	for k, val := range hdr {
		req.Header.Set(k, val)
	}
	if hc == nil {
		hc = client
	}
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", u, err)
	}
	defer func() { _ = resp.Body.Close() }() // read-only
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: status %d", u, resp.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(v); err != nil {
		return fmt.Errorf("GET %s: decode: %w", u, err)
	}
	return nil
}

// NPM reads dist-tag latest from an npm registry (GET <registry>/<pkg>/latest).
// UNVERIFIED against registry.npmjs.org; tests use httptest.
type NPM struct {
	URL  string // default https://registry.npmjs.org
	HTTP *http.Client
}

func (n NPM) Latest(ctx context.Context, pkg string) (string, error) {
	reg := n.URL
	if reg == "" {
		reg = "https://registry.npmjs.org"
	}
	var doc struct{ Name, Version string }
	if err := getJSON(ctx, n.HTTP, strings.TrimRight(reg, "/")+"/"+pkg+"/latest", nil, &doc); err != nil {
		return "", fmt.Errorf("npm %s: %w", pkg, err)
	}
	if doc.Name != pkg || !semverRe.MatchString(doc.Version) {
		return "", fmt.Errorf("npm %s: registry returned %s@%q", pkg, doc.Name, doc.Version)
	}
	return doc.Version, nil
}

// HTTPModels lists models from an OpenAI/Anthropic-style {"data":[{"id"}]}
// or Gemini-style {"models":[{"name":"models/<id>"}]} endpoint.
type HTTPModels struct {
	URL, APIKey string
	HTTP        *http.Client
}

func (h HTTPModels) List(ctx context.Context) ([]string, error) {
	var doc struct {
		Data   []struct{ ID string }   `json:"data"`
		Models []struct{ Name string } `json:"models"`
	}
	if err := eval.CheckSecureURL(h.URL); err != nil { // the gateway token rides along
		return nil, fmt.Errorf("list models: %w", err)
	}
	hdr := map[string]string{"anthropic-version": "2023-06-01"}
	if h.APIKey != "" {
		hdr["Authorization"] = "Bearer " + h.APIKey
	}
	if err := getJSON(ctx, h.HTTP, h.URL, hdr, &doc); err != nil {
		return nil, fmt.Errorf("list models: %w", err)
	}
	var out []string
	for _, d := range doc.Data {
		out = append(out, d.ID)
	}
	for _, m := range doc.Models {
		out = append(out, strings.TrimPrefix(m.Name, "models/"))
	}
	return out, nil
}

// ArtifactVerifier verifies through the same resolver `halo release build`
// uses, so a pin is only proposed for bytes halod would be allowed to install.
type ArtifactVerifier struct{ Resolver release.ArtifactResolver }

func (a ArtifactVerifier) Verify(ctx context.Context, h, ver string) (int, error) {
	rel := &release.Release{Manifest: release.Manifest{Harnesses: map[string]release.HarnessEntry{h: {Version: ver}}}}
	out, err := a.Resolver.Resolve(ctx, rel)
	if err != nil {
		return 0, err
	}
	if w := out.Manifest.Warnings; len(w) > 0 {
		return 0, errors.New(strings.Join(w, "; "))
	}
	n := len(out.Manifest.Harnesses[h].Artifacts)
	if n == 0 {
		return 0, fmt.Errorf("%s@%s: no verified artifacts", h, ver)
	}
	return n, nil
}

// modelIDRe bounds what an upstream model list may put into a policy file,
// a branch name, a PR title and a PR body.
var modelIDRe = regexp.MustCompile(`^[A-Za-z0-9._:@/-]{1,128}$`)

var semverRe = regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)(-[0-9A-Za-z.-]+)?$`)

// newer reports whether a is a strictly higher release than b. Prereleases
// are never candidates.
func newer(a, b string) bool {
	ma, mb := semverRe.FindStringSubmatch(a), semverRe.FindStringSubmatch(b)
	if ma == nil || mb == nil || ma[4] != "" {
		return false
	}
	for i := 1; i <= 3; i++ {
		x, _ := strconv.Atoi(ma[i])
		y, _ := strconv.Atoi(mb[i])
		if x != y {
			return x > y
		}
	}
	return mb[4] != "" // 1.2.3 > 1.2.3-rc.1
}

// Candidate kinds.
const (
	KindCLI   = "cli"
	KindModel = "model"
)

// Candidate is one proposed upgrade and what happened to it.
type Candidate struct {
	Kind      string `json:"kind"`
	Harness   string `json:"harness,omitempty"`
	Package   string `json:"package,omitempty"`
	Provider  string `json:"provider,omitempty"`
	Alias     string `json:"alias,omitempty"`
	From      string `json:"from"`
	To        string `json:"to"`
	Artifacts int    `json:"artifacts,omitempty"` // verified install artifacts (cli)
	Verdict   string `json:"verdict,omitempty"`   // gate verdict, or "" when not evaluated
	PR        string `json:"pr,omitempty"`
	Note      string `json:"note,omitempty"`

	// File and Edit are the candidate pin: the policy file it changes and how
	// to re-apply it to a given version of that file.
	File string                       `json:"file,omitempty"`
	Edit func([]byte) ([]byte, error) `json:"-"`
}

// Key identifies a candidate in the state file.
func (c Candidate) Key() string {
	if c.Kind == KindCLI {
		return "cli/" + c.Harness + "@" + c.To
	}
	return "model/" + c.Provider + "/" + c.To
}

// EvalFunc runs the eval suite for a candidate (control = current pin).
type EvalFunc func(ctx context.Context, c Candidate) (*eval.Scorecard, error)

// State is the watcher's on-disk memory: what it already handled.
type State struct {
	Handled map[string]string `json:"handled"` // candidate key -> verdict / PR url
}

// Watcher runs the check.
type Watcher struct {
	PolicyDir string
	Config    *Config
	Registry  Registry
	Models    map[string]ModelLister // by provider; nil = HTTPModels from Config
	Verifier  Verifier
	Eval      EvalFunc         // required unless DryRun
	PR        promote.PROpener // required unless DryRun
	DryRun    bool
	// Warn receives non-fatal notices (e.g. a skipped malformed model id); nil = discard.
	Warn func(string)
}

func (w *Watcher) warn(format string, args ...any) {
	if w.Warn != nil {
		w.Warn(fmt.Sprintf(format, args...))
	}
}

func (w *Watcher) statePath() string {
	if filepath.IsAbs(w.Config.State) {
		return w.Config.State
	}
	return filepath.Join(w.PolicyDir, w.Config.State)
}

func (w *Watcher) loadState() (State, error) {
	st := State{Handled: map[string]string{}}
	b, err := os.ReadFile(w.statePath())
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return st, fmt.Errorf("upgrade state: %w", err)
	}
	if err := json.Unmarshal(b, &st); err != nil {
		return st, fmt.Errorf("upgrade state %s: %w", w.statePath(), err)
	}
	if st.Handled == nil {
		st.Handled = map[string]string{}
	}
	return st, nil
}

func (w *Watcher) saveState(st State) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("upgrade state: %w", err)
	}
	p := w.statePath()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return fmt.Errorf("upgrade state: %w", err)
	}
	if err := fsutil.WriteAtomic(p, append(b, '\n'), 0o644); err != nil {
		return fmt.Errorf("upgrade state %s: %w", p, err)
	}
	return nil
}

// Candidates discovers new CLI versions and models without side effects.
func (w *Watcher) Candidates(ctx context.Context) ([]Candidate, error) {
	org, err := policy.Load(w.PolicyDir)
	if err != nil {
		return nil, fmt.Errorf("upgrade: load policy %s: %w", w.PolicyDir, err)
	}
	prof, err := org.ResolveProfile(w.Config.Profile)
	if err != nil {
		return nil, fmt.Errorf("upgrade: profile %s: %w", w.Config.Profile, err)
	}
	pdoc, err := yamledit.Find(w.PolicyDir, policy.KindProfile, w.Config.Profile)
	if err != nil {
		return nil, fmt.Errorf("upgrade: %w", err)
	}
	names := w.Config.Harnesses
	if len(names) == 0 {
		for n := range prof.Harnesses {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	var out []Candidate
	for _, h := range names {
		spec, ok := prof.Harnesses[h]
		pkg := npmPackage(h)
		if !ok || spec.Version == "" || pkg == "" {
			continue
		}
		latest, err := w.Registry.Latest(ctx, pkg)
		if err != nil {
			return nil, fmt.Errorf("upgrade: %s: %w", h, err)
		}
		if !newer(latest, spec.Version) {
			continue
		}
		c := Candidate{Kind: KindCLI, Harness: h, Package: pkg, From: spec.Version, To: latest, File: pdoc.Rel,
			Edit: scalarEdit(policy.KindProfile, w.Config.Profile, []string{"harnesses", h, "version"}, spec.Version, latest)}
		if c.Artifacts, err = w.Verifier.Verify(ctx, h, latest); err != nil {
			c.Note = "artifacts not verified: " + err.Error()
		}
		out = append(out, c)
	}
	if len(w.Config.Models) == 0 {
		return out, nil
	}
	if org.Gateway == nil {
		return nil, errors.New("upgrade: models are watched but the policy has no Gateway")
	}
	gdoc, err := yamledit.Find(w.PolicyDir, policy.KindGateway, org.Gateway.Name)
	if err != nil {
		return nil, fmt.Errorf("upgrade: %w", err)
	}
	for _, src := range w.Config.Models {
		route, ok := org.Gateway.Models[src.Alias]
		if !ok || route.Model == "" {
			return nil, fmt.Errorf("upgrade: gateway alias %q must exist as a single-target route (upstream + model)", src.Alias)
		}
		ml := w.Models[src.Provider]
		if ml == nil {
			key := ""
			if src.APIKeyEnv != "" {
				key = os.Getenv(src.APIKeyEnv)
			}
			ml = HTTPModels{URL: src.URL, APIKey: key}
		}
		ids, err := ml.List(ctx)
		if err != nil {
			return nil, fmt.Errorf("upgrade: %s: %w", src.Provider, err)
		}
		re := regexp.MustCompile(src.Match) // validated by LoadConfig
		sort.Strings(ids)
		for _, id := range ids {
			if !modelIDRe.MatchString(id) {
				w.warn("upgrade: %s: skipping malformed model id %q", src.Provider, truncate(id, 64))
				continue
			}
			if !re.MatchString(id) || slices.Contains(src.Known, id) || id == route.Model {
				continue
			}
			out = append(out, Candidate{Kind: KindModel, Provider: src.Provider, Alias: src.Alias, From: route.Model, To: id, File: gdoc.Rel,
				Edit: scalarEdit(policy.KindGateway, org.Gateway.Name, []string{"models", src.Alias, "model"}, route.Model, id)})
		}
	}
	return out, nil
}

// Check discovers candidates and, unless DryRun, evaluates each one not yet
// handled and opens a PR for every candidate whose gate is not block.
func (w *Watcher) Check(ctx context.Context) ([]Candidate, error) {
	cands, err := w.Candidates(ctx)
	if err != nil {
		return nil, err
	}
	if w.DryRun {
		for i := range cands {
			if cands[i].Note == "" {
				cands[i].Note = "dry run"
			}
		}
		return cands, nil
	}
	if w.Eval == nil || w.PR == nil {
		return nil, errors.New("upgrade: Eval and PR are required unless DryRun")
	}
	st, err := w.loadState()
	if err != nil {
		return nil, err
	}
	var errs []error
	for i := range cands {
		c := &cands[i]
		if prev, ok := st.Handled[c.Key()]; ok {
			c.Note = "already handled: " + prev
			continue
		}
		if c.Kind == KindCLI && c.Artifacts == 0 {
			continue // never pin bytes halod would refuse; retried next check
		}
		if err := w.handle(ctx, c); err != nil {
			// One bad candidate must not starve the rest; not recorded, so retried.
			c.Note = "error: " + err.Error()
			errs = append(errs, fmt.Errorf("upgrade %s: %w", c.Key(), err))
			continue
		}
		st.Handled[c.Key()] = c.Verdict + " " + c.PR
		if err := w.saveState(st); err != nil {
			return cands, err
		}
	}
	return cands, errors.Join(errs...)
}

func (w *Watcher) handle(ctx context.Context, c *Candidate) error {
	sc, err := w.Eval(ctx, *c)
	if err != nil {
		return fmt.Errorf("eval: %w", err)
	}
	c.Verdict = GateVerdict(sc)
	if c.Verdict == eval.GateBlock {
		c.Note = "blocked by the eval gate; no PR"
		return nil
	}
	cur, err := os.ReadFile(filepath.Join(w.PolicyDir, filepath.FromSlash(c.File)))
	if err != nil {
		return fmt.Errorf("read %s: %w", c.File, err)
	}
	preview, err := c.Edit(cur)
	if err != nil {
		return err
	}
	title := fmt.Sprintf("Upgrade %s: %s -> %s (eval: %s)", c.target(), c.From, c.To, c.Verdict)
	body := fmt.Sprintf("Automated upgrade candidate found by `halo upgrade watch`.\n\n- Target: `%s`\n- Pin: `%s` -> `%s` in `%s`\n",
		c.target(), c.From, c.To, c.File)
	if c.Kind == KindCLI {
		body += fmt.Sprintf("- Install artifacts: %d verified (sha256 / npm integrity) for `%s@%s`\n", c.Artifacts, c.Package, c.To)
	}
	body += fmt.Sprintf("- Eval gate: **%s**\n\n```diff\n%s```\n\n%s\n\nThis PR was opened by Halos and must be reviewed and merged by a human. "+
		"Merging changes policy only; releases and ring pointers stay with the normal release flow.\n",
		strings.ToUpper(c.Verdict), promote.UnifiedDiff(c.File, string(cur), string(preview)), sc.Markdown())
	edit := c.Edit
	file := c.File
	url, err := w.PR.OpenPR(ctx, promote.PRRequest{
		RepoDir: w.PolicyDir, Base: w.Config.Base,
		Branch: "halos/upgrade-" + branchSafe(c.target()+"-"+c.To),
		Title:  title, Body: body, Files: map[string][]byte{file: preview},
		Edit: func(read promote.ReadFunc) (map[string][]byte, error) {
			b, err := read(file)
			if err != nil {
				return nil, err
			}
			nb, err := edit(b)
			if err != nil {
				return nil, err
			}
			return map[string][]byte{file: nb}, nil
		},
	})
	if err != nil {
		return fmt.Errorf("open PR: %w", err)
	}
	c.PR = url
	return nil
}

// GateVerdict is the scorecard's gate verdict ("hold" if it has none).
func GateVerdict(sc *eval.Scorecard) string {
	if sc == nil || sc.Gate == nil {
		return eval.GateHold
	}
	return sc.Gate.Verdict
}

func (c Candidate) target() string {
	if c.Kind == KindCLI {
		return c.Harness
	}
	return c.Provider + "/" + c.Alias
}

var unsafeBranch = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func branchSafe(s string) string { return strings.Trim(unsafeBranch.ReplaceAllString(s, "-"), "-.") }

// scalarEdit returns an edit that replaces the scalar at path in the kind/name
// document, after checking it still holds old (so a concurrent bump is never
// silently overwritten). Comments and formatting are untouched.
func scalarEdit(kind policy.Kind, name string, path []string, old, val string) func([]byte) ([]byte, error) {
	return func(data []byte) ([]byte, error) {
		m, err := yamledit.Parse(data, kind, name)
		if err != nil || m == nil {
			return nil, fmt.Errorf("%s %s not found: %v", kind, name, err)
		}
		v := (&yamledit.Doc{Data: data, Mapping: m}).Get(path...)
		if v == nil || v.Kind != yaml.ScalarNode || v.Value != old {
			return nil, fmt.Errorf("%s %s: %s is no longer %q", kind, name, strings.Join(path, "."), old)
		}
		start := lineCol(data, v.Line, v.Column)
		lit := old
		if v.Style&(yaml.DoubleQuotedStyle|yaml.SingleQuotedStyle) != 0 {
			lit = string(data[start:min(start+len(old)+2, len(data))])
		}
		if start < 0 || !bytes.HasPrefix(data[start:], []byte(lit)) || strings.Trim(lit, `"'`) != old {
			return nil, fmt.Errorf("%s %s: cannot locate %s for editing", kind, name, strings.Join(path, "."))
		}
		return slices.Concat(data[:start], []byte(yamledit.Quote(val, v.Style)), data[start+len(lit):]), nil
	}
}

// lineCol is the byte offset of a 1-based line/column (ASCII columns: the
// values edited here are versions and model ids), or -1.
func lineCol(b []byte, line, col int) int {
	o := 0
	for l := 1; l < line; l++ {
		i := bytes.IndexByte(b[o:], '\n')
		if i < 0 {
			return -1
		}
		o += i + 1
	}
	if o+col-1 > len(b) {
		return -1
	}
	return o + col - 1
}

// Watch runs Check every interval until ctx ends, reporting each round.
func (w *Watcher) Watch(ctx context.Context, every time.Duration, report func([]Candidate, error)) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		report(w.Check(ctx))
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Table renders candidates as a compact terminal table.
func Table(cs []Candidate) string {
	var b strings.Builder
	if len(cs) == 0 {
		return "no upgrade candidates: every watched pin is current\n"
	}
	fmt.Fprintf(&b, "%-5s  %-22s  %-14s  %-14s  %-10s  %-5s  %s\n", "KIND", "TARGET", "FROM", "TO", "ARTIFACTS", "GATE", "PR / NOTE")
	for _, c := range cs {
		arts := "-"
		if c.Kind == KindCLI {
			arts = fmt.Sprintf("%d ok", c.Artifacts)
			if c.Artifacts == 0 {
				arts = "UNVERIFIED"
			}
		}
		fmt.Fprintf(&b, "%-5s  %-22s  %-14s  %-14s  %-10s  %-5s  %s\n", c.Kind, c.target(), c.From, c.To, arts, or(c.Verdict, "-"), or(c.PR, c.Note))
	}
	return b.String()
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

func or(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
