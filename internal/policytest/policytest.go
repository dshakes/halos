package policytest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"time"

	toml "github.com/pelletier/go-toml/v2"

	"github.com/dshakes/halos/internal/harness"
	"github.com/dshakes/halos/internal/impact"
	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/release"
	"github.com/dshakes/halos/internal/rollout"
)

// Check suites, in report order.
const (
	SuiteValidate   = "validate"
	SuiteRender     = "render"
	SuiteRelease    = "release"
	SuiteInvariants = "invariants"
	SuiteImpact     = "impact"
	SuiteCases      = "cases"
	SuiteRollout    = "rollout"
)

var suiteOrder = []string{SuiteValidate, SuiteRender, SuiteRelease, SuiteInvariants, SuiteImpact, SuiteCases, SuiteRollout}

// Status is the outcome of one check.
type Status string

// Check outcomes.
const (
	Pass Status = "pass"
	Fail Status = "fail"
	Skip Status = "skip"
)

const (
	// DefaultMaxImpact is the default --max-impact: a change that moves the
	// ring, experiment variant or effective settings of more than this share
	// (percent) of the sampled users of any ring fails the impact check.
	DefaultMaxImpact = 25.0
	// DefaultVersion is the release version label tests build with.
	DefaultVersion = "0.0.0-dev"
	// impactSamples is the hashed sample of anonymous users the impact preview
	// uses (the same as `halo plan --diff`: 0.1% resolution).
	impactSamples = 1000
	// minRingSample is the fewest sampled users a ring needs before its own
	// share is judged: a ring that the sample barely reaches is noise.
	minRingSample = 20
)

// Options configures Run.
type Options struct {
	Dir string // policy repo
	// Ring limits the render, release and invariant checks to one ring
	// ("" = every ring). Cases still resolve whatever ring their identity gets.
	Ring string
	// Against is a git ref of the policy to compare with; it turns on the
	// impact check.
	Against string
	// Strict fails the run on any warning: policy validation warnings and
	// adapter warnings in the release manifest.
	Strict bool
	// MaxImpact is the impact check's threshold in percent (0-100; 100 never
	// trips). Set it with DefaultMaxImpact.
	MaxImpact float64
	// Version is the release version label (default DefaultVersion).
	Version string
}

// Result is one check.
type Result struct {
	Suite     string   `json:"suite"`
	Name      string   `json:"name"`
	Status    Status   `json:"status"`
	Message   string   `json:"message,omitempty"`
	Details   []string `json:"details,omitempty"`  // why it failed, one line each
	Warnings  []string `json:"warnings,omitempty"` // surfaced, failing only under Strict
	ElapsedMS int64    `json:"elapsedMs"`
}

// Report is the outcome of a run.
type Report struct {
	Dir     string `json:"policyDir"`
	Org     string `json:"org,omitempty"`
	OK      bool   `json:"ok"`
	Strict  bool   `json:"strict"`
	Against string `json:"against,omitempty"`
	Passed  int    `json:"passed"`
	Failed  int    `json:"failed"`
	Skipped int    `json:"skipped"`
	// Warnings is the count of warnings across all checks.
	Warnings  int            `json:"warnings"`
	Results   []Result       `json:"results"`
	Impact    *impact.Report `json:"impact,omitempty"`
	NextSteps []string       `json:"next_steps"`
	ElapsedMS int64          `json:"elapsedMs"`
}

// ErrNoPolicy is wrapped by Run's error when Dir holds no policy repo.
var ErrNoPolicy = errors.New("no policy repo")

type runner struct {
	opt   Options
	org   *policy.Org
	rep   *Report
	built map[string]*built
	tmp   string
}

// built is a ring's release and its variant releases.
type built struct {
	rel      *release.Release
	variants []*release.Release
	err      error
}

// Run executes every offline check. A failed check is recorded in the
// report (OK false); an error means the run itself could not happen (no
// policy repo, a bad option, an unreadable git ref, cancellation).
func Run(ctx context.Context, opt Options) (*Report, error) {
	start := time.Now()
	if opt.Version == "" {
		opt.Version = DefaultVersion
	}
	if opt.MaxImpact < 0 || opt.MaxImpact > 100 {
		return nil, fmt.Errorf("policytest: max impact must be between 0 and 100 percent, got %v", opt.MaxImpact)
	}
	r := &runner{opt: opt, rep: &Report{Dir: opt.Dir, Strict: opt.Strict, Against: opt.Against, Results: []Result{}, NextSteps: []string{}}, built: map[string]*built{}}
	org, err := policy.Load(opt.Dir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, fmt.Errorf("policytest: %w: %w", ErrNoPolicy, err)
	case err != nil:
		r.add(Result{Suite: SuiteValidate, Name: "policy", Status: Fail, Message: "policy does not load", Details: []string{err.Error()}}, start)
		r.skipRest("policy does not load")
		return r.finish(start), nil
	}
	r.org, r.rep.Org = org, org.Name
	if opt.Ring != "" && !slices.ContainsFunc(org.Rings, func(x *policy.Ring) bool { return x.Name == opt.Ring }) {
		return nil, fmt.Errorf("policytest: unknown ring %q (rings in policy: %s)", opt.Ring, strings.Join(ringNames(org), ", "))
	}
	suites, badFiles, err := LoadSuites(opt.Dir)
	if err != nil {
		return nil, err
	}

	if !r.validate() {
		r.skipRest("policy does not validate")
		r.caseFileErrors(badFiles)
		return r.finish(start), nil
	}
	tmp, err := os.MkdirTemp("", "halo-test-")
	if err != nil {
		return nil, fmt.Errorf("policytest: temp dir: %w", err)
	}
	defer os.RemoveAll(tmp) //nolint:errcheck // best-effort cleanup of our own temp dir
	r.tmp = tmp

	if opt.Against != "" { // first: an unreadable ref is a usage error, found before the slow checks
		if err := r.impact(ctx); err != nil {
			return nil, err
		}
	}
	for _, ring := range r.ringsUnderTest() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		r.ring(ctx, ring)
	}
	r.caseFileErrors(badFiles)
	for _, s := range suites {
		for _, c := range s.Cases {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			r.runCase(s, c)
		}
	}
	for _, ro := range org.Rollouts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		r.simulate(ctx, ro)
	}
	return r.finish(start), nil
}

func ringNames(org *policy.Org) []string {
	out := make([]string, len(org.Rings))
	for i, r := range org.Rings {
		out[i] = r.Name
	}
	return out
}

func (r *runner) ringsUnderTest() []*policy.Ring {
	if r.opt.Ring == "" {
		return r.org.Rings
	}
	for _, x := range r.org.Rings {
		if x.Name == r.opt.Ring {
			return []*policy.Ring{x}
		}
	}
	return nil
}

// add records res, timing it from since.
func (r *runner) add(res Result, since time.Time) {
	res.ElapsedMS = time.Since(since).Milliseconds()
	r.rep.Results = append(r.rep.Results, res)
}

// skipRest records the checks that cannot run because the policy is unusable.
func (r *runner) skipRest(why string) {
	suites := []string{SuiteRender, SuiteRelease, SuiteInvariants, SuiteCases, SuiteRollout}
	if r.opt.Against != "" {
		suites = append(suites, SuiteImpact)
	}
	for _, s := range suites {
		r.rep.Results = append(r.rep.Results, Result{Suite: s, Name: "all", Status: Skip, Message: why})
	}
}

func (r *runner) caseFileErrors(bad []FileError) {
	for _, b := range bad {
		r.rep.Results = append(r.rep.Results, Result{Suite: SuiteCases, Name: b.File, Status: Fail, Message: "invalid test file", Details: []string{b.Err.Error()}})
	}
}

// validate is check 1: the policy loads and validates (org.Validate, the same
// as `halo validate`; supply-chain artifacts from git or oci are not fetched).
func (r *runner) validate() bool {
	start := time.Now()
	var errs, warns []string
	for _, i := range r.org.Validate() {
		if i.Severity == policy.SeverityError {
			errs = append(errs, i.String())
		} else {
			warns = append(warns, i.String())
		}
	}
	res := Result{Suite: SuiteValidate, Name: "policy", Status: Pass, Warnings: warns,
		Message: fmt.Sprintf("valid, %d warnings", len(warns))}
	switch {
	case len(errs) > 0:
		res.Status, res.Message, res.Details = Fail, fmt.Sprintf("%d errors, %d warnings", len(errs), len(warns)), errs
	case r.opt.Strict && len(warns) > 0:
		res.Status, res.Message, res.Details = Fail, fmt.Sprintf("%d warnings (--strict)", len(warns)), warns
	}
	r.add(res, start)
	return len(errs) == 0
}

// build returns ring's release and variant releases, building once. This is
// the render of every harness x OS through the adapters, with
// release.CheckRendered's security invariants applied to each file.
func (r *runner) build(ring string) *built {
	if b, ok := r.built[ring]; ok {
		return b
	}
	b := &built{}
	b.rel, b.variants, b.err = release.BuildRing(r.org, ring, release.Options{Version: r.opt.Version, Org: r.org.Name})
	r.built[ring] = b
	return b
}

// remoteArtifacts names the supply-chain artifacts that need a network fetch
// (git, oci) and have not been resolved: an offline build cannot include them.
func remoteArtifacts(org *policy.Org) []string {
	if org.SupplyChain == nil {
		return nil
	}
	var out []string
	for _, a := range org.SupplyChain.Artifacts {
		if c := org.ArtifactContent[a.Name]; a.Remote() && (c == nil || c.Files == nil) {
			out = append(out, a.Name)
		}
	}
	return out
}

// ring runs checks 2 to 4 for one ring: render, release consistency, invariants.
func (r *runner) ring(ctx context.Context, ring *policy.Ring) {
	start := time.Now()
	b := r.build(ring.Name)
	if b.err != nil {
		if remote := remoteArtifacts(r.org); len(remote) > 0 {
			why := fmt.Sprintf("needs network: remote artifacts %s are fetched by `halo release build`", strings.Join(remote, ", "))
			for _, s := range []string{SuiteRender, SuiteRelease, SuiteInvariants} {
				r.add(Result{Suite: s, Name: ring.Name, Status: Skip, Message: why, Details: []string{b.err.Error()}}, start)
			}
			return
		}
		r.add(Result{Suite: SuiteRender, Name: ring.Name, Status: Fail, Message: "render failed", Details: []string{b.err.Error()}}, start)
		r.add(Result{Suite: SuiteRelease, Name: ring.Name, Status: Skip, Message: "no release: render failed"}, time.Now())
		r.add(Result{Suite: SuiteInvariants, Name: ring.Name, Status: Skip, Message: "no release: render failed"}, time.Now())
		return
	}
	r.add(r.renderResult(ring, b), start)

	start = time.Now()
	res := Result{Suite: SuiteRelease, Name: ring.Name, Status: Pass}
	if errs := r.releaseConsistency(ctx, ring, b.rel); len(errs) > 0 {
		res.Status, res.Message, res.Details = Fail, fmt.Sprintf("%d inconsistencies", len(errs)), errs
	} else {
		res.Message = fmt.Sprintf("%s: manifest consistent, rebuild reproduces the digest", short(b.rel.Digest))
	}
	r.add(res, start)

	start = time.Now()
	res = Result{Suite: SuiteInvariants, Name: ring.Name, Status: Pass}
	rels := append([]*release.Release{b.rel}, b.variants...)
	blobs := 0
	var hits []string
	for _, rel := range rels {
		blobs += len(rel.Blobs)
		hits = append(hits, ScanBypass(rel)...)
	}
	if len(hits) > 0 {
		res.Status, res.Message, res.Details = Fail, fmt.Sprintf("%d permission-bypass tokens (invariant 1)", len(hits)), hits
	} else {
		res.Message = fmt.Sprintf("no bypassPermissions or danger-full-access in %d rendered blobs of %d release(s)", blobs, len(rels))
	}
	r.add(res, start)
}

// renderResult summarises ring's render: every enabled harness has a file
// list for every OS, and the adapter warnings are surfaced.
func (r *runner) renderResult(ring *policy.Ring, b *built) Result {
	m := b.rel.Manifest
	res := Result{Suite: SuiteRender, Name: ring.Name, Status: Pass, Warnings: m.Warnings}
	cells, files := 0, 0
	var missing []string
	for _, h := range sortedKeys(m.Harnesses) {
		for _, osName := range []harness.OS{harness.Darwin, harness.Linux, harness.Windows} {
			fl, ok := m.Harnesses[h].Files[string(osName)]
			if !ok {
				missing = append(missing, fmt.Sprintf("%s/%s: not rendered", h, osName))
				continue
			}
			cells++
			files += len(fl)
		}
	}
	res.Message = fmt.Sprintf("%d harnesses x 3 OS = %d cells, %d files, %d warnings", len(m.Harnesses), cells, files, len(m.Warnings))
	switch {
	case len(missing) > 0:
		res.Status, res.Message, res.Details = Fail, "harness x OS cells missing", missing
	case r.opt.Strict && len(m.Warnings) > 0:
		res.Status, res.Message, res.Details = Fail, fmt.Sprintf("%d adapter warnings (--strict)", len(m.Warnings)), m.Warnings
	}
	return res
}

// releaseConsistency writes rel to the temp dir as release.tar, reads it
// back and checks the manifest against the bundle and the policy; then
// rebuilds and expects the same digest (releases are content-addressed).
func (r *runner) releaseConsistency(ctx context.Context, ring *policy.Ring, rel *release.Release) []string {
	var errs []string
	dir := filepath.Join(r.tmp, ring.Name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return []string{fmt.Sprintf("temp dir: %v", err)}
	}
	p := filepath.Join(dir, "release.tar")
	if err := os.WriteFile(p, rel.Tar, 0o600); err != nil {
		return []string{fmt.Sprintf("write %s: %v", p, err)}
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return []string{fmt.Sprintf("read back %s: %v", p, err)}
	}
	got, err := release.Open(data)
	if err != nil {
		return []string{fmt.Sprintf("open built bundle: %v", err)}
	}
	if got.Digest != rel.Digest {
		errs = append(errs, fmt.Sprintf("digest changed on the way through the bundle: built %s, reopened %s", rel.Digest, got.Digest))
	}
	m := got.Manifest
	if m.Ring != ring.Name {
		errs = append(errs, fmt.Sprintf("manifest ring is %q, built for %q", m.Ring, ring.Name))
	}
	if m.Profile != ring.Profile {
		errs = append(errs, fmt.Sprintf("manifest profile is %q, the ring uses %q", m.Profile, ring.Profile))
	}
	if m.Org != r.org.Name {
		errs = append(errs, fmt.Sprintf("manifest org is %q, policy org is %q", m.Org, r.org.Name))
	}
	if m.Version != r.opt.Version {
		errs = append(errs, fmt.Sprintf("manifest version is %q, built as %q", m.Version, r.opt.Version))
	}
	if prof, err := r.org.ResolveProfile(ring.Profile); err == nil {
		want := sortedKeys(prof.Harnesses)
		if have := sortedKeys(m.Harnesses); !slices.Equal(want, have) {
			errs = append(errs, fmt.Sprintf("manifest harnesses %v, profile %s enables %v", have, ring.Profile, want))
		}
	}
	for _, h := range sortedKeys(m.Harnesses) {
		for _, osName := range sortedKeys(m.Harnesses[h].Files) {
			for _, f := range m.Harnesses[h].Files[osName] {
				blob, ok := got.Content(f)
				if !ok {
					errs = append(errs, fmt.Sprintf("%s/%s %s: blob %s missing", h, osName, f.Path, f.SHA256))
					continue
				}
				if sum := sha256.Sum256(blob); hex.EncodeToString(sum[:]) != f.SHA256 {
					errs = append(errs, fmt.Sprintf("%s/%s %s: content does not match its sha256 %s", h, osName, f.Path, f.SHA256))
				}
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return append(errs, err.Error())
	}
	again, _, err := release.BuildRing(r.org, ring.Name, release.Options{Version: r.opt.Version, Org: r.org.Name})
	switch {
	case err != nil:
		errs = append(errs, fmt.Sprintf("rebuild: %v", err))
	case again.Digest != rel.Digest:
		errs = append(errs, fmt.Sprintf("build is not reproducible: %s then %s\n%s", rel.Digest, again.Digest, release.Diff(rel, again)))
	}
	return errs
}

// ScanBypass lists every permission-bypass token (AGENTS.md invariant 1) in a
// release: the manifest and every blob, whatever its format, found with the
// one policy.BypassToken scan the validator and the release check use. It
// covers what CheckRendered's per-file pass does not reach: toggle fragments,
// unit overlays and cloud agent files.
func ScanBypass(rel *release.Release) []string {
	where := map[string]string{} // blob sha -> where the manifest puts it
	note := func(sha, at string) {
		if _, ok := where[sha]; !ok {
			where[sha] = at
		}
	}
	m := rel.Manifest
	for _, h := range sortedKeys(m.Harnesses) {
		for _, osName := range sortedKeys(m.Harnesses[h].Files) {
			for _, f := range m.Harnesses[h].Files[osName] {
				note(f.SHA256, fmt.Sprintf("%s/%s %s", h, osName, f.Path))
			}
		}
	}
	for _, t := range m.Toggles {
		for h, byOS := range t.Fragments {
			for osName, fl := range byOS {
				for _, f := range fl {
					note(f.SHA256, fmt.Sprintf("toggle %s %s/%s %s", t.Name, h, osName, f.Path))
				}
			}
		}
	}
	for _, f := range m.CloudAgents {
		note(f.SHA256, fmt.Sprintf("cloud agent %s %s", f.Vendor, f.Path))
	}
	var out []string
	if mj, err := json.Marshal(m); err == nil {
		if tok := policy.BypassToken(string(mj)); tok != "" {
			out = append(out, fmt.Sprintf("manifest (%s/%s): %q", m.Ring, m.Version, tok))
		}
	}
	for _, sha := range sortedKeys(rel.Blobs) {
		if tok := policy.BypassToken(string(rel.Blobs[sha])); tok != "" {
			at := where[sha]
			if at == "" {
				at = "blob " + short(sha)
			}
			out = append(out, fmt.Sprintf("%s (ring %s, release %s): %q", at, m.Ring, m.Version, tok))
		}
	}
	return out
}

func short(digest string) string {
	d := strings.TrimPrefix(digest, "sha256:")
	if len(d) > 12 {
		d = d[:12]
	}
	return "sha256:" + d
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// impact is check 5: who changes ring, variant or settings against the policy
// at Against, with a blast-radius judgement. The population is the policy-only
// estimate `halo plan --diff` uses without a server: the users and groups the
// policies name plus a hashed sample of everyone else. The sample stands for the
// general population, so its share is the share of the fleet a change reaches.
func (r *runner) impact(ctx context.Context) error {
	start := time.Now()
	baseDir, cleanup, err := impact.CheckoutAt(ctx, r.opt.Dir, r.opt.Against)
	if err != nil {
		return fmt.Errorf("policytest: --against %s: %w", r.opt.Against, err)
	}
	defer cleanup()
	base, err := policy.Load(baseDir)
	if err != nil {
		return fmt.Errorf("policytest: policy at %s: %w", r.opt.Against, err)
	}
	members := impact.PolicyMembers(impactSamples, base, r.org)
	rep := impact.Compute(base, r.org, members, 8)
	rep.Source = "policy"
	r.rep.Impact = &rep

	// The sample, by the ring each user lands in now.
	byRing := map[string][]impact.Member{}
	samples := 0
	for _, m := range members {
		if m.Kind != impact.KindSample {
			continue
		}
		samples++
		if ring := r.org.ResolveRing(policy.Subject{ID: m.ID}); ring != nil {
			byRing[ring.Name] = append(byRing[ring.Name], m)
		}
	}
	res := Result{Suite: SuiteImpact, Name: "blast radius vs " + r.opt.Against, Status: Pass}
	worst, worstWhere := 0.0, ""
	consider := func(where string, c impact.Counts) {
		if c.Total < minRingSample {
			return
		}
		pct := 100 * float64(c.Any) / float64(c.Total)
		line := fmt.Sprintf("%s: %.1f%% of %d sampled users change (ring %d, variant %d, settings %d)", where, pct, c.Total, c.Ring, c.Variant, c.Settings)
		res.Details = append(res.Details, line)
		if pct > r.opt.MaxImpact {
			res.Status = Fail
		}
		if pct >= worst {
			worst, worstWhere = pct, where
		}
	}
	consider("all users", rep.ByKind[impact.KindSample]) // the sample is exactly the sampled kind
	for _, ring := range r.org.Rings {
		if ms := byRing[ring.Name]; len(ms) >= minRingSample {
			consider(ring.Name, impact.Compute(base, r.org, ms, 0).ByKind[impact.KindSample])
		}
	}
	named := 0
	for _, k := range []string{impact.KindUser, impact.KindGroup, impact.KindAgent} {
		named += rep.ByKind[k].Any
	}
	switch res.Status {
	case Fail:
		res.Message = fmt.Sprintf("high blast radius: %.1f%% of %s change, above --max-impact %.0f%%", worst, worstWhere, r.opt.MaxImpact)
	default:
		res.Message = fmt.Sprintf("largest share %.1f%% (%s), within --max-impact %.0f%%; %d named users, groups or agents change", worst, worstWhere, r.opt.MaxImpact, named)
		if samples == 0 {
			res.Message = "no sampled users to judge"
		}
	}
	// Details are the failure reasons on a fail; on a pass they stay as the per-ring breakdown.
	r.add(res, start)
	return nil
}

// runCase is check 6 for one case: resolve the identity with the policy's own
// functions and compare ring, variants and rendered settings with expect.
func (r *runner) runCase(s Suite, c Case) {
	start := time.Now()
	res := Result{Suite: SuiteCases, Name: s.Name + "/" + c.Name, Status: Pass}
	fail := func(format string, a ...any) { res.Details = append(res.Details, fmt.Sprintf(format, a...)) }

	sub := policy.Subject{ID: c.Identity.User, Groups: c.Identity.Groups}
	ring := r.org.ResolveRing(sub)
	gotRing := ""
	if ring != nil {
		gotRing = ring.Name
	}
	got := map[string]string{} // running experiment -> variant
	var assigned []*policy.Experiment
	if ring != nil {
		for _, e := range r.org.Experiments {
			if v := e.ResolveVariant(sub, ring.Name); v != nil {
				got[e.Name] = v.Name
				assigned = append(assigned, e)
			}
		}
	}
	e := c.Expect
	if e.Ring != nil && *e.Ring != gotRing {
		fail("ring: want %s, got %s", quote(*e.Ring), quote(gotRing))
	}
	for _, exp := range sortedKeys(e.Variants) {
		if !slices.ContainsFunc(r.org.Experiments, func(x *policy.Experiment) bool { return x.Name == exp && x.Status == "running" }) {
			fail("variants.%s: no running experiment of that name", exp)
			continue
		}
		if want := e.Variants[exp]; want != got[exp] {
			fail("variants.%s: want %s, got %s", exp, quote(want), quote(got[exp]))
		}
	}
	if len(e.Settings) > 0 {
		r.checkSettings(c, ring, assigned, got, fail)
	}
	if len(res.Details) > 0 {
		res.Status, res.Message = Fail, fmt.Sprintf("%d expectations not met", len(res.Details))
	} else {
		res.Message = fmt.Sprintf("%s in %s", c.Identity.User, quote(gotRing))
	}
	r.add(res, start)
}

func quote(s string) string {
	if s == "" {
		return "(none)"
	}
	return fmt.Sprintf("%q", s)
}

// checkSettings compares the expected key paths with the files the identity
// would get: its ring's release, or the variant release of a client-axis
// experiment it is assigned a non-control variant of (as `halo plan --diff`'s
// impact preview resolves it). Unit overlays and toggles are not applied.
func (r *runner) checkSettings(c Case, ring *policy.Ring, assigned []*policy.Experiment, got map[string]string, fail func(string, ...any)) {
	if ring == nil {
		fail("settings: no ring matches, so there is nothing to render")
		return
	}
	b := r.build(ring.Name)
	if b.err != nil {
		fail("settings: ring %s does not build: %v", ring.Name, b.err)
		return
	}
	rel := b.rel
	for _, e := range assigned {
		if e.Axis != policy.AxisClient {
			continue
		}
		for _, v := range e.Variants {
			if v.Name != got[e.Name] || v.Profile == "" || v.Control {
				continue
			}
			for _, vr := range b.variants {
				if vr.Manifest.Experiment == e.Name && vr.Manifest.Variant == v.Name {
					rel = vr
				}
			}
		}
	}
	osName := c.OS
	if osName == "" {
		osName = "linux"
	}
	for _, h := range sortedKeys(c.Expect.Settings) {
		entry, ok := rel.Manifest.Harnesses[h]
		if !ok {
			fail("settings.%s: harness is not enabled in profile %s (ring %s)", h, rel.Manifest.Profile, ring.Name)
			continue
		}
		docs, err := parseFiles(rel, entry.Files[osName])
		if err != nil {
			fail("settings.%s: %v", h, err)
			continue
		}
		for _, path := range sortedKeys(c.Expect.Settings[h]) {
			want, err := normalize(c.Expect.Settings[h][path])
			if err != nil {
				fail("settings.%s.%s: %v", h, path, err)
				continue
			}
			have, found := lookupAny(docs, path)
			switch {
			case want == nil && found:
				fail("settings.%s.%s (%s): want absent, got %s", h, path, osName, show(have))
			case want != nil && !found:
				fail("settings.%s.%s (%s): want %s, but the key is absent", h, path, osName, show(want))
			case want != nil && !reflect.DeepEqual(want, have):
				fail("settings.%s.%s (%s): want %s, got %s", h, path, osName, show(want), show(have))
			}
		}
	}
}

// parseFiles decodes the JSON and TOML files of one harness x OS, in path order.
func parseFiles(rel *release.Release, files []release.FileEntry) ([]any, error) {
	var docs []any
	for _, f := range files {
		data, ok := rel.Content(f)
		if !ok {
			return nil, fmt.Errorf("release is missing the blob of %s", f.Path)
		}
		var doc map[string]any
		var err error
		switch strings.ToLower(filepath.Ext(f.Path)) {
		case ".json":
			err = json.Unmarshal(data, &doc)
		case ".toml":
			err = toml.Unmarshal(data, &doc)
		default:
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", f.Path, err)
		}
		// Normalise TOML's int64 and the like to JSON types, once.
		norm, err := normalize(doc)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", f.Path, err)
		}
		docs = append(docs, norm)
	}
	return docs, nil
}

// normalize round-trips v through JSON so YAML, TOML and JSON values compare.
func normalize(v any) (any, error) {
	if v == nil {
		return nil, nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("value is not representable as JSON: %w", err)
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func show(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(b)
}

// lookupAny finds a dotted key path in the first document that has it.
func lookupAny(docs []any, path string) (any, bool) {
	for _, d := range docs {
		if v, ok := Lookup(d, path); ok {
			return v, true
		}
	}
	return nil, false
}

// Lookup resolves a dotted key path ("permissions.defaultMode",
// "hooks.PreToolUse.0.matcher") in a decoded JSON document. Array elements are
// addressed by index. A map key that itself contains dots matches as the
// longest run of path segments that names a key.
func Lookup(doc any, path string) (any, bool) {
	return lookup(doc, strings.Split(path, "."))
}

func lookup(v any, segs []string) (any, bool) {
	if len(segs) == 0 {
		return v, true
	}
	switch t := v.(type) {
	case map[string]any:
		for n := len(segs); n >= 1; n-- {
			if next, ok := t[strings.Join(segs[:n], ".")]; ok {
				if out, ok := lookup(next, segs[n:]); ok {
					return out, true
				}
			}
		}
	case []any:
		var i int
		if _, err := fmt.Sscanf(segs[0], "%d", &i); err == nil && fmt.Sprint(i) == segs[0] && i >= 0 && i < len(t) {
			return lookup(t[i], segs[1:])
		}
	}
	return nil, false
}

// simulate is check 7: the rollout state machine runs on healthy synthetic
// evidence from "not started" and must reach "complete" (internal/rollout,
// the same gate logic as `halo rollout simulate`; nothing is written).
func (r *runner) simulate(ctx context.Context, ro *policy.Rollout) {
	start := time.Now()
	res := Result{Suite: SuiteRollout, Name: ro.Name, Status: Pass}
	sim, err := rollout.Simulate(ctx, r.opt.Dir, r.org, ro, rollout.SimOptions{Scenario: rollout.ScenarioHealthy})
	switch {
	case err != nil:
		res.Status, res.Message, res.Details = Fail, "simulation failed", []string{err.Error()}
	case sim.Outcome != rollout.Complete:
		res.Status, res.Message = Fail, fmt.Sprintf("healthy evidence ends in %q after %s, not complete: a gate can never pass", sim.Outcome, sim.Duration)
		if n := len(sim.Events); n > 0 {
			last := sim.Events[n-1]
			res.Details = append([]string{fmt.Sprintf("last event %s step %s: %s", last.At, last.Step, last.Action)}, last.Reasons...)
		}
	default:
		res.Message = fmt.Sprintf("completes after %s on healthy evidence (%d events)", sim.Duration, len(sim.Events))
	}
	r.add(res, start)
}

// finish totals the results and writes next_steps.
func (r *runner) finish(start time.Time) *Report {
	rep := r.rep
	for _, res := range rep.Results {
		switch res.Status {
		case Pass:
			rep.Passed++
		case Fail:
			rep.Failed++
		case Skip:
			rep.Skipped++
		}
		rep.Warnings += len(res.Warnings)
	}
	rep.OK = rep.Failed == 0
	rep.ElapsedMS = time.Since(start).Milliseconds()
	rep.NextSteps = r.nextSteps()
	return rep
}

func (r *runner) nextSteps() []string {
	rep := r.rep
	dir := shellQuote(rep.Dir)
	var out []string
	failed := map[string]bool{}
	for _, res := range rep.Results {
		if res.Status == Fail {
			failed[res.Suite] = true
		}
	}
	hint := map[string]string{
		SuiteValidate:   "fix the validate errors (`halo validate --policy-dir " + dir + "` prints them with paths)",
		SuiteRender:     "fix the render failures: an adapter or an override produced something release.CheckRendered refuses (`halo render --policy-dir " + dir + " --ring <ring>` shows the files)",
		SuiteRelease:    "the release for a ring is not consistent or reproducible: `halo release build --policy-dir " + dir + " --ring <ring>` reproduces it",
		SuiteInvariants: "remove the permission-bypass setting from policy (invariant 1); Halos never emits bypassPermissions or danger-full-access",
		SuiteImpact:     "review who is affected with `halo plan --policy-dir " + dir + " --diff " + rep.Against + "`; split the change across rings, or raise --max-impact after a human reviewed the blast radius",
		SuiteCases:      "a case disagrees with the policy: `halo whoami --policy-dir " + dir + " --user <user> --groups <groups>` shows the real ring and variants; fix the policy or the expectation",
		SuiteRollout:    "the rollout cannot complete on healthy evidence: `halo rollout plan <name> --policy-dir " + dir + "` shows its gates",
	}
	for _, s := range suiteOrder {
		if failed[s] {
			out = append(out, hint[s])
		}
	}
	if !rep.OK {
		return append(out, "rerun `halo test --policy-dir "+dir+"` until every check passes")
	}
	if rep.Against == "" {
		out = append(out, "before a PR: `halo test --policy-dir "+dir+" --against main` previews who the change reaches")
	}
	if !slices.ContainsFunc(rep.Results, func(x Result) bool { return x.Suite == SuiteCases }) {
		out = append(out, "no policy tests found: add PolicyTest documents under "+policy.TestsDir+"/ to pin who gets which ring, variant and setting (schemas/policytest.schema.json)")
	}
	if r.org != nil && len(r.org.Rollouts) > 0 {
		out = append(out, fmt.Sprintf("explore a rollout with failing evidence: `halo rollout simulate %s --scenario regression --policy-dir %s`", r.org.Rollouts[0].Name, dir))
	}
	out = append(out, "offline checks pass: the next tiers are `halo eval run` (Docker and provider keys) and a ring1 experiment; a human approves each")
	return out
}

func shellQuote(s string) string {
	if s != "" && strings.Trim(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._/-") == "" {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
