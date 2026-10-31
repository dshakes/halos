package server

import (
	"fmt"
	"io/fs"
	"log/slog"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dshakes/halos/internal/policy"
	"github.com/dshakes/halos/internal/storage"
)

// policyHolder loads the policy dir and reloads it when any file's mtime/size
// changes (checked per request) or after Invalidate (SIGHUP).
type policyHolder struct {
	dir string
	log *slog.Logger

	// sigs coalesces the per-request directory walk: concurrent reads share one
	// walk that started after the latest of them arrived (so a file changed
	// before a request is seen by it), and the walk runs outside mu.
	sigs    storage.Coalescer
	sigMu   sync.Mutex
	lastSig string

	mu sync.Mutex
	// org is the policy in effect: good, or good narrowed by a refused
	// policy's workload rule removals (policy.TightenWorkloads).
	org   *policy.Org
	good  *policy.Org // the last policy that passed policy.SecurityIssues
	view  PolicyView
	sig   string
	force bool
	err   error
	// refused counts loads refused by policy.SecurityIssues.
	refused atomic.Uint64
	// tightened counts refused loads whose workload rule removals were applied.
	tightened atomic.Uint64
	// skipped is the number of workload rules in the policy in effect that pin
	// no tenant, so the exchange never matches them (a gauge, set per load).
	skipped atomic.Int64
}

// Invalidate forces a reload on the next read.
func (p *policyHolder) Invalidate() { p.mu.Lock(); p.force = true; p.mu.Unlock() }

func dirSig(dir string) string {
	var latest time.Time
	var n, size int64
	if r, err := filepath.EvalSymlinks(dir); err == nil { // git-sync: dir is a symlink to the current worktree
		dir = r
	}
	_ = filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if fi, err := d.Info(); err == nil {
			n++
			size += fi.Size()
			if fi.ModTime().After(latest) {
				latest = fi.ModTime()
			}
		}
		return nil
	})
	return fmt.Sprint(latest.UnixNano(), "/", n, "/", size)
}

// currentSig is dirSig(p.dir) as of a walk that began after this call did. A
// request walking the tree alone costs a ReadDir and an lstat per file under
// the holder's lock, which capped every route that reads the policy (ring
// lookups, enrollment, launch) at one walk at a time.
func (p *policyHolder) currentSig() string {
	_ = p.sigs.Do(func() error {
		s := dirSig(p.dir)
		p.sigMu.Lock()
		p.lastSig = s
		p.sigMu.Unlock()
		return nil
	})
	// A later walk may have replaced lastSig by now; it began after this call too.
	p.sigMu.Lock()
	defer p.sigMu.Unlock()
	return p.lastSig
}

// Get returns the current org (nil + error if the dir has never loaded).
// A failed reload keeps serving the last good policy and returns its error.
// A policy refused for security validation errors still removes workload
// rules (policy.TightenWorkloads): the rules in effect become the last good
// policy's rules that the refused one still has unchanged.
func (p *policyHolder) Get() (*policy.Org, PolicyView, error) {
	sig := p.currentSig()
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.force || sig != p.sig || p.org == nil && p.err == nil {
		p.force, p.sig = false, sig
		org, err := policy.Load(p.dir)
		if err == nil {
			if iss := policy.SecurityIssues(org); len(iss) > 0 {
				p.refused.Add(1)
				err = fmt.Errorf("policy refused (keeping the last good policy): %d security validation error(s), first: %s", len(iss), iss[0])
				p.tighten(org)
			}
		}
		if err != nil {
			p.err = err
			p.log.Error("policy reload failed", "dir", p.dir, "err", err)
		} else {
			p.err, p.org, p.good = nil, org, org
			p.activate()
			p.log.Info("policy loaded", "org", org.Name, "rings", len(org.Rings), "experiments", len(org.Experiments))
		}
	}
	return p.org, p.view, p.err
}

// tighten applies a refused policy's workload rule removals to the last good
// policy (none loaded yet: nothing to narrow).
func (p *policyHolder) tighten(refused *policy.Org) {
	t, dropped := policy.TightenWorkloads(p.good, refused)
	if t == nil || t == p.org {
		return
	}
	p.org = t
	p.activate()
	if len(dropped) > 0 {
		p.tightened.Add(1)
		p.log.Warn("policy refused, but its workload rule removals are applied: these last-good rules are gone or changed in it and no longer match",
			"rules", dropped)
	}
}

// activate refreshes what derives from p.org: the view and the skipped-rule gauge.
func (p *policyHolder) activate() {
	p.view = buildPolicyView(p.org)
	skipped := p.org.Workloads.UnpinnedRules()
	p.skipped.Store(int64(len(skipped)))
	if len(skipped) > 0 { // unreachable after SecurityIssues; defence in depth
		p.log.Error("workload rules skipped: they pin no tenant", "rules", skipped)
	}
}

// PolicyView is the JSON shape of GET /api/v1/policy.
type PolicyView struct {
	Org         string           `json:"org"`
	Gateway     *policy.Gateway  `json:"gateway,omitempty"`
	Rings       []RingView       `json:"rings"`
	Profiles    []string         `json:"profiles"`
	Experiments []ExperimentView `json:"experiments"`
	Issues      []IssueView      `json:"issues"`
}

type RingView struct {
	Name       string            `json:"name"`
	Order      int               `json:"order"`
	Profile    string            `json:"profile"`
	Release    string            `json:"release,omitempty"`
	Membership policy.Membership `json:"membership"`
	Resolved   *policy.Profile   `json:"resolved,omitempty"`
	Error      string            `json:"error,omitempty"`
}

type ExperimentView struct {
	Name     string                `json:"name"`
	Type     policy.ExperimentType `json:"type"`
	Axis     policy.Axis           `json:"axis"`
	Status   string                `json:"status"`
	Rings    []string              `json:"rings"`
	Variants []policy.Variant      `json:"variants"`
	Sample   float64               `json:"sampleRate,omitempty"`
	Metrics  policy.Metrics        `json:"metrics"`
	Stopping policy.Stopping       `json:"stopping"`
}

type IssueView struct {
	Severity string `json:"severity"`
	Path     string `json:"path"`
	Message  string `json:"message"`
}

func buildPolicyView(o *policy.Org) PolicyView {
	v := PolicyView{Org: o.Name, Gateway: o.Gateway, Rings: []RingView{}, Profiles: []string{}, Experiments: []ExperimentView{}, Issues: []IssueView{}}
	for n := range o.Profiles {
		v.Profiles = append(v.Profiles, n)
	}
	sort.Strings(v.Profiles)
	for _, r := range o.Rings {
		rv := RingView{Name: r.Name, Order: r.Order, Profile: r.Profile, Release: r.Release, Membership: r.Membership}
		if p, err := o.ResolveProfile(r.Profile); err != nil {
			rv.Error = err.Error()
		} else {
			rv.Resolved = redact(p)
		}
		v.Rings = append(v.Rings, rv)
	}
	for _, e := range o.Experiments {
		st := e.Status
		if st == "" {
			st = "draft"
		}
		v.Experiments = append(v.Experiments, ExperimentView{e.Name, e.Type, e.Axis, st, e.Rings, e.Variants, e.SampleRate, e.Metrics, e.Stopping})
	}
	for _, i := range o.Validate() {
		v.Issues = append(v.Issues, IssueView{string(i.Severity), i.Path, i.Message})
	}
	return v
}

// redact masks values that may be credentials on a copy of p: every MCP
// header and Env value, and harness override string leaves that look secret.
func redact(p *policy.Profile) *policy.Profile {
	c := *p
	c.MCP.Servers = append([]policy.MCPServer(nil), p.MCP.Servers...)
	for i, s := range c.MCP.Servers {
		c.MCP.Servers[i].Headers = maskAll(s.Headers)
	}
	c.Env = maskAll(p.Env)
	if p.Harnesses != nil {
		c.Harnesses = make(map[string]policy.HarnessSpec, len(p.Harnesses))
		for k, h := range p.Harnesses {
			if h.Overrides != nil {
				h.Overrides = redactAny(h.Overrides).(map[string]any)
			}
			c.Harnesses[k] = h
		}
	}
	return &c
}

func maskAll(m map[string]string) map[string]string {
	if len(m) == 0 {
		return m
	}
	out := make(map[string]string, len(m))
	for k := range m {
		out[k] = "***"
	}
	return out
}

// redactAny deep-copies v, masking string leaves that look like credentials.
func redactAny(v any) any {
	switch x := v.(type) {
	case string:
		if policy.LooksSecret(x) {
			return "***"
		}
		return x
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[k] = redactAny(e)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = redactAny(e)
		}
		return out
	}
	return v
}
